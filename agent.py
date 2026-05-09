"""에이전트 코어: NL → SQL → Verify → Execute → Self-correct → Analysis"""

import json
import re
from typing import Any

from db_client import DBClient
from llm_client import LLMClient
from prompt_builder import (
    build_analysis_prompt,
    build_empty_result_prompt,
    build_sql_prompt,
    build_verification_prompt,
)
from config import MAX_SQL_RETRIES, USE_LANGGRAPH, USE_VANNA
from vanna_client import VannaTextToSQL, VannaUnavailable
from agent_graph import build_threat_workflow


def _extract_sql(text: str) -> str | None:
    """응답에서 ```sql ... ``` 또는 ``` ... ``` 코드 블록 추출"""
    match = re.search(r"```sql\s*(.*?)\s*```", text, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip()

    match = re.search(r"```\s*(.*?)\s*```", text, re.DOTALL)
    if match:
        return match.group(1).strip()

    lines = text.splitlines()
    sql_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped.upper().startswith(("SELECT", "WITH")) or sql_lines:
            sql_lines.append(stripped)
            if stripped.endswith(";"):
                break
    if sql_lines:
        return "\n".join(sql_lines).strip()
    return None


def _extract_json_object(text: str) -> dict[str, Any] | None:
    """LLM 응답에서 JSON object를 최대한 안전하게 추출한다."""
    if not text:
        return None
    raw = text.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
    raw = re.sub(r"\s*```$", "", raw)

    candidates = [raw]
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if match:
        candidates.append(match.group(0))

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue
    return None


def _boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "y", "1", "valid", "retry"}
    return bool(value)


class ThreatIntelAgent:
    """자연어 위협 인텔리전스 분석 에이전트"""

    def __init__(
        self,
        db_client: DBClient | None = None,
        llm_client: LLMClient | None = None,
        vanna_client: VannaTextToSQL | None = None,
        use_vanna: bool = USE_VANNA,
        use_langgraph: bool = USE_LANGGRAPH,
    ):
        self.db = db_client or DBClient()
        self.llm = llm_client or LLMClient()
        # Tests and offline tools often inject a fake LLM. Keep those deterministic
        # unless a Vanna client is explicitly supplied.
        self.use_vanna = use_vanna and (llm_client is None or vanna_client is not None)
        self.vanna = vanna_client if vanna_client is not None else (
            VannaTextToSQL(schema_provider=lambda: self.schema) if self.use_vanna else None
        )
        self.use_langgraph = use_langgraph
        self.workflow = build_threat_workflow(self) if self.use_langgraph else None
        self._schema: str | None = None

    @staticmethod
    def extract_sql(text: str) -> str | None:
        return _extract_sql(text)

    @property
    def schema(self) -> str:
        if self._schema is None:
            self._schema = self.db.get_schema()
        return self._schema

    def _verify_sql_intent(self, question: str, sql: str) -> dict[str, Any]:
        """생성 SQL이 질문 의도를 반영하는지 LLM으로 검증하고 필요 시 수정 SQL을 받는다."""
        prompt = build_verification_prompt(self.schema, question, sql)
        raw = self.llm.chat_completion(None, prompt)
        parsed = _extract_json_object(raw) or {}

        valid = _boolish(parsed.get("valid", False))
        corrected_sql = parsed.get("corrected_sql") or None
        if corrected_sql:
            extracted = _extract_sql(str(corrected_sql))
            corrected_sql = extracted or str(corrected_sql).strip()

        return {
            "valid": valid,
            "reason": str(parsed.get("reason") or "검증 응답을 해석할 수 없어 보수적으로 재검토가 필요합니다."),
            "corrected_sql": corrected_sql,
            "raw": raw,
        }

    def _handle_empty_result(self, question: str, sql: str, columns: list[str]) -> dict[str, Any]:
        """0건 결과가 질문 의도/데이터 표현 차이 때문인지 점검하고 fallback SQL을 요청한다."""
        prompt = build_empty_result_prompt(self.schema, question, sql, columns)
        raw = self.llm.chat_completion(None, prompt)
        parsed = _extract_json_object(raw) or {}
        retry = _boolish(parsed.get("retry", False))
        fallback_sql = parsed.get("sql") or parsed.get("fallback_sql") or None
        if fallback_sql:
            extracted = _extract_sql(str(fallback_sql))
            fallback_sql = extracted or str(fallback_sql).strip()

        return {
            "retry": retry and bool(fallback_sql),
            "reason": str(parsed.get("reason") or "0건 결과에 대한 추가 재조회가 필요하지 않습니다."),
            "sql": fallback_sql,
            "raw": raw,
        }

    def _generate_sql(self, question: str) -> tuple[str | None, dict[str, Any]]:
        """Generate SQL with Vanna first, then fall back to the legacy prompt chain."""
        metadata: dict[str, Any] = {"source": "legacy_prompt", "fallback_reason": None}
        if self.use_vanna and self.vanna is not None:
            try:
                sql = self.vanna.generate_sql(question, schema=self.schema)
                extracted = _extract_sql(sql) or sql.strip()
                return extracted, {"source": "vanna", "fallback_reason": None}
            except VannaUnavailable as e:
                metadata["fallback_reason"] = str(e)
            except Exception as e:
                metadata["fallback_reason"] = f"Vanna SQL 생성 실패: {e}"

        sql_prompt = build_sql_prompt(self.schema, question)
        raw_sql_response = self.llm.chat_completion(None, sql_prompt)
        return _extract_sql(raw_sql_response), metadata

    def train_sql_example(self, question: str, sql: str) -> dict[str, Any]:
        """Persist an approved question-SQL pair into Vanna memory."""
        if self.vanna is None:
            self.vanna = VannaTextToSQL(schema_provider=lambda: self.schema)
        ok = self.vanna.train_success(question, sql)
        return {
            "trained": ok,
            "message": "Vanna 학습 데이터에 반영했습니다." if ok else "Vanna 학습 반영에 실패했습니다.",
            "error": None if ok else self.vanna.last_error,
        }

    def run(self, question: str) -> dict[str, Any]:
        """동기 실행 API. 내부적으로 streaming workflow를 소비해 최종 결과만 반환한다."""
        final_result: dict[str, Any] | None = None
        for event in self.run_stream(question):
            if event.get("type") == "final":
                final_result = event["result"]
            elif event.get("type") == "error":
                final_result = event["result"]
        return final_result or {"question": question, "error": "워크플로가 최종 결과를 반환하지 못했습니다.", "trace": []}

    def run_stream(self, question: str):
        """
        단계별 이벤트를 yield하는 실행 API.
        Web UI는 이 이벤트를 받아 SQL 생성/검증/실행/분석 진행 상황을 실시간 표시한다.
        """
        if self.workflow is not None:
            started_events = {
                "generate_sql": {
                    "type": "step",
                    "step": "generate_sql",
                    "status": "started",
                    "detail": "스키마와 학습 예시를 참고해 질문에 맞는 SQL 후보를 생성합니다.",
                    "message": "SQL 생성 중",
                },
                "verify_sql": {
                    "type": "step",
                    "step": "verify_sql",
                    "status": "started",
                    "detail": "질문 의도와 SQL 조건, 테이블, 집계 기준이 일치하는지 검증합니다.",
                    "message": "SQL 의도 검증 중",
                },
                "execute_sql": {
                    "type": "step",
                    "step": "execute_sql",
                    "status": "started",
                    "detail": "읽기 전용 안전 검증 후 PostgreSQL에서 쿼리를 실행합니다.",
                    "message": "SQL 실행 중",
                },
                "handle_empty_result": {
                    "type": "step",
                    "step": "empty_result_check",
                    "status": "started",
                    "detail": "조회 결과가 비어 있거나 조건 보정이 필요한지 점검합니다.",
                    "message": "빈 결과 검증 중",
                },
                "analyze_results": {
                    "type": "step",
                    "step": "analyze_results",
                    "status": "started",
                    "detail": "조회 결과를 보안 분석 관점의 리포트로 요약합니다.",
                    "message": "분석 리포트 작성 중",
                },
            }
            next_nodes = {
                "generate_sql": "verify_sql",
                "verify_sql": "execute_sql",
                "execute_sql": "handle_empty_result",
                "handle_empty_result": "analyze_results",
            }
            initial = {
                "question": question,
                "sql": None,
                "rows": None,
                "columns": None,
                "analysis": None,
                "verification": None,
                "empty_result_check": None,
                "sql_source": None,
                "trace": [],
                "error": None,
            }
            result: dict[str, Any] = dict(initial)
            emitted_trace_count = 0
            yield started_events["generate_sql"]
            for chunk in self.workflow.stream(initial, stream_mode="updates"):
                if not isinstance(chunk, dict):
                    continue
                node_name, update = next(iter(chunk.items()))
                if not isinstance(update, dict):
                    continue
                result.update(update)
                trace = result.get("trace") or []
                for step in trace[emitted_trace_count:]:
                    yield {"type": "step", **step}
                emitted_trace_count = len(trace)

                if result.get("error"):
                    yield {"type": "error", "result": result}
                    return

                next_node = next_nodes.get(node_name)
                if next_node:
                    yield started_events[next_node]

            if result.get("error"):
                yield {"type": "error", "result": result}
            else:
                yield {"type": "final", "result": result}
            return

        trace: list[dict[str, Any]] = []
        result: dict[str, Any] = {
            "question": question,
            "sql": None,
            "rows": None,
            "columns": None,
            "analysis": None,
            "verification": None,
            "empty_result_check": None,
            "sql_source": None,
            "trace": trace,
            "error": None,
        }

        yield {"type": "step", "step": "generate_sql", "status": "started", "message": "SQL 생성 중"}
        sql, generation = self._generate_sql(question)
        result["sql_source"] = generation["source"]
        step = {
            "step": "generate_sql",
            "status": "ok" if sql else "failed",
            "sql": sql,
            "source": generation["source"],
            "fallback_reason": generation.get("fallback_reason"),
            "message": "SQL 생성 완료" if sql else "SQL 생성 실패",
        }
        trace.append(step)
        yield {"type": "step", **step}

        if not sql:
            result["error"] = "LLM이 유효한 SQL을 생성하지 못했습니다."
            yield {"type": "error", "result": result}
            return

        yield {"type": "step", "step": "verify_sql", "status": "started", "message": "SQL 의도 검증 중"}
        verification = self._verify_sql_intent(question, sql)
        if not verification["valid"] and verification.get("corrected_sql"):
            sql = verification["corrected_sql"]
            verification["valid"] = True
            step = {"step": "verify_sql", "status": "corrected", "reason": verification["reason"], "sql": sql, "message": "SQL 의도 검증 후 자기수정 완료"}
        else:
            step = {"step": "verify_sql", "status": "passed" if verification["valid"] else "needs_review", "reason": verification["reason"], "message": "SQL 의도 검증 완료"}
        trace.append(step)
        result["verification"] = verification
        result["sql"] = sql
        yield {"type": "step", **step}

        rows = None
        columns = None
        execution_error = None

        for attempt in range(MAX_SQL_RETRIES + 1):
            yield {"type": "step", "step": "execute_sql", "status": "started", "attempt": attempt + 1, "message": "SQL 실행 중"}
            try:
                rows, columns = self.db.execute_query(sql)
                step = {"step": "execute_sql", "status": "ok", "attempt": attempt + 1, "row_count": len(rows or []), "message": "SQL 실행 완료"}
                trace.append(step)
                yield {"type": "step", **step}
                break
            except Exception as e:
                execution_error = str(e)
                step = {"step": "execution_error", "status": "retrying" if attempt < MAX_SQL_RETRIES else "failed", "attempt": attempt + 1, "error": execution_error, "message": "SQL 실행 오류 감지"}
                trace.append(step)
                yield {"type": "step", **step}
                if attempt < MAX_SQL_RETRIES:
                    yield {"type": "step", "step": "regenerate_sql", "status": "started", "message": "오류 기반 SQL 재생성 중"}
                    feedback = (
                        "이전에 생성한 SQL을 실행하니 다음 오류가 발생했습니다:\n"
                        f"{execution_error}\n\n"
                        f"원래 질문: {question}\n"
                        f"실패 SQL: {sql}\n\n"
                        "오류를 수정하여 SELECT SQL만 다시 작성해주세요."
                    )
                    raw_sql_response = self.llm.chat_completion(None, feedback)
                    new_sql = _extract_sql(raw_sql_response)
                    if new_sql:
                        sql = new_sql
                        result["sql"] = sql
                        step = {"step": "regenerate_sql", "status": "ok", "sql": sql, "message": "SQL 재생성 완료"}
                        trace.append(step)
                        yield {"type": "step", **step}
                else:
                    result["error"] = f"SQL 실행 실패 (재시도 {MAX_SQL_RETRIES}회 초과): {execution_error}"
                    yield {"type": "error", "result": result}
                    return

        result["rows"] = rows
        result["columns"] = columns

        if rows == []:
            yield {"type": "step", "step": "empty_result_check", "status": "started", "message": "빈 결과 검증 중"}
            empty_check = self._handle_empty_result(question, sql, columns or [])
            result["empty_result_check"] = {**empty_check, "retried": False}
            if empty_check["retry"] and empty_check["sql"] and empty_check["sql"] != sql:
                try:
                    yield {"type": "step", "step": "empty_result_check", "status": "retrying", "reason": empty_check["reason"], "message": "fallback SQL 재조회 중"}
                    fallback_rows, fallback_columns = self.db.execute_query(empty_check["sql"])
                    sql = empty_check["sql"]
                    rows = fallback_rows
                    columns = fallback_columns
                    result["sql"] = sql
                    result["rows"] = rows
                    result["columns"] = columns
                    result["empty_result_check"]["retried"] = True
                    step = {"step": "empty_result_check", "status": "retried", "reason": empty_check["reason"], "row_count": len(fallback_rows or []), "message": "빈 결과 fallback 재조회 완료"}
                    trace.append(step)
                    yield {"type": "step", **step}
                except Exception as e:
                    step = {"step": "empty_result_check", "status": "fallback_failed", "reason": empty_check["reason"], "error": str(e), "message": "fallback SQL 실행 실패"}
                    trace.append(step)
                    yield {"type": "step", **step}
            else:
                step = {"step": "empty_result_check", "status": "not_retried", "reason": empty_check["reason"], "message": "빈 결과 검증 완료"}
                trace.append(step)
                yield {"type": "step", **step}
        else:
            result["empty_result_check"] = {"retry": False, "retried": False, "reason": "결과가 존재하므로 fallback 재조회가 필요하지 않습니다."}
            step = {"step": "empty_result_check", "status": "skipped", "reason": result["empty_result_check"]["reason"], "message": "결과 검증 완료"}
            trace.append(step)
            yield {"type": "step", **step}

        yield {"type": "step", "step": "analyze_results", "status": "started", "message": "분석 리포트 작성 중"}
        results_str = _format_results_for_llm(rows, columns or [])
        analysis_prompt = build_analysis_prompt(question, sql, results_str)
        analysis = self.llm.chat_completion(None, analysis_prompt)
        result["analysis"] = analysis
        step = {"step": "analyze_results", "status": "ok", "message": "분석 리포트 작성 완료"}
        trace.append(step)
        yield {"type": "step", **step}
        yield {"type": "final", "result": result}


def _format_results_for_llm(rows: list[dict] | None, columns: list[str]) -> str:
    """LLM에 전달할 결과 문자열 포맷팅 (너무 길면 자름)"""
    if rows is None:
        return "(결과 없음)"
    max_rows = 100
    trimmed = rows[:max_rows]
    lines = [str(dict(r)) for r in trimmed]
    if len(rows) > max_rows:
        lines.append(f"... ({len(rows) - max_rows}행 생략)")
    return "\n".join(lines)
