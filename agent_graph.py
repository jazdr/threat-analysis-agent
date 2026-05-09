"""LangGraph workflow for ThreatIntelAgent."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any, TypedDict

from langgraph.graph import END, StateGraph
from langsmith import traceable

from config import MAX_SQL_RETRIES
from prompt_builder import build_analysis_prompt

if TYPE_CHECKING:
    from agent import ThreatIntelAgent


class ThreatWorkflowState(TypedDict, total=False):
    question: str
    sql: str | None
    rows: list[dict] | None
    columns: list[str] | None
    analysis: str | None
    verification: dict[str, Any] | None
    empty_result_check: dict[str, Any] | None
    sql_source: str | None
    trace: list[dict[str, Any]]
    error: str | None


def _append(state: ThreatWorkflowState, step: dict[str, Any]) -> ThreatWorkflowState:
    trace = list(state.get("trace") or [])
    trace.append(step)
    return {"trace": trace}


def _format_results_for_llm(rows: list[dict] | None) -> str:
    if rows is None:
        return "(결과 없음)"
    max_rows = 100
    trimmed = rows[:max_rows]
    lines = [str(dict(r)) for r in trimmed]
    if len(rows) > max_rows:
        lines.append(f"... ({len(rows) - max_rows}행 생략)")
    return "\n".join(lines)


def _extract_tables(sql: str | None) -> list[str]:
    if not sql:
        return []
    matches = re.findall(r"\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_.]*)", sql, re.IGNORECASE)
    return sorted({m.replace("public.", "") for m in matches})


def build_threat_workflow(agent: "ThreatIntelAgent"):
    graph = StateGraph(ThreatWorkflowState)

    @traceable(name="generate_sql")
    def generate_sql(state: ThreatWorkflowState) -> ThreatWorkflowState:
        question = state["question"]
        sql, generation = agent._generate_sql(question)
        step = {
            "step": "generate_sql",
            "status": "ok" if sql else "failed",
            "sql": sql,
            "source": generation["source"],
            "fallback_reason": generation.get("fallback_reason"),
            "detail": (
                f"{generation['source']} 경로로 SQL 후보를 생성했습니다."
                if sql else "SQL 후보를 추출하지 못했습니다."
            ),
            "tables": _extract_tables(sql),
            "sql_preview": (sql[:180] + "...") if sql and len(sql) > 180 else sql,
            "message": "SQL 생성 완료" if sql else "SQL 생성 실패",
        }
        update: ThreatWorkflowState = {
            "sql": sql,
            "sql_source": generation["source"],
            **_append(state, step),
        }
        if not sql:
            update["error"] = "LLM이 유효한 SQL을 생성하지 못했습니다."
        return update

    @traceable(name="verify_sql")
    def verify_sql(state: ThreatWorkflowState) -> ThreatWorkflowState:
        sql = state.get("sql")
        if not sql:
            return {}
        verification = agent._verify_sql_intent(state["question"], sql)
        if not verification["valid"] and verification.get("corrected_sql"):
            sql = verification["corrected_sql"]
            verification["valid"] = True
            step = {
                "step": "verify_sql",
                "status": "corrected",
                "reason": verification["reason"],
                "sql": sql,
                "detail": "검증자가 질문 의도와 SQL을 비교했고 수정 SQL을 적용했습니다.",
                "tables": _extract_tables(sql),
                "message": "SQL 의도 검증 후 자기수정 완료",
            }
        else:
            step = {
                "step": "verify_sql",
                "status": "passed" if verification["valid"] else "needs_review",
                "reason": verification["reason"],
                "detail": "질문 조건, 대상 테이블, 집계/정렬 요구사항 반영 여부를 검토했습니다.",
                "tables": _extract_tables(sql),
                "message": "SQL 의도 검증 완료",
            }
        return {"sql": sql, "verification": verification, **_append(state, step)}

    @traceable(name="execute_sql")
    def execute_sql(state: ThreatWorkflowState) -> ThreatWorkflowState:
        sql = state.get("sql")
        if not sql:
            return {}
        trace_state = state
        for attempt in range(MAX_SQL_RETRIES + 1):
            try:
                rows, columns = agent.db.execute_query(sql)
                step = {
                    "step": "execute_sql",
                    "status": "ok",
                    "attempt": attempt + 1,
                    "row_count": len(rows or []),
                    "columns": columns,
                    "detail": "SQL 안전 검증, read-only transaction, timeout, row limit을 통과해 실행했습니다.",
                    "tables": _extract_tables(sql),
                    "message": "SQL 실행 완료",
                }
                return {"rows": rows, "columns": columns, "sql": sql, **_append(trace_state, step)}
            except Exception as e:
                execution_error = str(e)
                step = {
                    "step": "execution_error",
                    "status": "retrying" if attempt < MAX_SQL_RETRIES else "failed",
                    "attempt": attempt + 1,
                    "error": execution_error,
                    "detail": "DB 실행 오류를 감지했고 오류 메시지를 기반으로 재생성 여부를 판단합니다.",
                    "tables": _extract_tables(sql),
                    "message": "SQL 실행 오류 감지",
                }
                trace_update = _append(trace_state, step)
                trace_state = {**trace_state, **trace_update}
                if attempt < MAX_SQL_RETRIES:
                    feedback = (
                        "이전에 생성한 SQL을 실행하니 다음 오류가 발생했습니다:\n"
                        f"{execution_error}\n\n"
                        f"원래 질문: {state['question']}\n"
                        f"실패 SQL: {sql}\n\n"
                        "오류를 수정하여 SELECT SQL만 다시 작성해주세요."
                    )
                    raw_sql_response = agent.llm.chat_completion(None, feedback)
                    new_sql = agent.extract_sql(raw_sql_response)
                    if new_sql:
                        sql = new_sql
                        regen_step = {
                            "step": "regenerate_sql",
                            "status": "ok",
                            "sql": sql,
                            "detail": "실행 오류 피드백을 LLM에 전달해 수정 SQL을 다시 생성했습니다.",
                            "tables": _extract_tables(sql),
                            "sql_preview": (sql[:180] + "...") if len(sql) > 180 else sql,
                            "message": "SQL 재생성 완료",
                        }
                        trace_update = _append(trace_state, regen_step)
                        trace_state = {**trace_state, "sql": sql, **trace_update}
                else:
                    return {
                        "sql": sql,
                        "error": f"SQL 실행 실패 (재시도 {MAX_SQL_RETRIES}회 초과): {execution_error}",
                        "trace": trace_state.get("trace") or [],
                    }
        return {}

    @traceable(name="handle_empty_result")
    def handle_empty_result(state: ThreatWorkflowState) -> ThreatWorkflowState:
        rows = state.get("rows")
        sql = state.get("sql")
        columns = state.get("columns") or []
        if rows == [] and sql:
            empty_check = agent._handle_empty_result(state["question"], sql, columns)
            result_check = {**empty_check, "retried": False}
            if empty_check["retry"] and empty_check["sql"] and empty_check["sql"] != sql:
                try:
                    fallback_rows, fallback_columns = agent.db.execute_query(empty_check["sql"])
                    step = {
                        "step": "empty_result_check",
                        "status": "retried",
                        "reason": empty_check["reason"],
                        "row_count": len(fallback_rows or []),
                        "detail": "0건 결과 원인을 점검했고 fallback SQL로 재조회했습니다.",
                        "tables": _extract_tables(empty_check["sql"]),
                        "message": "빈 결과 fallback 재조회 완료",
                    }
                    result_check["retried"] = True
                    return {
                        "sql": empty_check["sql"],
                        "rows": fallback_rows,
                        "columns": fallback_columns,
                        "empty_result_check": result_check,
                        **_append(state, step),
                    }
                except Exception as e:
                    step = {
                        "step": "empty_result_check",
                        "status": "fallback_failed",
                        "reason": empty_check["reason"],
                        "error": str(e),
                        "detail": "0건 fallback SQL 실행 중 오류가 발생했습니다.",
                        "tables": _extract_tables(empty_check.get("sql")),
                        "message": "fallback SQL 실행 실패",
                    }
                    return {"empty_result_check": result_check, **_append(state, step)}
            step = {
                "step": "empty_result_check",
                "status": "not_retried",
                "reason": empty_check["reason"],
                "detail": "0건 결과를 점검했지만 fallback 재조회 조건은 아니라고 판단했습니다.",
                "tables": _extract_tables(sql),
                "message": "빈 결과 검증 완료",
            }
            return {"empty_result_check": result_check, **_append(state, step)}

        empty_result_check = {"retry": False, "retried": False, "reason": "결과가 존재하므로 fallback 재조회가 필요하지 않습니다."}
        step = {
            "step": "empty_result_check",
            "status": "skipped",
            "reason": empty_result_check["reason"],
            "detail": f"{len(rows or [])}건이 조회되어 빈 결과 보정 단계를 건너뜁니다.",
            "tables": _extract_tables(sql),
            "message": "결과 검증 완료",
        }
        return {"empty_result_check": empty_result_check, **_append(state, step)}

    @traceable(name="analyze_results")
    def analyze_results(state: ThreatWorkflowState) -> ThreatWorkflowState:
        sql = state.get("sql")
        rows = state.get("rows")
        columns = state.get("columns") or []
        results_str = _format_results_for_llm(rows)
        analysis_prompt = build_analysis_prompt(state["question"], sql or "", results_str)
        analysis = agent.llm.chat_completion(None, analysis_prompt)
        step = {
            "step": "analyze_results",
            "status": "ok",
            "detail": "조회 결과를 최대 100행으로 요약해 보안 분석 리포트를 생성했습니다.",
            "row_count": len(rows or []),
            "columns": columns,
            "message": "분석 리포트 작성 완료",
        }
        return {"analysis": analysis, **_append(state, step)}

    def route_after_generate(state: ThreatWorkflowState) -> str:
        return END if state.get("error") else "verify_sql"

    def route_after_execute(state: ThreatWorkflowState) -> str:
        return END if state.get("error") else "handle_empty_result"

    graph.add_node("generate_sql", generate_sql)
    graph.add_node("verify_sql", verify_sql)
    graph.add_node("execute_sql", execute_sql)
    graph.add_node("handle_empty_result", handle_empty_result)
    graph.add_node("analyze_results", analyze_results)
    graph.set_entry_point("generate_sql")
    graph.add_conditional_edges("generate_sql", route_after_generate)
    graph.add_edge("verify_sql", "execute_sql")
    graph.add_conditional_edges("execute_sql", route_after_execute)
    graph.add_edge("handle_empty_result", "analyze_results")
    graph.add_edge("analyze_results", END)
    return graph.compile()
