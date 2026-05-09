"""프롬프트 템플릿 조립"""

from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent / "prompts"


def _load_template(name: str) -> str:
    path = _PROMPTS_DIR / name
    if path.exists():
        return path.read_text(encoding="utf-8")
    raise FileNotFoundError(f"프롬프트 템플릿을 찾을 수 없습니다: {path}")


def build_sql_prompt(schema: str, question: str) -> str:
    """스키마 + 질문 → SQL 생성 프롬프트"""
    template = _load_template("sql_generator.txt")
    return template.format(schema=schema, question=question)


def build_verification_prompt(schema: str, question: str, sql: str) -> str:
    """질문 + 스키마 + SQL → 의미 검증 프롬프트"""
    template = _load_template("sql_verifier.txt")
    return template.format(schema=schema, question=question, sql=sql)


def build_empty_result_prompt(schema: str, question: str, sql: str, columns: list[str]) -> str:
    """0건 결과 → fallback 재조회 판단 프롬프트"""
    template = _load_template("empty_result_handler.txt")
    return template.format(schema=schema, question=question, sql=sql, columns=", ".join(columns or []))


def build_analysis_prompt(question: str, sql: str, results: str) -> str:
    """질문 + SQL + 결과 → 분석 프롬프트"""
    template = _load_template("result_analyzer.txt")
    return template.format(question=question, sql=sql, results=results)
