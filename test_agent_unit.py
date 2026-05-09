"""Agent 단위 테스트 (LLM 없이 코어 로직 검증)"""

from agent import _extract_sql, ThreatIntelAgent


def test_extract_sql():
    assert _extract_sql("```sql\nSELECT 1;\n```") == "SELECT 1;"
    assert _extract_sql("```\nSELECT 2\n```") == "SELECT 2"
    assert _extract_sql("Some text\n```sql\nSELECT 3;\n```\nMore text") == "SELECT 3;"
    assert _extract_sql("SELECT 4 FROM t WHERE x = 1;") == "SELECT 4 FROM t WHERE x = 1;"
    assert _extract_sql("No SQL here") is None
    print("_extract_sql: passed")


def test_agent_schema():
    agent = ThreatIntelAgent()
    schema = agent.schema
    assert "otx_threat_intel" in schema
    assert "malicious_ips" in schema
    assert "CVE" in schema or "cve" in schema
    print("agent.schema: passed")


if __name__ == "__main__":
    test_extract_sql()
    test_agent_schema()
