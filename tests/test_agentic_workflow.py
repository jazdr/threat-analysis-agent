import unittest

from agent import ThreatIntelAgent


class FakeDB:
    def __init__(self, responses):
        self.responses = list(responses)
        self.executed = []

    def get_schema(self):
        return "-- Table: malicious_ips\n  ip text\n  threat_severity text\n  malicious_votes integer\n"

    def execute_query(self, sql):
        self.executed.append(sql)
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class FakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts = []

    def chat_completion(self, system_prompt, user_prompt):
        self.prompts.append(user_prompt)
        return self.responses.pop(0)


class FakeVanna:
    def __init__(self, sql=None, error=None):
        self.sql = sql
        self.error = error
        self.trained = []

    def generate_sql(self, question, schema=None):
        if self.error:
            raise self.error
        return self.sql

    def train_success(self, question, sql):
        self.trained.append((question, sql))
        return True


class AgenticWorkflowTests(unittest.TestCase):
    def test_vanna_can_generate_initial_sql(self):
        db = FakeDB([
            ([{"high_risk_ip_count": 12}], ["high_risk_ip_count"]),
        ])
        llm = FakeLLM([
            '{"valid": true, "reason": "질문 의도와 SQL이 일치합니다.", "corrected_sql": null}',
            "요약\n- High 악성 IP는 12개입니다.",
        ])
        vanna = FakeVanna("SELECT COUNT(*) AS high_risk_ip_count FROM malicious_ips WHERE threat_severity = 'High';")

        result = ThreatIntelAgent(db_client=db, llm_client=llm, vanna_client=vanna).run("High 악성 IP 수")

        self.assertIsNone(result["error"])
        self.assertEqual(result["sql_source"], "vanna")
        self.assertEqual(db.executed, ["SELECT COUNT(*) AS high_risk_ip_count FROM malicious_ips WHERE threat_severity = 'High';"])
        self.assertEqual(result["trace"][0]["tables"], ["malicious_ips"])
        self.assertIn("SQL 후보", result["trace"][0]["detail"])
        self.assertEqual(result["trace"][2]["columns"], ["high_risk_ip_count"])

    def test_vanna_failure_falls_back_to_legacy_prompt(self):
        db = FakeDB([
            ([{"high_risk_ip_count": 12}], ["high_risk_ip_count"]),
        ])
        llm = FakeLLM([
            "```sql\nSELECT COUNT(*) AS high_risk_ip_count FROM malicious_ips WHERE threat_severity = 'High';\n```",
            '{"valid": true, "reason": "질문 의도와 SQL이 일치합니다.", "corrected_sql": null}',
            "요약\n- High 악성 IP는 12개입니다.",
        ])
        vanna = FakeVanna(error=RuntimeError("vanna unavailable"))

        result = ThreatIntelAgent(db_client=db, llm_client=llm, vanna_client=vanna).run("High 악성 IP 수")

        self.assertIsNone(result["error"])
        self.assertEqual(result["sql_source"], "legacy_prompt")
        self.assertIn("vanna unavailable", result["trace"][0]["fallback_reason"])

    def test_approved_sql_can_be_trained_into_vanna_memory(self):
        vanna = FakeVanna()
        agent = ThreatIntelAgent(db_client=FakeDB([]), llm_client=FakeLLM([]), vanna_client=vanna)

        result = agent.train_sql_example("High 악성 IP 수", "SELECT COUNT(*) FROM malicious_ips;")

        self.assertTrue(result["trained"])
        self.assertEqual(vanna.trained, [("High 악성 IP 수", "SELECT COUNT(*) FROM malicious_ips;")])

    def test_semantic_verification_can_correct_sql_before_execution(self):
        db = FakeDB([
            ([{"high_risk_ip_count": 12}], ["high_risk_ip_count"]),
        ])
        llm = FakeLLM([
            "```sql\nSELECT COUNT(*) AS cnt FROM malicious_domains;\n```",
            '{"valid": false, "reason": "질문은 악성 IP를 묻지만 SQL은 도메인 테이블을 조회합니다.", "corrected_sql": "SELECT COUNT(*) AS high_risk_ip_count FROM malicious_ips WHERE threat_severity = \'High\';"}',
            "요약\n- High 악성 IP는 12개입니다.",
        ])

        result = ThreatIntelAgent(db_client=db, llm_client=llm).run("심각도가 High인 악성 IP가 몇 개인가요?")

        self.assertIsNone(result["error"])
        self.assertEqual(db.executed, ["SELECT COUNT(*) AS high_risk_ip_count FROM malicious_ips WHERE threat_severity = 'High';"])
        self.assertEqual(result["sql"], "SELECT COUNT(*) AS high_risk_ip_count FROM malicious_ips WHERE threat_severity = 'High';")
        self.assertTrue(result["verification"]["valid"])
        self.assertIn("질문은 악성 IP", result["verification"]["reason"])
        self.assertEqual([step["step"] for step in result["trace"]], ["generate_sql", "verify_sql", "execute_sql", "empty_result_check", "analyze_results"])

    def test_empty_result_can_trigger_fallback_sql_and_reexecution(self):
        db = FakeDB([
            ([], ["ip", "threat_severity"]),
            ([{"ip": "1.2.3.4", "threat_severity": "High"}], ["ip", "threat_severity"]),
        ])
        llm = FakeLLM([
            "```sql\nSELECT ip, threat_severity FROM malicious_ips WHERE threat_severity = 'HIGH';\n```",
            '{"valid": true, "reason": "질문 의도와 테이블/컬럼이 일치합니다.", "corrected_sql": null}',
            '{"retry": true, "reason": "데이터는 High 대소문자 값을 사용할 수 있어 원문 조건으로 재시도합니다.", "sql": "SELECT ip, threat_severity FROM malicious_ips WHERE threat_severity = \'High\';"}',
            "요약\n- High 악성 IP 1건이 조회되었습니다.",
        ])

        result = ThreatIntelAgent(db_client=db, llm_client=llm).run("High 심각도 악성 IP를 보여줘")

        self.assertIsNone(result["error"])
        self.assertEqual(len(result["rows"]), 1)
        self.assertEqual(db.executed, [
            "SELECT ip, threat_severity FROM malicious_ips WHERE threat_severity = 'HIGH';",
            "SELECT ip, threat_severity FROM malicious_ips WHERE threat_severity = 'High';",
        ])
        self.assertEqual(result["empty_result_check"]["retried"], True)
        self.assertIn("empty_result_check", [step["step"] for step in result["trace"]])

    def test_run_stream_emits_live_step_events_before_final_result(self):
        db = FakeDB([
            ([{"high_risk_ip_count": 12}], ["high_risk_ip_count"]),
        ])
        llm = FakeLLM([
            "```sql\nSELECT COUNT(*) AS high_risk_ip_count FROM malicious_ips WHERE threat_severity = 'High';\n```",
            '{"valid": true, "reason": "질문 의도와 SQL이 일치합니다.", "corrected_sql": null}',
            "요약\n- High 악성 IP는 12개입니다.",
        ])

        events = list(ThreatIntelAgent(db_client=db, llm_client=llm).run_stream("심각도가 High인 악성 IP가 몇 개인가요?"))

        event_types = [event["type"] for event in events]
        self.assertEqual(event_types[-1], "final")
        self.assertIn("step", event_types)
        self.assertIn("generate_sql", [event.get("step") for event in events])
        self.assertIn("verify_sql", [event.get("step") for event in events])
        self.assertIn("execute_sql", [event.get("step") for event in events])
        self.assertIn("analyze_results", [event.get("step") for event in events])
        self.assertEqual(events[-1]["result"]["rows"], [{"high_risk_ip_count": 12}])

    def test_execution_error_retry_is_recorded_in_trace(self):
        db = FakeDB([
            RuntimeError("SQL 실행 오류: column severity does not exist"),
            ([{"high_risk_ip_count": 12}], ["high_risk_ip_count"]),
        ])
        llm = FakeLLM([
            "```sql\nSELECT COUNT(*) FROM malicious_ips WHERE severity = 'High';\n```",
            '{"valid": true, "reason": "악성 IP와 High 조건을 조회합니다.", "corrected_sql": null}',
            "```sql\nSELECT COUNT(*) AS high_risk_ip_count FROM malicious_ips WHERE threat_severity = 'High';\n```",
            "요약\n- High 악성 IP는 12개입니다.",
        ])

        result = ThreatIntelAgent(db_client=db, llm_client=llm).run("심각도가 High인 악성 IP가 몇 개인가요?")

        self.assertIsNone(result["error"])
        self.assertEqual(result["columns"], ["high_risk_ip_count"])
        self.assertIn("execution_error", [step["step"] for step in result["trace"]])
        self.assertIn("execute_sql", [step["step"] for step in result["trace"]])
        error_step = next(step for step in result["trace"] if step["step"] == "execution_error")
        self.assertEqual(error_step["attempt"], 1)
        self.assertIn("재생성", error_step["detail"])


if __name__ == "__main__":
    unittest.main()
