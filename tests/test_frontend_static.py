import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "static" / "app.js"
INDEX_HTML = ROOT / "static" / "index.html"
ANALYZER_PROMPT = ROOT / "prompts" / "result_analyzer.txt"


class FrontendStaticTests(unittest.TestCase):
    def test_app_js_is_valid_javascript(self):
        result = subprocess.run(
            ["node", "--check", str(APP_JS)],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_report_renderer_supports_structured_markdown_and_removes_raw_bold_tokens(self):
        app = APP_JS.read_text(encoding="utf-8")
        self.assertIn("function _mdInline", app)
        self.assertIn("document.createElement('strong')", app)
        self.assertIn("normalizeAnalysis", app)
        self.assertIn("replace(/\\*\\*/g, '')", app)
        self.assertIn("핵심 인사이트", app)
        self.assertIn("권장 조치", app)

    def test_history_has_clear_button_state_and_metadata(self):
        app = APP_JS.read_text(encoding="utf-8")
        html = INDEX_HTML.read_text(encoding="utf-8")
        self.assertIn('id="clearHistoryBtn"', html)
        self.assertIn('<aside class="w-72', html)
        self.assertIn("clearHistoryBtn", app)
        self.assertIn("addHistoryItem", app)
        self.assertIn("rowCount", app)
        self.assertIn("formatRelativeTime", app)

    def test_agentic_trace_panel_is_rendered_and_persisted(self):
        app = APP_JS.read_text(encoding="utf-8")
        html = INDEX_HTML.read_text(encoding="utf-8")
        self.assertIn('id="traceSection"', html)
        self.assertIn('id="traceList"', html)
        self.assertIn("renderTrace", app)
        self.assertIn("traceMetaItems", app)
        self.assertIn("traceStatusText", app)
        self.assertIn("item.detail", app)
        self.assertIn("item.tables", app)
        self.assertIn("item.columns", app)
        self.assertIn("item.fallback_reason", app)
        self.assertIn("sql_preview", app)
        self.assertIn("data.trace", app)
        self.assertIn("item.trace", app)

    def test_sql_trust_panel_surfaces_verification_metadata(self):
        app = APP_JS.read_text(encoding="utf-8")
        html = INDEX_HTML.read_text(encoding="utf-8")
        self.assertIn('id="trustSection"', html)
        self.assertIn('id="trustBadge"', html)
        self.assertIn('id="trustTables"', html)
        self.assertIn("renderTrustPanel", app)
        self.assertIn("extractTables", app)
        self.assertIn("data.verification", app)
        self.assertIn("emptyResultCheck", app)

    def test_vanna_training_button_and_endpoint_are_wired(self):
        app = APP_JS.read_text(encoding="utf-8")
        html = INDEX_HTML.read_text(encoding="utf-8")
        web = (ROOT / "web_app.py").read_text(encoding="utf-8")
        self.assertIn("Vanna 학습", html)
        self.assertIn("trainCurrentSql", app)
        self.assertIn("/api/training/sql", app)
        self.assertIn("@app.post(\"/api/training/sql\")", web)
        self.assertIn("TrainSqlRequest", web)

    def test_question_input_supports_table_mentions(self):
        app = APP_JS.read_text(encoding="utf-8")
        html = INDEX_HTML.read_text(encoding="utf-8")
        self.assertIn('id="tableMentionMenu"', html)
        self.assertIn("handleQuestionInput", html)
        self.assertIn("handleQuestionKeydown", html)
        self.assertIn("event.isComposing", app)
        self.assertIn("event.keyCode === 229", app)
        self.assertIn("availableTables", app)
        self.assertIn("renderTableMentionMenu", app)
        self.assertIn("insertMentionTable", app)
        self.assertIn("getMentionState", app)

    def test_direct_sql_console_is_wired_to_safe_execute_endpoint(self):
        app = APP_JS.read_text(encoding="utf-8")
        html = INDEX_HTML.read_text(encoding="utf-8")
        web = (ROOT / "web_app.py").read_text(encoding="utf-8")
        self.assertIn('id="sqlConsole"', html)
        self.assertIn('id="sqlConsoleInput"', html)
        self.assertIn("executeRawSql", app)
        self.assertIn("/api/sql/execute", app)
        self.assertIn("@app.post(\"/api/sql/execute\")", web)
        self.assertIn("SqlExecuteRequest", web)
        self.assertIn("client.execute_query(req.sql)", web)

    def test_dashboard_panel_and_api_are_wired(self):
        app = APP_JS.read_text(encoding="utf-8")
        html = INDEX_HTML.read_text(encoding="utf-8")
        web = (ROOT / "web_app.py").read_text(encoding="utf-8")
        self.assertIn('id="dashboardSection"', html)
        self.assertIn("toggleDashboard", html)
        self.assertIn("loadDashboard", app)
        self.assertIn("renderDashboard", app)
        self.assertIn("refreshDashboardIfOpen", app)
        self.assertIn("/api/dashboard", app)
        self.assertIn("@app.get(\"/api/dashboard\")", web)
        self.assertIn("metrics.summary()", web)

    def test_result_explorer_supports_filter_sort_csv_and_row_detail(self):
        app = APP_JS.read_text(encoding="utf-8")
        html = INDEX_HTML.read_text(encoding="utf-8")
        self.assertIn('id="resultFilter"', html)
        self.assertIn('id="rowDetail"', html)
        self.assertIn("applyResultFilter", app)
        self.assertIn("setResultSort", app)
        self.assertIn("exportResultsCsv", app)
        self.assertIn("showRowDetail", app)
        self.assertIn("currentFilteredRows", app)
        self.assertIn("whitespace-normal break-words", app)
        self.assertIn("overflowWrap = 'anywhere'", app)

    def test_streaming_query_endpoint_and_frontend_stream_reader_exist(self):
        app = APP_JS.read_text(encoding="utf-8")
        web = (ROOT / "web_app.py").read_text(encoding="utf-8")
        self.assertIn('/api/query/stream', web)
        self.assertIn('StreamingResponse', web)
        self.assertIn('/api/query/stream', app)
        self.assertIn('readStreamEvents', app)
        self.assertIn('handleStreamEvent', app)
        self.assertIn('SQL 생성 중', app)

    def test_query_question_is_rendered_above_sql(self):
        app = APP_JS.read_text(encoding="utf-8")
        html = INDEX_HTML.read_text(encoding="utf-8")
        self.assertIn('id="questionSection"', html)
        self.assertIn('id="queryQuestion"', html)
        self.assertIn("max-w-4xl mx-auto relative", html)
        self.assertIn('renderQuestion', app)
        self.assertIn('renderQuestion(question)', app)
        self.assertIn('renderQuestion(item.question)', app)

    def test_cisa_kev_recommendation_chips_are_available(self):
        html = INDEX_HTML.read_text(encoding="utf-8")
        self.assertIn("최근 CISA KEV", html)
        self.assertIn("마감 임박 KEV", html)
        self.assertIn("랜섬웨어 KEV", html)
        self.assertIn("cisa_known_exploited_vulnerabilities", (ROOT / "training" / "example_queries.json").read_text(encoding="utf-8"))

    def test_analysis_loading_state_is_shown_during_streaming_analysis(self):
        app = APP_JS.read_text(encoding="utf-8")
        self.assertIn('renderAnalysisLoading', app)
        self.assertIn('분석 리포트 작성 중', app)
        self.assertIn("event.step === 'analyze_results'", app)

    def test_generated_sql_display_is_multiline_and_highlighted_like_editor(self):
        app = APP_JS.read_text(encoding="utf-8")
        html = INDEX_HTML.read_text(encoding="utf-8")
        prompt = (ROOT / "prompts" / "sql_generator.txt").read_text(encoding="utf-8")
        self.assertIn("formatSqlForDisplay", app)
        self.assertIn("highlightSql", app)
        self.assertIn("sql-keyword", app)
        self.assertIn("sql-string", app)
        self.assertIn("sql-keyword", html)
        self.assertIn("SELECT ip, country, owner, network, malicious_votes, reputation_score, threat_severity", prompt)
        self.assertIn("FROM malicious_ips", prompt)
        self.assertIn("WHERE threat_severity = 'High';", prompt)

    def test_analysis_prompt_requests_security_analyst_friendly_structure_without_markdown_bold(self):
        prompt = ANALYZER_PROMPT.read_text(encoding="utf-8")
        self.assertIn("마크다운 굵게 표시 문법", prompt)
        self.assertIn("사용하지 마세요", prompt)
        self.assertIn("핵심 인사이트", prompt)
        self.assertIn("우선 대응", prompt)
        self.assertIn("후속 조회", prompt)


if __name__ == "__main__":
    unittest.main()
