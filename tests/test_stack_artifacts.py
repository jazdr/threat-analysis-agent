import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class StackArtifactsTests(unittest.TestCase):
    def test_langgraph_workflow_artifact_exists(self):
        graph = (ROOT / "agent_graph.py").read_text(encoding="utf-8")
        config = (ROOT / "config.py").read_text(encoding="utf-8")
        env = (ROOT / ".env.example").read_text(encoding="utf-8")
        self.assertIn("StateGraph", graph)
        self.assertIn("generate_sql", graph)
        self.assertIn("verify_sql", graph)
        self.assertIn("execute_sql", graph)
        self.assertIn("handle_empty_result", graph)
        self.assertIn("analyze_results", graph)
        self.assertIn("@traceable", graph)
        self.assertIn("LANGSMITH_TRACING_V2", config)
        self.assertIn("LANGCHAIN_TRACING_V2", config)
        self.assertIn("LANGSMITH_ENDPOINT", env)

    def test_ragas_eval_artifact_exists(self):
        eval_script = (ROOT / "eval" / "ragas_eval.py").read_text(encoding="utf-8")
        eval_set = json.loads((ROOT / "eval" / "eval_set.json").read_text(encoding="utf-8"))
        self.assertIn("SQLSemanticEquivalence", eval_script)
        self.assertIn("--ragas", eval_script)
        self.assertGreaterEqual(len(eval_set), 4)

    def test_colab_notebook_exists(self):
        notebook = json.loads((ROOT / "notebooks" / "threat_analysis_agent_colab.ipynb").read_text(encoding="utf-8"))
        source = "\n".join("".join(cell.get("source", [])) for cell in notebook["cells"])
        self.assertIn("pip install -r requirements.txt", source)
        self.assertIn("uvicorn web_app:app", source)
        self.assertIn("eval/ragas_eval.py", source)
        self.assertIn("scripts/import_cisa_kev.py", source)
        self.assertIn("LANGSMITH_API_KEY", source)

    def test_neon_gradio_colab_artifact_exists(self):
        helper = (ROOT / "colab_support" / "neon_gradio_threat_agent.py").read_text(encoding="utf-8")
        notebook = json.loads((ROOT / "notebooks" / "threat_intel_neon_gradio_colab.ipynb").read_text(encoding="utf-8"))
        source = "\n".join("".join(cell.get("source", [])) for cell in notebook["cells"])
        self.assertIn("load_csvs_to_neon", helper)
        self.assertIn("ensure_database", helper)
        self.assertIn("build_gradio_app", helper)
        self.assertIn("cisa_known_exploited_vulnerabilities", helper)
        self.assertIn("threat_intel_links", helper)
        self.assertIn("REFERENCES otx_threat_intel", helper)
        self.assertIn("CHECK", helper)
        self.assertIn("gpt-4o-mini", helper)
        self.assertIn("https://github.com/jazdr/threat-analysis-agent.git", source)
        self.assertIn("Neon DATABASE_URL", source)
        self.assertIn("threat_intel_agent", source)
        self.assertIn("table_counts()", source)
        self.assertIn("EXPECTED_ROWS", source)
        self.assertIn("(상관분석)", source)
        self.assertIn("demo.launch(share=True", source)

    def test_cisa_kev_import_artifact_exists(self):
        script = (ROOT / "scripts" / "import_cisa_kev.py").read_text(encoding="utf-8")
        docs = (ROOT / "training" / "schema_docs.md").read_text(encoding="utf-8")
        examples = json.loads((ROOT / "training" / "example_queries.json").read_text(encoding="utf-8"))
        self.assertIn("cisa_known_exploited_vulnerabilities", script)
        self.assertIn("execute_values", script)
        self.assertIn("CISA KEV 원본 카탈로그", docs)
        self.assertTrue(any("cisa_known_exploited_vulnerabilities" in item["sql"] for item in examples))


if __name__ == "__main__":
    unittest.main()
