import tempfile
import unittest
from pathlib import Path

from metrics_store import MetricsStore


class MetricsStoreTests(unittest.TestCase):
    def test_summary_counts_recent_events_and_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MetricsStore(path=str(Path(tmp) / "events.jsonl"), max_recent=2)
            store.record({"type": "nl_query", "status": "success", "sql_source": "vanna", "elapsed_ms": 100, "row_count": 3})
            store.record({"type": "direct_sql", "status": "error", "elapsed_ms": 50, "error": "blocked"})
            store.record({"type": "nl_query", "status": "success", "sql_source": "legacy_prompt", "elapsed_ms": 200})

            summary = store.summary()

            self.assertEqual(summary["total_events"], 3)
            self.assertEqual(summary["successes"], 2)
            self.assertEqual(summary["failures"], 1)
            self.assertEqual(summary["by_type"]["nl_query"], 2)
            self.assertEqual(summary["by_sql_source"]["vanna"], 1)
            self.assertEqual(summary["top_errors"][0]["message"], "blocked")
            self.assertEqual(len(summary["recent_events"]), 2)


if __name__ == "__main__":
    unittest.main()
