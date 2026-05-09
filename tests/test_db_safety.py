import unittest

from db_client import DBClient


class QuerySafetyTests(unittest.TestCase):
    def test_allows_select_and_read_only_cte(self):
        self.assertTrue(DBClient.is_safe_query("SELECT COUNT(*) FROM malicious_ips;"))
        self.assertTrue(DBClient.is_safe_query("WITH high_ips AS (SELECT ip FROM malicious_ips) SELECT * FROM high_ips"))

    def test_rejects_non_select_statements(self):
        for sql in [
            "SHOW TABLES",
            "VACUUM",
            "EXPLAIN SELECT 1",
            "SET statement_timeout = 1",
            "DELETE FROM malicious_ips",
            "SELECT 1; SELECT 2;",
        ]:
            with self.subTest(sql=sql):
                self.assertFalse(DBClient.is_safe_query(sql))

    def test_rejects_blocking_functions_and_preserves_string_literals(self):
        self.assertFalse(DBClient.is_safe_query("SELECT pg_sleep(10)"))
        self.assertTrue(DBClient.is_safe_query("SELECT 'DROP TABLE is only text' AS note"))

    def test_wraps_safe_query_with_result_limit(self):
        wrapped = DBClient._apply_result_limit("SELECT ip FROM malicious_ips ORDER BY ip;", max_rows=25)
        self.assertIn("SELECT * FROM (", wrapped)
        self.assertIn("SELECT ip FROM malicious_ips ORDER BY ip", wrapped)
        self.assertTrue(wrapped.endswith("LIMIT 25"))


if __name__ == "__main__":
    unittest.main()
