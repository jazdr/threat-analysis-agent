"""10개 샘플 쿼리 실행 검증"""

from db_client import DBClient

QUERIES = {
    "Q1 (Easy)": """
        SELECT COUNT(*) AS high_risk_ip_count
        FROM malicious_ips
        WHERE threat_severity = 'High';
    """,
    "Q2 (Easy)": """
        SELECT cve_id, vendor_project, product, vulnerability_name
        FROM cve_vulnerabilities
        WHERE date_added = '2026-04-28';
    """,
    "Q3 (Easy)": """
        SELECT domain, reputation, threat_severity, malicious_votes
        FROM malicious_domains
        WHERE data_source = 'VirusTotal'
        ORDER BY reputation ASC
        LIMIT 5;
    """,
    "Q4 (Medium)": """
        SELECT country,
               COUNT(*) AS malicious_ip_count,
               ROUND(AVG(reputation_score), 2) AS avg_reputation
        FROM malicious_ips
        WHERE malicious_votes > 0
        GROUP BY country
        ORDER BY malicious_ip_count DESC;
    """,
    "Q5 (Medium)": """
        WITH phishing_pulses AS (
            SELECT pulse_id, title, tags, attack_ids
            FROM otx_threat_intel
            WHERE LOWER(tags) LIKE '%phishing%'
        )
        SELECT DISTINCT c.cve_id, c.vendor_project, c.product, p.title
        FROM cve_vulnerabilities c
        JOIN phishing_pulses p
            ON LOWER(c.short_description) LIKE '%phish%'
        ORDER BY c.cve_id;
    """,
    "Q6 (Medium)": """
        SELECT cve_id, vendor_project, product, due_date, short_description
        FROM cve_vulnerabilities
        WHERE known_ransomware_campaign_use = 'Known'
           OR LOWER(short_description) LIKE '%ransomware%'
        ORDER BY due_date ASC
        LIMIT 5;
    """,
    "Q7 (Medium)": """
        SELECT ip, owner, network, country, malicious_votes, threat_severity
        FROM malicious_ips
        WHERE tor_node = 'Yes'
          AND malicious_votes >= 2
        ORDER BY malicious_votes DESC;
    """,
    "Q8 (Hard)": """
        WITH network_stats AS (
            SELECT network, AVG(reputation_score) AS avg_reputation
            FROM malicious_ips
            GROUP BY network
        ),
        ranked_ips AS (
            SELECT ip, network, reputation_score,
                   ROW_NUMBER() OVER (PARTITION BY network ORDER BY reputation_score ASC) AS rn
            FROM malicious_ips
            WHERE reputation_score IS NOT NULL
        )
        SELECT r.ip, r.network, r.reputation_score, ns.avg_reputation
        FROM ranked_ips r
        JOIN network_stats ns ON r.network = ns.network
        WHERE r.rn <= 3
        ORDER BY r.network, r.rn;
    """,
    "Q9 (Hard)": """
        WITH lumma_base AS (
            SELECT pulse_id, created, attack_ids
            FROM otx_threat_intel
            WHERE LOWER(tags || ' ' || COALESCE(malware_families,'')) LIKE '%lumma%'
              AND attack_ids IS NOT NULL
        ),
        attack_list AS (
            SELECT DISTINCT TRIM(t.aid) AS attack_id
            FROM lumma_base lb,
            LATERAL (SELECT unnest(string_to_array(lb.attack_ids, ',')) AS aid) t
            WHERE TRIM(t.aid) <> ''
        )
        SELECT DISTINCT o.pulse_id, o.title, o.created, o.tags, o.attack_ids
        FROM otx_threat_intel o
        JOIN attack_list a
            ON ',' || REPLACE(o.attack_ids, ' ', '') || ',' LIKE '%,' || a.attack_id || ',%'
        WHERE o.pulse_id NOT IN (SELECT pulse_id FROM lumma_base)
        ORDER BY o.created DESC
        LIMIT 10;
    """,
    "Q10 (Hard)": """
        WITH tag_list AS (
            SELECT TRIM(t.tag) AS tag, o.created
            FROM otx_threat_intel o,
            LATERAL (SELECT unnest(string_to_array(o.tags, ',')) AS tag) t
            WHERE o.created >= DATE '2026-04-03'
              AND o.tags IS NOT NULL
              AND TRIM(t.tag) <> ''
        ),
        tag_counts AS (
            SELECT tag,
                   COUNT(*) AS tag_count,
                   MIN(created) AS first_seen,
                   MAX(created) AS last_seen
            FROM tag_list
            GROUP BY tag
            HAVING COUNT(*) >= 2
        )
        SELECT tag,
               tag_count,
               first_seen,
               last_seen,
               ROW_NUMBER() OVER (ORDER BY tag_count DESC, last_seen DESC) AS rank
        FROM tag_counts
        ORDER BY tag_count DESC, last_seen DESC
        LIMIT 5;
    """,
}

if __name__ == "__main__":
    client = DBClient()
    ok = 0
    fail = 0
    for name, sql in QUERIES.items():
        try:
            rows, cols = client.execute_query(sql)
            print(f"[OK] {name}: {len(rows)} rows, cols={cols}")
            ok += 1
        except Exception as e:
            print(f"[FAIL] {name}: {e}")
            fail += 1
    print(f"\nResult: {ok} passed, {fail} failed")
