# ThreatIntel-Agent Text-to-SQL Training Notes

이 데이터베이스는 위협 인텔리전스 분석을 위한 PostgreSQL public schema이다.
사용자 질문은 대부분 악성 IP, 악성 도메인, CVE 취약점, OTX 위협 인텔리전스 보고서 조회와 집계에 관한 것이다.

## Query conventions

- 목록 조회에는 식별자와 판단 근거 컬럼을 함께 포함한다.
- `malicious_ips.threat_severity` 값은 `High`, `Medium`, `Low` 형태를 우선 사용한다.
- `malicious_domains.threat_severity` 값도 원본 대소문자를 우선 사용한다.
- `malicious_ips.tor_node` 값은 `Yes` 또는 `No` 형태를 우선 사용한다.
- `cve_vulnerabilities.known_ransomware_campaign_use` 값은 `Known` 또는 `Unknown` 형태를 우선 사용한다.
- 날짜 조건은 PostgreSQL ISO date literal을 사용한다.
- 사용자가 "상위 N개", "최근", "가장 높은"이라고 말하면 `ORDER BY`와 `LIMIT`를 함께 사용한다.
- 모든 SQL은 단일 read-only SELECT 또는 WITH ... SELECT 형태여야 한다.

## Table intent mapping

- 악성 IP, 국가별 IP, Tor 노드, ASN, 네트워크, 평판 점수: `malicious_ips`
- 악성 도메인, TLD, 등록기관, VirusTotal 평판, 도메인 심각도: `malicious_domains`
- 기존 CVE 샘플 데이터, 취약점, 공급업체, 제품, 랜섬웨어 악용 여부: `cve_vulnerabilities`
- CISA KEV 원본 카탈로그, Known Exploited Vulnerabilities, 대응 마감일, CWE, 참고 URL: `cisa_known_exploited_vulnerabilities`
- OTX pulse, 캠페인, 태그, malware family, MITRE ATT&CK ID: `otx_threat_intel`

## Preferred result columns

- High 악성 IP 목록: `ip, country, owner, network, malicious_votes, reputation_score, threat_severity`
- Tor 악성 IP 목록: `ip, owner, network, country, malicious_votes, threat_severity`
- 악성 도메인 목록: `domain, tld, registrar, reputation, malicious_votes, threat_severity`
- CVE 목록: `cve_id, vendor_project, product, vulnerability_name, due_date, known_ransomware_campaign_use`
- CISA KEV 원본 목록: `cve_id, vendor_project, product, vulnerability_name, date_added, due_date, known_ransomware_campaign_use, cwes`
- OTX 위협 보고서 목록: `pulse_id, title, created, modified, tags, malware_families, attack_ids`
