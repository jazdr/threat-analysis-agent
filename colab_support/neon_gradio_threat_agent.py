"""Standalone Neon + Gradio ThreatIntel demo for Google Colab.

This module is intentionally separate from the FastAPI/LangGraph application.
It implements the proposal workflow in a compact Colab-friendly form:

1. Create proposal tables in Neon PostgreSQL.
2. Load local/uploaded CSV threat-intel datasets.
3. Generate read-only SQL from natural language.
4. Execute safe SELECT queries.
5. Summarize results in Korean.
6. Launch a Gradio UI.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import pandas as pd
import psycopg2
from openai import OpenAI
from psycopg2.extras import RealDictCursor, execute_values


BASE_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = BASE_DIR.parent / "archive"
DEFAULT_CISA_KEV = BASE_DIR.parent / "CISA_Known_Exploited_Vulnerabilities.csv"


TABLE_CSVS = {
    "otx_threat_intel": "1_otx_threat_intel.csv",
    "cve_vulnerabilities": "2_cve_vulnerabilities.csv",
    "malicious_domains": "3_malicious_domains.csv",
    "malicious_ips": "4_malicious_ips.csv",
}


DDL_SQL = """
CREATE TABLE IF NOT EXISTS otx_threat_intel (
    pulse_id TEXT PRIMARY KEY,
    title TEXT,
    description TEXT,
    author TEXT,
    created TIMESTAMP,
    modified TIMESTAMP,
    tlp TEXT,
    tags TEXT,
    malware_families TEXT,
    attack_ids TEXT,
    industries TEXT,
    countries TEXT,
    indicators_count NUMERIC,
    subscribers NUMERIC
);

COMMENT ON TABLE otx_threat_intel IS 'AlienVault OTX 기반 위협 인텔리전스 보고서';
COMMENT ON COLUMN otx_threat_intel.pulse_id IS 'AlienVault OTX에서 발급한 위협 보고서 고유 ID';
COMMENT ON COLUMN otx_threat_intel.title IS '위협 분석 보고서의 제목';
COMMENT ON COLUMN otx_threat_intel.description IS '위협에 대한 상세 설명';
COMMENT ON COLUMN otx_threat_intel.tags IS '쉼표로 구분된 위협 키워드 태그';
COMMENT ON COLUMN otx_threat_intel.malware_families IS '연관 악성코드 패밀리';
COMMENT ON COLUMN otx_threat_intel.attack_ids IS 'MITRE ATT&CK 기법 ID 목록';

CREATE TABLE IF NOT EXISTS cve_vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added DATE,
    short_description TEXT,
    required_action TEXT,
    due_date DATE,
    known_ransomware_campaign_use TEXT,
    cwes TEXT
);

COMMENT ON TABLE cve_vulnerabilities IS 'CISA KEV 기반 취약점 및 대응 마감 정보';
COMMENT ON COLUMN cve_vulnerabilities.cve_id IS '국제적으로 통용되는 취약점 고유 식별자';
COMMENT ON COLUMN cve_vulnerabilities.vendor_project IS '취약점이 존재하는 공급업체명';
COMMENT ON COLUMN cve_vulnerabilities.product IS '취약한 제품 또는 서비스명';
COMMENT ON COLUMN cve_vulnerabilities.date_added IS 'CISA KEV 카탈로그 등록일';
COMMENT ON COLUMN cve_vulnerabilities.due_date IS 'CISA 대응 마감일';
COMMENT ON COLUMN cve_vulnerabilities.known_ransomware_campaign_use IS '랜섬웨어 캠페인 활용 여부';

CREATE TABLE IF NOT EXISTS malicious_domains (
    domain TEXT PRIMARY KEY,
    tld TEXT,
    domain_length INTEGER,
    has_numbers TEXT,
    has_hyphen TEXT,
    registrar TEXT,
    creation_date TEXT,
    last_update_date TEXT,
    reputation NUMERIC,
    malicious_votes INTEGER,
    suspicious_votes INTEGER,
    harmless_votes INTEGER,
    undetected_votes INTEGER,
    total_engines INTEGER,
    threat_severity TEXT,
    categories TEXT,
    popularity_rank TEXT,
    last_analysis_date TEXT,
    whois_summary TEXT,
    data_source TEXT
);

COMMENT ON TABLE malicious_domains IS 'VirusTotal 기반 악성 의심 도메인 평판 정보';
COMMENT ON COLUMN malicious_domains.domain IS '분석 대상 도메인 전체 주소';
COMMENT ON COLUMN malicious_domains.reputation IS 'VirusTotal 등이 산출한 종합 평판 점수';
COMMENT ON COLUMN malicious_domains.malicious_votes IS '악성으로 판단한 보안 엔진의 수';
COMMENT ON COLUMN malicious_domains.threat_severity IS '도메인 위협 심각도';

CREATE TABLE IF NOT EXISTS malicious_ips (
    ip TEXT PRIMARY KEY,
    country TEXT,
    continent TEXT,
    asn TEXT,
    owner TEXT,
    network TEXT,
    malicious_votes INTEGER,
    suspicious_votes INTEGER,
    harmless_votes INTEGER,
    undetected_votes INTEGER,
    total_reports INTEGER,
    reputation_score INTEGER,
    threat_label TEXT,
    threat_category TEXT,
    regional_registry TEXT,
    whois_summary TEXT,
    tor_node TEXT,
    times_submitted INTEGER,
    last_analysis_date TEXT,
    threat_severity TEXT
);

COMMENT ON TABLE malicious_ips IS 'VirusTotal 기반 악성 의심 IP 평판 및 네트워크 정보';
COMMENT ON COLUMN malicious_ips.ip IS '분석 대상 IPv4 또는 IPv6 주소';
COMMENT ON COLUMN malicious_ips.country IS 'IP가 할당된 국가 코드';
COMMENT ON COLUMN malicious_ips.owner IS 'IP 대역 소유 조직';
COMMENT ON COLUMN malicious_ips.reputation_score IS '평판 점수';
COMMENT ON COLUMN malicious_ips.tor_node IS 'Tor 노드 여부';
COMMENT ON COLUMN malicious_ips.threat_severity IS 'IP 위협 심각도';

CREATE TABLE IF NOT EXISTS cisa_known_exploited_vulnerabilities (
    cve_id TEXT PRIMARY KEY,
    vendor_project TEXT,
    product TEXT,
    vulnerability_name TEXT,
    date_added DATE,
    short_description TEXT,
    required_action TEXT,
    due_date DATE,
    known_ransomware_campaign_use TEXT,
    notes TEXT,
    cwes TEXT,
    source_file TEXT,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE cisa_known_exploited_vulnerabilities IS 'CISA Known Exploited Vulnerabilities 원본 CSV 적재 테이블';
COMMENT ON COLUMN cisa_known_exploited_vulnerabilities.notes IS 'CISA, 벤더, NVD 등 참고 URL';

CREATE TABLE IF NOT EXISTS threat_intel_links (
    link_id BIGSERIAL PRIMARY KEY,
    pulse_id TEXT NOT NULL REFERENCES otx_threat_intel(pulse_id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL REFERENCES cve_vulnerabilities(cve_id) ON DELETE CASCADE,
    relation_type TEXT NOT NULL,
    evidence TEXT,
    confidence NUMERIC,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (pulse_id, cve_id, relation_type)
);

COMMENT ON TABLE threat_intel_links IS 'OTX 보고서와 CVE 취약점 사이의 키워드 기반 연결 테이블';
COMMENT ON COLUMN threat_intel_links.link_id IS '연결 레코드 고유 ID';
COMMENT ON COLUMN threat_intel_links.pulse_id IS '연결된 OTX 위협 보고서 ID';
COMMENT ON COLUMN threat_intel_links.cve_id IS '연결된 CVE 취약점 ID';
COMMENT ON COLUMN threat_intel_links.relation_type IS '연결 유형(keyword_match, attack_context, ransomware_context)';
COMMENT ON COLUMN threat_intel_links.evidence IS '연결 근거가 된 키워드 또는 설명';
COMMENT ON COLUMN threat_intel_links.confidence IS '0~1 범위의 휴리스틱 연결 신뢰도';
COMMENT ON COLUMN threat_intel_links.created_at IS '연결 레코드 생성 시각';

CREATE INDEX IF NOT EXISTS idx_otx_created ON otx_threat_intel(created);
CREATE INDEX IF NOT EXISTS idx_otx_tags ON otx_threat_intel(tags);
CREATE INDEX IF NOT EXISTS idx_cve_due_date ON cve_vulnerabilities(due_date);
CREATE INDEX IF NOT EXISTS idx_cisa_kev_due_date ON cisa_known_exploited_vulnerabilities(due_date);
CREATE INDEX IF NOT EXISTS idx_domains_reputation ON malicious_domains(reputation);
CREATE INDEX IF NOT EXISTS idx_ips_reputation ON malicious_ips(reputation_score);
CREATE INDEX IF NOT EXISTS idx_links_pulse_id ON threat_intel_links(pulse_id);
CREATE INDEX IF NOT EXISTS idx_links_cve_id ON threat_intel_links(cve_id);

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_otx_tlp') THEN
        ALTER TABLE otx_threat_intel
        ADD CONSTRAINT chk_otx_tlp CHECK (tlp IS NULL OR tlp IN ('white', 'green', 'amber', 'red'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_cve_ransomware_use') THEN
        ALTER TABLE cve_vulnerabilities
        ADD CONSTRAINT chk_cve_ransomware_use CHECK (known_ransomware_campaign_use IS NULL OR known_ransomware_campaign_use IN ('Known', 'Unknown'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_domain_severity') THEN
        ALTER TABLE malicious_domains
        ADD CONSTRAINT chk_domain_severity CHECK (threat_severity IS NULL OR threat_severity IN ('Low', 'Medium', 'High'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_ip_severity') THEN
        ALTER TABLE malicious_ips
        ADD CONSTRAINT chk_ip_severity CHECK (threat_severity IS NULL OR threat_severity IN ('Low', 'Medium', 'High'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_ip_tor_node') THEN
        ALTER TABLE malicious_ips
        ADD CONSTRAINT chk_ip_tor_node CHECK (tor_node IS NULL OR tor_node IN ('Yes', 'No'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_link_relation_type') THEN
        ALTER TABLE threat_intel_links
        ADD CONSTRAINT chk_link_relation_type CHECK (relation_type IN ('keyword_match', 'attack_context', 'ransomware_context'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'chk_link_confidence') THEN
        ALTER TABLE threat_intel_links
        ADD CONSTRAINT chk_link_confidence CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1));
    END IF;
END $$;
"""


CSV_COLUMN_MAPS = {
    "otx_threat_intel": {
        "Pulse_ID": "pulse_id",
        "Title": "title",
        "Description": "description",
        "Author": "author",
        "Created": "created",
        "Modified": "modified",
        "TLP": "tlp",
        "Tags": "tags",
        "Malware_Families": "malware_families",
        "Attack_IDs": "attack_ids",
        "Industries": "industries",
        "Countries": "countries",
        "Indicators_Count": "indicators_count",
        "Subscribers": "subscribers",
    },
    "cve_vulnerabilities": {
        "cveID": "cve_id",
        "vendorProject": "vendor_project",
        "product": "product",
        "vulnerabilityName": "vulnerability_name",
        "dateAdded": "date_added",
        "shortDescription": "short_description",
        "requiredAction": "required_action",
        "dueDate": "due_date",
        "knownRansomwareCampaignUse": "known_ransomware_campaign_use",
        "cwes": "cwes",
    },
    "malicious_domains": {
        "Domain": "domain",
        "TLD": "tld",
        "Domain_Length": "domain_length",
        "Has_Numbers": "has_numbers",
        "Has_Hyphen": "has_hyphen",
        "Registrar": "registrar",
        "Creation_Date": "creation_date",
        "Last_Update_Date": "last_update_date",
        "Reputation": "reputation",
        "Malicious_Votes": "malicious_votes",
        "Suspicious_Votes": "suspicious_votes",
        "Harmless_Votes": "harmless_votes",
        "Undetected_Votes": "undetected_votes",
        "Total_Engines": "total_engines",
        "Threat_Severity": "threat_severity",
        "Categories": "categories",
        "Popularity_Rank": "popularity_rank",
        "Last_Analysis_Date": "last_analysis_date",
        "WHOIS_Summary": "whois_summary",
        "Data_Source": "data_source",
    },
    "malicious_ips": {
        "IP": "ip",
        "Country": "country",
        "Continent": "continent",
        "ASN": "asn",
        "Owner": "owner",
        "Network": "network",
        "Malicious_Votes": "malicious_votes",
        "Suspicious_Votes": "suspicious_votes",
        "Harmless_Votes": "harmless_votes",
        "Undetected_Votes": "undetected_votes",
        "Total_Reports": "total_reports",
        "Reputation_Score": "reputation_score",
        "Threat_Label": "threat_label",
        "Threat_Category": "threat_category",
        "Regional_Registry": "regional_registry",
        "WHOIS_Summary": "whois_summary",
        "TOR_Node": "tor_node",
        "Times_Submitted": "times_submitted",
        "Last_Analysis_Date": "last_analysis_date",
        "Threat_Severity": "threat_severity",
    },
    "cisa_known_exploited_vulnerabilities": {
        "cveID": "cve_id",
        "vendorProject": "vendor_project",
        "product": "product",
        "vulnerabilityName": "vulnerability_name",
        "dateAdded": "date_added",
        "shortDescription": "short_description",
        "requiredAction": "required_action",
        "dueDate": "due_date",
        "knownRansomwareCampaignUse": "known_ransomware_campaign_use",
        "notes": "notes",
        "cwes": "cwes",
    },
}


SAMPLE_QUESTIONS = [
    "심각도가 High인 악성 IP가 몇 개인가요?",
    "2026년 4월 28일에 CISA KEV에 추가된 취약점 목록을 보여주세요.",
    "데이터 소스가 VirusTotal인 도메인 중 평판 점수가 가장 낮은 TOP 5를 알려주세요.",
    "국가별로 악성으로 판정받은 IP 개수를 집계해주세요.",
    "phishing 키워드를 포함한 OTX 보고서와 연관된 CVE가 있나요?",
    "랜섬웨어로 알려진 취약점 중 대응 마감일이 가장 임박한 5개를 보여주세요.",
    "Tor 노드로 확인된 IP들 중 악성 판정이 2개 이상인 주소와 소유 조직을 보여주세요.",
    "네트워크 대역별로 평판 점수가 가장 낮은 상위 3개 IP와 해당 대역의 평균 평판 점수를 함께 보여주세요.",
    "Lumma 관련 태그가 등장한 후 동일 MITRE ATT&CK ID를 공유하는 보고서를 최신순으로 보여주세요.",
    "지난 30일간 위협 인텔리전스 데이터에서 가장 많이 등장한 키워드 태그 상위 5개를 추출해주세요.",
    "CISA KEV 원본 카탈로그에서 최근 추가된 취약점 5개를 보여줘.",
    "(상관분석) OTX 보고서와 CVE 취약점이 연결된 사례를 조인해서 보여주세요.",
    "(상관분석) 랜섬웨어 관련 CVE와 연결된 OTX 보고서를 보여주세요.",
    "(상관분석) Android/Windows 제품 취약점과 관련된 OTX 위협 보고서 수를 비교해주세요.",
    "(상관분석) ATT&CK ID가 있는 OTX 보고서와 연결된 CVE를 신뢰도 순으로 보여주세요.",
    "(상관분석) 최근 OTX 보고서와 대응 마감일이 임박한 CVE를 함께 보여주세요.",
]


FEW_SHOT_SQL = """
질문: 심각도가 High인 악성 IP가 몇 개인가요?
SQL:
SELECT COUNT(*) AS high_risk_ip_count
FROM malicious_ips
WHERE threat_severity = 'High';

질문: 2026년 4월 28일에 CISA KEV에 추가된 취약점 목록을 보여주세요.
SQL:
SELECT cve_id, vendor_project, product, vulnerability_name
FROM cve_vulnerabilities
WHERE date_added = DATE '2026-04-28';

질문: 데이터 소스가 VirusTotal인 도메인 중 평판 점수가 가장 낮은 TOP 5를 알려주세요.
SQL:
SELECT domain, reputation, threat_severity, malicious_votes
FROM malicious_domains
WHERE data_source = 'VirusTotal'
ORDER BY reputation ASC
LIMIT 5;

질문: 국가별로 악성으로 판정받은 IP 개수를 집계해주세요.
SQL:
SELECT country,
       COUNT(*) AS malicious_ip_count,
       ROUND(AVG(reputation_score), 2) AS avg_reputation
FROM malicious_ips
WHERE malicious_votes > 0
GROUP BY country
ORDER BY malicious_ip_count DESC;

질문: CISA KEV 원본 카탈로그에서 최근 추가된 취약점 5개를 보여줘.
SQL:
SELECT cve_id, vendor_project, product, vulnerability_name, date_added, due_date, known_ransomware_campaign_use
FROM cisa_known_exploited_vulnerabilities
ORDER BY date_added DESC
LIMIT 5;
"""


BLOCKED_SQL = {
    "drop",
    "delete",
    "update",
    "insert",
    "alter",
    "create",
    "truncate",
    "grant",
    "revoke",
    "copy",
    "call",
    "vacuum",
    "analyze",
    "explain",
    "set",
    "reset",
}


@dataclass
class QueryResult:
    question: str
    sql: str
    rows: list[dict[str, Any]]
    columns: list[str]
    analysis: str
    error: str | None = None


def clean_value(value: Any) -> Any:
    if pd.isna(value):
        return None
    if isinstance(value, str):
        stripped = value.strip()
        if stripped == "" or stripped.lower() in {"nan", "none", "null"}:
            return None
        return stripped.strip('"').strip()
    return value


def read_csv_for_table(path: Path, table: str) -> pd.DataFrame:
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    mapping = CSV_COLUMN_MAPS[table]
    df = df.rename(columns=mapping)
    columns = list(mapping.values())
    df = df[[c for c in columns if c in df.columns]]
    for column in columns:
        if column not in df.columns:
            df[column] = None
    df = df[columns]
    return df.apply(lambda column: column.map(clean_value))


def get_connection(database_url: str | None = None):
    dsn = database_url or os.getenv("DATABASE_URL") or os.getenv("NEON_DATABASE_URL")
    if not dsn:
        raise ValueError("DATABASE_URL 또는 NEON_DATABASE_URL 환경변수를 설정하세요.")
    return psycopg2.connect(dsn)


def database_url_for_name(database_url: str, database_name: str) -> str:
    parts = urlsplit(database_url)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database_name}", parts.query, parts.fragment))


def ensure_database(database_name: str = "threat_intel_agent", admin_database_url: str | None = None) -> str:
    admin_url = admin_database_url or os.getenv("NEON_ADMIN_DATABASE_URL") or os.getenv("DATABASE_URL") or os.getenv("NEON_DATABASE_URL")
    if not admin_url:
        raise ValueError("Neon 관리자 DATABASE_URL을 설정하세요.")
    if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]*", database_name):
        raise ValueError("database_name은 영문자, 숫자, underscore만 사용할 수 있습니다.")

    conn = psycopg2.connect(admin_url)
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (database_name,))
            if not cur.fetchone():
                cur.execute(f'CREATE DATABASE "{database_name}"')
    finally:
        conn.close()
    target_url = database_url_for_name(admin_url, database_name)
    os.environ["DATABASE_URL"] = target_url
    return target_url


def create_schema(database_url: str | None = None) -> None:
    conn = get_connection(database_url)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(DDL_SQL)
    finally:
        conn.close()


def upsert_dataframe(conn, table: str, df: pd.DataFrame, conflict_column: str) -> int:
    if df.empty:
        return 0
    df = df.dropna(subset=[conflict_column])
    df = df[df[conflict_column].astype(str).str.strip() != ""]
    df = df.drop_duplicates(subset=[conflict_column], keep="last")
    if df.empty:
        return 0
    columns = list(df.columns)
    values = [tuple(clean_value(row[col]) for col in columns) for _, row in df.iterrows()]
    quoted_cols = ", ".join(columns)
    update_cols = [col for col in columns if col != conflict_column]
    updates = ", ".join(f"{col}=EXCLUDED.{col}" for col in update_cols)
    sql = f"""
        INSERT INTO {table} ({quoted_cols})
        VALUES %s
        ON CONFLICT ({conflict_column}) DO UPDATE SET {updates}
    """
    with conn.cursor() as cur:
        execute_values(cur, sql, values, page_size=500)
    return len(values)


def populate_threat_intel_links(conn, limit: int = 500) -> int:
    """Populate a small FK-backed bridge table for proposal-grade schema checks."""
    limit = max(1, min(int(limit), 1000))
    with conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO threat_intel_links (pulse_id, cve_id, relation_type, evidence, confidence)
            SELECT pulse_id, cve_id, relation_type, evidence, confidence
            FROM (
                SELECT
                    o.pulse_id,
                    c.cve_id,
                    'keyword_match' AS relation_type,
                    CONCAT('OTX title/tag matched vendor/product: ', c.vendor_project, ' / ', c.product) AS evidence,
                    0.72::NUMERIC AS confidence,
                    ROW_NUMBER() OVER (ORDER BY o.created DESC NULLS LAST, o.pulse_id, c.cve_id) AS rn
                FROM otx_threat_intel o
                JOIN cve_vulnerabilities c ON (
                    LENGTH(c.product) > 5
                    AND LOWER(COALESCE(o.title, '') || ' ' || COALESCE(o.tags, '')) LIKE '%%' || LOWER(c.product) || '%%'
                ) OR (
                    LENGTH(c.vendor_project) > 5
                    AND LOWER(COALESCE(o.title, '') || ' ' || COALESCE(o.tags, '')) LIKE '%%' || LOWER(c.vendor_project) || '%%'
                )
            ) matched
            WHERE rn <= {limit}
            ON CONFLICT (pulse_id, cve_id, relation_type) DO NOTHING
            """
        )
        return cur.rowcount


def load_csvs_to_neon(
    data_dir: str | Path = DEFAULT_DATA_DIR,
    cisa_kev_csv: str | Path | None = DEFAULT_CISA_KEV,
    database_url: str | None = None,
) -> dict[str, int]:
    data_dir = Path(data_dir)
    create_schema(database_url)
    conn = get_connection(database_url)
    counts: dict[str, int] = {}
    try:
        with conn:
            for table, filename in TABLE_CSVS.items():
                path = data_dir / filename
                if not path.exists():
                    counts[table] = 0
                    continue
                df = read_csv_for_table(path, table)
                pk = "pulse_id" if table == "otx_threat_intel" else "cve_id" if table == "cve_vulnerabilities" else "domain" if table == "malicious_domains" else "ip"
                counts[table] = upsert_dataframe(conn, table, df, pk)

            if cisa_kev_csv:
                cisa_path = Path(cisa_kev_csv)
                if cisa_path.exists():
                    df = read_csv_for_table(cisa_path, "cisa_known_exploited_vulnerabilities")
                    df["source_file"] = cisa_path.name
                    counts["cisa_known_exploited_vulnerabilities"] = upsert_dataframe(
                        conn,
                        "cisa_known_exploited_vulnerabilities",
                        df,
                        "cve_id",
                    )
            counts["threat_intel_links"] = populate_threat_intel_links(conn)
    finally:
        conn.close()
    return counts


def get_schema_text(database_url: str | None = None) -> str:
    conn = get_connection(database_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                ORDER BY table_name
                """
            )
            tables = [row[0] for row in cur.fetchall()]
            lines: list[str] = []
            for table in tables:
                if table.startswith("_"):
                    continue
                lines.append(f"-- Table: {table}")
                cur.execute(
                    """
                    SELECT column_name, data_type, is_nullable
                    FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = %s
                    ORDER BY ordinal_position
                    """,
                    (table,),
                )
                for name, dtype, nullable in cur.fetchall():
                    null = "NULL" if nullable == "YES" else "NOT NULL"
                    lines.append(f"  {name} {dtype} {null}")
                lines.append("")
            return "\n".join(lines)
    finally:
        conn.close()


def strip_sql_comments(sql: str) -> str:
    return re.sub(r"--.*?$|/\*.*?\*/", " ", sql, flags=re.MULTILINE | re.DOTALL)


def is_safe_select(sql: str) -> bool:
    if not sql or not sql.strip():
        return False
    cleaned = strip_sql_comments(sql).strip().rstrip(";")
    lowered = cleaned.lower().lstrip()
    if not (lowered.startswith("select") or lowered.startswith("with")):
        return False
    if ";" in cleaned:
        return False
    tokens = set(re.findall(r"[a-z_][a-z0-9_]*", lowered))
    return not bool(tokens & BLOCKED_SQL)


def extract_sql(text: str) -> str:
    match = re.search(r"```sql\s*(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if match:
        return match.group(1).strip().rstrip(";") + ";"
    match = re.search(r"```\s*(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip().rstrip(";") + ";"
    stripped = text.strip()
    if stripped.lower().startswith(("select", "with")):
        return stripped.rstrip(";") + ";"
    return stripped


class ColabThreatIntelAgent:
    def __init__(
        self,
        database_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
    ):
        self.database_url = database_url or os.getenv("DATABASE_URL") or os.getenv("NEON_DATABASE_URL")
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        client_kwargs = {"api_key": api_key or os.getenv("OPENAI_API_KEY")}
        if base_url or os.getenv("OPENAI_BASE_URL"):
            client_kwargs["base_url"] = base_url or os.getenv("OPENAI_BASE_URL")
        self.client = OpenAI(**client_kwargs)

    def generate_sql(self, question: str) -> str:
        schema = get_schema_text(self.database_url)
        prompt = f"""
당신은 사이버 위협 인텔리전스 데이터베이스를 다루는 전문 SQL 생성 어시스턴트입니다.
아래 스키마와 예시를 참고하여 PostgreSQL SELECT 문 하나만 작성하세요.

규칙:
- SELECT 또는 WITH ... SELECT만 허용합니다.
- INSERT/UPDATE/DELETE/CREATE/DROP/ALTER/COPY는 절대 사용하지 마세요.
- 질문이 CISA KEV 원본, 최근 KEV, notes, 참고 URL을 말하면 cisa_known_exploited_vulnerabilities 테이블을 우선 사용하세요.
- 질문이 일반 CVE 샘플 또는 제안서의 CVE 질문이면 cve_vulnerabilities 테이블을 사용할 수 있습니다.
- 목록 조회는 식별자와 판단 근거 컬럼을 포함하세요.
- 결과 제한이 없으면 LIMIT 20을 사용하세요.

Few-shot:
{FEW_SHOT_SQL}

스키마:
{schema}

질문:
{question}

SQL 코드 블록만 반환하세요.
"""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.1,
        )
        sql = extract_sql(response.choices[0].message.content or "")
        if not is_safe_select(sql):
            raise ValueError(f"안전하지 않은 SQL이 생성되었습니다: {sql}")
        return sql

    def execute_sql(self, sql: str, limit: int = 500) -> tuple[list[dict[str, Any]], list[str]]:
        if not is_safe_select(sql):
            raise ValueError("SELECT/WITH read-only SQL만 실행할 수 있습니다.")
        limit = max(1, min(int(limit), 1000))
        conn = get_connection(self.database_url)
        try:
            conn.set_session(readonly=True)
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SET LOCAL statement_timeout = 8000")
                cur.execute(f"SELECT * FROM ({sql.strip().rstrip(';')}) AS q LIMIT {limit}")
                rows = [dict(row) for row in cur.fetchall()]
                columns = [desc[0] for desc in cur.description] if cur.description else []
                return rows, columns
        finally:
            conn.close()

    def analyze(self, question: str, sql: str, rows: list[dict[str, Any]]) -> str:
        preview = json.dumps(rows[:30], ensure_ascii=False, default=str, indent=2)
        prompt = f"""
당신은 SOC 분석가를 돕는 사이버 위협 인텔리전스 분석가입니다.
질문, SQL, 결과를 바탕으로 한국어 분석 의견을 작성하세요.

형식:
요약
- 1~2줄 핵심 결론

핵심 인사이트
- 2~4개 bullet

우선 대응
1. 즉시 확인할 항목
2. 패치/차단/자산 매칭/추가 조사 액션
3. 후속 관제 기준

후속 조회
- 다음 자연어 질문 1~2개

질문: {question}
SQL: {sql}
결과: {preview}
"""
        response = self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        return response.choices[0].message.content or ""

    def ask(self, question: str) -> QueryResult:
        try:
            sql = self.generate_sql(question)
            rows, columns = self.execute_sql(sql)
            analysis = self.analyze(question, sql, rows)
            return QueryResult(question=question, sql=sql, rows=rows, columns=columns, analysis=analysis)
        except Exception as exc:
            return QueryResult(question=question, sql="", rows=[], columns=[], analysis="", error=str(exc))


def table_counts(database_url: str | None = None) -> pd.DataFrame:
    conn = get_connection(database_url)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                ORDER BY table_name
                """
            )
            rows = []
            for (table,) in cur.fetchall():
                cur.execute(f'SELECT COUNT(*) FROM "{table}"')
                rows.append({"table": table, "rows": cur.fetchone()[0]})
            return pd.DataFrame(rows)
    finally:
        conn.close()


def build_gradio_app(agent: ColabThreatIntelAgent):
    import gradio as gr

    def run_question(question: str):
        result = agent.ask(question)
        if result.error:
            return "", pd.DataFrame(), f"오류: {result.error}"
        return result.sql, pd.DataFrame(result.rows), result.analysis

    def run_sql(sql: str):
        try:
            rows, _ = agent.execute_sql(sql)
            return pd.DataFrame(rows), "실행 성공"
        except Exception as exc:
            return pd.DataFrame(), f"오류: {exc}"

    def refresh_status():
        try:
            return table_counts(agent.database_url)
        except Exception as exc:
            return pd.DataFrame([{"table": "error", "rows": str(exc)}])

    with gr.Blocks(title="ThreatIntel-Agent Neon Demo") as demo:
        gr.Markdown("# ThreatIntel-Agent Neon + Gradio Demo\n자연어로 Neon PostgreSQL의 위협 인텔리전스 데이터를 조회합니다.")
        with gr.Row():
            with gr.Column(scale=1):
                sample = gr.Dropdown(SAMPLE_QUESTIONS, label="샘플 질문", value=SAMPLE_QUESTIONS[0])
                status = gr.Dataframe(label="Neon DB 테이블 현황", interactive=False)
                refresh = gr.Button("DB 현황 새로고침")
            with gr.Column(scale=2):
                question = gr.Textbox(label="자연어 질문", lines=2)
                ask_btn = gr.Button("질문 실행", variant="primary")
                sql_out = gr.Code(label="Generated SQL", language="sql")
                rows_out = gr.Dataframe(label="조회 결과", interactive=False)
                analysis_out = gr.Markdown(label="분석 의견")

        with gr.Accordion("직접 SQL 실행", open=False):
            sql_in = gr.Code(label="SELECT SQL", language="sql")
            sql_btn = gr.Button("SQL 실행")
            sql_rows = gr.Dataframe(label="SQL 결과", interactive=False)
            sql_msg = gr.Markdown()

        sample.change(lambda x: x, inputs=sample, outputs=question)
        ask_btn.click(run_question, inputs=question, outputs=[sql_out, rows_out, analysis_out])
        sql_btn.click(run_sql, inputs=sql_in, outputs=[sql_rows, sql_msg])
        refresh.click(refresh_status, outputs=status)
        demo.load(refresh_status, outputs=status)

    return demo
