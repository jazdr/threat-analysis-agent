"""Import CISA Known Exploited Vulnerabilities CSV into PostgreSQL."""

from __future__ import annotations

import argparse
import ast
import csv
import sys
from pathlib import Path

import psycopg2
from psycopg2.extras import execute_values

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import config


DEFAULT_CSV = ROOT.parent / "CISA_Known_Exploited_Vulnerabilities.csv"
TABLE_NAME = "cisa_known_exploited_vulnerabilities"


CREATE_TABLE_SQL = f"""
CREATE TABLE IF NOT EXISTS {TABLE_NAME} (
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
    cwes TEXT[],
    source_file TEXT,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE {TABLE_NAME} IS 'CISA Known Exploited Vulnerabilities catalog imported from CSV';
COMMENT ON COLUMN {TABLE_NAME}.cve_id IS 'CVE identifier from the CISA KEV catalog';
COMMENT ON COLUMN {TABLE_NAME}.vendor_project IS 'Vendor or open source project affected by the vulnerability';
COMMENT ON COLUMN {TABLE_NAME}.product IS 'Affected product or component';
COMMENT ON COLUMN {TABLE_NAME}.vulnerability_name IS 'CISA vulnerability title';
COMMENT ON COLUMN {TABLE_NAME}.date_added IS 'Date CISA added the vulnerability to the KEV catalog';
COMMENT ON COLUMN {TABLE_NAME}.short_description IS 'CISA summary of the vulnerability and impact';
COMMENT ON COLUMN {TABLE_NAME}.required_action IS 'Required remediation or mitigation action';
COMMENT ON COLUMN {TABLE_NAME}.due_date IS 'CISA remediation due date';
COMMENT ON COLUMN {TABLE_NAME}.known_ransomware_campaign_use IS 'Whether CISA identifies known ransomware campaign usage';
COMMENT ON COLUMN {TABLE_NAME}.notes IS 'Reference URLs and additional CISA notes';
COMMENT ON COLUMN {TABLE_NAME}.cwes IS 'Common Weakness Enumeration IDs associated with the CVE';
"""


UPSERT_SQL = f"""
INSERT INTO {TABLE_NAME} (
    cve_id,
    vendor_project,
    product,
    vulnerability_name,
    date_added,
    short_description,
    required_action,
    due_date,
    known_ransomware_campaign_use,
    notes,
    cwes,
    source_file
) VALUES %s
ON CONFLICT (cve_id) DO UPDATE SET
    vendor_project = EXCLUDED.vendor_project,
    product = EXCLUDED.product,
    vulnerability_name = EXCLUDED.vulnerability_name,
    date_added = EXCLUDED.date_added,
    short_description = EXCLUDED.short_description,
    required_action = EXCLUDED.required_action,
    due_date = EXCLUDED.due_date,
    known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
    notes = EXCLUDED.notes,
    cwes = EXCLUDED.cwes,
    source_file = EXCLUDED.source_file,
    imported_at = NOW();
"""


def clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    return text.strip('"').strip()


def parse_cwes(value: str | None) -> list[str]:
    text = clean_text(value)
    if not text:
        return []
    try:
        parsed = ast.literal_eval(text)
        if isinstance(parsed, list):
            return [str(item).strip() for item in parsed if str(item).strip()]
    except (SyntaxError, ValueError):
        pass
    return [part.strip() for part in text.replace("[", "").replace("]", "").replace("'", "").split(",") if part.strip()]


def parse_date(value: str | None) -> str | None:
    return clean_text(value)


def row_from_csv(item: dict[str, str], source_file: str) -> tuple:
    return (
        clean_text(item.get("cveID")),
        clean_text(item.get("vendorProject")),
        clean_text(item.get("product")),
        clean_text(item.get("vulnerabilityName")),
        parse_date(item.get("dateAdded")),
        clean_text(item.get("shortDescription")),
        clean_text(item.get("requiredAction")),
        parse_date(item.get("dueDate")),
        clean_text(item.get("knownRansomwareCampaignUse")),
        clean_text(item.get("notes")),
        parse_cwes(item.get("cwes")),
        source_file,
    )


def load_rows(csv_path: Path) -> list[tuple]:
    with csv_path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = [row_from_csv(item, csv_path.name) for item in reader]
    return [row for row in rows if row[0]]


def import_cisa_kev(csv_path: Path) -> dict[str, int | str]:
    rows = load_rows(csv_path)
    conn = psycopg2.connect(config.DB_DSN)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute(CREATE_TABLE_SQL)
                execute_values(cur, UPSERT_SQL, rows, page_size=500)
                cur.execute(f"SELECT COUNT(*) FROM {TABLE_NAME}")
                total = cur.fetchone()[0]
        return {"table": TABLE_NAME, "imported": len(rows), "total": total}
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Import CISA KEV CSV into the configured PostgreSQL database.")
    parser.add_argument("csv_path", nargs="?", default=str(DEFAULT_CSV), help="Path to CISA_Known_Exploited_Vulnerabilities.csv")
    args = parser.parse_args()
    result = import_cisa_kev(Path(args.csv_path).expanduser().resolve())
    print(f"Imported {result['imported']} rows into {result['table']} ({result['total']} total rows).")


if __name__ == "__main__":
    main()
