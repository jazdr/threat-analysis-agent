"""PostgreSQL DB 클라이언트: 스키마 조회 및 안전한 쿼리 실행"""

import re
import psycopg2
from psycopg2.extras import RealDictCursor
from config import DB_DSN, MAX_RESULT_ROWS, QUERY_TIMEOUT_MS


class DBClient:
    """PostgreSQL 연결, 스키마 introspection, SELECT-only 쿼리 실행"""

    # 차단할 SQL 키워드 (대소문자 구분 없이 검사)
    BLOCKED_KEYWORDS = [
        "drop", "delete", "update", "insert", "alter", "create",
        "truncate", "grant", "revoke", "execute", "copy", "call",
        "vacuum", "analyze", "explain", "show", "set", "reset",
        "listen", "notify", "refresh", "cluster", "reindex",
    ]
    BLOCKED_FUNCTIONS = [
        "pg_sleep", "pg_advisory_lock", "pg_advisory_xact_lock",
    ]

    # init.sql/proposal 기반 하드코딩 COMMENT (DB에 없을 때 대체용)
    FALLBACK_COMMENTS: dict[str, dict[str, str]] = {
        "otx_threat_intel": {
            "pulse_id": "AlienVault OTX에서 발급한 위협 보고서 고유 ID",
            "title": "위협 분석 보고서의 제목(공격 캠페인명 또는 주요 행위 요약)",
            "description": "위협에 대한 상세 설명으로 공격 기법, 영향 범위, 초기 접근 경로 등이 포함됨",
            "author": "보고서를 작성한 기관 또는 조직명(예: AlienVault, 커뮤니티 기여자)",
            "created": "해당 위협 보고서가 OTX에 최초 게시된 일시",
            "modified": "보고서 내용이 마지막으로 수정된 일시",
            "tlp": "Traffic Light Protocol 등급으로 정보 공유 범위를 결정(white=무제한, red=엄격)",
            "tags": "쉼표로 구분된 위협 키워드 태그(예: phishing, powershell, ransomware)",
            "malware_families": "해당 위협과 연관된 악성코드 패밀리 목록(예: Lumma Stealer, Kyber Ransomware)",
            "attack_ids": "MITRE ATT&CK 프레임워크 기법 ID 목록(예: T1566, T1059.001)",
            "industries": "위협으로부터 영향을 받은 주요 산업군",
            "countries": "공격 대상이 되거나 공격이 발원한 국가 목록",
            "indicators_count": "해당 보고서에 포함된 IOC(Indicator of Compromise) 총 개수",
            "subscribers": "해당 위협을 추적하는 OTX 사용자 수",
        },
        "cve_vulnerabilities": {
            "cve_id": "국제적으로 통용되는 취약점 고유 식별자(Common Vulnerabilities and Exposures)",
            "vendor_project": "취약점이 존재하는 소프트웨어를 개발한 공급업체명",
            "product": "취약한 제품 또는 서비스의 정확한 명칭",
            "vulnerability_name": "CISA가 공식 부여한 취약점 명칭",
            "date_added": "해당 취약점이 CISA KEV(Known Exploited Vulnerabilities) 카탈로그에 등록된 날짜",
            "short_description": "취약점의 원인, 영향, 공격 시나리오에 대한 요약",
            "required_action": "조직이 수행해야 할 우선 대응 조치(패치 적용, 설정 변경, 서비스 중단 등)",
            "due_date": "CISA에서 정한 해당 취약점 대응 마감일로 미준수 시 규정 위반 가능성 있음",
            "known_ransomware_campaign_use": "랜섬웨어 캠페인에서 실제로 활용된 적이 있는지 여부(Known/Unknown)",
            "cwes": "해당 취약점이 속하는 CWE(COMMON WEAKNESS ENUMERATION) 분류 코드",
        },
        "cisa_known_exploited_vulnerabilities": {
            "cve_id": "CISA Known Exploited Vulnerabilities 카탈로그의 CVE 식별자",
            "vendor_project": "취약점이 존재하는 벤더 또는 오픈소스 프로젝트",
            "product": "영향을 받는 제품 또는 컴포넌트",
            "vulnerability_name": "CISA가 제공하는 취약점 공식 제목",
            "date_added": "CISA KEV 카탈로그에 취약점이 추가된 날짜",
            "short_description": "취약점 원인과 영향에 대한 CISA 요약 설명",
            "required_action": "기관 또는 조직이 수행해야 하는 패치/완화 조치",
            "due_date": "CISA가 지정한 대응 마감일",
            "known_ransomware_campaign_use": "랜섬웨어 캠페인에서 실제 악용된 것으로 알려졌는지 여부",
            "notes": "CISA, 벤더, NVD 등 참고 URL과 추가 메모",
            "cwes": "취약점과 연결된 CWE 분류 코드 배열",
        },
        "malicious_domains": {
            "domain": "분석 대상 도메인 전체 주소(FQDN)",
            "tld": "최상위 도메인(Top-Level Domain, 예: com, ch, ru)",
            "domain_length": "도메인 문자열의 전체 길이로 DGA(Domain Generation Algorithm) 탐지에 사용 가능",
            "has_numbers": "도메인에 숫자가 포함되었는지 여부(YES/NO)로 의심 피처로 활용",
            "has_hyphen": "도메인에 하이픈이 포함되었는지 여부(YES/NO)",
            "registrar": "도메인 등록 대행 기관명",
            "creation_date": "도메인 최초 등록일(UNKNOWN인 경우도 있음)",
            "last_update_date": "도메인 등록 정보 마지막 변경일",
            "reputation": "Virustotal 등이 산출한 종합 평판 점수로 낮을수록 일반적으로 안전",
            "malicious_votes": "악성으로 판단한 보안 엔진의 수",
            "suspicious_votes": "의심으로 판단한 보안 엔진의 수",
            "harmless_votes": "무해로 판단한 보안 엔진의 수",
            "undetected_votes": "탐지하지 못한 보안 엔진의 수",
            "total_engines": "분석에 참여한 보안 엔진의 총 수",
            "threat_severity": "종합 평판을 바탕으로 산출한 위협 심각도(LOW/MEDIUM/HIGH)",
            "categories": "도메인에 부여된 분류 태그(JSON 또는 텍스트 형태)",
            "popularity_rank": "해당 도메인의 월간 방문 인기도 순위(UNKNOWN일 수 있음)",
            "last_analysis_date": "Virustotal 등에서 마지막으로 전체 엔진 분석을 수행한 일시",
            "whois_summary": "도메인 등록 정보의 요약 본문(DNSSEC, 등록자, 네임서버 등)",
            "data_source": "해당 평판 데이터의 수집 출처(예: VirusTotal)",
        },
        "malicious_ips": {
            "ip": "분석 대상 IPv4 또는 IPv6 주소",
            "country": "IP가 할당된 국가의 ISO 두 자리 코드(예: CH, NL, US)",
            "continent": "IP가 속한 대륙 코드(예: EU, NA, AS)",
            "asn": "해당 IP가 속한 자율시스템 번호(Autonomous System Number) 또는 UNKNOWN",
            "owner": "해당 IP 대역을 소유·관리하는 ISP 또는 기관명",
            "network": "IP가 속한 네트워크 대역(CIDR 표기법, 예: 176.10.96.0/19)",
            "malicious_votes": "악성으로 판단한 보안 엔진의 수",
            "suspicious_votes": "의심으로 판단한 보안 엔진의 수",
            "harmless_votes": "무해로 판단한 보안 엔진의 수",
            "undetected_votes": "탐지하지 못한 보안 엔진의 수",
            "total_reports": "해당 IP에 대한 총 보고서 제출 수",
            "reputation_score": "Virustotal 등이 산출한 평판 점수로 음수일수록 위협 가능성이 높음",
            "threat_label": "엔진이 부여한 구체적 위협 라벨(예: clean, unrated, malware)",
            "threat_category": "위협의 대분류(예: clean, malicious, suspicious)",
            "regional_registry": "할당 기관의 지역 레지스트리(RIPE NCC, APNIC, ARIN 등)",
            "whois_summary": "IP 주소에 대한 WHOIS 조회 결과 요약문(INETNUM, NETNAME, COUNTRY 등)",
            "tor_node": "해당 IP가 Tor 익명 네트워크의 출구/중계 노드인지 여부(YES/NO)",
            "times_submitted": "해당 IP가 위협 커뮤니티에 제출된 총 횟수",
            "last_analysis_date": "마지막 전체 엔진 분석 일시(UNIX 타임스탬프)",
            "threat_severity": "종합 평가에 따른 위협 심각도 단계(LOW/MEDIUM/HIGH)",
        },
    }

    def __init__(self, dsn: str = DB_DSN):
        self.dsn = dsn
        self._schema_text: str | None = None

    # ── connection helpers ─────────────────────────────

    def _connect(self):
        return psycopg2.connect(self.dsn)

    @staticmethod
    def _strip_sql_comments(sql: str) -> str:
        """SQL comments are ignored when validating single read-only statements."""
        result: list[str] = []
        i = 0
        in_single = False
        in_double = False
        while i < len(sql):
            ch = sql[i]
            nxt = sql[i + 1] if i + 1 < len(sql) else ""
            if in_single:
                result.append(ch)
                if ch == "'" and nxt == "'":
                    result.append(nxt)
                    i += 2
                    continue
                if ch == "'":
                    in_single = False
                i += 1
                continue
            if in_double:
                result.append(ch)
                if ch == '"' and nxt == '"':
                    result.append(nxt)
                    i += 2
                    continue
                if ch == '"':
                    in_double = False
                i += 1
                continue
            if ch == "'":
                in_single = True
                result.append(ch)
                i += 1
                continue
            if ch == '"':
                in_double = True
                result.append(ch)
                i += 1
                continue
            if ch == "-" and nxt == "-":
                i += 2
                while i < len(sql) and sql[i] not in "\r\n":
                    i += 1
                result.append(" ")
                continue
            if ch == "/" and nxt == "*":
                i += 2
                while i + 1 < len(sql) and not (sql[i] == "*" and sql[i + 1] == "/"):
                    i += 1
                i = min(i + 2, len(sql))
                result.append(" ")
                continue
            result.append(ch)
            i += 1
        return "".join(result)

    @staticmethod
    def _count_statement_semicolons(sql: str) -> int:
        count = 0
        in_single = False
        in_double = False
        for i, ch in enumerate(sql):
            prev = sql[i - 1] if i > 0 else ""
            if in_single:
                if ch == "'" and prev != "'":
                    in_single = False
                continue
            if in_double:
                if ch == '"' and prev != '"':
                    in_double = False
                continue
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == ";":
                count += 1
        return count

    @classmethod
    def _normalize_query(cls, sql: str) -> str:
        cleaned = cls._strip_sql_comments(sql).strip()
        if cleaned.endswith(";"):
            cleaned = cleaned[:-1].strip()
        return cleaned

    @classmethod
    def _with_leads_to_select(cls, sql: str) -> bool:
        depth = 0
        for match in re.finditer(r"\(|\)|\bselect\b", sql, re.IGNORECASE):
            token = match.group(0).lower()
            if token == "(":
                depth += 1
            elif token == ")":
                depth = max(0, depth - 1)
            elif token == "select" and depth == 0:
                return True
        return False

    @classmethod
    def _apply_result_limit(cls, sql: str, max_rows: int = MAX_RESULT_ROWS) -> str:
        normalized = cls._normalize_query(sql)
        return f"SELECT * FROM (\n{normalized}\n) AS threat_agent_query LIMIT {max_rows}"

    # ── schema introspection ───────────────────────────

    def get_schema(self, refresh: bool = False) -> str:
        """4개 테이블의 컬럼명, 타입, COMMENT를 포함한 스키마 문자열 반환"""
        if self._schema_text and not refresh:
            return self._schema_text

        conn = self._connect()
        cur = conn.cursor()

        lines: list[str] = []

        # 테이블 목록 (public 스키마)
        cur.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_type = 'BASE TABLE'
            ORDER BY table_name;
        """)
        tables = [row[0] for row in cur.fetchall()]

        for table in tables:
            lines.append(f"-- Table: {table}")
            cur.execute("""
                SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = %s
                ORDER BY ordinal_position;
            """, (table,))
            cols = cur.fetchall()

            # COMMENT 조회
            cur.execute("""
                SELECT a.attname AS column_name,
                       d.description
                FROM pg_attribute a
                JOIN pg_class c ON a.attrelid = c.oid
                JOIN pg_namespace n ON c.relnamespace = n.oid
                LEFT JOIN pg_description d ON d.objoid = c.oid
                                           AND d.objsubid = a.attnum
                WHERE n.nspname = 'public'
                  AND c.relname = %s
                  AND a.attnum > 0
                  AND NOT a.attisdropped
                ORDER BY a.attnum;
            """, (table,))
            comments = {row[0]: row[1] for row in cur.fetchall() if row[1]}

            for col_name, data_type, is_nullable in cols:
                comment = comments.get(col_name, "")
                if not comment:
                    comment = self.FALLBACK_COMMENTS.get(table, {}).get(col_name, "")
                null_str = "NULL" if is_nullable == "YES" else "NOT NULL"
                lines.append(f"  {col_name} {data_type} {null_str}")
                if comment:
                    lines.append(f"    -- {comment}")
            lines.append("")

        cur.close()
        conn.close()

        self._schema_text = "\n".join(lines)
        return self._schema_text

    # ── query safety ───────────────────────────────────

    @classmethod
    def is_safe_query(cls, sql: str) -> bool:
        """
        SELECT만 허용.
        1. 차단 키워드 포함 여부 (문자열 리터럴 내부 제외)
        2. 다중 쿼리 (세미콜론 2개 이상) 여부
        """
        if not sql or not sql.strip():
            return False

        stripped = cls._strip_sql_comments(sql).strip()
        # 최종 문자가 ; 이어도 OK, 중간 ; 가 2개 이상이면 차단
        semicolons = cls._count_statement_semicolons(stripped)
        if semicolons > 1 or (semicolons == 1 and not stripped.endswith(";")):
            return False

        normalized = cls._normalize_query(stripped)
        lowered = normalized.lower().lstrip()
        if lowered.startswith("with "):
            if not cls._with_leads_to_select(normalized):
                return False
        elif not lowered.startswith("select"):
            return False

        # 문자열 리터럴 제거 (작은따옴표, 큰따옴표 모두)
        cleaned = re.sub(r"'(?:''|[^'])*'", "''", normalized)
        cleaned = re.sub(r'"[^"]*"', '""', cleaned)

        # 단순화된 토큰화 (문자/숫자/밑줄만)
        tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", cleaned.lower())
        for token in tokens:
            if token in cls.BLOCKED_KEYWORDS:
                return False
            if token in cls.BLOCKED_FUNCTIONS:
                return False
        return True

    # ── query execution ────────────────────────────────

    def execute_query(self, sql: str) -> tuple[list[dict], list[str]]:
        """
        안전 검증 후 SELECT 쿼리 실행.
        반환: (결과 행 리스트, 컬럼명 리스트)
        """
        if not self.is_safe_query(sql):
            raise ValueError("안전하지 않은 쿼리입니다. SELECT 문만 실행할 수 있습니다.")

        conn = self._connect()
        conn.set_session(readonly=True)
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute("SET LOCAL statement_timeout = %s", (QUERY_TIMEOUT_MS,))
            cur.execute(self._apply_result_limit(sql))
            rows = cur.fetchall()
            colnames = [desc[0] for desc in cur.description] if cur.description else []
            return rows, colnames
        except psycopg2.Error as e:
            raise RuntimeError(f"SQL 실행 오류: {e}") from e
        finally:
            cur.close()
            conn.close()


# ── quick test ────────────────────────────────────────
if __name__ == "__main__":
    client = DBClient()
    print("=== Schema ===")
    print(client.get_schema())
    print("\n=== Sample Query ===")
    rows, cols = client.execute_query(
        "SELECT COUNT(*) AS cnt FROM malicious_ips WHERE threat_severity = 'High';"
    )
    print("Columns:", cols)
    print("Rows:", rows)
