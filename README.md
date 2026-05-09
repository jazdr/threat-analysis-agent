# ThreatIntel-Agent

자연어 기반 위협 인텔리전스 분석 CLI 에이전트

PostgreSQL에 적재된 사이버 위협 데이터(OTX, CVE, 악성 도메인/IP)에 대해 자연어 질문을 입력하면, LLM이 SQL을 자동 생성하고 실행한 뒤 결과를 분석하여 한국어로 답변합니다.

## 기능

- **Vanna 기반 자연어 → SQL 변환**: DDL/문서/예시 SQL을 ChromaDB 메모리에 학습하여 SQL 생성 정확도 향상
- **Fallback SQL 생성**: Vanna 사용 불가 또는 실패 시 기존 LLM 프롬프트 방식으로 자동 전환
- **자가학습 루프**: Web UI에서 검증된 질문-SQL 쌍을 Vanna 학습 데이터로 추가
- **안전한 쿼리 실행**: read-only `SELECT`/`WITH ... SELECT`만 허용, timeout/row limit 적용
- **에러 재시도**: SQL 오류 시 실행 에러를 LLM에 피드백하여 최대 2회 재생성
- **2단계 분석**: SQL 생성 → 결과 분석을 분리하여 품질 향상
- **Rich CLI**: SQL 하이라이팅, 결과 테이블, 분석 의견을 예쁘게 출력
- **Web UI**: FastAPI 기반 3패널 UI (좌측 DB 탐색기 · 중앙 채팅/쿼리/결과 · 우측 분석 패널)

## 기술 스택

- Python 3.10+
- psycopg2-binary (PostgreSQL)
- openai (OpenAI-compatible API)
- vanna + chromadb (Text-to-SQL training memory)
- langgraph (상태 기반 에이전트 FSM)
- langsmith (선택적 tracing)
- ragas (오프라인 정량 평가)
- python-dotenv (환경변수)
- rich (CLI 스타일링)
- fastapi + uvicorn (Web UI 서버)

## 설치 및 실행

```bash
cd threat-analysis-agent
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt

# .env 설정 (LLM 엔드포인트 변경 가능)
cp .env.example .env

# CLI 실행
python main.py

# Web UI 실행
./venv/bin/uvicorn web_app:app --host 0.0.0.0 --port 8080 --reload
# 브라우저에서 http://localhost:8080 열기
```

## 환경변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| DB_HOST | localhost | PostgreSQL 호스트 |
| DB_PORT | 15432 | PostgreSQL 포트 |
| DB_NAME | threat_intel | 데이터베이스명 |
| DB_USER | admin | DB 사용자 |
| DB_PASSWORD | admin123 | DB 비밀번호 |
| LLM_BASE_URL | http://localhost:11434/v1 | OpenAI-compatible 엔드포인트 |
| LLM_API_KEY | ollama | API 키 |
| LLM_MODEL | kimi-k2.6 | 모델명 |
| LLM_TEMPERATURE | 0.1 | 샘플링 온도 |
| USE_VANNA | true | Vanna 우선 SQL 생성 사용 여부 |
| VANNA_PERSIST_DIR | ./vanna_chroma | ChromaDB 학습 메모리 저장 경로 |
| VANNA_TRAINING_DIR | ./training | 초기 학습 자료 경로 |
| VANNA_AUTO_TRAIN | true | 시작 후 최초 생성 시 초기 학습 자동 수행 |
| QUERY_TIMEOUT_MS | 5000 | SQL 실행 timeout |
| MAX_RESULT_ROWS | 500 | 최대 반환 행 수 |
| USE_LANGGRAPH | true | LangGraph FSM 실행 여부 |
| LANGSMITH_TRACING | false | LangSmith tracing 활성화 여부 |
| LANGSMITH_TRACING_V2 | false | LangSmith traceable 호환 플래그 |
| LANGCHAIN_TRACING_V2 | false | LangChain/LangGraph legacy tracing 호환 플래그 |
| LANGSMITH_API_KEY |  | LangSmith API 키 |
| LANGSMITH_PROJECT | threat-analysis-agent | LangSmith 프로젝트명 |
| LANGSMITH_ENDPOINT | https://api.smith.langchain.com | LangSmith API endpoint |

## 프로젝트 구조

```
threat-analysis-agent/
├── main.py              # CLI 진입점
├── web_app.py           # FastAPI Web UI 서버
├── config.py            # 환경변수/설정
├── db_client.py         # PostgreSQL 연결 및 안전 실행
├── llm_client.py        # 로컬 LLM 호출
├── vanna_client.py      # Vanna Text-to-SQL 어댑터
├── agent_graph.py       # LangGraph 상태 기반 에이전트 워크플로우
├── metrics_store.py     # Dashboard용 JSONL 메트릭 저장소
├── prompt_builder.py    # 프롬프트 템플릿 조립
├── agent.py             # 핵심 에이전트 로직 (NL→SQL→Execute→Analysis)
├── colab_support/
│   └── neon_gradio_threat_agent.py  # Colab용 Neon + Gradio 독립 데모
├── eval/
│   ├── eval_set.json
│   └── ragas_eval.py
├── notebooks/
│   ├── threat_analysis_agent_colab.ipynb
│   └── threat_intel_neon_gradio_colab.ipynb
├── training/            # Vanna 초기 학습 자료
│   ├── schema_docs.md
│   └── example_queries.json
├── prompts/
│   ├── sql_generator.txt
│   └── result_analyzer.txt
├── static/
│   ├── index.html       # Web UI (DataGrip-style 3-panel)
│   └── app.js           # 프론트엔드 로직
├── .env
├── .env.example
├── requirements.txt
└── README.md
```

## CLI 명령어

- 질문 입력 → SQL 생성 → 결과 출력 → 분석 의견
- `/quit` - 종료
- `/schema` - DB 스키마 출력
- `/help` - 도움말

## 데이터 적재

CISA Known Exploited Vulnerabilities CSV를 현재 PostgreSQL DB의 별도 테이블로 적재할 수 있습니다.

```bash
./venv/bin/python scripts/import_cisa_kev.py ../CISA_Known_Exploited_Vulnerabilities.csv
```

- 테이블명: `cisa_known_exploited_vulnerabilities`
- 적재 방식: `cve_id` 기준 upsert
- Web UI Dashboard, `@` 테이블 멘션, Vanna Text-to-SQL 스키마에 자동 반영

## Colab + Neon + Gradio 독립 데모

기존 FastAPI/LangGraph 앱과 별개로, 제안서 내용을 Google Colab에서 바로 시연할 수 있는 독립 구현을 추가했습니다.

- 노트북: `notebooks/threat_intel_neon_gradio_colab.ipynb`
- 지원 모듈: `colab_support/neon_gradio_threat_agent.py`
- 적재 대상: `archive/1_otx_threat_intel.csv` ~ `archive/4_malicious_ips.csv`, `../CISA_Known_Exploited_Vulnerabilities.csv`
- Neon 테이블: `otx_threat_intel`, `cve_vulnerabilities`, `malicious_domains`, `malicious_ips`, `cisa_known_exploited_vulnerabilities`, `threat_intel_links`
- 제안서 루브릭 보강: `CHECK` 제약, `COMMENT ON TABLE`, FK 기반 `threat_intel_links` 연결 테이블, 10개 샘플 SQL 실행 검증 셀 포함
- UI: Gradio 기반 자연어 질문, 생성 SQL 확인, 조회 결과, 분석 의견, 직접 SELECT SQL 실행

Colab에서 실행 순서는 다음과 같습니다.

```python
%pip install psycopg2-binary pandas openai gradio python-dotenv

import os
os.environ["DATABASE_URL"] = "<Neon PostgreSQL connection string>"
os.environ["OPENAI_API_KEY"] = "<OpenAI API key>"
os.environ["OPENAI_MODEL"] = "gpt-4o-mini"

from pathlib import Path
from colab_support.neon_gradio_threat_agent import (
    ColabThreatIntelAgent,
    build_gradio_app,
    load_csvs_to_neon,
)

load_csvs_to_neon(Path("../archive"), Path("../CISA_Known_Exploited_Vulnerabilities.csv"))
agent = ColabThreatIntelAgent()
demo = build_gradio_app(agent)
demo.launch(share=True, debug=True)
```

실제 Neon 적재는 위 노트북에서 `DATABASE_URL`을 설정하고 `load_csvs_to_neon(...)` 셀을 실행할 때 수행됩니다. 자연어 질의와 분석은 OpenAI API를 호출하므로 실행량에 따라 비용이 발생할 수 있습니다.

## LangSmith 모니터링

LangSmith API 키가 있으면 `.env`에서 tracing을 켜고 서버를 재시작합니다.

```bash
LANGSMITH_TRACING=true
LANGSMITH_API_KEY=<your_langsmith_api_key>
LANGSMITH_PROJECT=threat-analysis-agent
```

`config.py`가 `LANGSMITH_TRACING=true`를 감지하면 현재 LangSmith SDK와 LangChain/LangGraph 호환 플래그인 `LANGSMITH_TRACING_V2`, `LANGCHAIN_TRACING_V2`를 자동 설정합니다. `agent_graph.py`의 각 LangGraph node는 `@traceable`로 감싸져 있어 `generate_sql`, `verify_sql`, `execute_sql`, `handle_empty_result`, `analyze_results` 단위로 입력/출력을 추적할 수 있습니다.

## 평가 실행

기본 평가는 LLM으로 SQL을 생성한 뒤 deterministic check를 수행합니다.

```bash
./venv/bin/python eval/ragas_eval.py
```

Ragas의 LLM 기반 SQL semantic equivalence까지 실행하려면 OpenAI-compatible API 비용이 발생할 수 있습니다.

```bash
./venv/bin/python eval/ragas_eval.py --ragas
```

## 아키텍처 특징 (Web UI 확장용)

- `agent.py`, `db_client.py`, `llm_client.py`는 순수 Python 로직으로 FastAPI/Flask 등에서 재사용 가능
- `vanna_client.py`는 선택적 Text-to-SQL 레이어이며, 실패 시 기존 프롬프트 체인으로 fallback됨
- `agent_graph.py`는 `generate_sql → verify_sql → execute_sql → handle_empty_result → analyze_results` 흐름을 LangGraph FSM으로 실행함
- LangSmith는 `LANGSMITH_TRACING=true`일 때 LangGraph node 단위 trace를 수집함
- `eval/ragas_eval.py`는 샘플 질문셋 기준 SQL 안전성/정확도와 선택적 Ragas SQL semantic equivalence를 평가함
- Web UI의 "Vanna 학습" 버튼은 `/api/training/sql`을 호출하여 승인된 질문-SQL 쌍을 저장함
- `main.py`는 Thin CLI wrapper 역할만 수행
- 향후 Web UI 개발 시 `agent.run(question)` 메서드를 API 엔드포인트에서 직접 호출하면 됨

## 검증 결과

- 10개 샘플 질문 SQL 실행: 전부 정상
- Schema COMMENT 매칭: proposal과 일치 (DB에 없을 시 fallback 적용)
- SQL 안전성: DROP/DELETE/UPDATE/INSERT/ALTER 등 차단 확인
