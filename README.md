# ThreatIntel-Agent Colab Submission

Colab에서 Neon PostgreSQL에 배포된 `threat_intel_agent` DB를 조회하고, OpenAI API 기반 자연어 질의와 Gradio UI를 검증하는 과제 제출용 최소 패키지입니다.

## 포함 파일

```text
.
├── colab_support/
│   └── neon_gradio_threat_agent.py
├── docs/
│   └── project_proposal.md
├── notebooks/
│   └── threat_intel_neon_gradio_colab.ipynb
├── requirements.txt
└── README.md
```

## Colab 실행

노트북:

```text
notebooks/threat_intel_neon_gradio_colab.ipynb
```

Colab 첫 단계에서 이 repo를 clone합니다.

```python
!git clone https://github.com/jazdr/threat-analysis-agent.git
%cd threat-analysis-agent
```

이후 노트북에서 다음 값을 직접 입력합니다.

- Neon `DATABASE_URL`: 이미 데이터가 적재된 `threat_intel_agent` DB 접속 문자열
- OpenAI API Key: 자연어 SQL 생성과 결과 분석용

## 검증 범위

- Neon DB 테이블 row count 확인
- 제안서 샘플 SQL 10개 실행 검증
- `(상관분석)` 3-table join 질의 검증
- OpenAI `gpt-4o-mini` 기반 자연어 → SQL → 실행 → 분석
- Gradio UI 실행

## 보안 주의

이 저장소에는 API Key, Neon password, `.env`, CSV 원본 데이터를 포함하지 않습니다. 접속 정보는 Colab 실행 시 `getpass()`로 직접 입력합니다.
