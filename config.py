"""설정 관리 모듈 (환경변수 기반)"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── LangSmith tracing compatibility ───────────────────
# langsmith versions differ on whether they read LANGSMITH_TRACING,
# LANGSMITH_TRACING_V2, or the legacy LANGCHAIN_TRACING_V2 flag.
LANGSMITH_TRACING = os.getenv("LANGSMITH_TRACING", "false").strip().lower() in {"1", "true", "yes", "on"}
LANGSMITH_PROJECT = os.getenv("LANGSMITH_PROJECT", "threat-analysis-agent")
if LANGSMITH_TRACING:
    os.environ.setdefault("LANGSMITH_TRACING_V2", "true")
    os.environ.setdefault("LANGCHAIN_TRACING_V2", "true")
os.environ.setdefault("LANGSMITH_PROJECT", LANGSMITH_PROJECT)

# ── Database ──────────────────────────────────────────
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "15432"))
DB_NAME = os.getenv("DB_NAME", "threat_intel")
DB_USER = os.getenv("DB_USER", "admin")
DB_PASSWORD = os.getenv("DB_PASSWORD", "admin123")

DB_DSN = f"host={DB_HOST} port={DB_PORT} dbname={DB_NAME} user={DB_USER} password={DB_PASSWORD}"

# ── LLM ───────────────────────────────────────────────
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:11434/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "ollama")
LLM_MODEL = os.getenv("LLM_MODEL", "kimi-k2.6")
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.1"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "4096"))
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "60"))

# ── Agent ─────────────────────────────────────────────
MAX_SQL_RETRIES = int(os.getenv("MAX_SQL_RETRIES", "2"))
QUERY_TIMEOUT_MS = int(os.getenv("QUERY_TIMEOUT_MS", "5000"))
MAX_RESULT_ROWS = int(os.getenv("MAX_RESULT_ROWS", "500"))
MAX_QUESTION_LENGTH = int(os.getenv("MAX_QUESTION_LENGTH", "1000"))
USE_LANGGRAPH = os.getenv("USE_LANGGRAPH", "true").strip().lower() in {"1", "true", "yes", "on"}

# ── Vanna Text-to-SQL ─────────────────────────────────
USE_VANNA = os.getenv("USE_VANNA", "true").strip().lower() in {"1", "true", "yes", "on"}
VANNA_PERSIST_DIR = os.getenv("VANNA_PERSIST_DIR", "./vanna_chroma")
VANNA_TRAINING_DIR = os.getenv("VANNA_TRAINING_DIR", "./training")
VANNA_AUTO_TRAIN = os.getenv("VANNA_AUTO_TRAIN", "true").strip().lower() in {"1", "true", "yes", "on"}
