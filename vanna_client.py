"""Vanna-based Text-to-SQL adapter with local Chroma training memory."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from typing import Callable

import config


class VannaUnavailable(RuntimeError):
    """Raised when Vanna is disabled, missing, or cannot generate SQL."""


class VannaTextToSQL:
    """Thin wrapper around Vanna so the agent can fall back cleanly."""

    def __init__(
        self,
        schema_provider: Callable[[], str] | None = None,
        persist_dir: str = config.VANNA_PERSIST_DIR,
        training_dir: str = config.VANNA_TRAINING_DIR,
        auto_train: bool = config.VANNA_AUTO_TRAIN,
    ):
        self.schema_provider = schema_provider
        self.persist_dir = Path(persist_dir)
        self.training_dir = Path(training_dir)
        self.auto_train = auto_train
        self._vn = None
        self._trained = False
        self.last_error: str | None = None

    def _build_client(self):
        try:
            from vanna.chromadb import ChromaDB_VectorStore
            from vanna.openai import OpenAI_Chat
        except Exception:
            try:
                from vanna.legacy.chromadb import ChromaDB_VectorStore
                from vanna.legacy.openai import OpenAI_Chat
            except Exception as e:
                raise VannaUnavailable(f"Vanna 패키지를 사용할 수 없습니다: {e}") from e

        try:
            from openai import OpenAI
        except Exception as e:
            raise VannaUnavailable(f"OpenAI 클라이언트를 사용할 수 없습니다: {e}") from e

        class ThreatIntelVanna(ChromaDB_VectorStore, OpenAI_Chat):
            def __init__(self, chroma_config: dict, llm_config: dict, client):
                ChromaDB_VectorStore.__init__(self, config=chroma_config)
                OpenAI_Chat.__init__(self, client=client, config=llm_config)

        class LocalHashEmbedding:
            """Small deterministic embedding function to avoid external downloads."""

            def __call__(self, input):
                return [self._embed(text) for text in input]

            def embed_query(self, input=None, **kwargs):
                texts = input if input is not None else kwargs.get("input", [])
                if isinstance(texts, str):
                    return self._embed(texts)
                return [self._embed(text) for text in texts]

            def embed_documents(self, input=None, **kwargs):
                texts = input if input is not None else kwargs.get("input", [])
                return [self._embed(text) for text in texts]

            @staticmethod
            def name() -> str:
                return "threat-local-hash"

            @staticmethod
            def get_config() -> dict:
                return {"dimensions": 384}

            @staticmethod
            def _embed(text: str) -> list[float]:
                dims = 384
                vector = [0.0] * dims
                tokens = str(text).lower().replace("_", " ").split()
                if not tokens:
                    tokens = [str(text).lower()]
                for token in tokens:
                    digest = hashlib.sha256(token.encode("utf-8")).digest()
                    idx = int.from_bytes(digest[:4], "big") % dims
                    sign = 1.0 if digest[4] % 2 == 0 else -1.0
                    vector[idx] += sign
                norm = sum(v * v for v in vector) ** 0.5 or 1.0
                return [v / norm for v in vector]

        self.persist_dir.mkdir(parents=True, exist_ok=True)
        chroma_config = {"path": str(self.persist_dir), "embedding_function": LocalHashEmbedding()}
        llm_config = {
            "model": config.LLM_MODEL,
            "temperature": config.LLM_TEMPERATURE,
        }
        client_kwargs = {"api_key": config.LLM_API_KEY}
        if config.LLM_BASE_URL:
            client_kwargs["base_url"] = config.LLM_BASE_URL
        return ThreatIntelVanna(chroma_config, llm_config, OpenAI(**client_kwargs))

    @property
    def vn(self):
        if self._vn is None:
            self._vn = self._build_client()
        return self._vn

    def _train_documentation_file(self):
        path = self.training_dir / "schema_docs.md"
        if path.exists():
            self.vn.train(documentation=path.read_text(encoding="utf-8"))

    def _train_example_queries(self):
        path = self.training_dir / "example_queries.json"
        if not path.exists():
            return
        examples = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(examples, list):
            raise VannaUnavailable(f"Vanna 예시 학습 파일 형식이 잘못되었습니다: {path}")
        for item in examples:
            question = str(item.get("question") or "").strip()
            sql = str(item.get("sql") or "").strip()
            if question and sql:
                self.vn.train(question=question, sql=sql)

    def train_static(self, schema: str | None = None):
        """Train Vanna once with current schema text and local examples."""
        if self._trained or not self.auto_train:
            return
        schema_text = schema
        if schema_text is None and self.schema_provider is not None:
            schema_text = self.schema_provider()
        if schema_text:
            self.vn.train(documentation="현재 PostgreSQL public schema:\n\n" + schema_text)
        self._train_documentation_file()
        self._train_example_queries()
        self._trained = True

    def generate_sql(self, question: str, schema: str | None = None) -> str:
        """Generate SQL using Vanna. Raises VannaUnavailable on any failure."""
        try:
            self.train_static(schema)
            sql = self.vn.generate_sql(question=question)
            if not sql or not str(sql).strip():
                raise VannaUnavailable("Vanna가 빈 SQL을 반환했습니다.")
            return str(sql).strip()
        except VannaUnavailable:
            raise
        except Exception as e:
            self.last_error = str(e)
            raise VannaUnavailable(f"Vanna SQL 생성 실패: {e}") from e

    def train_success(self, question: str, sql: str) -> bool:
        """Add an approved question-SQL pair to Vanna memory."""
        if not question.strip() or not sql.strip():
            return False
        try:
            self.vn.train(question=question.strip(), sql=sql.strip())
            return True
        except Exception as e:
            self.last_error = str(e)
            return False
