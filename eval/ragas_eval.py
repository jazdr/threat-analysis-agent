"""Offline Text-to-SQL evaluation with optional Ragas SQL equivalence.

Default mode generates SQL for eval/eval_set.json and reports deterministic
local checks. Pass --ragas to add LLM-judged SQL semantic equivalence.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from pathlib import Path
from statistics import mean
from typing import Any

from openai import AsyncOpenAI

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import config
from agent import ThreatIntelAgent
from db_client import DBClient

DEFAULT_EVAL_SET = ROOT / "eval" / "eval_set.json"
DEFAULT_OUTPUT = ROOT / "eval" / "ragas_results.json"


def normalize_sql(sql: str) -> str:
    cleaned = re.sub(r"--.*?$", "", sql, flags=re.MULTILINE)
    cleaned = re.sub(r"/\*.*?\*/", "", cleaned, flags=re.DOTALL)
    cleaned = re.sub(r"\s+", " ", cleaned.strip().rstrip(";")).lower()
    return cleaned


def load_eval_set(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Evaluation set must be a list: {path}")
    return data


async def score_with_ragas(rows: list[dict[str, Any]], schema: str) -> list[dict[str, Any]]:
    from ragas.llms.base import llm_factory
    from ragas.metrics.collections import SQLSemanticEquivalence

    client_kwargs = {"api_key": config.LLM_API_KEY}
    if config.LLM_BASE_URL:
        client_kwargs["base_url"] = config.LLM_BASE_URL
    llm = llm_factory(config.LLM_MODEL, client=AsyncOpenAI(**client_kwargs))
    metric = SQLSemanticEquivalence(llm=llm)

    for row in rows:
        if row.get("generated_sql"):
            result = await metric.ascore(
                response=row["generated_sql"],
                reference=row["reference_sql"],
                reference_contexts=[schema],
            )
            row["ragas_sql_semantic_equivalence"] = result.value
            row["ragas_reason"] = result.reason
        else:
            row["ragas_sql_semantic_equivalence"] = 0.0
            row["ragas_reason"] = "No generated SQL"
    return rows


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--eval-set", type=Path, default=DEFAULT_EVAL_SET)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--ragas", action="store_true", help="Run LLM-based Ragas SQL semantic equivalence")
    args = parser.parse_args()

    examples = load_eval_set(args.eval_set)
    agent = ThreatIntelAgent()
    schema = agent.schema

    rows: list[dict[str, Any]] = []
    for item in examples:
        generated_sql, generation = agent._generate_sql(item["question"])
        exact_match = normalize_sql(generated_sql or "") == normalize_sql(item["reference_sql"])
        rows.append(
            {
                "id": item.get("id"),
                "question": item["question"],
                "reference_sql": item["reference_sql"],
                "generated_sql": generated_sql,
                "sql_source": generation.get("source"),
                "fallback_reason": generation.get("fallback_reason"),
                "safe_query": DBClient.is_safe_query(generated_sql or ""),
                "normalized_exact_match": exact_match,
            }
        )

    if args.ragas:
        rows = await score_with_ragas(rows, schema)

    summary = {
        "total": len(rows),
        "safe_query_rate": mean([1.0 if r["safe_query"] else 0.0 for r in rows]) if rows else 0.0,
        "normalized_exact_match_rate": mean([1.0 if r["normalized_exact_match"] else 0.0 for r in rows]) if rows else 0.0,
    }
    if args.ragas:
        summary["ragas_sql_semantic_equivalence_avg"] = mean(
            [float(r.get("ragas_sql_semantic_equivalence") or 0.0) for r in rows]
        ) if rows else 0.0

    payload = {"summary": summary, "rows": rows}
    args.output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    asyncio.run(main())
