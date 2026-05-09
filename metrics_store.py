"""Lightweight JSONL metrics store for dashboard views."""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any


class MetricsStore:
    def __init__(self, path: str = "metrics/query_events.jsonl", max_recent: int = 50):
        self.path = Path(path)
        self.max_recent = max_recent
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: dict[str, Any]) -> dict[str, Any]:
        payload = {
            "ts": time.time(),
            **event,
        }
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
        return payload

    def read_events(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        events: list[dict[str, Any]] = []
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        events.append(parsed)
                except json.JSONDecodeError:
                    continue
        return events

    def summary(self) -> dict[str, Any]:
        events = self.read_events()
        total = len(events)
        successes = sum(1 for e in events if e.get("status") == "success")
        failures = sum(1 for e in events if e.get("status") == "error")
        avg_elapsed = 0.0
        elapsed_values = [float(e.get("elapsed_ms") or 0) for e in events if e.get("elapsed_ms") is not None]
        if elapsed_values:
            avg_elapsed = round(sum(elapsed_values) / len(elapsed_values), 1)

        by_type = Counter(str(e.get("type") or "unknown") for e in events)
        by_sql_source = Counter(str(e.get("sql_source") or "unknown") for e in events if e.get("type") == "nl_query")
        errors = Counter(str(e.get("error") or "unknown")[:120] for e in events if e.get("status") == "error")

        return {
            "total_events": total,
            "successes": successes,
            "failures": failures,
            "avg_elapsed_ms": avg_elapsed,
            "by_type": dict(by_type),
            "by_sql_source": dict(by_sql_source),
            "top_errors": [{"message": message, "count": count} for message, count in errors.most_common(5)],
            "recent_events": events[-self.max_recent:][::-1],
        }
