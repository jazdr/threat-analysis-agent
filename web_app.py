"""FastAPI Web UI Server for ThreatIntel-Agent"""

import json
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import config
from agent import ThreatIntelAgent
from db_client import DBClient
from metrics_store import MetricsStore

agent: ThreatIntelAgent | None = None
metrics = MetricsStore()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global agent
    agent = ThreatIntelAgent()
    # 프론트 로드 시 schema 늦지 않게 미리 warm-up
    try:
        _ = agent.schema
    except Exception as e:
        print(f"Schema warm-up skipped: {e}")
    yield
    agent = None


app = FastAPI(title="ThreatIntel-Agent", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


# ── Models ────────────────────────────────────────────

class QueryRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=config.MAX_QUESTION_LENGTH)


class TrainSqlRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=config.MAX_QUESTION_LENGTH)
    sql: str = Field(..., min_length=1, max_length=20000)


class SqlExecuteRequest(BaseModel):
    sql: str = Field(..., min_length=1, max_length=20000)


# ── Endpoints ─────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    with open("static/index.html", encoding="utf-8") as f:
        return f.read()


@app.get("/api/databases")
def get_databases():
    """사용자에게 할당된 DB 목록. 현재는 1개지만 확장 대응."""
    client = DBClient()
    try:
        conn = client._connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            ORDER BY table_name;
        """)
        tables = [row[0] for row in cur.fetchall()]
        cur.close()
        conn.close()
    except Exception:
        tables = ["otx_threat_intel", "cve_vulnerabilities", "malicious_domains", "malicious_ips"]

    return {
        "databases": [
            {
                "name": config.DB_NAME,
                "host": f"{config.DB_HOST}:{config.DB_PORT}",
                "user": config.DB_USER,
                "tables": tables,
            }
        ]
    }


@app.post("/api/query")
def query(req: QueryRequest):
    if agent is None:
        return JSONResponse({"error": "Agent not ready"}, status_code=503)

    try:
        started = time.time()
        result = agent.run(req.question)
        metrics.record({
            "type": "nl_query",
            "status": "error" if result.get("error") else "success",
            "question": req.question,
            "sql": result.get("sql"),
            "sql_source": result.get("sql_source"),
            "row_count": len(result.get("rows") or []),
            "elapsed_ms": round((time.time() - started) * 1000, 1),
            "error": result.get("error"),
        })
        # RealDictRow -> plain dict (JSON serializable)
        if result.get("rows"):
            result["rows"] = [dict(r) for r in result["rows"]]
        return result
    except Exception as e:
        metrics.record({
            "type": "nl_query",
            "status": "error",
            "question": req.question,
            "elapsed_ms": None,
            "error": str(e),
        })
        return JSONResponse({"error": f"서버 오류: {str(e)}"}, status_code=500)


@app.post("/api/query/stream")
def query_stream(req: QueryRequest):
    if agent is None:
        return JSONResponse({"error": "Agent not ready"}, status_code=503)

    def event_generator():
        started = time.time()
        final_recorded = False
        try:
            for event in agent.run_stream(req.question):
                if event.get("type") in {"final", "error"} and event.get("result", {}).get("rows"):
                    event["result"]["rows"] = [dict(r) for r in event["result"]["rows"]]
                if event.get("type") in {"final", "error"}:
                    result = event.get("result", {})
                    metrics.record({
                        "type": "nl_query",
                        "status": "error" if result.get("error") else "success",
                        "question": req.question,
                        "sql": result.get("sql"),
                        "sql_source": result.get("sql_source"),
                        "row_count": len(result.get("rows") or []),
                        "elapsed_ms": round((time.time() - started) * 1000, 1),
                        "error": result.get("error"),
                    })
                    final_recorded = True
                yield "data: " + json.dumps(event, ensure_ascii=False, default=str) + "\n\n"
        except Exception as e:
            if not final_recorded:
                metrics.record({
                    "type": "nl_query",
                    "status": "error",
                    "question": req.question,
                    "elapsed_ms": round((time.time() - started) * 1000, 1),
                    "error": str(e),
                })
            error_event = {"type": "error", "result": {"error": f"서버 오류: {str(e)}", "trace": []}}
            yield "data: " + json.dumps(error_event, ensure_ascii=False, default=str) + "\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@app.post("/api/sql/execute")
def execute_sql(req: SqlExecuteRequest):
    """Execute a user-written read-only SQL query through DBClient safety guards."""
    client = DBClient()
    started = time.time()
    try:
        rows, columns = client.execute_query(req.sql)
        metrics.record({
            "type": "direct_sql",
            "status": "success",
            "sql": req.sql,
            "row_count": len(rows),
            "elapsed_ms": round((time.time() - started) * 1000, 1),
            "error": None,
        })
        return {
            "sql": req.sql,
            "rows": [dict(r) for r in rows],
            "columns": columns,
            "row_count": len(rows),
        }
    except Exception as e:
        metrics.record({
            "type": "direct_sql",
            "status": "error",
            "sql": req.sql,
            "elapsed_ms": round((time.time() - started) * 1000, 1),
            "error": str(e),
        })
        return JSONResponse({"error": f"SQL 실행 오류: {str(e)}"}, status_code=400)


@app.get("/api/dashboard")
def dashboard():
    """Operational dashboard data: DB status, table counts, and recent usage metrics."""
    client = DBClient()
    db_status: dict[str, object] = {
        "connected": False,
        "name": config.DB_NAME,
        "host": f"{config.DB_HOST}:{config.DB_PORT}",
        "user": config.DB_USER,
        "error": None,
        "tables": [],
    }
    try:
        conn = client._connect()
        cur = conn.cursor()
        cur.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            ORDER BY table_name;
        """)
        tables = [row[0] for row in cur.fetchall()]
        table_stats = []
        for table in tables:
            cur.execute(f'SELECT COUNT(*) FROM "{table}"')
            table_stats.append({"name": table, "row_count": cur.fetchone()[0]})
        cur.close()
        conn.close()
        db_status["connected"] = True
        db_status["tables"] = table_stats
    except Exception as e:
        db_status["error"] = str(e)

    return {
        "database": db_status,
        "metrics": metrics.summary(),
        "limits": {
            "query_timeout_ms": config.QUERY_TIMEOUT_MS,
            "max_result_rows": config.MAX_RESULT_ROWS,
            "use_vanna": config.USE_VANNA,
        },
    }


@app.get("/api/schema")
def get_schema():
    if agent is None:
        return JSONResponse({"error": "Agent not ready"}, status_code=503)
    return {"schema": agent.schema}


@app.post("/api/training/sql")
def train_sql(req: TrainSqlRequest):
    """Store an approved question-SQL pair in Vanna memory."""
    if agent is None:
        return JSONResponse({"error": "Agent not ready"}, status_code=503)
    try:
        return agent.train_sql_example(req.question, req.sql)
    except Exception as e:
        return JSONResponse({"error": f"Vanna 학습 오류: {str(e)}"}, status_code=500)
