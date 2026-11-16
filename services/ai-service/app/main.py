from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.compliance.report import build_report
from app.models import ComplianceReport, TaskRequest, TaskResponse
from app.orchestrator.graph import run_task
from app.orchestrator.mcp_server import mcp, transport_security

mcp_asgi = mcp.streamable_http_app(transport_security=transport_security)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    async with mcp.session_manager.run():
        yield


app = FastAPI(title="ai-service", lifespan=lifespan)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/tasks", response_model=TaskResponse)
def create_task(body: TaskRequest) -> TaskResponse:
    return run_task(body.message)


@app.post("/compliance/reports", response_model=ComplianceReport)
def create_report() -> ComplianceReport:
    return build_report()


app.mount("/", mcp_asgi)
