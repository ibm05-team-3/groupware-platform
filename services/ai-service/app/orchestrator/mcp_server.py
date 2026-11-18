from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

from app.compliance.report import build_report
from app.orchestrator.graph import run_task

mcp = MCPServer("groupware-ai")

transport_security = TransportSecuritySettings(
    allowed_hosts=[
        "localhost",
        "localhost:*",
        "127.0.0.1",
        "127.0.0.1:*",
        "ai-service",
        "ai-service:*",
    ],
)


@mcp.tool()
def run_hr_task(message: str) -> str:
    """인사 급여 요청을 계획하고 담당 모듈에 전달한다."""
    return run_task(message).model_dump_json()


@mcp.tool()
def create_compliance_report() -> str:
    """4대보험과 연차 촉진 준수 보고서를 만든다."""
    return build_report().model_dump_json()
