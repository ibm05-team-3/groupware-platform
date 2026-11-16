from typing import Literal

from langgraph.graph import END, START, StateGraph
from typing_extensions import TypedDict

from app.models import TaskResponse
from app.orchestrator.routing import choose_specialist
from app.planner.planner import plan
from app.researcher.researcher import research
from app.specialists.leave_draft import draft_leave
from app.specialists.menu import find_menu
from app.specialists.policy_qa import answer_policy


class AgentState(TypedDict):
    message: str
    plan: list[str]
    specialist: str
    output: str


def plan_node(state: AgentState) -> dict[str, list[str] | str]:
    message = state["message"]
    specialist = choose_specialist(message)
    steps = plan(message)
    output = ""
    if specialist == "planner":
        output = "담당 모듈을 정하지 못했습니다. 메뉴, 휴가 신청, 사내규정, 외부 자료 중 하나를 지정해 주세요."
    return {"plan": steps, "specialist": specialist, "output": output}


def specialist_node(state: AgentState) -> dict[str, str]:
    message = state["message"]
    specialist = state["specialist"]
    if specialist == "menu":
        output = find_menu(message)
    elif specialist == "leave_draft":
        output = draft_leave(message)
    elif specialist == "policy_qa":
        output = answer_policy(message)
    elif specialist == "researcher":
        output = research(message)
    else:
        output = state["output"]
    return {"output": output}


def route_after_plan(state: AgentState) -> Literal["specialist", "end"]:
    if state["specialist"] == "planner":
        return "end"
    return "specialist"


def build_graph():
    graph = StateGraph(AgentState)
    graph.add_node("plan", plan_node)
    graph.add_node("specialist", specialist_node)
    graph.add_edge(START, "plan")
    graph.add_conditional_edges(
        "plan",
        route_after_plan,
        {"specialist": "specialist", "end": END},
    )
    graph.add_edge("specialist", END)
    return graph.compile()


graph = build_graph()


def run_task(message: str) -> TaskResponse:
    result = graph.invoke(
        {"message": message, "plan": [], "specialist": "", "output": ""}
    )
    return TaskResponse(
        plan=result["plan"],
        specialist=result["specialist"],
        output=result["output"],
    )
