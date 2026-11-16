from app.orchestrator.routing import choose_specialist

SPECIALIST_LABELS = {
    "menu": "메뉴 위치 찾기",
    "leave_draft": "휴가 신청서 초안",
    "policy_qa": "사내규정·노무 Q&A",
    "researcher": "외부 공식 자료 검색",
    "planner": "추가 분류",
}


def plan(message: str) -> list[str]:
    specialist = choose_specialist(message)
    label = SPECIALIST_LABELS[specialist]
    return [
        "요청을 한 가지 작업으로 나눈다.",
        f"담당: {label}",
    ]
