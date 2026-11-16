def choose_specialist(message: str) -> str:
    if any(word in message for word in ("메뉴", "화면", "어디")):
        return "menu"
    if any(word in message for word in ("휴가", "연차 신청", "신청서")):
        return "leave_draft"
    if any(word in message for word in ("규정", "노무", "온보딩", "오프보딩", "입사", "퇴사")):
        return "policy_qa"
    if any(word in message for word in ("법령", "공식", "고용노동", "검색")):
        return "researcher"
    return "planner"
