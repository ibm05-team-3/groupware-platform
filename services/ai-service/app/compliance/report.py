from datetime import datetime, timezone

from app.models import ComplianceItem, ComplianceReport

CHECKS = (
    ("four_insurances", "4대보험"),
    ("annual_leave_promotion", "연차 촉진"),
)


def build_report() -> ComplianceReport:
    return ComplianceReport(
        checked_at=datetime.now(timezone.utc),
        items=[
            ComplianceItem(
                code=code,
                title=title,
                status="no_data",
                detail="인사 데이터가 연결되지 않아 준수 여부를 판단하지 않았습니다.",
            )
            for code, title in CHECKS
        ],
    )
