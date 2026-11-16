from datetime import datetime

from pydantic import BaseModel, Field


class TaskRequest(BaseModel):
    message: str = Field(min_length=1)


class TaskResponse(BaseModel):
    plan: list[str]
    specialist: str
    output: str


class ComplianceItem(BaseModel):
    code: str
    title: str
    status: str
    detail: str


class ComplianceReport(BaseModel):
    checked_at: datetime
    items: list[ComplianceItem]
