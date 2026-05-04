from datetime import datetime
from decimal import Decimal
from typing import Optional

from pydantic import BaseModel, Field, field_validator

from app.models.credit_application import ApplicationStatus


class ApplicationCreate(BaseModel):
    amount: Decimal = Field(gt=0, le=Decimal("10000000.00"))
    purpose: str = Field(min_length=10, max_length=500, strip_whitespace=True)
    term_months: int = Field(ge=1, le=360)


class DecisionRequest(BaseModel):
    decision: ApplicationStatus
    manager_comment: str = Field(min_length=5, max_length=1000, strip_whitespace=True)

    @field_validator("decision")
    @classmethod
    def decision_cannot_be_pending(cls, v: ApplicationStatus) -> ApplicationStatus:
        if v == ApplicationStatus.pending:
            raise ValueError("Decision must be 'approved' or 'rejected'")
        return v


class ApplicationResponse(BaseModel):
    id: int
    client_id: int
    amount: Decimal
    purpose: str
    term_months: int
    status: ApplicationStatus
    manager_comment: Optional[str] = None
    created_at: datetime
    decided_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AuditLogResponse(BaseModel):
    id: int
    actor_id: int
    action: str
    target_type: Optional[str] = None
    target_id: Optional[int] = None
    ip_address: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}
