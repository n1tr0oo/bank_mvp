import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.dependencies import (
    get_client_ip,
    get_current_user,
    get_db,
    require_application_access,
    require_role,
)
from app.models.credit_application import ApplicationStatus, CreditApplication
from app.models.user import User, UserRole
from app.schemas.application import ApplicationCreate, ApplicationResponse, DecisionRequest
from app.services.audit import write_audit_log

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/", response_model=ApplicationResponse, status_code=status.HTTP_201_CREATED)
def create_application(
    data: ApplicationCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.client)),
):
    application = CreditApplication(
        client_id=current_user.id,
        amount=data.amount,
        purpose=data.purpose,
        term_months=data.term_months,
    )
    db.add(application)
    db.commit()
    db.refresh(application)

    write_audit_log(
        db,
        actor_id=current_user.id,
        action="SUBMIT_APPLICATION",
        target_type="credit_application",
        target_id=application.id,
        ip_address=get_client_ip(request),
    )
    return application


@router.get("/", response_model=List[ApplicationResponse])
def list_applications(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role in (UserRole.manager, UserRole.admin):
        return db.query(CreditApplication).order_by(CreditApplication.created_at.desc()).all()

    return (
        db.query(CreditApplication)
        .filter(CreditApplication.client_id == current_user.id)
        .order_by(CreditApplication.created_at.desc())
        .all()
    )


@router.get("/{application_id}", response_model=ApplicationResponse)
def get_application(
    application_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    application = (
        db.query(CreditApplication)
        .filter(CreditApplication.id == application_id)
        .first()
    )
    if not application:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    require_application_access(application, current_user)
    return application


@router.put("/{application_id}/decision", response_model=ApplicationResponse)
def decide_application(
    application_id: int,
    decision: DecisionRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.manager)),
):
    application = (
        db.query(CreditApplication)
        .filter(CreditApplication.id == application_id)
        .first()
    )
    if not application:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    if application.status != ApplicationStatus.pending:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Application has already been decided",
        )

    application.status = decision.decision
    application.manager_comment = decision.manager_comment
    application.decided_by = current_user.id
    application.decided_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(application)

    write_audit_log(
        db,
        actor_id=current_user.id,
        action=f"APPLICATION_{decision.decision.value.upper()}",
        target_type="credit_application",
        target_id=application.id,
        ip_address=get_client_ip(request),
    )
    return application
