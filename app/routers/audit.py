import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.dependencies import get_client_ip, get_db, require_role
from app.models.audit_log import AuditLog
from app.models.user import User, UserRole
from app.schemas.application import AuditLogResponse
from app.services.audit import write_audit_log
from app.services.csv_export import (
    AUDIT_EXPORT_FIELDS,
    safe_export_filename,
    stream_audit_csv,
)

router = APIRouter()
logger = logging.getLogger(__name__)

# Жёсткий лимит количества строк, выгружаемых одним экспортом (CWE-770).
EXPORT_HARD_LIMIT = 10_000


@router.get("/", response_model=List[AuditLogResponse])
def list_audit_logs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.manager, UserRole.admin)),
):
    return (
        db.query(AuditLog)
        .order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/export")
def export_audit_logs(
    request: Request,
    since: Optional[datetime] = Query(default=None),
    until: Optional[datetime] = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.admin)),
):
    """
    Экспорт аудит-логов в CSV. Только роль admin (CWE-285).
    - Allowlist полей (CWE-200);
    - Защита от Formula Injection (CWE-1236);
    - StreamingResponse + батчи + жёсткий лимит строк (CWE-770);
    - Имя файла формируется без пользовательского ввода (CWE-22).
    """
    if since and until and since > until:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="`since` must be earlier than `until`",
        )

    query = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if since is not None:
        query = query.filter(AuditLog.created_at >= since)
    if until is not None:
        query = query.filter(AuditLog.created_at <= until)
    rows = query.limit(EXPORT_HARD_LIMIT).yield_per(200)

    write_audit_log(
        db,
        actor_id=current_user.id,
        action="EXPORT_AUDIT_LOGS",
        target_type="audit_log",
        ip_address=get_client_ip(request),
    )

    filename = safe_export_filename("audit_logs", "csv")
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
    }
    return StreamingResponse(
        stream_audit_csv(rows, AUDIT_EXPORT_FIELDS),
        media_type="text/csv; charset=utf-8",
        headers=headers,
    )
