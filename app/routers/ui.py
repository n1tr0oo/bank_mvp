"""
UI-роутер для Jinja2-страниц.

Архитектура:
- Аутентификация — JWT, который для UI кладётся в HttpOnly + SameSite=Lax cookie.
- Все страницы используют те же бизнес-функции и Pydantic-схемы, что и API.
- На страницах с изменением состояния (login, register, decision, deactivate)
  используется POST + Origin-проверка (минимальная защита от CSRF, см. _check_origin).
- Роли проверяются на сервере (никакой клиентской «защиты»).
"""
from datetime import datetime, timedelta, timezone
import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.dependencies import (
    SESSION_COOKIE_NAME,
    get_client_ip,
    get_current_user,
    get_current_user_optional,
    get_db,
)
from app.models.audit_log import AuditLog
from app.models.credit_application import ApplicationStatus, CreditApplication
from app.models.revoked_token import RevokedToken
from app.models.user import User, UserRole
from app.schemas.application import ApplicationCreate, DecisionRequest
from app.schemas.user import UserCreate
from app.services.audit import write_audit_log
from app.services.security import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)

router = APIRouter()
logger = logging.getLogger(__name__)
templates = Jinja2Templates(directory="app/templates")


# ---------- helpers ----------


def _set_session_cookie(response: RedirectResponse, token: str) -> None:
    """
    Cookie с JWT для UI.
    - HttpOnly: недоступен JS (защита от XSS-краж).
    - SameSite=Lax: блокирует CSRF на cross-origin POST (с сохранением навигаций).
    - Secure: ставится только при ENABLE_SECURE_COOKIE=true (production за TLS).
    - max_age = TTL JWT (без рассинхронизации).
    """
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=not settings.ENABLE_DOCS,  # в dev (DOCS=true) Secure=false, в prod — true
        samesite="lax",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )


def _clear_session_cookie(response: RedirectResponse) -> None:
    response.delete_cookie(key=SESSION_COOKIE_NAME, path="/")


def _check_origin(request: Request) -> None:
    """
    Минимальная защита от CSRF для UI POST-эндпоинтов:
    Origin/Referer должен совпадать с хостом запроса.
    Cookie уже SameSite=Lax, это второй слой.
    """
    origin = request.headers.get("origin") or request.headers.get("referer")
    if origin is None:
        # Браузеры шлют Origin для всех POST. Если его нет — отвергаем.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing Origin")
    expected = f"{request.url.scheme}://{request.url.netloc}"
    if not origin.startswith(expected):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Origin mismatch")


def _redirect(url: str, status_code: int = status.HTTP_303_SEE_OTHER) -> RedirectResponse:
    return RedirectResponse(url=url, status_code=status_code)


def _ui_role_check(current_user: User, *roles: UserRole) -> None:
    if current_user.role not in roles:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")


# ---------- public pages ----------


@router.get("/")
def root(current_user: User | None = Depends(get_current_user_optional)):
    if current_user is None:
        return _redirect("/ui/login")
    return _redirect("/ui/applications")


@router.get("/ui/login")
def login_page(request: Request, current_user: User | None = Depends(get_current_user_optional)):
    if current_user is not None:
        return _redirect("/ui/applications")
    return templates.TemplateResponse(
        request, "login.html", {"current_user": None}
    )


@router.post("/ui/login")
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    _check_origin(request)
    user = db.query(User).filter(User.email == email).first()

    dummy_hash = "$2b$12$KIXSVi8SCfHIrXJ7q4rZNOjXB3Wt5.yCfwkfZDqEWH2tGPF2QlYy"
    password_ok = verify_password(password, user.hashed_password if user else dummy_hash)

    if not user or not password_ok or not user.is_active:
        # Аналогично API: одно сообщение для отсутствующего и неверного пароля.
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "current_user": None,
                "email": email,
                "error": "Неверный email или пароль",
            },
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    write_audit_log(db, actor_id=user.id, action="LOGIN", ip_address=get_client_ip(request))
    token = create_access_token({"sub": str(user.id), "role": user.role})
    response = _redirect("/ui/applications")
    _set_session_cookie(response, token)
    return response


@router.get("/ui/register")
def register_page(request: Request, current_user: User | None = Depends(get_current_user_optional)):
    if current_user is not None:
        return _redirect("/ui/applications")
    return templates.TemplateResponse(request, "register.html", {"current_user": None})


@router.post("/ui/register")
def register_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    full_name: str = Form(...),
    db: Session = Depends(get_db),
):
    _check_origin(request)
    try:
        payload = UserCreate(email=email, password=password, full_name=full_name)
    except ValidationError as exc:
        first = exc.errors()[0]
        return templates.TemplateResponse(
            request,
            "register.html",
            {
                "current_user": None,
                "email": email,
                "full_name": full_name,
                "error": f"{first['loc'][-1]}: {first['msg']}",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    if db.query(User).filter(User.email == payload.email).first():
        return templates.TemplateResponse(
            request,
            "register.html",
            {
                "current_user": None,
                "email": email,
                "full_name": full_name,
                "error": "Регистрация не удалась",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    user = User(
        email=payload.email,
        hashed_password=hash_password(payload.password),
        full_name=payload.full_name,
        role=UserRole.client,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("UI: new user registered id=%s", user.id)

    write_audit_log(db, actor_id=user.id, action="REGISTER", ip_address=get_client_ip(request))
    token = create_access_token({"sub": str(user.id), "role": user.role})
    response = _redirect("/ui/applications")
    _set_session_cookie(response, token)
    return response


@router.post("/ui/logout")
def logout_submit(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    _check_origin(request)
    raw_token = request.cookies.get(SESSION_COOKIE_NAME)
    if raw_token and current_user is not None:
        try:
            payload = decode_access_token(raw_token)
            jti = payload.get("jti")
            exp_ts = payload.get("exp")
            if isinstance(jti, str) and exp_ts is not None:
                expires_at = datetime.fromtimestamp(float(exp_ts), tz=timezone.utc)
                try:
                    db.add(RevokedToken(jti=jti, expires_at=expires_at))
                    db.commit()
                except IntegrityError:
                    db.rollback()
                write_audit_log(
                    db, actor_id=current_user.id, action="LOGOUT",
                    ip_address=get_client_ip(request),
                )
        except Exception:  # noqa: BLE001 — даже при битом токене корректно разлогиним UI
            db.rollback()
    response = _redirect("/ui/login")
    _clear_session_cookie(response)
    return response


# ---------- applications ----------


@router.get("/ui/applications")
def applications_list(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role in (UserRole.manager, UserRole.admin):
        applications = (
            db.query(CreditApplication)
            .order_by(CreditApplication.created_at.desc())
            .limit(500)
            .all()
        )
        title = "Все заявки"
        # Метрики только для manager/admin: считаем по всей таблице, не по выборке.
        total = db.query(CreditApplication).count()
        pending = db.query(CreditApplication).filter(
            CreditApplication.status == ApplicationStatus.pending
        ).count()
        approved = db.query(CreditApplication).filter(
            CreditApplication.status == ApplicationStatus.approved
        ).count()
        rejected = db.query(CreditApplication).filter(
            CreditApplication.status == ApplicationStatus.rejected
        ).count()
        metrics = {"total": total, "pending": pending, "approved": approved, "rejected": rejected}
    else:
        applications = (
            db.query(CreditApplication)
            .filter(CreditApplication.client_id == current_user.id)
            .order_by(CreditApplication.created_at.desc())
            .all()
        )
        title = "Мои заявки"
        metrics = None

    return templates.TemplateResponse(
        request,
        "applications_list.html",
        {
            "current_user": current_user,
            "applications": applications,
            "title": title,
            "metrics": metrics,
        },
    )


@router.get("/ui/applications/new")
def application_new_page(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    _ui_role_check(current_user, UserRole.client)
    return templates.TemplateResponse(
        request, "application_new.html", {"current_user": current_user}
    )


@router.post("/ui/applications/new")
def application_new_submit(
    request: Request,
    amount: str = Form(...),
    purpose: str = Form(...),
    term_months: int = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _check_origin(request)
    _ui_role_check(current_user, UserRole.client)
    try:
        data = ApplicationCreate(amount=amount, purpose=purpose, term_months=term_months)
    except ValidationError as exc:
        first = exc.errors()[0]
        return templates.TemplateResponse(
            request,
            "application_new.html",
            {
                "current_user": current_user,
                "amount": amount,
                "purpose": purpose,
                "term_months": term_months,
                "error": f"{first['loc'][-1]}: {first['msg']}",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

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
    return _redirect(f"/ui/applications/{application.id}")


@router.get("/ui/applications/{application_id}")
def application_detail(
    request: Request,
    application_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    application = db.query(CreditApplication).filter(
        CreditApplication.id == application_id
    ).first()
    if not application:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    # Объектная авторизация (CWE-639):
    # client видит только свою; manager/admin — все.
    if current_user.role == UserRole.client and application.client_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")

    can_decide = (
        current_user.role == UserRole.manager
        and application.status == ApplicationStatus.pending
    )
    return templates.TemplateResponse(
        request,
        "application_detail.html",
        {
            "current_user": current_user,
            "application": application,
            "can_decide": can_decide,
        },
    )


@router.post("/ui/applications/{application_id}/decision")
def application_decide(
    request: Request,
    application_id: int,
    decision: str = Form(...),
    manager_comment: str = Form(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _check_origin(request)
    _ui_role_check(current_user, UserRole.manager)
    try:
        decision_data = DecisionRequest(decision=decision, manager_comment=manager_comment)
    except ValidationError as exc:
        first = exc.errors()[0]
        return templates.TemplateResponse(
            request,
            "application_detail.html",
            {
                "current_user": current_user,
                "application": db.get(CreditApplication, application_id),
                "can_decide": True,
                "error": f"{first['loc'][-1]}: {first['msg']}",
            },
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    application = db.query(CreditApplication).filter(
        CreditApplication.id == application_id
    ).first()
    if not application:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    if application.status != ApplicationStatus.pending:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Application has already been decided",
        )

    application.status = decision_data.decision
    application.manager_comment = decision_data.manager_comment
    application.decided_by = current_user.id
    application.decided_at = datetime.now(timezone.utc)
    db.commit()

    write_audit_log(
        db,
        actor_id=current_user.id,
        action=f"APPLICATION_{decision_data.decision.value.upper()}",
        target_type="credit_application",
        target_id=application.id,
        ip_address=get_client_ip(request),
    )
    return _redirect(f"/ui/applications/{application_id}")


# ---------- audit-logs ----------


@router.get("/ui/audit-logs")
def audit_logs_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ui_role_check(current_user, UserRole.manager, UserRole.admin)
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(200).all()
    return templates.TemplateResponse(
        request,
        "audit_logs.html",
        {"current_user": current_user, "logs": logs},
    )


# ---------- admin ----------


@router.get("/ui/admin/users")
def admin_users_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _ui_role_check(current_user, UserRole.admin)
    users = db.query(User).order_by(User.id.asc()).all()
    return templates.TemplateResponse(
        request,
        "admin_users.html",
        {"current_user": current_user, "users": users},
    )


@router.post("/ui/admin/users/{user_id}/deactivate")
def admin_deactivate_user(
    request: Request,
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _check_origin(request)
    _ui_role_check(current_user, UserRole.admin)
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Admin cannot deactivate themselves",
        )
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    user.is_active = False
    db.commit()

    write_audit_log(
        db,
        actor_id=current_user.id,
        action="DEACTIVATE_USER",
        target_type="user",
        target_id=user.id,
        ip_address=get_client_ip(request),
    )
    return _redirect("/ui/admin/users")


@router.post("/ui/admin/cleanup-revoked")
def admin_cleanup_revoked(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _check_origin(request)
    _ui_role_check(current_user, UserRole.admin)
    now = datetime.now(timezone.utc)
    db.query(RevokedToken).filter(RevokedToken.expires_at < now).delete(
        synchronize_session=False
    )
    db.commit()
    write_audit_log(
        db,
        actor_id=current_user.id,
        action="CLEANUP_REVOKED_TOKENS",
        target_type="revoked_token",
        ip_address=get_client_ip(request),
    )
    return _redirect("/ui/admin/users")
