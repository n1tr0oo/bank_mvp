# Bank Credit MVP — Практическая работа № 6

> **Тема:** Разработка и оценка защищённости MVP-продукта в соответствии с принципами Secure SDLC и OWASP Top 10.
> **Вариант:** 1 — Банковское дело: одобрение кредитов и мониторинг.
> **Автор:** Махан Азат, CSE-2503M.

Сервис подачи и обработки кредитных заявок: клиент подаёт заявку через веб-интерфейс, менеджер принимает решение, администратор управляет пользователями и просматривает аудит-логи. Реализован полный сценарий «подача → рассмотрение → решение → аудит» с акцентом на безопасность по 10 классам OWASP Top 10.

---

## Стек технологий

| Слой | Инструмент |
|------|-----------|
| Язык | Python 3.12 |
| Web framework | FastAPI 0.115 + Starlette |
| ORM | SQLAlchemy 2.0 |
| БД | PostgreSQL 16 |
| Шаблоны UI | Jinja2 (server-side rendering) |
| Валидация | Pydantic v2 + EmailStr |
| Хеширование паролей | bcrypt (через passlib) |
| Токены | JWT HS256 (`python-jose`) + jti blacklist |
| Rate limiting | slowapi |
| Контейнеризация | Docker + docker-compose |
| SAST / SCA | bandit, pip-audit |

---

## Архитектура

```
                ┌──────────────────────────────────────────┐
   Browser ──►  │  TLS / Reverse-proxy (вне образа)        │
                └────────────┬─────────────────────────────┘
                             ▼
                ┌──────────────────────────────────────────┐
                │ FastAPI app                              │
                │  ├ MaxBodySizeMiddleware  (CWE-770)      │
                │  ├ SecurityHeadersMiddleware (HSTS/CSP/…)│
                │  ├ SlowAPIMiddleware      (CWE-307)      │
                │  ├ Routers                               │
                │  │   /auth        (register/login/out)   │
                │  │   /applications (CRUD заявок)         │
                │  │   /audit-logs   (журнал + CSV-export) │
                │  │   /admin        (пользователи)        │
                │  │   /ui/*         (Jinja2 UI)           │
                │  └ Глобальные exception handlers         │
                └────────────┬─────────────────────────────┘
                             ▼
                ┌──────────────────────────────────────────┐
                │ PostgreSQL                               │
                │  users · credit_applications ·           │
                │  audit_logs · revoked_tokens             │
                └──────────────────────────────────────────┘
```

### Сущности БД

| Таблица | Назначение |
|---------|------------|
| `users` | пользователи системы (роли: client/manager/admin) |
| `credit_applications` | кредитные заявки (pending/approved/rejected) |
| `audit_logs` | журнал критичных действий (login/logout/decision/admin actions) |
| `revoked_tokens` | blacklist отозванных JWT (jti + exp) |

### Роли

| Роль | Права |
|------|-------|
| `client` | подать заявку, видеть **только свои** заявки |
| `manager` | видеть все заявки, принимать решения, читать аудит-логи |
| `admin` | управление пользователями (деактивация), экспорт аудит-логов в CSV, очистка blacklist токенов |

---

## API-эндпоинты

| Метод | Путь | Доступ | Описание |
|-------|------|--------|----------|
| POST | `/auth/register` | публ. | Регистрация клиента (роль зашита) |
| POST | `/auth/login` | публ. | Логин, выдача JWT |
| POST | `/auth/logout` | auth | Отзыв JWT (jti → blacklist) |
| POST | `/auth/token` | публ. | OAuth2-вариант для Swagger UI |
| POST | `/applications/` | client | Создать заявку |
| GET | `/applications/` | auth | Список заявок (по роли: свои/все) |
| GET | `/applications/{id}` | auth | Детали заявки (объектная авторизация) |
| PUT | `/applications/{id}/decision` | manager | Принять решение |
| GET | `/audit-logs/` | manager+ | Постраничный список аудит-логов |
| GET | `/audit-logs/export` | admin | Экспорт CSV (формула-инъекции защищены) |
| GET | `/admin/users` | admin | Список пользователей |
| POST | `/admin/users/{id}/deactivate` | admin | Деактивировать пользователя |
| POST | `/admin/revoked-tokens/cleanup` | admin | Удалить истёкшие токены из blacklist |
| GET | `/health` | публ. | Healthcheck (для Docker) |

UI на server-side Jinja2: `/ui/login`, `/ui/register`, `/ui/applications`, `/ui/applications/new`, `/ui/applications/{id}`, `/ui/audit-logs`, `/ui/admin/users`.

---

## Запуск

### Вариант A — Docker Compose (рекомендуется)

```bash
cp .env.example .env
# отредактировать .env: задать SECRET_KEY и POSTGRES_PASSWORD
docker compose up --build -d
docker compose run --rm app python seed.py     # 200+ строк в каждой ключевой таблице
```

UI: <http://localhost:8000/ui/login>
Health: <http://localhost:8000/health>
Swagger (если `ENABLE_DOCS=true`): <http://localhost:8000/docs>

### Вариант B — локальный Python + локальный PostgreSQL

```bash
python -m venv .venv && . .venv/Scripts/activate     # Windows PowerShell
pip install -r requirements.txt
cp .env.example .env
# отредактировать .env: DATABASE_URL → ваш Postgres, SECRET_KEY → новый
python seed.py
uvicorn app.main:app --reload
```

### Демо-аккаунты (после `python seed.py`)

| Роль | Email | Пароль |
|------|-------|--------|
| client | `client1@bank.com` | `Client@1111` |
| client | `client2@bank.com` | `Client@2222` |
| manager | `manager@bank.com` | `Manager@3333` |
| admin | `admin@bank.com` | `Admin@44444` |

---

## Реализованные механизмы безопасности

| OWASP Top 10 (2021/2025) | Реализация |
|---|---|
| A01 Broken Access Control | RBAC через `require_role`; объектная авторизация `require_application_access` (CWE-639); 404 вместо 403 на чужие ресурсы; роль приходит **только** с сервера (не из тела `/auth/register`) |
| A02 Cryptographic Failures | bcrypt cost=12 для паролей; JWT HS256 + uniq jti; SECRET_KEY ≥ 64 hex; HSTS заголовок |
| A03 Injection | ORM SQLAlchemy 2.0 (без сырых SQL); Pydantic-валидация на типы/диапазоны/длины; `_sanitize` для CRLF (CWE-117); защита от Formula Injection в CSV (CWE-1236) |
| A04 Insecure Design | Поэтапные проверки: размер тела → JWT → роль → объектный доступ → бизнес-инвариант (нельзя пересмотреть уже принятое решение) |
| A05 Security Misconfiguration | `ENABLE_DOCS=false` в production; CSP `default-src 'none'` для API, `'self'` для UI; X-Frame-Options DENY; `cap_drop: [ALL]` + `read_only` в Docker; non-root юзер |
| A06 Vulnerable & Outdated Components | Версии зависимостей зафиксированы; `python-jose` 3.4.0 (CVE-2024-33663); `pyasn1` 0.6.3; pip-audit/bandit запускаются на каждом этапе |
| A07 Identification and Authentication Failures | Политика паролей ≥10 символов + 3 класса + deny-list (CWE-521); rate-limiting 5/min на login и register; одинаковое сообщение для отсутствующего/неверного пароля; logout инвалидирует jti |
| A08 Software and Data Integrity Failures | requirements.txt с pinned-версиями; Docker pin-версия Python и Postgres; `read_only` rootfs; HttpOnly + SameSite=Lax cookie |
| A09 Security Logging & Monitoring Failures | `audit_logs` для всех критичных событий (LOGIN, LOGOUT, REGISTER, SUBMIT, APPROVED, REJECTED, DEACTIVATE_USER, EXPORT_AUDIT_LOGS, CLEANUP_REVOKED_TOKENS); IP клиента (защита от подмены X-Forwarded-For); CSV-экспорт; пароли/токены в логах не появляются |
| A10 Server-Side Request Forgery | Приложение не делает исходящих HTTP-запросов из бизнес-логики, поверхность атаки минимальная |

Дополнительно:
- **CSRF (для UI):** HttpOnly + SameSite=Lax cookie + Origin-проверка на всех POST.
- **DoS:** `MaxBodySizeMiddleware` 1 МБ; `slowapi` rate-limit; жёсткий лимит 10000 строк на CSV-экспорт.
- **Утечка ошибок (CWE-209):** глобальный exception handler возвращает нейтральный JSON для API и редиректит UI на `/ui/login` без подробностей.

---

## Журналирование

В таблицу `audit_logs` пишутся:

| Действие | Когда |
|----------|-------|
| `LOGIN` | успешный вход (через API или UI) |
| `LOGOUT` | отзыв токена |
| `REGISTER` | регистрация клиента через UI |
| `SUBMIT_APPLICATION` | подача кредитной заявки |
| `APPLICATION_APPROVED` / `APPLICATION_REJECTED` | решение менеджера |
| `DEACTIVATE_USER` | админ заблокировал пользователя |
| `CLEANUP_REVOKED_TOKENS` | админ очистил blacklist |
| `EXPORT_AUDIT_LOGS` | админ выгрузил CSV |

Поля: `actor_id`, `action`, `target_type`, `target_id`, `ip_address`, `created_at`.
Чувствительные данные (пароли, JWT, ПДн) в логах **не сохраняются**, только идентификаторы.

---

## Тестирование защищённости

```bash
# SAST
pip install bandit
bandit -r app/ -f txt -o bandit_report.txt

# SCA
pip install pip-audit
pip-audit -r requirements.txt -o pip_audit_report.txt
```

Полные результаты анализа OWASP Top 10 — в файле [`P6_Makhan_Azat.md`](P6_Makhan_Azat.md).

---

## Структура репозитория

```
mvp/
├── app/
│   ├── main.py                # FastAPI app + middleware + exception handlers
│   ├── config.py              # Pydantic-настройки (берутся из .env)
│   ├── database.py            # SQLAlchemy engine + session factory
│   ├── dependencies.py        # get_db / get_current_user / require_role / cookie auth
│   ├── middleware/            # MaxBodySize, SecurityHeaders
│   ├── models/                # User, CreditApplication, AuditLog, RevokedToken
│   ├── routers/               # auth, applications, audit, admin, ui
│   ├── schemas/               # Pydantic схемы запроса/ответа
│   ├── services/              # security (bcrypt+JWT), audit, csv_export
│   ├── templates/             # Jinja2 шаблоны UI
│   └── static/                # CSS UI (только локально, без CDN)
├── seed.py                    # сидирование 200+ строк в каждой таблице
├── requirements.txt           # pinned-зависимости
├── Dockerfile                 # non-root, slim, healthcheck
├── docker-compose.yml         # postgres + app, read_only rootfs, no-new-privileges
├── .env.example               # шаблон .env (реальные секреты в .env, не коммитятся)
├── .gitignore
├── .dockerignore
├── README.md                  # этот файл
├── P6_Makhan_Azat.md          # отчёт по практической работе
└── mvp_ai/                    # Задание 2 — AI-ассистированная версия
```

---

## Лицензия и авторство

Учебный проект ENU CSE-2503M. Не предназначен для production-эксплуатации без дополнительного аудита. Преподаватель: Lisnevskyi Rostyslav.
