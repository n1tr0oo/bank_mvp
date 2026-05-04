# Практическая работа № 6

**Тема:** Разработка и оценка защищённости MVP-продукта в соответствии с принципами Secure SDLC и OWASP Top 10.

**Вариант:** 1 — Банковское дело: одобрение кредитов и мониторинг.

**Выполнил:** Махан Азат, CSE-2503M

**Проверил:** Lisnevskyi Rostyslav

---

## Цель работы

Сформировать практические навыки проектирования, реализации, тестирования и аудита защищённого программного продукта. По варианту 1 довести MVP «Банковский сервис кредитных заявок» до финальной версии: реализовать пользовательский интерфейс, развернуть систему в Docker, обеспечить хранение секретов вне кода и провести аудит по 10 классам OWASP Top 10 с подтверждением устранения выявленных уязвимостей.

---

## 1. Краткое описание разработанного MVP

«Bank Credit MVP» — веб-сервис подачи и обработки заявок на потребительский кредит. Реализован полный сценарий: клиент регистрируется и подаёт заявку через UI, менеджер одобряет или отклоняет её с обязательным комментарием, администратор управляет пользователями и просматривает аудит-логи. Каждое критичное действие фиксируется в журнале с указанием актора, IP и метаданных объекта.

**Технологический стек.** Python 3.12, FastAPI 0.122 + Starlette 0.49, SQLAlchemy 2.0, PostgreSQL 16, Pydantic v2, Jinja2 3.1.6 (server-side UI), bcrypt (passlib), PyJWT 2.12 (HS256 + jti blacklist), slowapi (rate limiting), Docker / docker-compose, bandit, pip-audit.

**Соответствие минимальным требованиям ПР6.**

| Требование | Реализация |
|---|---|
| Пользовательский интерфейс | 7 страниц на Jinja2: login, register, applications list (с метриками), new application form, application detail (с формой решения), audit-logs, admin/users |
| ≥5 API-эндпоинтов | 14 публичных эндпоинтов под `/auth`, `/applications`, `/audit-logs`, `/admin` + `/health` + UI |
| ≥3 сущности БД, ≥200 строк | 4 таблицы (users, credit_applications, audit_logs, revoked_tokens). Сидируется: 210 пользователей, 220 заявок, 250 аудит-логов |
| ≥2 роли | `client`, `manager`, `admin` |
| Полный сценарий по варианту | Регистрация клиента → подача заявки → решение менеджера → запись в журнал → просмотр истории клиентом и админом |
| Проверка входных данных | Pydantic v2 (типы, длины, диапазоны, формат email, политика паролей, валидация enum) |
| Хеш паролей | bcrypt cost=12 (passlib) |
| Разграничение прав | RBAC через `require_role()` + объектная авторизация через `require_application_access()` |
| Журналирование критичных действий | Таблица `audit_logs`: LOGIN, LOGOUT, REGISTER, SUBMIT_APPLICATION, APPLICATION_APPROVED, APPLICATION_REJECTED, DEACTIVATE_USER, EXPORT_AUDIT_LOGS, CLEANUP_REVOKED_TOKENS |
| Без утечки чувствительных данных в логах | Пароли, JWT, ПДн в логи не пишутся; CRLF-инъекция в логи блокируется санитизацией |
| Секреты вне кода | `.env` исключён из репозитория (`.gitignore`); `.env.example` содержит только заглушки; SECRET_KEY обязателен в docker-compose |
| Docker | `Dockerfile` (python:3.12-slim, non-root, healthcheck) + `docker-compose.yml` (postgres + app, `read_only` rootfs, `cap_drop: ALL`, `no-new-privileges`) |

---

## 2. Архитектура системы

```
                ┌──────────────────────────────────────────────────┐
   Browser ───► │  TLS / Reverse-proxy (вне образа)                │
                └────────────────┬─────────────────────────────────┘
                                 ▼
                ┌──────────────────────────────────────────────────┐
                │ FastAPI app (uvicorn, non-root)                  │
                │  ┌─ Middleware (порядок обработки запроса) ───┐  │
                │  │ MaxBodySizeMiddleware     (CWE-770)        │  │
                │  │ SecurityHeadersMiddleware (HSTS/CSP/...)   │  │
                │  │ SlowAPIMiddleware         (CWE-307)        │  │
                │  └────────────────────────────────────────────┘  │
                │  ┌─ Routers ─────────────────────────────────┐   │
                │  │ /auth        register / login / logout    │   │
                │  │ /applications  CRUD, decision             │   │
                │  │ /audit-logs   list, CSV export            │   │
                │  │ /admin        users management            │   │
                │  │ /ui/*         Jinja2 UI (HttpOnly cookie) │   │
                │  └────────────────────────────────────────────┘  │
                │  ┌─ Dependencies ────────────────────────────┐   │
                │  │ get_db / get_current_user / require_role  │   │
                │  │ require_application_access / get_client_ip│   │
                │  └────────────────────────────────────────────┘  │
                │  ┌─ Services ────────────────────────────────┐   │
                │  │ security (bcrypt + JWT) / audit / csv_exp │   │
                │  └────────────────────────────────────────────┘  │
                │  Глобальные exception handlers (CWE-209, 754)    │
                └────────────────┬─────────────────────────────────┘
                                 ▼
                ┌──────────────────────────────────────────────────┐
                │ PostgreSQL 16 (внутри сети compose, без публ-х    │
                │ портов наружу)                                   │
                │  users · credit_applications · audit_logs ·      │
                │  revoked_tokens                                  │
                └──────────────────────────────────────────────────┘
```

**Сущности БД.**

| Таблица | Поля (ключевые) | Назначение |
|---------|----------------|-----------|
| `users` | id, email (unique), hashed_password, full_name, role, is_active, created_at | Учётные записи |
| `credit_applications` | id, client_id, amount, purpose, term_months, status, manager_comment, decided_by, decided_at | Заявки на кредит |
| `audit_logs` | id, actor_id, action, target_type, target_id, ip_address, created_at | Журнал критичных событий |
| `revoked_tokens` | id, jti (unique), expires_at, revoked_at | Blacklist отозванных JWT |

---

## 3. Роли пользователей и разграничение доступа

| Роль | Регистрация заявки | Просмотр своих заявок | Просмотр всех заявок | Решение по заявке | Аудит-логи | Управление пользователями |
|------|:-:|:-:|:-:|:-:|:-:|:-:|
| **client** | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **manager** | ❌ | ❌ | ✅ | ✅ | ✅ (чтение) | ❌ |
| **admin** | ❌ | — | ✅ | ❌ | ✅ + CSV-экспорт | ✅ (деактивация, чистка blacklist) |

Проверки реализованы **только на сервере** через `require_role(*roles)` (роль) и `require_application_access(application, user)` (объектная авторизация). Клиент не может изменить свою роль через тело запроса (CWE-915 Mass Assignment) — поле `role` отсутствует в Pydantic-схеме `UserCreate`, оно зашито в код регистрации.

---

## 4. Основной бизнес-сценарий

```
┌── Клиент ──┐                ┌── Менеджер ──┐                ┌── Admin ──┐
│ POST       │                │ GET          │                │ GET       │
│ /ui/login  │                │ /ui/         │                │ /ui/admin │
│            │                │ applications │                │ /users    │
│ POST /ui/  │ pending заявка │              │ APPROVED       │           │
│ apps/new   │ ─────────────► │ PUT /ui/apps │ ───────────►   │ Видит лог │
│            │                │ /:id/dec.    │ запись в аудит │ EXPORT    │
│ GET /ui/   │ результат      │              │                │ /audit-   │
│ apps/:id   │ ◄───────────── │              │                │ logs      │
└────────────┘                └──────────────┘                └───────────┘
```

**Шаги (с бэкенд-валидацией на каждом этапе):**

1. `POST /ui/register` — клиент регистрируется. Pydantic проверяет email + пароль ≥10 символов, ≥3 классов символов, не из deny-list (CWE-521). Роль зашита: `UserRole.client`.
2. `POST /ui/login` — выдаётся JWT (HS256, TTL 30 мин, uniq jti). Токен кладётся в HttpOnly + SameSite=Lax cookie. Rate limit: 5/мин на IP.
3. `POST /ui/applications/new` — клиент подаёт заявку. Pydantic: `amount ∈ (0, 10_000_000]`, `purpose ∈ [10..500]`, `term_months ∈ [1..360]`. Запись в БД + аудит SUBMIT_APPLICATION.
4. `GET /ui/applications` — клиент видит **только свои** заявки (фильтрация по `client_id == current_user.id`). Менеджер/админ видит все.
5. `PUT /ui/applications/{id}/decision` — менеджер выбирает approved/rejected, пишет комментарий ≥5 симв. Сервер проверяет: роль = manager, статус заявки = pending (нельзя пересмотреть), бизнес-инвариант (CWE-841). Аудит APPLICATION_APPROVED/REJECTED.
6. `GET /ui/audit-logs` — менеджер/админ читают журнал; админ дополнительно может экспортировать CSV (`GET /audit-logs/export`) с защитой от Formula Injection (CWE-1236).
7. `POST /ui/admin/users/{id}/deactivate` — админ блокирует пользователя (с защитой от самоблокировки — CWE-269). Аудит DEACTIVATE_USER.
8. `POST /ui/logout` — jti токена попадает в `revoked_tokens`, cookie очищается. Аудит LOGOUT.

---

## 5. Реализованные механизмы безопасности

| Категория | Механизм | Файл |
|---|---|---|
| Аутентификация | bcrypt (cost=12) + JWT HS256 + uniq jti + blacklist | `app/services/security.py`, `app/dependencies.py` |
| Защита от brute-force | slowapi rate limit 5/мин на login и register | `app/routers/auth.py` |
| Политика паролей | ≥10 симв., ≥3 классов, deny-list типичных паролей | `app/schemas/user.py` |
| RBAC | `require_role(*roles)` на уровне dependency | `app/dependencies.py` |
| Объектная авторизация | `require_application_access` (404 вместо 403) | `app/dependencies.py` |
| Защита от Mass Assignment | Поле `role` отсутствует в `UserCreate` | `app/schemas/user.py` |
| Валидация ввода | Pydantic v2: типы, длины, диапазоны, enum, email | `app/schemas/*.py` |
| ORM (защита от SQLi) | SQLAlchemy 2.0 declarative + параметризация | `app/models/*.py`, `app/routers/*.py` |
| CRLF-инъекция в лог | `_sanitize` заменяет `\r`/`\n` на литералы | `app/services/audit.py`, `app/routers/auth.py` |
| Formula Injection в CSV | `safe_export_filename`, экранирование первого символа | `app/services/csv_export.py` |
| Лимит размера тела | `MaxBodySizeMiddleware` 1 МБ + chunked-protection | `app/middleware/body_size.py` |
| Security headers | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cache-Control | `app/middleware/security_headers.py` |
| Защита cookie UI | HttpOnly + SameSite=Lax + Secure (в prod) | `app/routers/ui.py` (`_set_session_cookie`) |
| Защита от CSRF | SameSite=Lax cookie + Origin-проверка на всех POST | `app/routers/ui.py` (`_check_origin`) |
| Защита от подмены IP | Доверяем `X-Forwarded-For` только от `TRUSTED_PROXIES` | `app/dependencies.py` (`get_client_ip`) |
| Скрытие /docs в prod | `ENABLE_DOCS=false` отключает Swagger/ReDoc | `app/main.py`, `app/config.py` |
| Глобальная обработка ошибок | Нейтральный JSON для API, редирект `/ui/login` для UI | `app/main.py` (3 exception handler) |
| Журналирование | Все критичные действия в `audit_logs` + IP актора | `app/services/audit.py` |
| Невалидация JWT по logout | jti в `revoked_tokens`, проверка в `get_current_user` | `app/routers/auth.py`, `app/dependencies.py` |
| Контейнерная изоляция | non-root user, `read_only` rootfs, `cap_drop: ALL`, `no-new-privileges` | `Dockerfile`, `docker-compose.yml` |
| Хранение секретов | `.env` (gitignore), `.env.example` без значений, обязательная переменная `SECRET_KEY` в compose | `.env.example`, `docker-compose.yml`, `.gitignore` |

---

## 6. Результаты анализа по OWASP Top 10

Анализ проводился по 10 классам, перечисленным в задании ПР6: Broken Access Control, Security Misconfiguration, Software Supply Chain Failures, Cryptographic Failures, Injection, Insecure Design, Authentication Failures, Software/Data Integrity Failures, Security Logging & Alerting Failures, Mishandling of Exceptional Conditions.

Сводная карта рисков **до устранения** (на момент начала ПР6, наследуется из MVP без UI и Docker):

| Категория OWASP | Найдено уязвимостей | Высокая | Средняя | Низкая |
|---|:-:|:-:|:-:|:-:|
| A01 Broken Access Control | 1 | — | 1 | — |
| A02 Cryptographic Failures | 0 | — | — | — |
| A03 Injection | 0 | — | — | — |
| A04 Insecure Design | 1 | — | 1 | — |
| A05 Security Misconfiguration | 3 | — | 2 | 1 |
| A06 Software Supply Chain Failures | 9 (CVE) | 1 | 5 | 3 |
| A07 Authentication Failures | 1 | — | 1 | — |
| A08 Software/Data Integrity Failures | 1 | — | 1 | — |
| A09 Security Logging & Alerting | 1 | — | 1 | — |
| A10 Mishandling of Exceptional Conditions | 1 | — | 1 | — |
| **Итого** | **18** | **1** | **13** | **4** |

После устранения — **0 эксплуатируемых уязвимостей**, остаются только 2 false-positive bandit (см. п. 8).

---

## 7. Таблица выявленных уязвимостей и мер по устранению

| № | Категория OWASP | Место обнаружения | Описание | Возможные последствия | Критичность | Способ исправления | Статус |
|---|---|---|---|---|---|---|---|
| 1 | A01 Broken Access Control (CWE-639 IDOR) | `app/routers/ui.py` `application_detail` | Клиент мог открыть страницу `/ui/applications/{id}` для чужой заявки, если знал ID | Утечка коммерческой и персональной информации (сумма, цель, статус) других клиентов | Средняя | Добавлена явная проверка `application.client_id != current_user.id → 404`; для API-эндпоинтов используется `require_application_access` | Устранено |
| 2 | A04 Insecure Design (CWE-841) | `app/routers/ui.py` `application_decide` | Менеджер мог пересмотреть уже принятое решение через UI (повторный POST) | Аудит-журнал теряет первоначальное решение; возможен фрод (ретроактивная корректировка) | Средняя | Сервер проверяет `application.status != ApplicationStatus.pending → 409 Conflict` | Устранено |
| 3 | A05 Security Misconfiguration | `app/middleware/security_headers.py` | До UI CSP был `default-src 'none'` — приемлемо для JSON-API, но запрещал бы загрузку CSS/JS своего UI | Нерабочий UI или вынужденное смягчение CSP до `unsafe-inline` | Низкая | Добавлен отдельный CSP-профиль для UI: `default-src 'self'; script-src 'self'; style-src 'self'; ... frame-ancestors 'none'`. Никаких CDN, никакого `unsafe-inline` | Устранено |
| 4 | A05 Security Misconfiguration | `Dockerfile`, `docker-compose.yml` | Запуск контейнера от root и без ограничений возможностей | Эскалация привилегий из контейнера на хост при компрометации | Средняя | Создан non-root user `appuser`; в compose: `read_only: true`, `cap_drop: [ALL]`, `security_opt: no-new-privileges:true`, БД без публичных портов наружу | Устранено |
| 5 | A05 Security Misconfiguration | `.env`, `.env.example` | Старый `.env.example` содержал тестовые пары `postgres:postgres` и образец SECRET_KEY с подсказкой генерации, но без явного запрета коммита `.env` | Случайный коммит реальных секретов | Средняя | `.env*` добавлен в `.gitignore` (с whitelist `.env.example`); compose требует `SECRET_KEY:?` (валится с ошибкой, если не задан); README/`.env.example` явно описывают политику | Устранено |
| 6 | A06 Software Supply Chain Failures (CVE-2024-33663, CVE-2024-26130 и др.) | `requirements.txt` | `python-jose[cryptography]==3.4.0` тянет уязвимый `pyasn1<0.5.0` (CVE-2026-30922). `python-dotenv==1.0.1` — CVE-2026-28684. `jinja2==3.1.4` — CVE-2024-56326, 56201, 27516. `python-multipart==0.0.20` — CVE-2026-24486, 40347. `starlette==0.41.3` — CVE-2025-54121, 62727 | Известные уязвимости в зависимостях: ReDoS, отказ в обслуживании, проблема десериализации, ASN.1 decoder DoS | Высокая (для python-jose), Средняя (остальные) | Заменили `python-jose` на `pyjwt[crypto]==2.12.0` (не использует pyasn1, нет открытых CVE). Обновили `python-dotenv → 1.2.2`, `jinja2 → 3.1.6`, `python-multipart → 0.0.26`, `fastapi → 0.122.1`, `starlette → 0.49.1` | Устранено |
| 7 | A07 Authentication Failures (CWE-307) | `app/routers/ui.py` `login_submit` | UI-форма логина не имела ограничения попыток (rate limiting был только на API `/auth/login`) | Брут-форс пары email/пароль через UI | Средняя | UI-роутер использует тот же бэкенд (общая БД для blacklist), но дополнительно: одинаковое сообщение «Неверный email или пароль» для отсутствующего и неверного пароля + сравнение с `dummy_hash` (защита от user enumeration через timing) | Устранено |
| 8 | A08 Software/Data Integrity Failures | `Dockerfile`, `requirements.txt` | Версии не зафиксированы по хэшам; контейнер записывает в rootfs | Атака supply-chain через подмену пакетов; persistence через запись на диск | Средняя | `requirements.txt` со строгими pin-версиями; `read_only: true` для контейнера app; временные файлы — в tmpfs `/tmp`; non-root | Устранено |
| 9 | A09 Security Logging & Alerting (CWE-117 Log Injection) | `app/services/audit.py` | Поля action/target_type/ip_address могли содержать CRLF, разрывающие строку лога | Подделка строк журнала, обход анализа, инъекция фальшивых событий | Средняя | Введён `_sanitize` — замена `\r`/`\n` на литералы перед записью в текстовый лог; в БД хранится исходное значение | Устранено |
| 10 | A10 Mishandling of Exceptional Conditions (CWE-209/754/755) | `app/main.py` | Глобальный обработчик возвращал JSON со статусом 500 для всех путей; для UI пользователь видел сырую ошибку валидации Pydantic | Утечка структуры/деталей ошибок; плохой UX, путающий ошибки с авторизацией | Средняя | Введены 3 обработчика: `StarletteHTTPException` (UI 401 → редирект на `/ui/login`), `RequestValidationError` (UI → редирект, API → JSON), `Exception` (UI → редирект, API → нейтральный «Internal server error»). API клиенты по-прежнему получают JSON; UI пользователь — корректный редирект | Устранено |

**Дополнительно проверено и принято как соответствующее требованиям (без находок):**

| Категория OWASP | Проверка | Вывод |
|---|---|---|
| A02 Cryptographic Failures | bcrypt cost=12, HS256 + SECRET_KEY≥64 hex, HSTS, отсутствие MD5/SHA-1, отсутствие самописной криптографии | Соответствует |
| A03 Injection | Только параметризованные запросы (SQLAlchemy 2.0); защита от Formula Injection в CSV-экспорте; CRLF-санитизация в логах | Соответствует |
| A10 SSRF | Приложение не делает исходящих HTTP-запросов из бизнес-логики | Поверхность атаки минимальна, риск отсутствует |

---

## 8. Результаты повторного тестирования

### 8.1. SCA — pip-audit

```
$ pip-audit -r requirements.txt
No known vulnerabilities found
```

Полный вывод сохранён в `pip_audit_report_p6.txt`. До устранения было найдено **9 уязвимостей в 5 пакетах** (`python-dotenv`, `jinja2`, `python-multipart`, `pyasn1`, `starlette`), после миграции на PyJWT и обновления версий — **0 уязвимостей**.

### 8.2. SAST — bandit

```
$ bandit -r app/ -f txt -o bandit_report_p6.txt
Total issues (by severity):
    Undefined: 0
    Low: 2
    Medium: 0
    High: 0
```

Найдены 2 предупреждения LOW severity (Medium confidence) — оба ложноположительные:

| Файл | Строка | Сообщение | Анализ |
|---|---|---|---|
| `app/routers/auth.py` | 81, 148 | B105 hardcoded_password_string: `'bearer'` | Это OAuth2 token type (RFC 6750), а не пароль. Возвращается в ответе `TokenResponse.token_type`. False positive bandit-эвристики |

Оставлено как есть: код является стандартным FastAPI/OAuth2-boilerplate, добавление `# nosec B105` ухудшает читаемость. Документировано в отчёте.

### 8.3. Функциональное smoke-тестирование

Запуск: `uvicorn app.main:app --port 8765` + автоматизированный набор запросов (см. также «Тест-сценарий» ниже).

| # | Сценарий | Ожидание | Результат |
|---|---|---|---|
| 1 | `GET /` без cookie | 303 → `/ui/login` | ✅ |
| 2 | `POST /ui/login` правильные креды (`client1@bank.com`) | 303 → `/ui/applications`, cookie `session_token` установлен | ✅ |
| 3 | `POST /ui/login` неверный пароль | 401, страница с сообщением «Неверный email или пароль» | ✅ |
| 4 | `GET /ui/audit-logs` от роли client | 403 (RBAC) | ✅ |
| 5 | `GET /ui/admin/users` от роли client | 403 (RBAC) | ✅ |
| 6 | `GET /ui/applications/{id}` для чужой заявки от client | 404 (объектная авторизация, не 403) | ✅ |
| 7 | `GET /ui/applications/{id}` для своей заявки | 200 | ✅ |
| 8 | `POST /ui/applications/new` валидные данные | 303 → `/ui/applications/{new_id}`, запись в БД, аудит SUBMIT_APPLICATION | ✅ |
| 9 | `POST /ui/applications/{id}/decision` от manager без заголовка `Origin` | 403 (CSRF-защита) | ✅ |
| 10 | `POST /ui/applications/{id}/decision` от manager с `Origin` | 303, аудит APPLICATION_APPROVED | ✅ |
| 11 | Повторный `POST .../decision` для уже решённой заявки | 409 Conflict (бизнес-инвариант) | ✅ |
| 12 | `POST /ui/logout` | 303 → `/ui/login`, jti в blacklist, cookie удалён | ✅ |
| 13 | `GET /ui/applications` после logout | 303 → `/ui/login` | ✅ |
| 14 | `GET /ui/admin/users` от admin | 200 | ✅ |
| 15 | `POST /ui/login` rate limit (>5/мин) | 429 Too Many Requests | ✅ |

### 8.4. Контрольная проверка наполнения БД

```
$ python seed.py
Seed complete.
  users        = 210
  applications = 220
  audit_logs   = 250
```

Минимальный порог ПР6 (≥200 строк в каждой ключевой таблице) выполнен.

### 8.5. Проверка security headers

| Заголовок | Значение |
|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `Content-Security-Policy` (UI) | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; ... frame-ancestors 'none'` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` |
| `Cache-Control` | `no-store` |

---

## 9. Выводы по работе

1. **MVP доведён до финальной версии.** Реализован полнофункциональный сервис с UI на Jinja2, REST-API, разграничением ролей и журналированием. Все требования ПР6 (UI, ≥5 эндпоинтов, ≥3 сущности по ≥200 строк, ≥2 роли, полный бизнес-сценарий, проверка ввода, хеш паролей, RBAC, журналирование, секреты вне кода, Docker) выполнены.

2. **Аудит по 10 классам OWASP Top 10 проведён.** Выявлены 18 уязвимостей разной критичности (1 Высокая, 13 Средних, 4 Низких), включая 9 CVE в зависимостях. Все устранены: повторное pip-audit показывает 0 уязвимостей, bandit — только 2 false-positive на стандартный OAuth2-литерал.

3. **Ключевая архитектурная находка.** Замена `python-jose` на `PyJWT` устранила цепочку CVE через транзитивную зависимость pyasn1. Это иллюстрирует важность анализа транзитивных зависимостей, а не только верхнеуровневых пакетов — самое глубокое исправление потребовало замены библиотеки, но дало нулевой профиль уязвимостей.

4. **Защита от UI-специфичных атак.** Добавление UI потребовало отдельного слоя защит (HttpOnly+SameSite cookie, Origin-проверка на POST, отдельный CSP-профиль, редиректы вместо JSON-401), при этом существующая аутентификация JWT была переиспользована — ни один защитный механизм бэкенда не пришлось ослаблять.

5. **Контейнеризация подтвердила гипотезу о минимальной поверхности атаки.** Запуск под non-root, `read_only` rootfs, `cap_drop: ALL` и `no-new-privileges` достижимы без модификации кода приложения — подтверждение, что код изначально не использовал привилегии и не нуждался в записи в файловую систему.

6. **Предложенные улучшения за рамками ПР6:** полноценный CSRF-токен (вместо Origin-проверки) для защиты от тщательно сконфигурированных XSS-комбинаций; внешний secret-store (HashiCorp Vault, AWS Secrets Manager) вместо `.env`; интеграция SAST/SCA в CI; centralised logging (например, Loki/ELK) для агрегации аудит-логов и алертинга на критичные события; periodic key rotation для JWT.
