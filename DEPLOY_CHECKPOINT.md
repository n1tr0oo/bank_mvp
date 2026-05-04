# DEPLOY CHECKPOINT — следующий шаг: деплой на Render + UptimeRobot

## Где остановились

Проект полностью готов локально. Следующий шаг — задеплоить на Render (бесплатно) и подключить UptimeRobot чтобы сервер не засыпал.

---

## Выбранный план деплоя

```
GitHub (mvp/) → Render (FastAPI + PostgreSQL) + UptimeRobot (keepalive)
```

- **Render** — хостинг FastAPI + встроенный PostgreSQL бесплатно (90 дней)
- **UptimeRobot** — пингует `/health` каждые 5 мин, сервер не засыпает
- **Supabase не нужен** — Postgres встроен в Render
- **Vercel не подходит** — он для статических сайтов/Next.js, не для нашего FastAPI

---

## Текущее состояние проекта

### Git репозиторий
- Папка: `c:\dequ\Investigation of software source code\mvp\`
- Ветка: `main`
- Коммитов: 2
- Автор: `n1tr0oo <azatmahan@gmail.com>`
- GitHub: **ещё не запушен** (нужно создать репо и сделать push)

### Что готово в коде
- FastAPI 0.122 + Jinja2 UI (7 страниц)
- PostgreSQL через SQLAlchemy ORM
- JWT аутентификация (PyJWT 2.12, HttpOnly cookie для UI)
- RBAC: роли client / manager / admin
- Docker: `Dockerfile` + `docker-compose.yml`
- `pip-audit`: 0 уязвимостей
- `bandit`: 2 LOW (false-positive)
- Seed: 210 пользователей, 220 заявок, 250 аудит-логов

### Демо-аккаунты (после seed)
| Роль | Email | Пароль |
|------|-------|--------|
| client | client1@bank.com | Client@1111 |
| client | client2@bank.com | Client@2222 |
| manager | manager@bank.com | Manager@3333 |
| admin | admin@bank.com | Admin@44444 |

---

## Пошаговый план деплоя

### Шаг 1 — Запушить на GitHub (если ещё не сделано)
```powershell
cd "c:\dequ\Investigation of software source code\mvp"
git remote add origin https://github.com/n1tr0oo/<имя-репо>.git
git push -u origin main
```

### Шаг 2 — Создать PostgreSQL на Render
1. Зайти на https://render.com → войти через GitHub
2. New → **PostgreSQL**
3. Name: `bank-credit-db`
4. Plan: **Free**
5. Нажать **Create Database**
6. Скопировать **Internal Database URL** (формат `postgresql://...`) — понадобится на шаге 3

### Шаг 3 — Создать Web Service на Render
1. New → **Web Service**
2. Подключить GitHub репозиторий `mvp/`
3. Настройки:
   - **Name:** `bank-credit-mvp`
   - **Runtime:** `Docker`
   - **Branch:** `main`
   - **Plan:** `Free`
4. В разделе **Environment Variables** добавить:

| Key | Value |
|-----|-------|
| `DATABASE_URL` | Internal Database URL из шага 2 (заменить `postgresql://` на `postgresql+psycopg2://`) |
| `SECRET_KEY` | сгенерировать: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ALGORITHM` | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` |
| `ENABLE_DOCS` | `false` |
| `MAX_BODY_BYTES` | `1048576` |
| `TRUSTED_PROXIES` | _(оставить пустым)_ |

5. Нажать **Create Web Service** → Render начнёт сборку Docker-образа (~3-5 мин)

### Шаг 4 — Запустить seed на Render
После первого деплоя в консоли Render (Shell):
```bash
python seed.py
```
Это создаст 210 пользователей, 220 заявок, 250 аудит-логов.

### Шаг 5 — Подключить UptimeRobot (чтобы сервер не засыпал)
1. Зайти на https://uptimerobot.com → зарегистрироваться бесплатно
2. **Add New Monitor**:
   - Monitor Type: `HTTP(s)`
   - Friendly Name: `Bank Credit MVP`
   - URL: `https://<твой-сайт>.onrender.com/health`
   - Monitoring Interval: **5 minutes**
3. Нажать **Create Monitor**

Теперь сервер пингуется каждые 5 минут и никогда не засыпает.

---

## Важные нюансы

### DATABASE_URL: замена протокола
Render даёт URL вида:
```
postgresql://user:pass@host/dbname
```
В `.env` / переменной окружения нужно:
```
postgresql+psycopg2://user:pass@host/dbname
```
Просто добавь `+psycopg2` после `postgresql`.

### ENABLE_DOCS=false в production
В production `/docs` и `/redoc` скрыты. Это правильно — не меняй.

### Логи Render
Render → твой сервис → вкладка **Logs** — там в реальном времени видно всё что пишет uvicorn и FastAPI.

### Обновление кода
После push на GitHub Render **автоматически** пересобирает и деплоит. Ждать ~3-5 минут.

---

## Структура папок (напоминание)
```
mvp/                         ← это деплоим на Render
├── app/                     FastAPI + Jinja2 UI
├── Dockerfile               Render использует его для сборки
├── docker-compose.yml       только для локального запуска
├── requirements.txt
├── seed.py
└── .env.example             образец (реальный .env не в git)

mvp_part2/                   ← НЕ деплоим, это архив П3/П4/П5 + AI-версия
```

---

## Что НЕ нужно делать
- Не пушить `.env` в GitHub (он в `.gitignore`)
- Не включать `ENABLE_DOCS=true` на production
- Не деплоить `mvp_part2/` — это только для отчётов

---

## Быстрые команды для следующей сессии

```powershell
# Проверить git статус
cd "c:\dequ\Investigation of software source code\mvp"
git log --oneline
git remote -v

# Если remote ещё не добавлен:
git remote add origin https://github.com/n1tr0oo/<repo>.git
git push -u origin main

# Сгенерировать SECRET_KEY для Render:
python -c "import secrets; print(secrets.token_hex(32))"
```
