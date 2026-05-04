# DEPLOY CHECKPOINT — задеплоен ✅

## Live URL

**https://bank-mvp-4pnt.onrender.com**

- `/` → редирект на `/ui/login`
- `/ui/login` → форма входа
- `/health` → `{"status":"ok"}` (используется UptimeRobot)
- `/docs` и `/redoc` скрыты в production (`ENABLE_DOCS=false`)

---

## Архитектура production

```
GitHub (n1tr0oo/bank_mvp)
        │  push
        ▼
   Render Web Service ──────► Render PostgreSQL (Free)
   bank-credit-mvp              bank-credit-db
   (Docker, Frankfurt)          (Frankfurt)
        │
        ▼
   UptimeRobot (ping /health каждые 5 мин — сервер не засыпает)
```

---

## Демо-аккаунты

| Роль | Email | Пароль |
|------|-------|--------|
| client | client1@bank.com | Client@1111 |
| client | client2@bank.com | Client@2222 |
| manager | manager@bank.com | Manager@3333 |
| admin | admin@bank.com | Admin@44444 |

После seed создано: 210 пользователей, 220 заявок, 250 аудит-логов.

---

## Render — настройки

### Web Service
- **Name:** bank-credit-mvp
- **Runtime:** Docker
- **Branch:** main (auto-deploy при push)
- **Region:** Frankfurt
- **Plan:** Free
- **Health check path:** `/health`

### Environment Variables
| Key | Источник |
|-----|----------|
| `DATABASE_URL` | External URL из Render Postgres (с `+psycopg2`) |
| `SECRET_KEY` | сгенерирован через `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ALGORITHM` | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` |
| `ENABLE_DOCS` | `false` |
| `MAX_BODY_BYTES` | `1048576` |
| `TRUSTED_PROXIES` | _(пусто)_ |

### PostgreSQL
- **Name:** bank-credit-db
- **Database:** bank_mvp
- **Region:** Frankfurt
- **Plan:** Free (90 дней — после нужно либо пересоздать, либо платить $7/мес)

---

## Как обновлять production

1. Изменения в коде → коммит в `main`
2. `git push origin main`
3. Render автоматически собирает Docker и деплоит (3-5 мин)
4. Логи: Render → Web Service → **Logs**

---

## Запуск seed против production-БД (если нужно повторить)

```powershell
cd "c:\dequ\Investigation of software source code\mvp"
$env:DATABASE_URL = "postgresql+psycopg2://<external_url_from_render>"
$env:SECRET_KEY = "any-string-for-seed-only"
$env:PYTHONIOENCODING = "utf-8"
python seed.py
```

Скрипт идемпотентный — допишет до целевых чисел, не сломает существующие данные.

---

## Известные ограничения Free tier

- **PostgreSQL Free:** 90 дней, потом нужно мигрировать или платить
- **Web Service Free:** засыпает через 15 мин неактивности → мы решили UptimeRobot'ом
- **Без custom domain** на free tier (только `*.onrender.com`)
- **Без shell** на free tier — для выполнения команд используем локальный запуск против External URL

---

## Локальный запуск (для разработки)

```powershell
cd "c:\dequ\Investigation of software source code\mvp"
docker compose up --build       # вариант с Postgres-контейнером
# или
uvicorn app.main:app --reload   # если Postgres стоит локально и в .env правильный DATABASE_URL
```

См. также `README.md` и `mvp_part2/` (Задание 2 — AI-версия).

---

## Чек-лист сдачи ПР6

- ✅ MVP в Docker (`Dockerfile`, `docker-compose.yml`)
- ✅ Push в GitHub: <https://github.com/n1tr0oo/bank_mvp>
- ✅ Live deployment: <https://bank-mvp-4pnt.onrender.com>
- ✅ README.md с описанием, инструкцией, демо-аккаунтами
- ✅ Отчёт П6 (Задание 1): `P6_Makhan_Azat.md/.docx`
- ✅ Отчёт П6 (Задание 2): `mvp_part2/P6_Task2_Makhan_Azat.md/.docx`
- ✅ Аудит pip-audit: 0 уязвимостей
- ✅ Аудит bandit: 2 LOW false-positive
- ✅ Секреты в `.env` (исключён из git), production secrets в Render env vars
- ✅ UptimeRobot ping `/health` каждые 5 мин
