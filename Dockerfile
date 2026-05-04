# P6 — Bank Credit MVP
# Минимальный образ FastAPI-приложения. Многослойный COPY для кеширования зависимостей.
# Запуск под не-root пользователем (CWE-250: principle of least privilege).
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# psycopg2-binary тянет libpq уже внутри wheel, поэтому build-essential не нужен.
# curl нужен только для healthcheck.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Кладём только то, что нужно в runtime.
COPY app ./app
COPY seed.py ./seed.py

# Создаём non-root пользователя и отдаём ему рабочую директорию.
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
 && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -fsS http://localhost:8000/health || exit 1

# Один воркер достаточен для MVP. В production за reverse-proxy (TLS termination).
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
