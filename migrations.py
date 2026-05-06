"""
Идемпотентные миграции схемы БД.

Запускать после обновления кода (локально и/или против production-БД):
    python migrations.py

Поддерживает PostgreSQL (production через Render) и SQLite (если кто-то
запустит локально без Postgres). Все ALTER TABLE написаны через
"ADD COLUMN IF NOT EXISTS" — повторный запуск ничего не сломает.
"""
from sqlalchemy import text

from app.database import engine


# Список миграций. Каждая — пара (описание, список SQL-команд).
# При добавлении новой миграции просто допишите ещё одну запись.
MIGRATIONS = [
    (
        "2FA: добавить totp_secret и totp_enabled в users",
        [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret VARCHAR(32)",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN NOT NULL DEFAULT FALSE",
        ],
    ),
]


def run() -> None:
    dialect = engine.dialect.name
    print(f"Running migrations against dialect: {dialect}")
    with engine.begin() as conn:
        for desc, sqls in MIGRATIONS:
            print(f"  - {desc}")
            for sql in sqls:
                # SQLite не поддерживает IF NOT EXISTS в ALTER TABLE — обрабатываем
                # ошибку 'duplicate column' как ОК (идемпотентность).
                if dialect == "sqlite" and "IF NOT EXISTS" in sql:
                    sql_sqlite = sql.replace(" IF NOT EXISTS", "")
                    try:
                        conn.execute(text(sql_sqlite))
                    except Exception as e:  # noqa: BLE001
                        if "duplicate column" in str(e).lower():
                            continue
                        raise
                else:
                    conn.execute(text(sql))
    print("Migrations complete.")


if __name__ == "__main__":
    run()
