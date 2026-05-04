"""Сидирование AI-версии: 200+ строк в каждой ключевой таблице."""
import hashlib
import random
import sqlite3

DB = "bank.db"


def h(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


def seed():
    db = sqlite3.connect(DB)
    cur = db.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT,
        role TEXT DEFAULT 'client'
    );
    CREATE TABLE IF NOT EXISTS applications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        purpose TEXT NOT NULL,
        term_months INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        manager_comment TEXT,
        decided_by INTEGER,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)

    demo = [
        ("client1@bank.com", "123456", "Клиент Один", "client"),
        ("client2@bank.com", "123456", "Клиент Два", "client"),
        ("manager@bank.com", "123456", "Менеджер", "manager"),
        ("admin@bank.com", "123456", "Админ", "admin"),
    ]
    for email, pw, name, role in demo:
        cur.execute(
            "INSERT OR IGNORE INTO users (email,password,full_name,role) VALUES (?,?,?,?)",
            (email, h(pw), name, role),
        )

    rng = random.Random(42)
    for i in range(1, 211):
        email = f"u{i}@bank.com"
        cur.execute(
            "INSERT OR IGNORE INTO users (email,password,full_name,role) VALUES (?,?,?,?)",
            (email, h("123456"), f"Пользователь {i}", "client"),
        )

    rows = cur.execute("SELECT id FROM users WHERE role='client'").fetchall()
    client_ids = [r[0] for r in rows]
    purposes = ["Авто", "Ремонт", "Бизнес", "Лечение", "Образование",
                "Свадьба", "Стройматериалы", "Техника", "Дача", "Туризм"]
    for _ in range(220):
        cur.execute(
            "INSERT INTO applications (client_id,amount,purpose,term_months,status) VALUES (?,?,?,?,?)",
            (rng.choice(client_ids),
             rng.choice([50000, 100000, 200000, 500000, 1000000]),
             rng.choice(purposes),
             rng.choice([6, 12, 24, 36, 60]),
             rng.choice(["pending", "approved", "rejected"])),
        )

    db.commit()
    print("AI seed:")
    print("  users        =", cur.execute("SELECT COUNT(*) FROM users").fetchone()[0])
    print("  applications =", cur.execute("SELECT COUNT(*) FROM applications").fetchone()[0])
    db.close()


if __name__ == "__main__":
    seed()
