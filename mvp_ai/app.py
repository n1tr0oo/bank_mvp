"""
Bank Credit MVP — AI-сгенерированная версия (Задание 2 ПР6).

Сгенерировано через серию промптов к Claude (Anthropic), модель claude-sonnet-4-5,
без явных запросов на security-hardening. См. PROMPTS.md в этой же директории.

ВНИМАНИЕ: данная версия специально оставлена «как сгенерировал AI», без ручных
доработок безопасности — для последующего сравнения с MVP из Задания 1.
Не использовать в production.
"""
import hashlib
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, flash, g, redirect, render_template, request, session, url_for,
)

app = Flask(__name__)
# AI-сгенерированный код часто хардкодит ключ "для простоты".
app.secret_key = "supersecret123"
DATABASE = "bank.db"


# ----- DB helpers -----

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
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
    db.commit()
    db.close()


# ----- auth helpers -----

def hash_password(pw):
    # AI-генерация чаще всего предлагает SHA-256 «для скорости».
    return hashlib.sha256(pw.encode()).hexdigest()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def current_user():
    if "user_id" not in session:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


# ----- routes -----

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("apps"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        full_name = request.form.get("full_name", "")
        # AI-генерация: роль приходит из формы, без серверной фиксации (Mass Assignment).
        role = request.form.get("role", "client")
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)",
                (email, hash_password(password), full_name, role),
            )
            db.commit()
        except sqlite3.IntegrityError as e:
            # AI-генерация: показываем ошибку как есть.
            return f"Ошибка регистрации: {e}", 400
        flash("Регистрация успешна, войдите в систему.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email=? AND password=?",
            (email, hash_password(password)),
        ).fetchone()
        if user:
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            return redirect(url_for("apps"))
        # AI-генерация: разные сообщения помогают отладке (но раскрывают существование email).
        existing = db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            return render_template("login.html", error="Неверный пароль")
        return render_template("login.html", error="Пользователь не найден")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/apps")
@login_required
def apps():
    db = get_db()
    user = current_user()
    if user["role"] in ("manager", "admin"):
        rows = db.execute("SELECT * FROM applications ORDER BY id DESC").fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM applications WHERE client_id=? ORDER BY id DESC",
            (user["id"],),
        ).fetchall()
    return render_template("apps.html", apps=rows)


@app.route("/apps/new", methods=["GET", "POST"])
@login_required
def new_app():
    if request.method == "POST":
        amount = request.form["amount"]
        purpose = request.form["purpose"]
        term_months = request.form["term_months"]
        db = get_db()
        db.execute(
            "INSERT INTO applications (client_id, amount, purpose, term_months) VALUES (?, ?, ?, ?)",
            (session["user_id"], amount, purpose, term_months),
        )
        db.commit()
        return redirect(url_for("apps"))
    return render_template("new_app.html")


@app.route("/apps/<int:app_id>")
@login_required
def app_detail(app_id):
    db = get_db()
    # AI-генерация: проверка владельца не сделана (IDOR).
    a = db.execute("SELECT * FROM applications WHERE id=?", (app_id,)).fetchone()
    if not a:
        return "Заявка не найдена", 404
    return render_template("app_detail.html", a=a)


@app.route("/apps/<int:app_id>/decide", methods=["POST"])
@login_required
def decide(app_id):
    user = current_user()
    # AI-генерация: проверка роли через if в коде (без dependency-механизма).
    if user["role"] != "manager":
        return "Доступ запрещён", 403
    decision = request.form["decision"]
    comment = request.form.get("comment", "")
    db = get_db()
    db.execute(
        "UPDATE applications SET status=?, manager_comment=?, decided_by=? WHERE id=?",
        (decision, comment, user["id"], app_id),
    )
    db.commit()
    return redirect(url_for("app_detail", app_id=app_id))


@app.route("/admin/users")
@login_required
def admin_users():
    # AI-генерация: проверка роли только в шаблоне через {% if %},
    # а на сервере — лишь login_required. Любой залогиненный увидит список.
    db = get_db()
    users = db.execute("SELECT id, email, full_name, role FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/search")
@login_required
def search():
    """AI-генерация по запросу 'добавь поиск по заявкам'."""
    q = request.args.get("q", "")
    db = get_db()
    cur = db.cursor()
    # AI-генерация: f-string в SQL — классическая SQL-инъекция.
    sql = f"SELECT * FROM applications WHERE purpose LIKE '%{q}%'"
    rows = cur.execute(sql).fetchall()
    return render_template("apps.html", apps=rows)


if __name__ == "__main__":
    init_db()
    # AI-генерация: debug=True «чтобы видеть ошибки» — раскрывает stacktrace.
    app.run(host="0.0.0.0", port=5000, debug=True)
