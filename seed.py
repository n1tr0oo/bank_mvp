"""
P6: расширенный seed для воспроизводимого окружения.

Гарантирует:
- 4 фиксированных демо-аккаунта (client1, client2, manager, admin) с известными паролями;
- 200+ дополнительных клиентов (детерминированно сгенерированные ФИО + email);
- 200+ заявок (часть pending, часть approved/rejected, разные клиенты);
- 200+ записей аудит-лога (LOGIN/SUBMIT_APPLICATION/APPLICATION_APPROVED/REJECTED).

Идемпотентен: повторный запуск пропускает уже созданных пользователей и
не создаёт дубликаты заявок/логов сверх целевого количества.

CWE-330 (предсказуемость) к фиктивным данным неприменим: всё сидируется
ради воспроизводимости, реальные пользователи устанавливают свои пароли
через /auth/register с проверкой политики (CWE-521).
"""
import random
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from app.database import SessionLocal
from app.models.audit_log import AuditLog
from app.models.credit_application import ApplicationStatus, CreditApplication
from app.models.user import User, UserRole
from app.services.security import hash_password


# Целевые пороги — задание П6 требует >=200 строк в каждой ключевой сущности.
TARGET_USERS = 210
TARGET_APPLICATIONS = 220
TARGET_AUDIT_LOGS = 250

DEMO_USERS = [
    {"email": "client1@bank.com", "password": "Client@1111",
     "full_name": "Махан Азат", "role": UserRole.client},
    {"email": "client2@bank.com", "password": "Client@2222",
     "full_name": "Алия Жумабекова", "role": UserRole.client},
    {"email": "manager@bank.com", "password": "Manager@3333",
     "full_name": "Дмитрий Петров", "role": UserRole.manager},
    {"email": "admin@bank.com", "password": "Admin@44444",
     "full_name": "Системный Администратор", "role": UserRole.admin},
]

FIRST_NAMES = [
    "Айгерим", "Бауржан", "Виктор", "Гульнара", "Дамир", "Елена", "Жанибек",
    "Зарина", "Ислам", "Карина", "Леонид", "Мадина", "Нурлан", "Олжас",
    "Полина", "Рустам", "Светлана", "Тимур", "Ульяна", "Фарид",
]
LAST_NAMES = [
    "Абенов", "Бекова", "Валиев", "Гайнуллин", "Ержанов", "Жукова", "Зайцев",
    "Ибраев", "Калиева", "Лисов", "Молдабеков", "Нурпеисов", "Орлов",
    "Петров", "Рахимов", "Соколова", "Темирбекова", "Усманова", "Файзуллин",
    "Шаймерден",
]

PURPOSES = [
    "Покупка автомобиля для семьи",
    "Ремонт квартиры (санузел, окна)",
    "Открытие малого бизнеса — кофейня",
    "Покупка бытовой техники",
    "Свадебные расходы",
    "Образование ребёнка в вузе",
    "Лечение и медицинские расходы",
    "Покупка дачного участка",
    "Расширение производства мебели",
    "Закуп оборудования для автосервиса",
    "Туристическая поездка с семьёй",
    "Покупка стройматериалов",
    "Рефинансирование задолженности",
    "Установка солнечных панелей",
    "Покупка коммерческой недвижимости",
]


def _make_user(idx: int) -> dict:
    """Детерминированно генерирует данные клиента по индексу."""
    first = FIRST_NAMES[idx % len(FIRST_NAMES)]
    last = LAST_NAMES[(idx * 7) % len(LAST_NAMES)]
    return {
        "email": f"client{idx}@bank.com",
        "password": f"Seed#User{idx:04d}",
        "full_name": f"{first} {last}",
        "role": UserRole.client,
    }


def _seed_users(db) -> list[User]:
    """Создаёт демо-аккаунты + достаёт/создаёт TARGET_USERS клиентов."""
    print(f"  Seeding users (target >={TARGET_USERS})...")

    # 1) Демо-аккаунты с известными паролями.
    for u in DEMO_USERS:
        if not db.query(User).filter(User.email == u["email"]).first():
            db.add(User(
                email=u["email"],
                hashed_password=hash_password(u["password"]),
                full_name=u["full_name"],
                role=u["role"],
            ))
    db.commit()

    # 2) Bulk-клиенты. Только если в системе меньше TARGET_USERS — дозаполняем.
    current_total = db.query(User).count()
    needed = max(0, TARGET_USERS - current_total)
    if needed:
        print(f"    Adding {needed} bulk clients...")
        # Одинаковый bcrypt-хеш для всех bulk-клиентов резко ускоряет seed
        # (bcrypt при cost=12 ~250мс на хеш). На безопасность производства
        # это не влияет — реальные пользователи регистрируются через /auth/register.
        bulk_hash = hash_password("Seed#User0000")
        idx = 1
        added = 0
        while added < needed:
            data = _make_user(idx)
            idx += 1
            if db.query(User).filter(User.email == data["email"]).first():
                continue
            db.add(User(
                email=data["email"],
                hashed_password=bulk_hash,
                full_name=data["full_name"],
                role=data["role"],
            ))
            added += 1
            if added % 50 == 0:
                db.commit()
        db.commit()

    return db.query(User).order_by(User.id.asc()).all()


def _seed_applications(db, users: list[User]) -> None:
    print(f"  Seeding credit applications (target >={TARGET_APPLICATIONS})...")
    existing = db.query(CreditApplication).count()
    needed = max(0, TARGET_APPLICATIONS - existing)
    if not needed:
        return

    rng = random.Random(20260504)  # детерминированный seed
    clients = [u for u in users if u.role == UserRole.client]
    managers = [u for u in users if u.role == UserRole.manager]
    if not clients or not managers:
        print("    !! Нет клиентов или менеджеров — заявки не создаются.")
        return

    base_time = datetime.now(timezone.utc) - timedelta(days=180)
    for i in range(needed):
        client = rng.choice(clients)
        amount = Decimal(str(rng.choice([
            50000, 100000, 150000, 200000, 300000, 500000,
            750000, 1000000, 1500000, 2500000,
        ])))
        purpose = rng.choice(PURPOSES)
        term_months = rng.choice([6, 12, 18, 24, 36, 48, 60, 84, 120])
        # Детерминированный микс статусов: 40% pending, 35% approved, 25% rejected.
        roll = rng.random()
        if roll < 0.40:
            status = ApplicationStatus.pending
            decided_by = None
            decided_at = None
            comment = None
        elif roll < 0.75:
            status = ApplicationStatus.approved
            decided_by = rng.choice(managers).id
            decided_at = base_time + timedelta(days=rng.randint(0, 180))
            comment = "Одобрено по результатам проверки кредитной истории."
        else:
            status = ApplicationStatus.rejected
            decided_by = rng.choice(managers).id
            decided_at = base_time + timedelta(days=rng.randint(0, 180))
            comment = "Отклонено: недостаточный уровень дохода."

        db.add(CreditApplication(
            client_id=client.id,
            amount=amount,
            purpose=purpose,
            term_months=term_months,
            status=status,
            decided_by=decided_by,
            decided_at=decided_at,
            manager_comment=comment,
        ))
        if (i + 1) % 50 == 0:
            db.commit()
    db.commit()


def _seed_audit_logs(db, users: list[User]) -> None:
    print(f"  Seeding audit logs (target >={TARGET_AUDIT_LOGS})...")
    existing = db.query(AuditLog).count()
    needed = max(0, TARGET_AUDIT_LOGS - existing)
    if not needed:
        return

    rng = random.Random(20260601)
    actions = [
        ("LOGIN", None, None),
        ("LOGOUT", None, None),
        ("SUBMIT_APPLICATION", "credit_application", "id"),
        ("APPLICATION_APPROVED", "credit_application", "id"),
        ("APPLICATION_REJECTED", "credit_application", "id"),
    ]
    app_ids = [a.id for a in db.query(CreditApplication.id).all()]
    base_time = datetime.now(timezone.utc) - timedelta(days=120)

    for i in range(needed):
        actor = rng.choice(users)
        action, target_type, _ = rng.choice(actions)
        target_id = rng.choice(app_ids) if target_type and app_ids else None
        # IP — фиктивный, чтобы заполнить столбец и продемонстрировать наличие.
        ip = f"10.0.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
        log = AuditLog(
            actor_id=actor.id,
            action=action,
            target_type=target_type,
            target_id=target_id,
            ip_address=ip,
        )
        # created_at — server_default; в seed поверх ставим past time через прямой insert.
        log.created_at = base_time + timedelta(minutes=rng.randint(0, 120 * 24 * 60))
        db.add(log)
        if (i + 1) % 100 == 0:
            db.commit()
    db.commit()


def seed() -> None:
    db = SessionLocal()
    try:
        users = _seed_users(db)
        _seed_applications(db, users)
        _seed_audit_logs(db, users)

        print("\nSeed complete.")
        print(f"  users        = {db.query(User).count()}")
        print(f"  applications = {db.query(CreditApplication).count()}")
        print(f"  audit_logs   = {db.query(AuditLog).count()}")
        print("\nDemo credentials:")
        for u in DEMO_USERS:
            print(f"  {u['email']:<22}  {u['password']}  ({u['role'].value})")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
