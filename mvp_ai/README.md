# mvp_ai — AI-сгенерированная версия (Задание 2 ПР6)

Альтернативная реализация банковского MVP, сгенерированная серией промптов к Claude (Anthropic) без явных запросов на security-hardening. См. полный лог промптов в [PROMPTS.md](PROMPTS.md).

## Стек

- Python 3.12 + Flask 2.0.1
- SQLite (файл `bank.db`)
- Jinja2 шаблоны
- SHA-256 для паролей (как сгенерировал AI)
- Сессии Flask по умолчанию (секрет в коде)

## Запуск

```bash
cd mvp_ai
pip install -r requirements.txt
python seed_ai.py    # создаст bank.db и заполнит 200+ строк
python app.py        # http://localhost:5000
```

## Демо-аккаунты

| Роль | Email | Пароль |
|------|-------|--------|
| client | client1@bank.com | 123456 |
| client | client2@bank.com | 123456 |
| manager | manager@bank.com | 123456 |
| admin | admin@bank.com | 123456 |

## Сравнение с Заданием 1

См. отчёт [`P6_Task2_Makhan_Azat.md`](../P6_Task2_Makhan_Azat.md) — сравнительная таблица из 12 критериев и анализ влияния AI-ассистированной разработки на безопасность.

**Кратко:** AI сгенерировал работающее приложение за ~25 минут, но допустил **15+ уязвимостей** по 9 из 10 классов OWASP Top 10, в том числе:
- SQL-инъекция в эндпоинте `/search`
- Mass Assignment (роль через форму регистрации)
- IDOR (нет проверки владельца заявки)
- Хеш SHA-256 без соли для паролей
- Хардкод `secret_key`
- `debug=True` в production-готовом коде
- 4 CVE в зависимостях (Flask 2.0.1, Jinja2 3.0.1)
- Нет CSRF, нет security headers, нет rate limiting, нет аудит-логов

В версии из Задания 1 (после устранения находок) — 0 эксплуатируемых уязвимостей.
