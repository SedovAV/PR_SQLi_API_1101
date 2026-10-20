# PR_SQLi_API_1101

## Практическая работа: SQL-инъекции в API и методы защиты

### Цель: Научиться выявлять уязвимости SQL-инъекций в REST API на Python (Flask, FastAPI) и устранять их с помощью параметризованных запросов и валидации.

<b>Стек:</b> Python 3.x, Flask, FastAPI, SQLite (для простоты, без развертывания полноценной СУБД).

### Подготовка окружения
Создайте папку для проекта и установите зависимости:

```
pip install flask fastapi uvicorn
```

Создайте файл init_db.py для инициализации тестовой базы данных (SQLite):

```
import sqlite3

def init_db():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    # Таблица пользователей
    cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                      (id INTEGER PRIMARY KEY, email TEXT, password TEXT, role TEXT)''')
    # Таблица заказов
    cursor.execute('''CREATE TABLE IF NOT EXISTS orders 
                      (id INTEGER PRIMARY KEY, user_id INTEGER, total_amount REAL, created_at TEXT)''')
    
    # Тестовые данные
    cursor.execute("DELETE FROM users")
    cursor.execute("DELETE FROM orders")
    cursor.execute("INSERT INTO users (email, password, role) VALUES ('admin@test.com', 'secret123', 'admin')")
    cursor.execute("INSERT INTO users (email, password, role) VALUES ('user@test.com', 'pass', 'user')")
    
    cursor.execute("INSERT INTO orders (user_id, total_amount, created_at) VALUES (1, 100.50, '2023-10-01')")
    cursor.execute("INSERT INTO orders (user_id, total_amount, created_at) VALUES (2, 50.00, '2023-10-02')")
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
    print("База данных test.db успешно создана.")
```
## Часть 1. Flask: Уязвимый и безопасный поиск пользователя

### Шаг 1.1. Уязвимый код (In-band SQLi)
Создайте файл `flask_vuln.py`. Здесь мы используем f-строки для формирования SQL-запроса, что является грубой ошибкой.

```
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('test.db')
    conn.row_factory = sqlite3.Row
    return conn

# УЯЗВИМЫЙ ENDPOINT
@app.route('/api/users', methods=['GET'])
def get_user_vuln():
    user_id = request.args.get('id', '')
    
    conn = get_db_connection()
    # ПЛОХО: Прямая подстановка пользовательского ввода в SQL
    query = f"SELECT id, email, role FROM users WHERE id = '{user_id}'"
    
    try:
        user = conn.execute(query).fetchall()
        conn.close()
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify([dict(row) for row in user])
    except Exception as e:
        # ПЛОХО: Возврат деталей ошибки БД клиенту
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
```

### Задание 1.1:

* Запустите сервер: `python flask_vuln.py`
* Откройте браузер или Postman. Сделайте запрос: `http://127.0.0.1:5000/api/users?id=1`
* Проведите атаку: Выполните запрос `http://127.0.0.1:5000/api/users?id=1' OR '1'='1`
* Результат: Вы получите данные всех пользователей, включая админа.
* Попробуйте вызвать ошибку (например, `id=1'`), чтобы увидеть, как API возвращает `stack trace/ошибку БД`.

### Шаг 1.2. Безопасный код (Исправление)

Создайте файл `flask_secure.py`.
```
from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('test.db')
    conn.row_factory = sqlite3.Row
    return conn

# БЕЗОПАСНЫЙ ENDPOINT
@app.route('/api/users', methods=['GET'])
def get_user_secure():
    user_id = request.args.get('id')
    
    # ХОРОШО: Строгая валидация типа
    if not user_id or not user_id.isdigit():
        return jsonify({"error": "Invalid user ID"}), 400
        
    conn = get_db_connection()
    # ХОРОШО: Параметризованный запрос (placeholder ?)
    query = "SELECT id, email, role FROM users WHERE id = ?"
    
    try:
        user = conn.execute(query, (user_id,)).fetchall()
        conn.close()
        if not user:
            return jsonify({"error": "User not found"}), 404
        return jsonify([dict(row) for row in user])
    except Exception as e:
        # ХОРОШО: Логируем внутри, наружу отдаем общую ошибку
        print(f"DB Error: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5001)
```

### Задание 1.2:

* Запустите сервер на порту `5001`.
* Повторите атаку `?id=1' OR '1'='1`. Убедитесь, что API возвращает `400 Bad Request` благодаря проверке `isdigit()`. Инъекция заблокирована.

## Часть 2. FastAPI: JSON body, Path-параметры и динамическая сортировка

FastAPI часто используется для современных API, где данные приходят в формате JSON, а параметры сортировки передаются в query string.

### Шаг 2.1. Уязвимый код

Создайте файл `fastapi_vuln.py`.

```
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import sqlite3

app = FastAPI()

def get_db_connection():
    conn = sqlite3.connect('test.db')
    conn.row_factory = sqlite3.Row
    return conn

class LoginData(BaseModel):
    email: str
    password: str

# 1. Уязвимость в JSON body (Classic SQLi)
@app.post("/api/login")
def login_vuln(data: LoginData):
    conn = get_db_connection()
    # ПЛОХО: Интерполяция данных из JSON
    query = f"SELECT * FROM users WHERE email = '{data.email}' AND password = '{data.password}'"
    
    try:
        user = conn.execute(query).fetchone()
        conn.close()
        if user:
            return {"message": "Login successful", "role": user["role"]}
        return {"message": "Invalid credentials"}
    except Exception as e:
        return {"error": str(e)}

# 2. Уязвимость в динамической сортировке (ORDER BY)
@app.get("/api/orders")
def get_orders_vuln(sort: str = "id", order: str = "ASC"):
    conn = get_db_connection()
    # ПЛОХО: Пользователь контролирует имена колонок и направление
    query = f"SELECT * FROM orders ORDER BY {sort} {order}"
    
    try:
        orders = conn.execute(query).fetchall()
        conn.close()
        return [dict(row) for row in orders]
    except Exception as e:
        return {"error": str(e)}
```

### Задание 2.1:

* Запустите сервер: `uvicorn fastapi_vuln:app --reload --port 8000`
* Атака на Login (JSON): Используйте Swagger UI (`http://127.0.0.1:8000/docs`) или `curl`:

```
{
  "email": "admin@test.com' --",
  "password": "any"
}
```

<b>Результат:</b> Вы войдете как админ, так как пароль закомментирован (`--`).

* Атака на ORDER BY: Выполните запрос `http://127.0.0.1:8000/api/orders?sort=id&order=DESC` (это легитимно).

А теперь попробуйте: `http://127.0.0.1:8000/api/orders?sort=(CASE WHEN (SELECT role FROM users WHERE id=1)='admin' THEN id ELSE total_amount END)` — это пример Blind SQLi через сортировку.

### Шаг 2.2. Безопасный код (Исправление)

Создайте файл `fastapi_secure.py`.

```
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, EmailStr
import sqlite3

app = FastAPI()

def get_db_connection():
    conn = sqlite3.connect('test.db')
    conn.row_factory = sqlite3.Row
    return conn

class LoginData(BaseModel):
    email: EmailStr # ХОРОШО: Валидация формата email
    password: str

# БЕЛЫЕ СПИСКИ для динамических частей
SORT_FIELDS = {
    "id": "id",
    "date": "created_at",
    "amount": "total_amount"
}
ALLOWED_ORDER = ["ASC", "DESC"]

# 1. Безопасный JSON body
@app.post("/api/login")
def login_secure(data: LoginData):
    conn = get_db_connection()
    # ХОРОШО: Параметризация через ?
    query = "SELECT * FROM users WHERE email = ? AND password = ?"
    
    try:
        user = conn.execute(query, (data.email, data.password)).fetchone()
        conn.close()
        if user:
            return {"message": "Login successful", "role": user["role"]}
        return {"message": "Invalid credentials"}
    except Exception:
        return {"error": "Internal Server Error"}

# 2. Безопасная сортировка (Белый список)
@app.get("/api/orders")
def get_orders_secure(
    sort: str = Query("id", description="Field to sort by"),
    order: str = Query("ASC", description="Sort direction")
):
    # ХОРОШО: Строгая проверка по белому списку
    if sort not in SORT_FIELDS:
        raise HTTPException(status_code=400, detail="Invalid sort field")
    if order.upper() not in ALLOWED_ORDER:
        raise HTTPException(status_code=400, detail="Invalid order direction")

    # Безопасно подставляем значения из маппинга, а не из запроса напрямую
    safe_sort_column = SORT_FIELDS[sort]
    safe_order = order.upper()
    
    conn = get_db_connection()
    # Имена таблиц/колонок нельзя параметризовать, поэтому используем f-строку
    # Но только с жестко контролируемыми значениями из белого списка
    query = f"SELECT * FROM orders ORDER BY {safe_sort_column} {safe_order}"
    
    try:
        orders = conn.execute(query).fetchall()
        conn.close()
        return [dict(row) for row in orders]
    except Exception:
        return {"error": "Internal Server Error"}
```

### Задание 2.2:

* Запустите безопасный сервер на порту `8001`.
* Повторите атаку на `/api/login`. Запрос вернет `422 Unprocessable Entity` (из-за невалидного email с кавычками) или `Invalid credentials`.
* Попробуйте атаковать `/api/orders?sort=id; DROP TABLE users;--`. Сервер вернет `400 Bad Request`, так как поля нет в `SORT_FIELDS`.

## Часть 3. Вопросы для самопроверки (из лекции)

Ответьте на вопросы (письменно):

* Почему параметризация (`placeholders ?`) не работает для имен колонок в `ORDER BY`?
* Как white-list (белый список) защищает от SQLi в параметрах сортировки?
* В чем разница между обычной инъекцией и second-order SQLi? Приведите пример для API (например, сохранение имени пользователя в БД, а затем использование этого имени в сыром SQL в другом endpoint'е).
* Почему возврат str(e) (детальной ошибки) клиенту в Flask/FastAPI опасен? Какие данные может получить атакующий?

### Домашнее задание
* Дополните `fastapi_secure.py` `endpoint'ом` для получения пользователей по массиву `ID` (например, `POST /api/users/batch с JSON {"ids": [1, 2, 3]})`.
* Напишите для него уязвимую версию (через `IN ({','.join(ids)})`) и безопасную (используя динамическое создание плейсхолдеров `IN (?, ?, ?)` в SQLite).
* Продемонстрируйте, как атакующий может эксплуатировать уязвимую версию (подсказка: передайте в массиве строку `"1) OR (1=1")`.
