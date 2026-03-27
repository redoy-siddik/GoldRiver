from flask import Flask, request, jsonify, send_from_directory
import sqlite3
import hashlib
import datetime
import os
import secrets

app = Flask(__name__, static_folder='static')
DB_PATH = os.path.join(os.path.dirname(__file__), 'bank.db')

# ─── DB SETUP ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_account_number():
    return str(int(datetime.datetime.now().timestamp() * 1000))[-10:]

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS bank_config (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            serial TEXT NOT NULL,
            total_balance REAL DEFAULT 0,
            total_loan REAL DEFAULT 0,
            loan_system INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            address TEXT NOT NULL,
            account_type TEXT NOT NULL,
            account_number TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            balance REAL DEFAULT 0,
            loan_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            address TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_number TEXT NOT NULL,
            transaction_type TEXT NOT NULL,
            amount REAL NOT NULL,
            from_name TEXT NOT NULL,
            to_name TEXT NOT NULL,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            account_number TEXT,
            admin_name TEXT,
            role TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Seed bank config if not exists
    existing = c.execute("SELECT id FROM bank_config WHERE id=1").fetchone()
    if not existing:
        c.execute("INSERT INTO bank_config (id, name, serial, total_balance, total_loan, loan_system) VALUES (1, 'GoldRiver Bank', '7777', 0, 0, 1)")
    conn.commit()
    conn.close()

init_db()

# ─── AUTH HELPERS ─────────────────────────────────────────────────────────────

def create_session(role, account_number=None, admin_name=None):
    token = secrets.token_hex(32)
    conn = get_db()
    conn.execute("INSERT INTO sessions (token, account_number, admin_name, role) VALUES (?,?,?,?)",
                 (token, account_number, admin_name, role))
    conn.commit()
    conn.close()
    return token

def get_session(token):
    if not token:
        return None
    conn = get_db()
    row = conn.execute("SELECT * FROM sessions WHERE token=?", (token,)).fetchone()
    conn.close()
    return dict(row) if row else None

def require_user(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        session = get_session(token)
        if not session or session['role'] != 'user':
            return jsonify({'error': 'Unauthorized'}), 401
        return f(session, *args, **kwargs)
    return decorated

def require_admin(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        session = get_session(token)
        if not session or session['role'] != 'admin':
            return jsonify({'error': 'Unauthorized'}), 401
        return f(session, *args, **kwargs)
    return decorated

# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

# Bank info
@app.route('/api/bank', methods=['GET'])
def get_bank():
    conn = get_db()
    bank = dict(conn.execute("SELECT name, serial FROM bank_config WHERE id=1").fetchone())
    conn.close()
    return jsonify(bank)

# ── USER AUTH ──
@app.route('/api/user/signup', methods=['POST'])
def user_signup():
    data = request.json
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    address = data.get('address', '').strip()
    account_type = data.get('account_type', '').strip()
    password = data.get('password', '').strip()

    if not all([name, email, address, account_type, password]):
        return jsonify({'error': 'All fields are required'}), 400

    account_number = generate_account_number()
    pw_hash = hash_password(password)

    try:
        conn = get_db()
        conn.execute("""INSERT INTO users (name, email, address, account_type, account_number, password_hash)
                        VALUES (?,?,?,?,?,?)""",
                     (name, email, address, account_type, account_number, pw_hash))
        conn.commit()
        conn.close()
        token = create_session('user', account_number=account_number)
        return jsonify({'message': 'Account created', 'account_number': account_number, 'token': token, 'name': name})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'User already exists'}), 409

@app.route('/api/user/login', methods=['POST'])
def user_login():
    data = request.json
    account_number = data.get('account_number', '').strip()
    password = data.get('password', '').strip()
    pw_hash = hash_password(password)

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE account_number=? AND password_hash=?",
                        (account_number, pw_hash)).fetchone()
    conn.close()
    if user:
        token = create_session('user', account_number=account_number)
        return jsonify({'message': 'Login successful', 'token': token, 'name': user['name'], 'account_number': account_number})
    return jsonify({'error': 'Invalid credentials'}), 401

# ── ADMIN AUTH ──
@app.route('/api/admin/signup', methods=['POST'])
def admin_signup():
    data = request.json
    name = data.get('name', '').strip()
    email = data.get('email', '').strip()
    address = data.get('address', '').strip()
    password = data.get('password', '').strip()

    if not all([name, email, address, password]):
        return jsonify({'error': 'All fields are required'}), 400

    pw_hash = hash_password(password)
    try:
        conn = get_db()
        conn.execute("INSERT INTO admins (name, email, address, password_hash) VALUES (?,?,?,?)",
                     (name, email, address, pw_hash))
        conn.commit()
        conn.close()
        token = create_session('admin', admin_name=name)
        return jsonify({'message': 'Admin account created', 'token': token, 'name': name})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Admin already exists'}), 409

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.json
    name = data.get('name', '').strip()
    password = data.get('password', '').strip()
    pw_hash = hash_password(password)

    conn = get_db()
    admin = conn.execute("SELECT * FROM admins WHERE name=? AND password_hash=?", (name, pw_hash)).fetchone()
    conn.close()
    if admin:
        token = create_session('admin', admin_name=name)
        return jsonify({'message': 'Login successful', 'token': token, 'name': name})
    return jsonify({'error': 'Invalid credentials'}), 401

# ── USER OPERATIONS ──
@app.route('/api/user/me', methods=['GET'])
@require_user
def get_user_info(session):
    conn = get_db()
    user = dict(conn.execute("SELECT name, email, address, account_type, account_number, balance, loan_count FROM users WHERE account_number=?",
                              (session['account_number'],)).fetchone())
    conn.close()
    return jsonify(user)

@app.route('/api/user/deposit', methods=['POST'])
@require_user
def deposit(session):
    amount = float(request.json.get('amount', 0))
    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400
    acc = session['account_number']
    conn = get_db()
    conn.execute("UPDATE users SET balance = balance + ? WHERE account_number=?", (amount, acc))
    conn.execute("UPDATE bank_config SET total_balance = total_balance + ? WHERE id=1", (amount,))
    user = dict(conn.execute("SELECT name FROM users WHERE account_number=?", (acc,)).fetchone())
    conn.execute("INSERT INTO transactions (account_number, transaction_type, amount, from_name, to_name) VALUES (?,?,?,?,?)",
                 (acc, 'Deposit', amount, user['name'], 'GoldRiver Bank'))
    conn.commit()
    new_bal = conn.execute("SELECT balance FROM users WHERE account_number=?", (acc,)).fetchone()['balance']
    conn.close()
    return jsonify({'message': f'Deposited {amount} successfully', 'balance': new_bal})

@app.route('/api/user/withdraw', methods=['POST'])
@require_user
def withdraw(session):
    amount = float(request.json.get('amount', 0))
    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400
    acc = session['account_number']
    conn = get_db()
    user = dict(conn.execute("SELECT * FROM users WHERE account_number=?", (acc,)).fetchone())
    bank = dict(conn.execute("SELECT total_balance FROM bank_config WHERE id=1").fetchone())

    if user['balance'] < amount:
        conn.close()
        return jsonify({'error': 'Insufficient balance'}), 400
    if bank['total_balance'] < amount:
        conn.close()
        return jsonify({'error': 'Bank is bankrupt!'}), 400

    conn.execute("UPDATE users SET balance = balance - ? WHERE account_number=?", (amount, acc))
    conn.execute("UPDATE bank_config SET total_balance = total_balance - ? WHERE id=1", (amount,))
    conn.execute("INSERT INTO transactions (account_number, transaction_type, amount, from_name, to_name) VALUES (?,?,?,?,?)",
                 (acc, 'Withdraw', amount, 'GoldRiver Bank', user['name']))
    conn.commit()
    new_bal = conn.execute("SELECT balance FROM users WHERE account_number=?", (acc,)).fetchone()['balance']
    conn.close()
    return jsonify({'message': f'Withdrew {amount} successfully', 'balance': new_bal})

@app.route('/api/user/transfer', methods=['POST'])
@require_user
def transfer(session):
    data = request.json
    to_acc = data.get('to_account', '').strip()
    amount = float(data.get('amount', 0))
    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400
    from_acc = session['account_number']
    if from_acc == to_acc:
        return jsonify({'error': 'Cannot transfer to same account'}), 400

    conn = get_db()
    from_user = conn.execute("SELECT * FROM users WHERE account_number=?", (from_acc,)).fetchone()
    to_user = conn.execute("SELECT * FROM users WHERE account_number=?", (to_acc,)).fetchone()

    if not to_user:
        conn.close()
        return jsonify({'error': 'Recipient account not found'}), 404
    if from_user['balance'] < amount:
        conn.close()
        return jsonify({'error': 'Insufficient balance'}), 400

    conn.execute("UPDATE users SET balance = balance - ? WHERE account_number=?", (amount, from_acc))
    conn.execute("UPDATE users SET balance = balance + ? WHERE account_number=?", (amount, to_acc))
    conn.execute("INSERT INTO transactions (account_number, transaction_type, amount, from_name, to_name) VALUES (?,?,?,?,?)",
                 (from_acc, 'Transfer', amount, from_user['name'], to_user['name']))
    conn.execute("INSERT INTO transactions (account_number, transaction_type, amount, from_name, to_name) VALUES (?,?,?,?,?)",
                 (to_acc, 'Received', amount, from_user['name'], to_user['name']))
    conn.commit()
    new_bal = conn.execute("SELECT balance FROM users WHERE account_number=?", (from_acc,)).fetchone()['balance']
    conn.close()
    return jsonify({'message': f'Transferred {amount} to {to_user["name"]}', 'balance': new_bal})

@app.route('/api/user/loan', methods=['POST'])
@require_user
def loan(session):
    amount = float(request.json.get('amount', 0))
    if amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400
    acc = session['account_number']
    conn = get_db()
    bank = dict(conn.execute("SELECT * FROM bank_config WHERE id=1").fetchone())

    if not bank['loan_system']:
        conn.close()
        return jsonify({'error': 'Loan system is currently disabled'}), 400

    user = dict(conn.execute("SELECT * FROM users WHERE account_number=?", (acc,)).fetchone())
    if user['loan_count'] >= 2:
        conn.close()
        return jsonify({'error': 'Loan limit exceeded (max 2 loans)'}), 400
    if bank['total_balance'] < amount:
        conn.close()
        return jsonify({'error': 'Bank does not have enough funds'}), 400

    conn.execute("UPDATE users SET balance = balance + ?, loan_count = loan_count + 1 WHERE account_number=?", (amount, acc))
    conn.execute("UPDATE bank_config SET total_balance = total_balance - ?, total_loan = total_loan + ? WHERE id=1", (amount, amount))
    conn.execute("INSERT INTO transactions (account_number, transaction_type, amount, from_name, to_name) VALUES (?,?,?,?,?)",
                 (acc, 'Loan', amount, 'GoldRiver Bank', user['name']))
    conn.commit()
    new_bal = conn.execute("SELECT balance FROM users WHERE account_number=?", (acc,)).fetchone()['balance']
    conn.close()
    return jsonify({'message': f'Loan of {amount} granted', 'balance': new_bal})

@app.route('/api/user/transactions', methods=['GET'])
@require_user
def get_transactions(session):
    conn = get_db()
    rows = conn.execute("SELECT * FROM transactions WHERE account_number=? ORDER BY timestamp DESC LIMIT 50",
                        (session['account_number'],)).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

# ── ADMIN OPERATIONS ──
@app.route('/api/admin/users', methods=['GET'])
@require_admin
def admin_get_users(session):
    conn = get_db()
    rows = conn.execute("SELECT name, email, address, account_type, account_number, balance, loan_count, created_at FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/admin/delete_user', methods=['DELETE'])
@require_admin
def admin_delete_user(session):
    account_number = request.json.get('account_number', '').strip()
    conn = get_db()
    user = conn.execute("SELECT id FROM users WHERE account_number=?", (account_number,)).fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    conn.execute("DELETE FROM users WHERE account_number=?", (account_number,))
    conn.execute("DELETE FROM sessions WHERE account_number=?", (account_number,))
    conn.commit()
    conn.close()
    return jsonify({'message': f'Account {account_number} deleted'})

@app.route('/api/admin/bank_stats', methods=['GET'])
@require_admin
def admin_bank_stats(session):
    conn = get_db()
    bank = dict(conn.execute("SELECT * FROM bank_config WHERE id=1").fetchone())
    user_count = conn.execute("SELECT COUNT(*) as cnt FROM users").fetchone()['cnt']
    conn.close()
    return jsonify({**bank, 'user_count': user_count})

@app.route('/api/admin/loan_system', methods=['POST'])
@require_admin
def toggle_loan(session):
    flag = request.json.get('enabled')
    conn = get_db()
    conn.execute("UPDATE bank_config SET loan_system=? WHERE id=1", (1 if flag else 0,))
    conn.commit()
    conn.close()
    status = 'enabled' if flag else 'disabled'
    return jsonify({'message': f'Loan system {status}'})

@app.route('/api/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    conn = get_db()
    conn.execute("DELETE FROM sessions WHERE token=?", (token,))
    conn.commit()
    conn.close()
    return jsonify({'message': 'Logged out'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
