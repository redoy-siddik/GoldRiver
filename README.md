# ABC Bank — Full-Stack Banking Application

A modern banking system with a Flask backend, SQLite database, and a beautiful HTML/JS frontend.

## Project Structure

```
bank_app/
├── app.py          # Flask backend + REST API + SQLite database
├── bank.db         # SQLite database (auto-created on first run)
├── static/
│   └── index.html  # Single-page frontend application
└── README.md
```

## Requirements

- Python 3.8+
- Flask (built-in with most Python environments)

Install Flask if needed:
```bash
pip install flask
```

## Run the Application

```bash
cd bank_app
python app.py
```

Then open your browser at: **http://localhost:5000**

## Features

### User Portal
- ✅ Sign up with name, email, address, account type, password
- ✅ Log in with account number + password
- ✅ Deposit funds
- ✅ Withdraw funds
- ✅ Transfer money to another account
- ✅ Apply for loans (max 2 active loans)
- ✅ View full transaction history

### Admin Portal
- ✅ Admin sign up / log in
- ✅ View all users and their balances
- ✅ Delete user accounts
- ✅ View bank total balance and total loans
- ✅ Enable / disable the loan system

## Database Schema

| Table           | Description                        |
|-----------------|------------------------------------|
| `bank_config`   | Bank name, total balance, loan sum |
| `users`         | User accounts and balances         |
| `admins`        | Admin accounts                     |
| `transactions`  | Full transaction audit log         |
| `sessions`      | Auth tokens (Bearer tokens)        |

## Security Notes

- Passwords are SHA-256 hashed before storage
- All protected endpoints require a Bearer token
- Sessions are stored server-side in the database
- Foreign keys are enforced via SQLite PRAGMA
