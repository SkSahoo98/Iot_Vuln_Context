# Database setup guide (Phase 4)

This guide walks through creating the PostgreSQL schema for the IoT Security Framework.

## Prerequisites

- PostgreSQL 18+ installed (`psql --version`)
- Python 3.13 virtual environment in `backend/.venv`
- A `.env` file at the project root (copy from `.env.example`)

## Step-by-step (quick path)

Run the all-in-one setup script from **Windows PowerShell**:

```powershell
cd c:\Users\KIIT\Desktop\Web_Project\IOT_Security_Framework\backend
.\.venv\Scripts\Activate.ps1
python scripts/setup_database.py
```

When prompted, enter the **postgres** user password you chose during PostgreSQL installation.

**Non-interactive** (password via environment variable):

```powershell
$env:IOT_POSTGRES_PASSWORD = "YOUR_PASSWORD"
python scripts/setup_database.py
```

---

## Step-by-step (manual path)

### 1. Configure environment

```powershell
cd c:\Users\KIIT\Desktop\Web_Project\IOT_Security_Framework
copy .env.example .env
```

Edit `.env` and replace `CHANGE_ME` with your real PostgreSQL `postgres` user password.

### 2. Create virtual environment and install packages

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Create the database

```powershell
python scripts/create_database.py
```

Expected output: `Database 'iot_security' created successfully.` or `already exists.`

### 4. Generate and apply migration

```powershell
alembic revision --autogenerate -m "initial schema"
alembic upgrade head
```

### 5. Insert synthetic seed data

```powershell
python scripts/seed_data.py
```

Expected output: `Seed data inserted successfully.`

### 6. Run database tests

```powershell
pytest
```

## Verification queries

```powershell
psql -U postgres -d iot_security -c "\dt"
psql -U postgres -d iot_security -c "SELECT device_name, ip_address, criticality FROM devices;"
psql -U postgres -d iot_security -c "SELECT score, risk_level FROM risk_scores rs JOIN devices d ON d.id = rs.device_id WHERE d.device_name = 'ESP32-02';"
```

## Rollback (development only)

```powershell
alembic downgrade base
```

Do not use `downgrade base` on production data you need to keep.
