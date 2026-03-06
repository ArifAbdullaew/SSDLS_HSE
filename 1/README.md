# PostgreSQL + Python Demo Project

PostgreSQL + Python demo project for university task.  
Contains a custom PostgreSQL Docker image (ru_RU.UTF-8 locale, SCRAM-SHA-256 auth) and a Python app that connects to the database and runs `SELECT VERSION()`.

## Project Structure
```
.
├─ app/
│  ├─ app.py
│  ├─ config.json
│  └─ requirements.txt
├─ postgres/
│  ├─ Dockerfile
│  ├─ 00-locale-scram.sh
│  ├─ 10-init.sql
│  └─ postgresql.conf
```

## How to Build and Run

### 1. Build and Run PostgreSQL
```bash
docker build -t task-postgres ./postgres
docker run -d --name task-pg -p 5432:5432 task-postgres
```

### 2. Run the Python App
```bash
cd app
pip install -r requirements.txt
python app.py
```

When prompted, enter:
- **Login:** `appuser`  
- **Password:** `app_password`

Expected output:
```
PostgreSQL VERSION(): PostgreSQL 17 ...
```

## Notes
- Locale: `ru_RU.UTF-8`
- Password encryption: `scram-sha-256`
- Config file: `app/config.json`
