import os
import logging
from functools import wraps

from flask import (
    Flask, render_template, request, session,
    redirect, url_for, flash, g
)
from dotenv import load_dotenv

from db import DB, ALLOWED_TABLES, SOURCE_TABLES

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-in-prod")

# ── Failed-login logger ────────────────────────────────────────────────────────
_log_file = os.getenv("LOG_FILE", "logs/app.log")
os.makedirs(os.path.dirname(os.path.abspath(_log_file)), exist_ok=True)

_fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")

_auth_logger = logging.getLogger("auth")
_auth_logger.setLevel(logging.WARNING)

_fh = logging.FileHandler(_log_file)
_fh.setFormatter(_fmt)
_auth_logger.addHandler(_fh)

_sh = logging.StreamHandler()
_sh.setFormatter(_fmt)
_auth_logger.addHandler(_sh)


# ── Helpers ────────────────────────────────────────────────────────────────────

def login_required(f):
    @wraps(f)
    def _inner(*args, **kwargs):
        if "db_creds" not in session:
            flash("Сначала войдите в систему.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return _inner


def get_db() -> DB:
    """Return a per-request DB connection stored in Flask's g."""
    if "db" not in g:
        db = DB(**session["db_creds"])
        db.connect()
        g.db = db
    return g.db


@app.teardown_appcontext
def _close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("dashboard" if "db_creds" in session else "login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "db_creds" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        host     = request.form.get("host",     "localhost").strip()
        port_str = request.form.get("port",     "5432").strip()
        dbname   = request.form.get("dbname",   "cve_db").strip()
        user     = request.form.get("user",     "").strip()
        password = request.form.get("password", "")

        try:
            port = int(port_str)
        except ValueError:
            flash("Порт должен быть числом.", "error")
            return render_template("login.html")

        creds = dict(host=host, port=port, dbname=dbname, user=user, password=password)
        probe = DB(**creds)
        try:
            probe.connect()
            probe.close()
        except Exception as exc:
            _auth_logger.warning(
                "FAILED_LOGIN ip=%s user=%s host=%s dbname=%s reason=%s",
                request.remote_addr, user, host, dbname, exc
            )
            flash("Ошибка подключения: неверные данные или БД недоступна.", "error")
            return render_template("login.html")

        session.clear()
        session["db_creds"] = creds
        session["db_user"]  = user
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Вы вышли из системы.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", db_user=session.get("db_user", ""))


# ── View ───────────────────────────────────────────────────────────────────────

@app.route("/view", methods=["GET", "POST"])
@login_required
def view():
    tables         = sorted(ALLOWED_TABLES.keys())
    rows           = None
    columns        = None
    error          = None
    selected_table = None

    if request.method == "POST":
        selected_table = request.form.get("table", "").strip()
        filter_col     = request.form.get("filter_col", "").strip()
        filter_val     = request.form.get("filter_val", "").strip()

        try:
            db      = get_db()
            filters = [(filter_col, filter_val)] if filter_col and filter_val else None
            rows    = db.select(selected_table, filters)
            columns = list(rows[0].keys()) if rows else list(ALLOWED_TABLES.get(selected_table, {}) )
        except Exception as exc:
            error = str(exc)

    return render_template(
        "view.html",
        tables=tables,
        rows=rows,
        columns=columns,
        selected_table=selected_table,
        error=error,
    )


# ── Insert ─────────────────────────────────────────────────────────────────────

@app.route("/insert", methods=["GET", "POST"])
@login_required
def insert():
    tables         = sorted(ALLOWED_TABLES.keys())
    result         = None
    error          = None
    selected_table = (
        request.form.get("table") or request.args.get("table") or tables[0]
    )
    # exclude auto-generated columns from the form
    _auto = {"id", "created_at", "ingested_at"}
    table_cols = sorted(ALLOWED_TABLES.get(selected_table, set()) - _auto)

    if request.method == "POST" and request.form.get("action") == "submit":
        values = {
            col: request.form.get(f"col_{col}", "").strip()
            for col in table_cols
            if request.form.get(f"col_{col}", "").strip()
        }
        try:
            if not values:
                raise ValueError("Введите хотя бы одно значение.")
            db     = get_db()
            new_id = db.insert_one(selected_table, values)
            result = f"Запись добавлена, ID = {new_id}"
        except Exception as exc:
            error = str(exc)

    return render_template(
        "insert.html",
        tables=tables,
        table_cols=table_cols,
        selected_table=selected_table,
        result=result,
        error=error,
    )


# ── Update ─────────────────────────────────────────────────────────────────────

@app.route("/update", methods=["GET", "POST"])
@login_required
def update():
    tables         = sorted(ALLOWED_TABLES.keys())
    result         = None
    error          = None
    selected_table = (
        request.form.get("table") or request.args.get("table") or tables[0]
    )
    _auto      = {"id", "created_at", "ingested_at"}
    table_cols = sorted(ALLOWED_TABLES.get(selected_table, set()) - _auto)

    if request.method == "POST" and request.form.get("action") == "submit":
        row_id_str = request.form.get("row_id", "").strip()
        updates = {
            col: request.form.get(f"col_{col}", "").strip()
            for col in table_cols
            if request.form.get(f"col_{col}", "").strip()
        }
        try:
            if not row_id_str:
                raise ValueError("Укажите ID записи.")
            if not updates:
                raise ValueError("Введите хотя бы одно поле для обновления.")
            db = get_db()
            db.update_one(selected_table, int(row_id_str), updates)
            result = f"Запись ID={row_id_str} успешно обновлена."
        except Exception as exc:
            error = str(exc)

    return render_template(
        "update.html",
        tables=tables,
        table_cols=table_cols,
        selected_table=selected_table,
        result=result,
        error=error,
    )


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
