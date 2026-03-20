import os, sys, time, logging, signal
from datetime import datetime
from psycopg import connect
import hvac  # Шаг 9: клиент для HashiCorp Vault


# ---------------------------------------------------------------------------
# Шаги 10-11: Vault — получение логина/пароля к БД перед каждым запросом
# ---------------------------------------------------------------------------

def _vault_credentials():
    """Аутентифицируется в Vault через AppRole и возвращает (username, password)."""
    # Шаг 10: параметры клиента Vault из переменных среды окружения
    vault_addr = os.getenv("VAULT_ADDR", "http://vault:8200")
    secret_path = os.getenv("VAULT_SECRET_PATH", "pinger/db")

    # role-id и secret-id читаем из файлов (shared volume) или env vars
    role_id = os.getenv("VAULT_ROLE_ID")
    if not role_id:
        role_id_file = os.getenv("VAULT_ROLE_ID_FILE", "/vault-secrets/role-id")
        with open(role_id_file) as f:
            role_id = f.read().strip()

    secret_id = os.getenv("VAULT_SECRET_ID")
    if not secret_id:
        secret_id_file = os.getenv("VAULT_SECRET_ID_FILE", "/vault-secrets/secret-id")
        with open(secret_id_file) as f:
            secret_id = f.read().strip()

    # Шаг 11: аутентифицируемся и получаем секрет
    client = hvac.Client(url=vault_addr)
    client.auth.approle.login(role_id=role_id, secret_id=secret_id)

    secret = client.secrets.kv.v2.read_secret_version(
        path=secret_path, mount_point="secret"
    )
    data = secret["data"]["data"]
    return data["username"], data["password"]


# ---------------------------------------------------------------------------
# Параметры подключения к БД (без логина/пароля — берём из Vault)
# ---------------------------------------------------------------------------

def _db_params():
    timeout_ms = int(os.getenv("DB_STATEMENT_TIMEOUT_MS", "3000"))
    return {
        "host": os.getenv("DB_HOST", "db"),
        "port": int(os.getenv("DB_PORT", "5432")),
        "dbname": os.getenv("DB_NAME", "appdb"),
        "sslmode": os.getenv("DB_SSLMODE", "disable"),
        "connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT", "5")),
        "options": f"-c statement_timeout={timeout_ms}",
    }


def _log_setup():
    lg = logging.getLogger("svc")
    lg.setLevel(logging.INFO)

    class _flt(logging.Filter):
        def filter(self, rec):
            return rec.levelno < logging.ERROR

    sh = logging.StreamHandler(stream=sys.stdout)
    sh.setLevel(logging.INFO)
    sh.addFilter(_flt())
    lg.addHandler(sh)

    eh = logging.StreamHandler(stream=sys.stderr)
    eh.setLevel(logging.ERROR)
    lg.addHandler(eh)

    lf = os.getenv("LOG_FILE_PATH")
    if lf:
        fh = logging.FileHandler(lf, encoding="utf-8")
        fh.setLevel(logging.INFO)
        lg.addHandler(fh)

    return lg


STOP_FLAG = False
CFG = _db_params()
WAIT = int(os.getenv("PING_INTERVAL_SECONDS", os.getenv("PING_INTERVAL_MINUTES", "0")) or 0) or 300
LOG = _log_setup()


def _stopper(sig, frame):
    global STOP_FLAG
    STOP_FLAG = True
    LOG.info("Shutting down gracefully...")


def _signals():
    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, _stopper)


def _probe():
    """Шаг 11: получает логин/пароль из Vault перед каждым запросом к БД."""
    try:
        user, password = _vault_credentials()
        LOG.info("Vault: credentials fetched (user=%s)", user)
        params = dict(CFG, user=user, password=password)
        with connect(**params) as cx, cx.cursor() as cr:
            cr.execute("SELECT version();")
            res = cr.fetchone()
            if not res:
                LOG.info("Empty response from version query (unusual).")
                return
            (ver,) = res
            if not isinstance(ver, str):
                LOG.info("Unexpected version response (%s): %r", type(ver).__name__, ver)
            else:
                LOG.info("Connection OK. PostgreSQL version: %s", ver)
    except Exception as ex:
        LOG.error("Connection/query error: %s", ex)


def run():
    LOG.info("Service started. Interval=%s sec Host=%s:%s DB=%s",
             WAIT, CFG["host"], CFG["port"], CFG["dbname"])
    while not STOP_FLAG:
        ts = datetime.now().isoformat(timespec="seconds")
        LOG.info("Probing DB connection (%s)...", ts)
        _probe()
        slept = 0
        while not STOP_FLAG and slept < WAIT:
            time.sleep(min(1, WAIT - slept))
            slept += 1
    LOG.info("Service finished.")


if __name__ == "__main__":
    _signals()
    run()
