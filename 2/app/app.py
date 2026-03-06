import os, sys, time, logging, signal
from datetime import datetime
from psycopg import connect

def _interval():
    val = int(os.getenv("PING_INTERVAL_SECONDS", os.getenv("PING_INTERVAL_MINUTES", "0")) or 0)
    return val if val > 0 else 300

def _db_params():
    timeout_ms = int(os.getenv("DB_STATEMENT_TIMEOUT_MS", "3000"))
    return {
        "host": os.getenv("DB_HOST", "db"),
        "port": int(os.getenv("DB_PORT", "5432")),
        "dbname": os.getenv("DB_NAME", "appdb"),
        "user": os.getenv("DB_USER", ""),
        "password": os.getenv("DB_PASSWORD", ""),
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
WAIT = _interval()
LOG = _log_setup()

def _stopper(sig, frame):
    global STOP_FLAG
    STOP_FLAG = True
    LOG.info("Shutting down gracefully...")

def _signals():
    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, _stopper)

def _probe():
    try:
        with connect(**CFG) as cx, cx.cursor() as cr:
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
