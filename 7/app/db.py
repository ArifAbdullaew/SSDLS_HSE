import logging
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from psycopg2 import sql

logger = logging.getLogger("cve-web.db")

ALLOWED_TABLES: Dict[str, set] = {
    "cve":        {"id", "cve_id", "title", "created_at"},
    "cve_nvd":    {"id", "cve_id_ref", "source_cve_id", "summary", "published_date",
                   "last_modified", "source_url", "raw_json", "ingested_at"},
    "cve_rhel":   {"id", "cve_id_ref", "advisory_name", "summary", "severity",
                   "published_date", "source_url", "raw_json", "ingested_at"},
    "cve_mitre":  {"id", "cve_id_ref", "description", "assigner", "published_date",
                   "source_url", "raw_json", "ingested_at"},
    "cve_github": {"id", "cve_id_ref", "gh_advisory_id", "summary", "ecosystem",
                   "published_date", "source_url", "raw_json", "ingested_at"},
    "cvss_score": {"id", "source_name", "source_entry_id", "version", "vector",
                   "score", "created_at"},
    "reference":  {"id", "cve_id_ref", "source_name", "source_entry_id", "url", "note"},
}

SOURCE_TABLES: Dict[str, Tuple[str, str]] = {
    "nvd":    ("cve_nvd",    "id"),
    "rhel":   ("cve_rhel",   "id"),
    "mitre":  ("cve_mitre",  "id"),
    "github": ("cve_github", "id"),
}


class DB:
    def __init__(self, host: str, port: int, dbname: str, user: str, password: str):
        self.conn = None
        self._dsn = dict(host=host, port=port, dbname=dbname, user=user, password=password)

    def connect(self):
        self.conn = psycopg2.connect(**self._dsn)
        self.conn.autocommit = True
        logger.info("DB connection established")

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    # ── Internal helpers ───────────────────────────────────────────────────────

    def _validate(self, table: str, cols: List[str]):
        if table not in ALLOWED_TABLES:
            raise ValueError(f"Недопустимая таблица: {table!r}")
        for c in cols:
            if c not in ALLOWED_TABLES[table]:
                raise ValueError(f"Недопустимое имя колонки {c!r} для таблицы {table!r}")

    # ── Reads ──────────────────────────────────────────────────────────────────

    def select(
        self,
        table: str,
        filters: Optional[List[Tuple[str, Any]]] = None,
    ) -> List[dict]:
        self._validate(table, [])
        query  = sql.SQL("SELECT * FROM {t}").format(t=sql.Identifier(table))
        params: List[Any] = []

        if filters:
            self._validate(table, [c for c, _ in filters])
            clauses = [
                sql.SQL("{c} = %s").format(c=sql.Identifier(c))
                for c, _ in filters
            ]
            query  = query + sql.SQL(" WHERE ") + sql.SQL(" AND ").join(clauses)
            params = [v for _, v in filters]

        with self.conn.cursor() as cur:
            cur.execute(query, params)
            cols = [d.name for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    def select_in(self, table: str, column: str, values: List[Any]) -> List[dict]:
        """SELECT * FROM table WHERE column = ANY(%s)  — safe group-of-values query."""
        self._validate(table, [column])
        query = sql.SQL("SELECT * FROM {t} WHERE {c} = ANY(%s)").format(
            t=sql.Identifier(table), c=sql.Identifier(column)
        )
        with self.conn.cursor() as cur:
            cur.execute(query, (values,))
            cols = [d.name for d in cur.description]
            return [dict(zip(cols, row)) for row in cur.fetchall()]

    # ── Writes ─────────────────────────────────────────────────────────────────

    def insert_one(self, table: str, values: Dict[str, Any]) -> int:
        self._validate(table, list(values.keys()))
        cols  = list(values.keys())
        query = sql.SQL(
            "INSERT INTO {t} ({cols}) VALUES ({vals}) RETURNING id"
        ).format(
            t    = sql.Identifier(table),
            cols = sql.SQL(", ").join(sql.Identifier(c) for c in cols),
            vals = sql.SQL(", ").join(sql.Placeholder() for _ in cols),
        )
        with self.conn.cursor() as cur:
            cur.execute(query, list(values.values()))
            return cur.fetchone()[0]

    def bulk_insert(self, table: str, rows: List[Dict[str, Any]]):
        if not rows:
            return
        cols = list(rows[0].keys())
        self._validate(table, cols)
        head = sql.SQL("INSERT INTO {t} ({cols}) VALUES ").format(
            t    = sql.Identifier(table),
            cols = sql.SQL(", ").join(sql.Identifier(c) for c in cols),
        )
        row_tpl = sql.SQL("({})".format(", ".join(["%s"] * len(cols))))
        values_part = sql.SQL(", ").join(row_tpl for _ in rows)
        query  = head + values_part
        params: List[Any] = []
        for r in rows:
            params.extend(r[c] for c in cols)
        with self.conn.cursor() as cur:
            cur.execute(query, params)

    def update_one(self, table: str, row_id: int, updates: Dict[str, Any]):
        if "id" in updates:
            raise ValueError("Нельзя изменять поле id.")
        self._validate(table, list(updates.keys()))
        set_clause = sql.SQL(", ").join(
            sql.SQL("{c} = %s").format(c=sql.Identifier(k)) for k in updates
        )
        query  = sql.SQL("UPDATE {t} SET {s} WHERE id = %s").format(
            t=sql.Identifier(table), s=set_clause
        )
        params = list(updates.values()) + [row_id]
        with self.conn.cursor() as cur:
            cur.execute(query, params)

    def update_many_set(
        self,
        table: str,
        column: str,
        new_value: Any,
        where_in_col: str,
        where_in_vals: List[Any],
    ):
        """UPDATE … SET col = %s WHERE where_col = ANY(%s) — safe list parameter."""
        self._validate(table, [column, where_in_col])
        query = sql.SQL(
            "UPDATE {t} SET {c} = %s WHERE {wc} = ANY(%s)"
        ).format(
            t  = sql.Identifier(table),
            c  = sql.Identifier(column),
            wc = sql.Identifier(where_in_col),
        )
        with self.conn.cursor() as cur:
            cur.execute(query, (new_value, where_in_vals))
