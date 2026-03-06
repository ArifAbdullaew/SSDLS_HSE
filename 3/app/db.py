import os
import sys
import logging
import getpass
from typing import Dict, List, Tuple, Any, Optional

import psycopg2
from psycopg2 import sql

LOGGER = logging.getLogger("cve-app")
LOGGER.setLevel(logging.INFO)

stdout_h = logging.StreamHandler(stream=sys.stdout)
stdout_h.setLevel(logging.INFO)
stdout_h.addFilter(lambda r: r.levelno <= logging.INFO)
stderr_h = logging.StreamHandler(stream=sys.stderr)
stderr_h.setLevel(logging.WARNING)

LOGGER.addHandler(stdout_h)
LOGGER.addHandler(stderr_h)

log_file = os.getenv("LOG_FILE")
if log_file:
    file_h = logging.FileHandler(log_file)
    file_h.setLevel(logging.INFO)
    LOGGER.addHandler(file_h)


ALLOWED_TABLES = {
    "cve": {"id", "cve_id", "title", "created_at"},
    "cve_nvd": {"id", "cve_id_ref", "source_cve_id", "summary", "published_date",
                "last_modified", "source_url", "raw_json", "ingested_at"},
    "cve_rhel": {"id", "cve_id_ref", "advisory_name", "summary", "severity",
                 "published_date", "source_url", "raw_json", "ingested_at"},
    "cve_mitre": {"id", "cve_id_ref", "description", "assigner", "published_date",
                  "source_url", "raw_json", "ingested_at"},
    "cve_github": {"id", "cve_id_ref", "gh_advisory_id", "summary", "ecosystem",
                   "published_date", "source_url", "raw_json", "ingested_at"},
    "cvss_score": {"id", "source_name", "source_entry_id", "version", "vector",
                   "score", "created_at"},
    "reference": {"id", "cve_id_ref", "source_name", "source_entry_id", "url", "note"},
}

SOURCE_TABLES = {
    "nvd": ("cve_nvd", "id"),
    "rhel": ("cve_rhel", "id"),
    "mitre": ("cve_mitre", "id"),
    "github": ("cve_github", "id"),
}


class DB:
    def __init__(self, host: str, port: int, dbname: str, user: str, password: str):
        self.conn = None
        self.dsn = dict(host=host, port=port, dbname=dbname, user=user, password=password)

    def connect(self):
        try:
            self.conn = psycopg2.connect(**self.dsn)
            self.conn.autocommit = True
            LOGGER.info("Подключение к БД установлено")
        except Exception:
            LOGGER.error("Не удалось подключиться к БД. Проверьте адрес/логин/пароль.")
            raise

    def close(self):
        if self.conn:
            self.conn.close()

    def _check_table_and_columns(self, table: str, cols: List[str]):
        if table not in ALLOWED_TABLES:
            raise ValueError(f"Недопустимая таблица: {table}")
        for c in cols:
            if c not in ALLOWED_TABLES[table]:
                raise ValueError(f"Недопустимое имя колонки: {c}")

    def select(self, table: str, filters: Optional[List[Tuple[str, Any]]] = None) -> List[dict]:
        self._check_table_and_columns(table, [])
        query = sql.SQL("SELECT * FROM {tbl}").format(tbl=sql.Identifier(table))
        params: List[Any] = []

        if filters:
            cols = [c for c, _ in filters]
            self._check_table_and_columns(table, cols)
            where_clauses = [sql.SQL("{col} = %s").format(col=sql.Identifier(c)) for c, _ in filters]
            query = query + sql.SQL(" WHERE ") + sql.SQL(" AND ").join(where_clauses)
            params = [v for _, v in filters]

        with self.conn.cursor() as cur:
            try:
                cur.execute(query, params)
                colnames = [d.name for d in cur.description]
                rows = [dict(zip(colnames, r)) for r in cur.fetchall()]
                LOGGER.info("Запрос выполнен успешно")
                return rows
            except Exception:
                LOGGER.error("Ошибка при выполнении SELECT")
                raise

    def select_in(self, table: str, column: str, values: List[Any]) -> List[dict]:
        self._check_table_and_columns(table, [column])
        query = sql.SQL("SELECT * FROM {tbl} WHERE {col} = ANY(%s)").format(
            tbl=sql.Identifier(table), col=sql.Identifier(column)
        )
        with self.conn.cursor() as cur:
            try:
                cur.execute(query, (values,))
                colnames = [d.name for d in cur.description]
                rows = [dict(zip(colnames, r)) for r in cur.fetchall()]
                LOGGER.info("Запрос выполнен успешно")
                return rows
            except Exception:
                LOGGER.error("Ошибка при выполнении SELECT IN")
                raise

    def update_one(self, table: str, row_id: int, updates: Dict[str, Any]):
        if "id" in updates:
            raise ValueError("Нельзя изменять поле id")
        self._check_table_and_columns(table, list(updates.keys()))
        set_clause = sql.SQL(", ").join(
            sql.SQL("{col} = %s").format(col=sql.Identifier(k)) for k in updates.keys()
        )
        query = sql.SQL("UPDATE {tbl} SET {setc} WHERE id = %s").format(
            tbl=sql.Identifier(table), setc=set_clause
        )
        params = list(updates.values()) + [row_id]
        with self.conn.cursor() as cur:
            try:
                cur.execute(query, params)
                LOGGER.info("Запись обновлена")
            except Exception:
                LOGGER.error("Не удалось обновить запись")
                raise

    def update_many_set(self, table: str, column: str, new_value: Any,
                        where_in_col: str, where_in_vals: List[Any]):
        self._check_table_and_columns(table, [column, where_in_col])
        query = sql.SQL(
            "UPDATE {tbl} SET {col} = %s WHERE {wcol} = ANY(%s)"
        ).format(tbl=sql.Identifier(table),
                 col=sql.Identifier(column),
                 wcol=sql.Identifier(where_in_col))
        with self.conn.cursor() as cur:
            try:
                cur.execute(query, (new_value, where_in_vals))
                LOGGER.info("Множественное обновление выполнено")
            except Exception:
                LOGGER.error("Не удалось выполнить множественное обновление")
                raise

    def insert_one(self, table: str, values: Dict[str, Any]) -> int:
        self._check_table_and_columns(table, list(values.keys()))
        cols = list(values.keys())
        query = sql.SQL("INSERT INTO {tbl} ({cols}) VALUES ({vals}) RETURNING id").format(
            tbl=sql.Identifier(table),
            cols=sql.SQL(", ").join(sql.Identifier(c) for c in cols),
            vals=sql.SQL(", ").join(sql.Placeholder() for _ in cols)
        )
        with self.conn.cursor() as cur:
            try:
                cur.execute(query, list(values.values()))
                new_id = cur.fetchone()[0]
                LOGGER.info("Запись добавлена")
                return new_id
            except Exception:
                LOGGER.error("Не удалось вставить запись")
                raise

    def bulk_insert(self, table: str, rows: List[Dict[str, Any]]):
        if not rows:
            return
        cols = list(rows[0].keys())
        self._check_table_and_columns(table, cols)
        head = sql.SQL("INSERT INTO {tbl} ({cols}) VALUES ").format(
            tbl=sql.Identifier(table),
            cols=sql.SQL(", ").join(sql.Identifier(c) for c in cols)
        )
        values_tpl = sql.SQL(", ").join(
            sql.SQL("(" + ", ".join(["%s"] * len(cols)) + ")") for _ in rows
        )
        query = head + values_tpl
        params: List[Any] = []
        for r in rows:
            params.extend([r[c] for c in cols])
        with self.conn.cursor() as cur:
            try:
                cur.execute(query, params)
                LOGGER.info("Множественная вставка выполнена")
            except Exception:
                LOGGER.error("Не удалось выполнить множественную вставку")
                raise

    def select_raw(self, query: str, params=None) -> List[dict]:
        with self.conn.cursor() as cur:
            cur.execute(query, params or [])
            colnames = [d.name for d in cur.description]
            return [dict(zip(colnames, r)) for r in cur.fetchall()]

    def upsert_cve_get_id(self, cve_id: str, title: Optional[str] = None) -> int:
        q = """
        INSERT INTO cve (cve_id, title)
        VALUES (%s, %s)
        ON CONFLICT (cve_id) DO UPDATE
        SET title = COALESCE(EXCLUDED.title, cve.title)
        RETURNING id;
        """
        with self.conn.cursor() as cur:
            cur.execute(q, (cve_id, title))
            return cur.fetchone()[0]

    def insert_source_entry_with_cvss(
        self,
        source_name: str,               
        cve_id: str,                    
        source_fields: Dict[str, Any],  
        cvss_list: Optional[List[Dict[str, Any]]] = None  
    ) -> Dict[str, Any]:
        if source_name not in SOURCE_TABLES:
            raise ValueError("Unknown source_name")

        table_name, pk_col = SOURCE_TABLES[source_name]
        self._check_table_and_columns(table_name, list(source_fields.keys()))

        with self.conn:
            with self.conn.cursor() as cur:

                fallback_title = source_fields.get("summary") or source_fields.get("description")
                cve_row_id = self.upsert_cve_get_id(cve_id, fallback_title)

                cols = ["cve_id_ref"] + list(source_fields.keys())
                placeholders = [sql.Placeholder() for _ in cols]
                insert_sql = sql.SQL("INSERT INTO {tbl} ({cols}) VALUES ({vals}) RETURNING {pk}").format(
                    tbl=sql.Identifier(table_name),
                    cols=sql.SQL(", ").join(sql.Identifier(c) for c in cols),
                    vals=sql.SQL(", ").join(placeholders),
                    pk=sql.Identifier(pk_col)
                )
                params = [cve_row_id] + [source_fields[k] for k in source_fields.keys()]
                cur.execute(insert_sql, params)
                source_entry_id = cur.fetchone()[0]

                inserted_cvss: List[int] = []
                if cvss_list:
                    for item in cvss_list:
                        for k in ("version", "vector", "score"):
                            if k not in item:
                                raise ValueError(f"cvss item missing '{k}'")
                        cur.execute(
                            """
                            INSERT INTO cvss_score (source_name, source_entry_id, version, vector, score)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT (source_name, source_entry_id, version) DO UPDATE
                            SET vector = EXCLUDED.vector, score = EXCLUDED.score
                            RETURNING id
                            """,
                            (source_name, source_entry_id, item["version"], item["vector"], item["score"])
                        )
                        inserted_cvss.append(cur.fetchone()[0])

                LOGGER.info("Комплексная вставка источника+CVSS выполнена")
                return {"cve_id_ref": cve_row_id, "source_entry_id": source_entry_id, "cvss_ids": inserted_cvss}


def prompt_credentials_from_user() -> Tuple[str, int, str, str, str]:
    host = os.getenv("DB_HOST") or input("DB host [localhost]: ") or "localhost"
    port = int(os.getenv("DB_PORT") or input("DB port [5432]: ") or "5432")
    dbname = os.getenv("DB_NAME") or input("DB name [cve_db]: ") or "cve_db"
    user = os.getenv("DB_USER") or input("DB user [cve_app]: ") or "cve_app"
    password = os.getenv("DB_PASSWORD") or getpass.getpass("DB password: ")
    return host, port, dbname, user, password
