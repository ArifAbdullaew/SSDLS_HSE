import argparse
import json
from typing import List, Tuple

from db import DB, prompt_credentials_from_user, ALLOWED_TABLES, SOURCE_TABLES


def parse_kv_list(pairs: List[str]) -> List[Tuple[str, str]]:
    out = []
    for p in pairs or []:
        if "=" not in p:
            raise ValueError("Ожидается формат col=value")
        k, v = p.split("=", 1)
        out.append((k.strip(), v.strip()))
    return out


def main():
    parser = argparse.ArgumentParser(description="CVE DB CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_view = sub.add_parser("view", help="Просмотр таблицы")
    p_view.add_argument("--table", required=True, choices=ALLOWED_TABLES.keys())
    p_view.add_argument("--where", nargs="*", help="Фильтры col=value (можно несколько)")

    p_viewin = sub.add_parser("view-in", help="Просмотр WHERE col IN (..)")
    p_viewin.add_argument("--table", required=True, choices=ALLOWED_TABLES.keys())
    p_viewin.add_argument("--column", required=True)
    p_viewin.add_argument("--values", required=True, help="JSON-массив значений")

    p_upd1 = sub.add_parser("update-one", help="Обновить одну запись по id")
    p_upd1.add_argument("--table", required=True, choices=ALLOWED_TABLES.keys())
    p_upd1.add_argument("--id", required=True, type=int)
    p_upd1.add_argument("--set", nargs="+", required=True, help="col=value ...")

    p_upd_many = sub.add_parser("update-many", help="Обновить несколько записей одним значением")
    p_upd_many.add_argument("--table", required=True, choices=ALLOWED_TABLES.keys())
    p_upd_many.add_argument("--column", required=True, help="Колонка для SET")
    p_upd_many.add_argument("--value", required=True, help="Новое значение")
    p_upd_many.add_argument("--where-in-col", required=True, help="Колонка для IN")
    p_upd_many.add_argument("--where-in", required=True, help="JSON-массив значений")

    p_ins1 = sub.add_parser("insert-one", help="INSERT одной строки")
    p_ins1.add_argument("--table", required=True, choices=ALLOWED_TABLES.keys())
    p_ins1.add_argument("--values", nargs="+", required=True, help="col=value ...")

    p_bulk = sub.add_parser("bulk-insert", help="Множественная вставка в таблицу")
    p_bulk.add_argument("--table", required=True, choices=ALLOWED_TABLES.keys())
    p_bulk.add_argument("--rows", required=True, help="JSON-массив объектов")

    p_ins_src = sub.add_parser("insert-source", help="Вставить запись источника для CVE + CVSS[]")
    p_ins_src.add_argument("--source", required=True, choices=SOURCE_TABLES.keys())  # nvd/rhel/mitre/github
    p_ins_src.add_argument("--cve-id", required=True, help="CVE-YYYY-NNNN")
    p_ins_src.add_argument("--fields", required=True, help="JSON объект полей источника (кроме cve_id_ref)")
    p_ins_src.add_argument("--cvss", help="JSON-массив объектов {'version','vector','score'}")

    p_cons = sub.add_parser("consolidate-score", help="Макс/сред/мин CVSS по CVE среди всех источников")
    p_cons.add_argument("--cve-id", required=True)

    args = parser.parse_args()

    host, port, dbname, user, password = prompt_credentials_from_user()
    db = DB(host, port, dbname, user, password)
    db.connect()

    try:
        if args.cmd == "view":
            filters = parse_kv_list(args.where)
            rows = db.select(args.table, filters)
            print(json.dumps(rows, ensure_ascii=False, indent=2))

        elif args.cmd == "view-in":
            vals = json.loads(args.values)
            rows = db.select_in(args.table, args.column, vals)
            print(json.dumps(rows, ensure_ascii=False, indent=2))

        elif args.cmd == "update-one":
            updates = dict(parse_kv_list(args.set))
            db.update_one(args.table, args.id, updates)

        elif args.cmd == "update-many":
            vals = json.loads(args.where_in)
            db.update_many_set(args.table, args.column, args.value, args.where_in_col, vals)

        elif args.cmd == "insert-one":
            kv = dict(parse_kv_list(args.values))
            new_id = db.insert_one(args.table, kv)
            print(json.dumps({"id": new_id}, ensure_ascii=False))

        elif args.cmd == "bulk-insert":
            rows = json.loads(args.rows)
            db.bulk_insert(args.table, rows)

        elif args.cmd == "insert-source":
            fields = json.loads(args.fields)
            cvss = json.loads(args.cvss) if args.cvss else None
            res = db.insert_source_entry_with_cvss(args.source, args.cve_id, fields, cvss)
            print(json.dumps(res, ensure_ascii=False, indent=2))

        elif args.cmd == "consolidate-score":
            q = """
            WITH srcs AS (
                SELECT n.id AS id, 'nvd' AS src FROM cve_nvd n WHERE n.cve_id_ref = (SELECT id FROM cve WHERE cve_id = %s)
                UNION ALL
                SELECT r.id, 'rhel' FROM cve_rhel r WHERE r.cve_id_ref = (SELECT id FROM cve WHERE cve_id = %s)
                UNION ALL
                SELECT m.id, 'mitre' FROM cve_mitre m WHERE m.cve_id_ref = (SELECT id FROM cve WHERE cve_id = %s)
                UNION ALL
                SELECT g.id, 'github' FROM cve_github g WHERE g.cve_id_ref = (SELECT id FROM cve WHERE cve_id = %s)
            )
            SELECT
                MAX(cs.score) AS max_score,
                AVG(cs.score) AS avg_score,
                MIN(cs.score) AS min_score
            FROM cvss_score cs
            JOIN srcs s ON s.src = cs.source_name AND s.id = cs.source_entry_id;
            """
            rows = db.select_raw(q, [args.cve_id] * 4)
            print(json.dumps(rows, ensure_ascii=False, indent=2))

    finally:
        db.close()


if __name__ == "__main__":
    main()
