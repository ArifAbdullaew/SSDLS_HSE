#!/usr/bin/env python3

import json, re, sys, getpass
from psycopg import connect  


def load_config(path="config.json"):
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    for k in ("host", "port", "name"):
        if k not in cfg.get("db", {}):
            raise ValueError(f"В config.json отсутствует db.{k}")
    return cfg


def prompt_credentials():
    login = input("Введите логин PostgreSQL: ").strip()
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", login):
        raise ValueError("Неверный формат логина.")
    password = getpass.getpass("Введите пароль PostgreSQL: ")
    return {"user": login, "password": password}


def build_params(cfg, creds):
    db = cfg["db"]
    return {
        "host": db["host"],
        "port": int(db["port"]),
        "dbname": db["name"],
        "user": creds["user"],
        "password": creds["password"],
        "sslmode": db.get("sslmode", "disable"),
    }


def run_version_query(params):
    with connect(**params) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT VERSION();")
            return cur.fetchone()[0]


def main():
    try:
        cfg = load_config()
        creds = prompt_credentials()
        params = build_params(cfg, creds)
        version = run_version_query(params)
        print("PostgreSQL VERSION():", version)
        return 0
    except Exception as e:
        print("Ошибка:", e)
        return 2


if __name__ == "__main__":
    sys.exit(main())
