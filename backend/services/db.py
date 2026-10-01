from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent.parent

load_dotenv(BASE_DIR / ".env")


DATABASE_HOST = os.getenv(
    "EASYSURF_DATABASE_HOST",
    "aws-0-ap-southeast-1.pooler.supabase.com",
).strip()

DATABASE_PORT = int(
    os.getenv("EASYSURF_DATABASE_PORT", "5432").strip()
)

DATABASE_NAME = os.getenv(
    "EASYSURF_DATABASE_NAME",
    "postgres",
).strip()

DATABASE_USER = os.getenv(
    "EASYSURF_DATABASE_USER",
    "postgres.vlmttibwmwzxqxsbxejr",
).strip()

DATABASE_PASSWORD = os.getenv(
    "EASYSURF_DATABASE_PASSWORD",
    "",
)


if not DATABASE_PASSWORD:
    raise RuntimeError(
        "EASYSURF_DATABASE_PASSWORD is not configured"
    )


def connect():
    return psycopg.connect(
        host=DATABASE_HOST,
        port=DATABASE_PORT,
        dbname=DATABASE_NAME,
        user=DATABASE_USER,
        password=DATABASE_PASSWORD,
        connect_timeout=10,
        row_factory=dict_row,
    )


def test_connection() -> dict[str, Any]:
    conn = connect()

    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    current_database() AS database_name,
                    current_user AS database_user,
                    version() AS server_version
                """
            )

            row = cur.fetchone()

            return {
                "ok": True,
                "database": row["database_name"],
                "user": row["database_user"],
                "version": row["server_version"],
            }

    finally:
        conn.close()


if __name__ == "__main__":
    result = test_connection()

    print("SUPABASE POSTGRESQL CONNECTION: OK")
    print("DATABASE:", result["database"])
    print("USER:", result["user"])
    print(
        "SERVER:",
        result["version"].split(",", 1)[0],
    )
