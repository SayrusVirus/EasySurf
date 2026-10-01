from __future__ import annotations

import sqlite3
import time
from pathlib import Path


from services.db_config import DB_PATH


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_today_stats(user_id: int) -> dict:
    """
    Return today's completed tasks and earned amount.

    EasySurf stores completed task rewards in transactions.
    Positive transactions are treated as earnings.
    """

    today_start = int(time.time() // 86400) * 86400

    conn = _connect()

    try:
        row = conn.execute(
            """
            SELECT
                COUNT(*) AS tasks_completed,
                COALESCE(SUM(amount), 0) AS earned
            FROM transactions
            WHERE user_id = ?
              AND amount > 0
              AND created_at >= ?
            """,
            (user_id, today_start),
        ).fetchone()

        return {
            "user_id": user_id,
            "tasks_completed": int(row["tasks_completed"] or 0),
            "earned": float(row["earned"] or 0),
        }

    finally:
        conn.close()


def get_streak(user_id: int) -> int:
    """
    Calculate the current earning streak.

    A day counts when the user has at least one positive
    transaction on that day.
    """

    conn = _connect()

    try:
        rows = conn.execute(
            """
            SELECT DISTINCT
                CAST(created_at / 86400 AS INTEGER) AS day
            FROM transactions
            WHERE user_id = ?
              AND amount > 0
            ORDER BY day DESC
            """,
            (user_id,),
        ).fetchall()

        if not rows:
            return 0

        days = {int(row["day"]) for row in rows}

        current = int(time.time() // 86400)

        if current not in days:
            return 0

        streak = 0

        while current in days:
            streak += 1
            current -= 1

        return streak

    finally:
        conn.close()


def get_total_earned(user_id: int) -> float:
    """
    Return the user's total positive earnings.
    """

    conn = _connect()

    try:
        row = conn.execute(
            """
            SELECT COALESCE(SUM(amount), 0) AS total
            FROM transactions
            WHERE user_id = ?
              AND amount > 0
            """,
            (user_id,),
        ).fetchone()

        return float(row["total"] or 0)

    finally:
        conn.close()


def get_completed_tasks_count(user_id: int) -> int:
    """
    Return the number of completed earning transactions.

    This project no longer uses the old 'completions' table,
    so the current transaction ledger is used instead.
    """

    conn = _connect()

    try:
        row = conn.execute(
            """
            SELECT COUNT(*) AS total
            FROM transactions
            WHERE user_id = ?
              AND amount > 0
            """,
            (user_id,),
        ).fetchone()

        return int(row["total"] or 0)

    finally:
        conn.close()
