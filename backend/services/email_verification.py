from __future__ import annotations

import hashlib
import os
import secrets
import smtplib
import sqlite3
import time
from email.message import EmailMessage
from typing import Optional


TOKEN_TTL_SECONDS = 30 * 60
RESEND_WINDOW_SECONDS = 10 * 60
RESEND_MAX_ATTEMPTS = 3


def _now() -> int:
    return int(time.time())


def _hash_token(token: str) -> str:
    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def smtp_configured() -> bool:
    return bool(
        _env("SMTP_HOST")
        and _env("SMTP_FROM")
    )


def _smtp_port() -> int:
    raw = _env("SMTP_PORT", "587")

    try:
        port = int(raw)
    except ValueError:
        port = 587

    if port <= 0 or port > 65535:
        port = 587

    return port


def _smtp_use_tls() -> bool:
    return _env("SMTP_USE_TLS", "1").lower() not in {
        "0",
        "false",
        "no",
        "off",
    }


def ensure_schema(c: sqlite3.Connection) -> None:
    """
    Add email verification support without breaking existing users.

    Existing users are marked verified automatically.
    New users must explicitly use email_verified=0.
    """

    columns = {
        row[1]
        for row in c.execute("PRAGMA table_info(users)").fetchall()
    }

    if "email_verified" not in columns:
        c.execute(
            """
            ALTER TABLE users
            ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1
            """
        )

    c.execute(
        """
        CREATE TABLE IF NOT EXISTS email_verification_tokens(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at INTEGER NOT NULL,
            used_at INTEGER,
            created_at INTEGER NOT NULL
        )
        """
    )

    c.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_email_verification_tokens_user
        ON email_verification_tokens(user_id)
        """
    )

    c.execute(
        """
        CREATE INDEX IF NOT EXISTS
        idx_email_verification_tokens_expires
        ON email_verification_tokens(expires_at)
        """
    )


def create_token(
    c: sqlite3.Connection,
    user_id: int,
) -> str:
    """
    Create a new one-time verification token.

    Only the SHA-256 hash is stored in the database.
    """

    c.execute(
        """
        UPDATE email_verification_tokens
        SET used_at=?
        WHERE user_id=?
          AND used_at IS NULL
        """,
        (_now(), user_id),
    )

    token = secrets.token_urlsafe(32)

    c.execute(
        """
        INSERT INTO email_verification_tokens
        (
            user_id,
            token_hash,
            expires_at,
            used_at,
            created_at
        )
        VALUES(?,?,?,?,?)
        """,
        (
            user_id,
            _hash_token(token),
            _now() + TOKEN_TTL_SECONDS,
            None,
            _now(),
        ),
    )

    return token


def verify_token(
    c: sqlite3.Connection,
    token: str,
) -> Optional[int]:
    """
    Verify and consume a token atomically.

    Returns the user id on success.
    Returns None for invalid, expired or already-used tokens.
    """

    token = str(token or "").strip()

    if not token or len(token) > 256:
        return None

    token_hash = _hash_token(token)

    row = c.execute(
        """
        SELECT id,user_id,expires_at,used_at
        FROM email_verification_tokens
        WHERE token_hash=?
        """,
        (token_hash,),
    ).fetchone()

    if not row:
        return None

    if row["used_at"] is not None:
        return None

    if int(row["expires_at"]) < _now():
        return None

    updated = c.execute(
        """
        UPDATE email_verification_tokens
        SET used_at=?
        WHERE id=?
          AND used_at IS NULL
          AND expires_at>=?
        """,
        (
            _now(),
            row["id"],
            _now(),
        ),
    ).rowcount

    if updated != 1:
        return None

    return int(row["user_id"])


def build_verification_url(
    base_url: str,
    token: str,
) -> str:
    base = str(base_url or "").strip().rstrip("/")

    if not base:
        raise ValueError("Verification base URL is not configured")

    return f"{base}/verify-email?token={token}"


def send_verification_email(
    email: str,
    verification_url: str,
) -> bool:
    """
    Send the verification message through SMTP.

    Returns True when SMTP accepts the message.
    Raises RuntimeError when SMTP is not configured or sending fails.
    """

    host = _env("SMTP_HOST")
    username = _env("SMTP_USERNAME")
    password = _env("SMTP_PASSWORD")
    sender = _env("SMTP_FROM")

    if not host or not sender:
        raise RuntimeError(
            "SMTP is not configured"
        )

    recipient = str(email or "").strip().lower()

    if not recipient or len(recipient) > 320:
        raise RuntimeError(
            "Invalid recipient email"
        )

    message = EmailMessage()

    message["Subject"] = "Verify your EasySurf account"
    message["From"] = sender
    message["To"] = recipient

    message.set_content(
        "Welcome to EasySurf.\n\n"
        "Please verify your email address by opening this link:\n\n"
        f"{verification_url}\n\n"
        "This verification link expires in 30 minutes "
        "and can only be used once.\n\n"
        "If you did not create an EasySurf account, "
        "you can ignore this email.\n\n"
        "EasySurf"
    )

    port = _smtp_port()

    try:
        if _smtp_use_tls():
            with smtplib.SMTP(
                host,
                port,
                timeout=20,
            ) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()

                if username:
                    smtp.login(username, password)

                smtp.send_message(message)

        else:
            with smtplib.SMTP(
                host,
                port,
                timeout=20,
            ) as smtp:

                smtp.ehlo()

                if username:
                    smtp.login(username, password)

                smtp.send_message(message)

    except Exception as exc:
        raise RuntimeError(
            "Email delivery failed"
        ) from exc

    return True
