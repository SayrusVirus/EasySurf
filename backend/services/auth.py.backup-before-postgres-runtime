"""
EasySurf authentication service.

This module contains authentication database logic only.
It does not import main.py, FastAPI, or Starlette.
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
from dataclasses import dataclass
from typing import Any


EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 64


@dataclass(frozen=True)
class AuthResult:
    ok: bool
    reason: str = ""
    user_id: int | None = None
    is_admin: bool = False


def normalize_email(email: str) -> str:
    return str(email or "").strip().lower()


def validate_email(email: str) -> bool:
    value = normalize_email(email)

    return (
        bool(value)
        and len(value) <= 320
        and bool(EMAIL_RE.fullmatch(value))
    )


def validate_password(password: str) -> str:
    value = str(password or "")

    if len(value) < MIN_PASSWORD_LENGTH:
        return "short"

    if len(value) > MAX_PASSWORD_LENGTH:
        return "long"

    return ""


def hash_password(password: str) -> str:
    """
    Same scrypt format as the stable EasySurf main.py:

        salt_hex:scrypt_digest_hex
    """

    salt = secrets.token_bytes(16)

    digest = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
    ).hex()

    return f"{salt.hex()}:{digest}"


def verify_password(
    password: str,
    encoded: str,
) -> bool:
    try:
        salt_hex, expected = str(
            encoded or ""
        ).split(":", 1)

        actual = hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt_hex),
            n=2**14,
            r=8,
            p=1,
        ).hex()

        return secrets.compare_digest(
            actual,
            expected,
        )

    except Exception:
        return False


def admin_email() -> str:
    return normalize_email(
        os.getenv(
            "EASYSURF_ADMIN_EMAIL",
            "",
        )
    )


def is_admin_email(email: str) -> bool:
    configured = admin_email()

    return bool(
        configured
        and normalize_email(email) == configured
    )


def find_user_by_email(
    conn: Any,
    email: str,
) -> Any:
    normalized = normalize_email(email)

    return conn.execute(
        """
        SELECT *
        FROM users
        WHERE lower(email)=lower(?)
        """,
        (normalized,),
    ).fetchone()


def find_user_by_id(
    conn: Any,
    user_id: int,
) -> Any:
    return conn.execute(
        """
        SELECT *
        FROM users
        WHERE id=?
        """,
        (int(user_id),),
    ).fetchone()


def generate_referral_code(conn: Any) -> str:
    while True:
        value = (
            secrets.token_urlsafe(7)
            .replace("-", "")
            .replace("_", "")
            .upper()
        )[:8]

        exists = conn.execute(
            """
            SELECT 1
            FROM users
            WHERE referral_code=?
            """,
            (value,),
        ).fetchone()

        if not exists:
            return value


def create_user(
    conn: Any,
    email: str,
    password: str,
    now_value: int,
    referral: str = "",
) -> AuthResult:
    normalized = normalize_email(email)

    if not validate_email(normalized):
        return AuthResult(
            ok=False,
            reason="invalid_email",
        )

    password_error = validate_password(password)

    if password_error:
        return AuthResult(
            ok=False,
            reason=password_error,
        )

    existing = find_user_by_email(
        conn,
        normalized,
    )

    if existing:
        return AuthResult(
            ok=False,
            reason="exists",
            user_id=int(existing["id"]),
            is_admin=bool(
                int(existing["is_admin"] or 0)
            ),
        )

    referral_code = str(
        referral or ""
    ).strip().upper()

    referred_by = None

    if referral_code:
        referrer = conn.execute(
            """
            SELECT id
            FROM users
            WHERE referral_code=?
            """,
            (referral_code,),
        ).fetchone()

        if referrer:
            referred_by = int(
                referrer["id"]
            )

    new_referral_code = generate_referral_code(
        conn
    )

    make_admin = 1 if is_admin_email(
        normalized
    ) else 0

    cursor = conn.execute(
        """
        INSERT INTO users(
            email,
            password_hash,
            created_at,
            referral_code,
            referred_by,
            email_verified,
            is_admin
        )
        VALUES(?,?,?,?,?,?,?)
        """,
        (
            normalized,
            hash_password(password),
            int(now_value),
            new_referral_code,
            referred_by,
            1,
            make_admin,
        ),
    )

    user_id = int(
        cursor.lastrowid
    )

    # Preserve the existing EasySurf referral bonus.
    if referred_by is not None:
        bonus = 50

        conn.execute(
            """
            UPDATE users
            SET balance=balance+?
            WHERE id=?
            """,
            (
                bonus,
                referred_by,
            ),
        )

        conn.execute(
            """
            INSERT INTO transactions(
                user_id,
                amount,
                kind,
                description,
                created_at
            )
            VALUES(?,?,?,?,?)
            """,
            (
                referred_by,
                bonus,
                "referral_bonus",
                "Referral signup bonus",
                int(now_value),
            ),
        )

        conn.execute(
            """
            INSERT INTO referrals(
                referrer_id,
                referred_id,
                bonus,
                created_at
            )
            VALUES(?,?,?,?)
            """,
            (
                referred_by,
                user_id,
                bonus,
                int(now_value),
            ),
        )

    return AuthResult(
        ok=True,
        reason="created",
        user_id=user_id,
        is_admin=bool(make_admin),
    )


def authenticate_user(
    conn: Any,
    email: str,
    password: str,
) -> AuthResult:
    normalized = normalize_email(email)

    current = find_user_by_email(
        conn,
        normalized,
    )

    if not current:
        return AuthResult(
            ok=False,
            reason="invalid",
        )

    if not verify_password(
        password,
        current["password_hash"],
    ):
        return AuthResult(
            ok=False,
            reason="invalid",
        )

    # The configured EasySurf admin email receives admin access
    # at login. No startup/init database modification is needed.
    configured_admin = admin_email()

    if (
        configured_admin
        and normalized == configured_admin
    ):
        conn.execute(
            """
            UPDATE users
            SET is_admin=1,
                email_verified=1
            WHERE id=?
            """,
            (
                int(current["id"]),
            ),
        )

        current = find_user_by_id(
            conn,
            int(current["id"]),
        )

    return AuthResult(
        ok=True,
        reason="success",
        user_id=int(current["id"]),
        is_admin=bool(
            int(current["is_admin"] or 0)
        ),
    )
