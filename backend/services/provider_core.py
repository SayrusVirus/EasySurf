from __future__ import annotations

import hashlib
import hmac
import os
import time
from decimal import Decimal, InvalidOperation, ROUND_FLOOR
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from services.pg_compat import db


# ============================================================
# BITLABS PROVIDER
# ============================================================

BITLABS_API_BASE = "https://api.bitlabs.ai"
BITLABS_WEB_BASE = "https://web.bitlabs.ai"


def bitlabs_token() -> str:
    return os.getenv("BITLABS_API_TOKEN", "").strip()


def bitlabs_secret() -> str:
    return os.getenv("BITLABS_APP_SECRET", "").strip()


def bitlabs_configured() -> bool:
    return bool(bitlabs_token())


def bitlabs_callback_configured() -> bool:
    return bool(
        bitlabs_token()
        and bitlabs_secret()
    )


def bitlabs_usd_to_reward(value_usd) -> int:
    """
    Convert BitLabs USD amount into EasySurf balance units.

    EasySurf stores USD in thousandths:
        1    = $0.001
        10   = $0.010
        100  = $0.100
        1000 = $1.000
    """

    try:
        amount = Decimal(str(value_usd).strip())
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("Invalid BitLabs USD value")

    if not amount.is_finite():
        raise ValueError("Invalid BitLabs USD value")

    if amount == 0:
        return 0

    if amount > 0:
        return int(
            (amount * Decimal("1000")).to_integral_value(
                rounding=ROUND_FLOOR
            )
        )

    return -int(
        ((-amount) * Decimal("1000")).to_integral_value(
            rounding=ROUND_FLOOR
        )
    )


def verify_bitlabs_callback_hash(
    callback_url_without_hash: str,
    supplied_hash: str,
) -> bool:
    """
    Verify BitLabs reward callback.

    BitLabs uses HMAC-SHA1 over the complete callback URL,
    excluding the final hash parameter.
    """

    secret = bitlabs_secret()

    if not secret:
        return False

    url = str(callback_url_without_hash or "")
    received = str(supplied_hash or "").strip().lower()

    if not url or not received:
        return False

    expected = hmac.new(
        secret.encode("utf-8"),
        url.encode("utf-8"),
        hashlib.sha1,
    ).hexdigest().lower()

    return hmac.compare_digest(
        expected,
        received,
    )


def build_bitlabs_offerwall_url(
    user_id,
    display_mode: str = "all",
    theme: str | None = None,
) -> str:
    """
    Build the BitLabs Web Offerwall URL for an EasySurf user.
    """

    token = bitlabs_token()

    if not token:
        raise RuntimeError(
            "BITLABS_API_TOKEN is not configured"
        )

    uid = str(user_id).strip()

    if not uid:
        raise ValueError(
            "BitLabs uid cannot be empty"
        )

    if len(uid) > 255:
        raise ValueError(
            "BitLabs uid is too long"
        )

    params = {
        "uid": uid,
        "token": token,
        "display_mode": display_mode or "all",
        "sdk": "IFRAME",
    }

    if theme in {"LIGHT", "DARK"}:
        params["theme"] = theme

    return (
        BITLABS_WEB_BASE
        + "?"
        + urlencode(params)
    )


def _bitlabs_get(
    path: str,
    user_id,
    params: dict | None = None,
):
    """
    Perform an authenticated BitLabs user-based API request.
    """

    import json

    token = bitlabs_token()

    if not token:
        raise RuntimeError(
            "BITLABS_API_TOKEN is not configured"
        )

    uid = str(user_id).strip()

    if not uid:
        raise ValueError(
            "BitLabs uid cannot be empty"
        )

    url = (
        BITLABS_API_BASE.rstrip("/")
        + "/"
        + path.lstrip("/")
    )

    query = params or {}

    if query:
        url += "?" + urlencode(query)

    request = Request(
        url,
        headers={
            "X-Api-Token": token,
            "X-User-Id": uid,
            "Accept": "application/json",
        },
        method="GET",
    )

    try:
        with urlopen(request, timeout=15) as response:
            body = response.read().decode("utf-8")
            return json.loads(body)

    except HTTPError as exc:
        body = exc.read().decode(
            "utf-8",
            errors="replace",
        )

        raise RuntimeError(
            f"BitLabs API HTTP {exc.code}: {body[:1000]}"
        ) from exc

    except URLError as exc:
        raise RuntimeError(
            f"BitLabs API connection error: {exc}"
        ) from exc


def get_bitlabs_offers(
    user_id,
    limit: int | None = None,
):
    """
    Return user-specific BitLabs offers.
    """

    params = {}

    if limit is not None:
        params["limit"] = int(limit)

    return _bitlabs_get(
        "/v2/client/offers",
        user_id,
        params,
    )


def get_bitlabs_surveys(
    user_id,
    limit: int | None = None,
):
    """
    Return user-specific BitLabs surveys.
    """

    params = {}

    if limit is not None:
        params["limit"] = int(limit)

    return _bitlabs_get(
        "/v2/client/surveys",
        user_id,
        params,
    )


def ensure_bitlabs_postbacks_table():
    """
    Create the BitLabs callback storage table if it does not exist.

    This table is separate from offerwall_postbacks because
    offerwall_postbacks belongs to the existing Offerwall.GG
    integration.
    """

    c = db()

    try:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS bitlabs_postbacks (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL,
                transaction_id TEXT NOT NULL,
                value_currency TEXT,
                value_usd TEXT,
                reward INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                callback_hash TEXT NOT NULL,
                raw_url TEXT,
                reference_id TEXT,
                created_at BIGINT NOT NULL
            )
            """
        )

        c.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
            ux_bitlabs_postbacks_hash
            ON bitlabs_postbacks(callback_hash)
            """
        )

        c.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_bitlabs_postbacks_user
            ON bitlabs_postbacks(user_id,created_at)
            """
        )

        c.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_bitlabs_postbacks_transaction
            ON bitlabs_postbacks(transaction_id)
            """
        )

        c.commit()

    finally:
        c.close()


def _credit_user(
    c,
    user_id,
    reward,
    kind,
    description,
):
    if reward <= 0:
        raise ValueError(
            "Reward must be greater than zero"
        )

    updated = c.execute(
        """
        UPDATE users
        SET balance=balance+?
        WHERE id=?
        """,
        (
            int(reward),
            int(user_id),
        ),
    ).rowcount

    if updated != 1:
        raise ValueError(
            "User not found"
        )

    c.execute(
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
            int(user_id),
            int(reward),
            kind,
            description,
            now(),
        ),
    )


def process_bitlabs_callback(
    user_id,
    transaction_id,
    value_currency,
    value_usd,
    callback_hash,
    raw_url=None,
    reference_id=None,
):
    """
    Process one BitLabs reward callback.

    Positive callbacks:
        - credit the EasySurf user
        - create a transaction
        - create an activity record

    Duplicate callbacks:
        - ignored safely

    Zero/negative callbacks:
        - recorded as reconciliation events
        - no automatic balance deduction is performed

    Negative reconciliation is deliberately kept separate so that
    a provider reconciliation cannot unexpectedly push a user
    balance below zero or remove already-spent funds.
    """

    ensure_bitlabs_postbacks_table()

    uid = str(user_id).strip()
    tx = str(transaction_id).strip()
    cb_hash = str(callback_hash).strip().lower()

    if not uid:
        raise ValueError(
            "BitLabs user id is empty"
        )

    if not tx:
        raise ValueError(
            "BitLabs transaction id is empty"
        )

    if not cb_hash:
        raise ValueError(
            "BitLabs callback hash is empty"
        )

    try:
        user_id_int = int(uid)
    except ValueError as exc:
        raise ValueError(
            "BitLabs user id must be an integer"
        ) from exc

    reward = bitlabs_usd_to_reward(value_usd)

    c = db()

    try:
        c.execute("BEGIN")

        existing = c.execute(
            """
            SELECT
                id,
                status,
                reward
            FROM bitlabs_postbacks
            WHERE callback_hash=?
            LIMIT 1
            """,
            (cb_hash,),
        ).fetchone()

        if existing:
            c.rollback()

            return {
                "ok": True,
                "status": "duplicate",
                "reward": int(existing["reward"]),
                "postback_id": int(existing["id"]),
            }

        user = c.execute(
            """
            SELECT
                id,
                email
            FROM users
            WHERE id=?
            LIMIT 1
            """,
            (user_id_int,),
        ).fetchone()

        if not user:
            c.rollback()

            return {
                "ok": False,
                "status": "user_not_found",
                "message": "EasySurf user was not found.",
            }

        if reward > 0:
            _credit_user(
                c,
                user_id_int,
                reward,
                "bitlabs_reward",
                "BitLabs reward",
            )

            status = "credited"

        elif reward < 0:
            status = "reconciliation"

        else:
            status = "zero"

        c.execute(
            """
            INSERT INTO bitlabs_postbacks(
                user_id,
                transaction_id,
                value_currency,
                value_usd,
                reward,
                status,
                callback_hash,
                raw_url,
                reference_id,
                created_at
            )
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                user_id_int,
                tx,
                str(value_currency or ""),
                str(value_usd or ""),
                reward,
                status,
                cb_hash,
                raw_url,
                str(reference_id or ""),
                now(),
            ),
        )

        if reward > 0:
            c.execute(
                """
                INSERT INTO activity_log(
                    user_id,
                    activity_type,
                    title,
                    amount,
                    status,
                    reference_id,
                    created_at
                )
                VALUES(?,?,?,?,?,?,?)
                """,
                (
                    user_id_int,
                    "bitlabs_reward",
                    "BitLabs reward",
                    reward,
                    "completed",
                    None,
                    now(),
                ),
            )

        c.commit()

        return {
            "ok": True,
            "status": status,
            "reward": reward,
            "transaction_id": tx,
            "user_id": user_id_int,
        }

    except Exception:
        c.rollback()
        raise

    finally:
        c.close()


# ============================================================
# GENERAL PROVIDER / INVENTORY FUNCTIONS
# ============================================================


def db_connection():
    """
    Compatibility alias.

    Existing code may use db() directly, so the public db()
    function remains available through the imported pg_compat db.
    """
    return db()


def now():
    return int(time.time())


def _active_clause():
    return "status='active'"


def get_apps(limit=100):
    c = db()

    try:
        return c.execute(
            """
            SELECT
                a.*,
                p.name AS provider_name,
                p.provider_type AS provider_type
            FROM apps a
            LEFT JOIN providers p ON p.id=a.provider_id
            WHERE a.status='active'
            ORDER BY a.id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()

    finally:
        c.close()


def get_offers(limit=100):
    c = db()

    try:
        ts = now()

        return c.execute(
            """
            SELECT
                o.*,
                p.name AS provider_name,
                p.provider_type AS provider_type
            FROM offers o
            LEFT JOIN providers p ON p.id=o.provider_id
            WHERE o.status='active'
              AND (
                    o.expires_at IS NULL
                    OR o.expires_at=0
                    OR o.expires_at>?
              )
            ORDER BY o.id DESC
            LIMIT ?
            """,
            (
                ts,
                int(limit),
            ),
        ).fetchall()

    finally:
        c.close()


def get_surveys(limit=100):
    c = db()

    try:
        ts = now()

        return c.execute(
            """
            SELECT
                s.*,
                p.name AS provider_name,
                p.provider_type AS provider_type
            FROM surveys s
            LEFT JOIN providers p ON p.id=s.provider_id
            WHERE s.status='active'
              AND (
                    s.expires_at IS NULL
                    OR s.expires_at=0
                    OR s.expires_at>?
              )
            ORDER BY s.id DESC
            LIMIT ?
            """,
            (
                ts,
                int(limit),
            ),
        ).fetchall()

    finally:
        c.close()


def get_games(limit=100):
    c = db()

    try:
        return c.execute(
            """
            SELECT
                g.*,
                p.name AS provider_name,
                p.provider_type AS provider_type
            FROM games g
            LEFT JOIN providers p ON p.id=g.provider_id
            WHERE g.status='active'
            ORDER BY g.id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()

    finally:
        c.close()


def get_inventory_counts():
    c = db()

    try:
        ts = now()

        apps = c.execute(
            """
            SELECT COUNT(*)
            FROM apps
            WHERE status='active'
            """
        ).fetchone()[0]

        offers = c.execute(
            """
            SELECT COUNT(*)
            FROM offers
            WHERE status='active'
              AND (
                    expires_at IS NULL
                    OR expires_at=0
                    OR expires_at>?
              )
            """,
            (ts,),
        ).fetchone()[0]

        surveys = c.execute(
            """
            SELECT COUNT(*)
            FROM surveys
            WHERE status='active'
              AND (
                    expires_at IS NULL
                    OR expires_at=0
                    OR expires_at>?
              )
            """,
            (ts,),
        ).fetchone()[0]

        games = c.execute(
            """
            SELECT COUNT(*)
            FROM games
            WHERE status='active'
            """
        ).fetchone()[0]

        return {
            "apps": apps,
            "offers": offers,
            "surveys": surveys,
            "games": games,
        }

    finally:
        c.close()


def _provider_is_active(
    c,
    provider_id,
):
    if provider_id is None:
        return True

    row = c.execute(
        """
        SELECT active
        FROM providers
        WHERE id=?
        """,
        (provider_id,),
    ).fetchone()

    if row is None:
        return False

    return bool(row["active"])


def complete_offer(
    user_id,
    offer_id,
    external_id=None,
    provider_amount=None,
):
    c = db()

    try:
        c.execute("BEGIN")

        offer = c.execute(
            """
            SELECT *
            FROM offers
            WHERE id=?
              AND status='active'
            """,
            (offer_id,),
        ).fetchone()

        if not offer:
            c.rollback()

            return {
                "ok": False,
                "status": "not_found",
                "message": "Offer is not available.",
            }

        if not _provider_is_active(
            c,
            offer["provider_id"],
        ):
            c.rollback()

            return {
                "ok": False,
                "status": "provider_inactive",
                "message": "Offer provider is not active.",
            }

        if offer["expires_at"]:
            if int(offer["expires_at"]) <= now():
                c.rollback()

                return {
                    "ok": False,
                    "status": "expired",
                    "message": "Offer has expired.",
                }

        duplicate = c.execute(
            """
            SELECT id
            FROM offer_completions
            WHERE user_id=?
              AND offer_id=?
              AND status IN (
                    'pending',
                    'approved',
                    'completed'
              )
            LIMIT 1
            """,
            (
                user_id,
                offer_id,
            ),
        ).fetchone()

        if duplicate:
            c.rollback()

            return {
                "ok": False,
                "status": "duplicate",
                "message": (
                    "This offer has already been "
                    "started or completed."
                ),
            }

        reward = int(offer["reward"])

        c.execute(
            """
            INSERT INTO offer_completions(
                user_id,
                offer_id,
                external_id,
                status,
                reward,
                provider_amount,
                created_at,
                updated_at
            )
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                user_id,
                offer_id,
                external_id,
                "completed",
                reward,
                (
                    provider_amount
                    if provider_amount is not None
                    else 0
                ),
                now(),
                now(),
            ),
        )

        _credit_user(
            c,
            user_id,
            reward,
            "offer_reward",
            offer["title"],
        )

        c.commit()

        return {
            "ok": True,
            "status": "completed",
            "reward": reward,
            "offer_id": offer_id,
        }

    except Exception:
        c.rollback()
        raise

    finally:
        c.close()


def complete_survey(
    user_id,
    survey_id,
    external_id=None,
    provider_amount=None,
):
    c = db()

    try:
        c.execute("BEGIN")

        survey = c.execute(
            """
            SELECT *
            FROM surveys
            WHERE id=?
              AND status='active'
            """,
            (survey_id,),
        ).fetchone()

        if not survey:
            c.rollback()

            return {
                "ok": False,
                "status": "not_found",
                "message": "Survey is not available.",
            }

        if not _provider_is_active(
            c,
            survey["provider_id"],
        ):
            c.rollback()

            return {
                "ok": False,
                "status": "provider_inactive",
                "message": "Survey provider is not active.",
            }

        if survey["expires_at"]:
            if int(survey["expires_at"]) <= now():
                c.rollback()

                return {
                    "ok": False,
                    "status": "expired",
                    "message": "Survey has expired.",
                }

        duplicate = c.execute(
            """
            SELECT id
            FROM survey_completions
            WHERE user_id=?
              AND survey_id=?
              AND status IN (
                    'pending',
                    'approved',
                    'completed'
              )
            LIMIT 1
            """,
            (
                user_id,
                survey_id,
            ),
        ).fetchone()

        if duplicate:
            c.rollback()

            return {
                "ok": False,
                "status": "duplicate",
                "message": (
                    "This survey has already been "
                    "started or completed."
                ),
            }

        reward = int(survey["reward"])

        c.execute(
            """
            INSERT INTO survey_completions(
                user_id,
                survey_id,
                external_id,
                status,
                reward,
                provider_amount,
                created_at,
                updated_at
            )
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                user_id,
                survey_id,
                external_id,
                "completed",
                reward,
                (
                    provider_amount
                    if provider_amount is not None
                    else 0
                ),
                now(),
                now(),
            ),
        )

        _credit_user(
            c,
            user_id,
            reward,
            "survey_reward",
            survey["title"],
        )

        c.commit()

        return {
            "ok": True,
            "status": "completed",
            "reward": reward,
            "survey_id": survey_id,
        }

    except Exception:
        c.rollback()
        raise

    finally:
        c.close()


def provider_status():
    c = db()

    try:
        rows = c.execute(
            """
            SELECT
                id,
                name,
                provider_type,
                active,
                created_at
            FROM providers
            ORDER BY id
            """
        ).fetchall()

        return [
            dict(row)
            for row in rows
        ]

    finally:
        c.close()