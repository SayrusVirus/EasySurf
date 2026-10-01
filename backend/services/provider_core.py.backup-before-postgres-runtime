from pathlib import Path
import sqlite3
import time


from services.db_config import DB_PATH


def db():
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA busy_timeout=10000")
    return c


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
              AND (o.expires_at IS NULL OR o.expires_at=0 OR o.expires_at>?)
            ORDER BY o.id DESC
            LIMIT ?
            """,
            (ts, int(limit)),
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
              AND (s.expires_at IS NULL OR s.expires_at=0 OR s.expires_at>?)
            ORDER BY s.id DESC
            LIMIT ?
            """,
            (ts, int(limit)),
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
            "SELECT COUNT(*) FROM apps WHERE status='active'"
        ).fetchone()[0]

        offers = c.execute(
            """
            SELECT COUNT(*)
            FROM offers
            WHERE status='active'
              AND (expires_at IS NULL OR expires_at=0 OR expires_at>?)
            """,
            (ts,),
        ).fetchone()[0]

        surveys = c.execute(
            """
            SELECT COUNT(*)
            FROM surveys
            WHERE status='active'
              AND (expires_at IS NULL OR expires_at=0 OR expires_at>?)
            """,
            (ts,),
        ).fetchone()[0]

        games = c.execute(
            "SELECT COUNT(*) FROM games WHERE status='active'"
        ).fetchone()[0]

        return {
            "apps": apps,
            "offers": offers,
            "surveys": surveys,
            "games": games,
        }
    finally:
        c.close()


def _provider_is_active(c, provider_id):
    if provider_id is None:
        return True

    row = c.execute(
        "SELECT active FROM providers WHERE id=?",
        (provider_id,),
    ).fetchone()

    if row is None:
        return False

    return bool(row["active"])


def _credit_user(c, user_id, reward, kind, description):
    if reward <= 0:
        raise ValueError("Reward must be greater than zero")

    updated = c.execute(
        """
        UPDATE users
        SET balance=balance+?
        WHERE id=?
        """,
        (reward, user_id),
    ).rowcount

    if updated != 1:
        raise ValueError("User not found")

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
            user_id,
            reward,
            kind,
            description,
            now(),
        ),
    )


def complete_offer(
    user_id,
    offer_id,
    external_id=None,
    provider_amount=None,
):
    c = db()

    try:
        c.execute("BEGIN IMMEDIATE")

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

        if not _provider_is_active(c, offer["provider_id"]):
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
              AND status IN ('pending','approved','completed')
            LIMIT 1
            """,
            (user_id, offer_id),
        ).fetchone()

        if duplicate:
            c.rollback()
            return {
                "ok": False,
                "status": "duplicate",
                "message": "This offer has already been started or completed.",
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
                provider_amount if provider_amount is not None else 0,
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
        c.execute("BEGIN IMMEDIATE")

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

        if not _provider_is_active(c, survey["provider_id"]):
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
              AND status IN ('pending','approved','completed')
            LIMIT 1
            """,
            (user_id, survey_id),
        ).fetchone()

        if duplicate:
            c.rollback()
            return {
                "ok": False,
                "status": "duplicate",
                "message": "This survey has already been started or completed.",
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
                provider_amount if provider_amount is not None else 0,
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

        return [dict(r) for r in rows]

    finally:
        c.close()
