from __future__ import annotations

import html
import secrets
import time
from urllib.parse import quote

from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from services.pg_compat import db
from services.auth import hash_password


router = APIRouter()


# ---------------------------------------------------------------------------
# EasySurf administrative roles
# ---------------------------------------------------------------------------

OWNER_EMAIL = "dilmurod2022@gmail.com"


def esc(value) -> str:
    return html.escape("" if value is None else str(value))


def money(value) -> str:
    try:
        return f"${int(value or 0) / 1000:.3f}"
    except Exception:
        return "$0.000"


def now() -> int:
    return int(time.time())


def is_owner(user) -> bool:
    if not user:
        return False

    try:
        return str(user["email"] or "").strip().lower() == OWNER_EMAIL
    except Exception:
        return False


def role_name(user) -> str:
    if not user:
        return "user"

    if is_owner(user):
        return "OWNER"

    try:
        if int(user["is_admin"] or 0):
            return "ADMIN"
    except Exception:
        pass

    return "user"


def current_admin(request: Request):
    """
    Read the logged-in user from the existing EasySurf session.

    The normal EasySurf session uses user_id. A few fallback keys
    are accepted so this module remains compatible with older sessions.
    """
    uid = (
        request.session.get("user_id")
        or request.session.get("uid")
        or request.session.get("user")
    )

    if not uid:
        return None

    try:
        uid = int(uid)
    except Exception:
        return None

    c = db()

    try:
        row = c.execute(
            "SELECT * FROM users WHERE id=? LIMIT 1",
            (uid,),
        ).fetchone()
    finally:
        c.close()

    if not row:
        return None

    if not int(row["is_admin"] or 0):
        return None

    return row


def require_admin(request: Request):
    u = current_admin(request)

    if not u:
        return None, RedirectResponse("/login", status_code=303)

    return u, None


def csrf_token(request: Request) -> str:
    token = request.session.get("admin_csrf")

    if not token:
        token = secrets.token_urlsafe(32)
        request.session["admin_csrf"] = token

    return token


def check_csrf(request: Request, token: str) -> bool:
    expected = request.session.get("admin_csrf")
    return bool(
        expected
        and token
        and secrets.compare_digest(str(expected), str(token))
    )


def page(title: str, body: str, request: Request) -> HTMLResponse:
    u = current_admin(request)
    token = csrf_token(request)

    email = esc(u["email"] if u else "")
    role = role_name(u)

    if role == "OWNER":
        role_badge = (
            '<span style="background:#f59e0b;color:#111827;'
            'padding:4px 9px;border-radius:999px;font-weight:700;'
            'font-size:12px">OWNER</span>'
        )
    elif role == "ADMIN":
        role_badge = (
            '<span style="background:#2563eb;color:#fff;'
            'padding:4px 9px;border-radius:999px;font-weight:700;'
            'font-size:12px">ADMIN</span>'
        )
    else:
        role_badge = ""

    html_page = f"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} - EasySurf Admin</title>
<style>
*{{box-sizing:border-box}}
body{{margin:0;background:#f4f6f8;color:#18202a;font-family:Arial,Helvetica,sans-serif}}
a{{color:#1769aa;text-decoration:none}}
a:hover{{text-decoration:underline}}
.top{{background:#111827;color:#fff;padding:18px 24px;display:flex;justify-content:space-between;align-items:center;gap:20px}}
.top strong{{font-size:21px}}
.top span{{font-size:14px;opacity:.9}}
.wrap{{max-width:1500px;margin:0 auto;padding:22px}}
.nav{{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px}}
.nav a{{background:#fff;border:1px solid #d7dce2;padding:10px 13px;border-radius:8px;font-size:14px}}
.nav a:hover{{background:#f8fafc;text-decoration:none}}
.card{{background:#fff;border:1px solid #e0e4e8;border-radius:12px;padding:18px;margin-bottom:18px;box-shadow:0 1px 2px rgba(0,0,0,.04)}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}}
.stat{{background:#fff;border:1px solid #e0e4e8;border-radius:12px;padding:18px}}
.stat b{{display:block;font-size:27px;margin-top:8px}}
table{{width:100%;border-collapse:collapse;font-size:14px}}
th,td{{padding:10px 8px;border-bottom:1px solid #e5e7eb;text-align:left;vertical-align:top}}
th{{background:#f8fafc}}
input,select,textarea{{width:100%;padding:9px 10px;border:1px solid #cbd5e1;border-radius:7px;margin:5px 0 12px}}
textarea{{min-height:90px;resize:vertical}}
button{{border:0;border-radius:7px;padding:9px 13px;background:#2563eb;color:#fff;cursor:pointer}}
button:hover{{opacity:.9}}
button.danger{{background:#dc2626}}
button.secondary{{background:#64748b}}
.inline{{display:inline-block;margin:0 4px 4px 0}}
.badge{{display:inline-block;padding:4px 8px;border-radius:999px;background:#e5e7eb;font-size:12px}}
.ok{{background:#dcfce7;color:#166534}}
.warn{{background:#fef3c7;color:#92400e}}
.bad{{background:#fee2e2;color:#991b1b}}
.formgrid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}}
.small{{font-size:12px;color:#64748b}}
h1{{margin-top:0}}
h2{{margin-top:0}}
.money{{font-weight:700}}
.actions{{white-space:nowrap}}
.role-owner{{color:#92400e;font-weight:700}}
.role-admin{{color:#1d4ed8;font-weight:700}}
.protected{{background:#fffbeb;border:1px solid #f59e0b;padding:12px;border-radius:8px}}
</style>
</head>
<body>
<div class="top">
  <strong>EasySurf Admin</strong>
  <span>
    {email}
    &nbsp;|&nbsp;
    {role_badge}
    &nbsp;|&nbsp;
    <a href="/dashboard" style="color:#fff">User site</a>
  </span>
</div>

<div class="wrap">

<div class="nav">
<a href="/admin">Dashboard</a>
<a href="/admin/users">Users</a>
<a href="/admin/balances">Balances</a>
<a href="/admin/payouts">Payouts</a>
<a href="/admin/activity">Activity</a>
<a href="/admin/tasks">Tasks</a>
<a href="/admin/offers">Offers</a>
<a href="/admin/surveys">Surveys</a>
<a href="/admin/games">Games</a>
<a href="/admin/apps">Apps</a>
<a href="/admin/providers">Providers</a>
<a href="/admin/fraud">Fraud</a>
<a href="/admin/postbacks">Postbacks</a>
<a href="/admin/rewards">Rewards</a>
<a href="/admin/statistics">Statistics</a>
</div>

{body}

</div>
</body>
</html>
"""

    return HTMLResponse(html_page)


def redirect_admin(path: str = "/admin"):
    return RedirectResponse(path, status_code=303)


@router.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    c = db()

    try:
        users = c.execute(
            "SELECT COUNT(*) AS n FROM users"
        ).fetchone()["n"]

        balance = c.execute(
            "SELECT COALESCE(SUM(balance),0) AS n FROM users"
        ).fetchone()["n"]

        payouts = c.execute(
            "SELECT COUNT(*) AS n FROM payouts WHERE status='pending'"
        ).fetchone()["n"]

        tasks = c.execute(
            "SELECT COUNT(*) AS n FROM tasks WHERE active=1"
        ).fetchone()["n"]

        offers = c.execute(
            "SELECT COUNT(*) AS n FROM offers WHERE status='active'"
        ).fetchone()["n"]

        surveys = c.execute(
            "SELECT COUNT(*) AS n FROM surveys WHERE status='active'"
        ).fetchone()["n"]

        games = c.execute(
            "SELECT COUNT(*) AS n FROM games WHERE status='active'"
        ).fetchone()["n"]

        apps = c.execute(
            "SELECT COUNT(*) AS n FROM apps WHERE status='active'"
        ).fetchone()["n"]

        fraud = c.execute(
            "SELECT COUNT(*) AS n FROM fraud_events WHERE resolved=0"
        ).fetchone()["n"]

        postbacks = c.execute(
            "SELECT COUNT(*) AS n FROM offerwall_postbacks"
        ).fetchone()["n"]

        transactions = c.execute(
            "SELECT COUNT(*) AS n FROM transactions"
        ).fetchone()["n"]

        rewards = c.execute(
            "SELECT COUNT(*) AS n FROM reward_events"
        ).fetchone()["n"]

        admin_count = c.execute(
            "SELECT COUNT(*) AS n FROM users WHERE is_admin=1"
        ).fetchone()["n"]

    finally:
        c.close()

    body = f"""
<h1>Admin Dashboard</h1>

<div class="grid">

<div class="stat">
Users
<b>{users}</b>
</div>

<div class="stat">
Total balances
<b>{money(balance)}</b>
</div>

<div class="stat">
Pending payouts
<b>{payouts}</b>
</div>

<div class="stat">
Active tasks
<b>{tasks}</b>
</div>

<div class="stat">
Active offers
<b>{offers}</b>
</div>

<div class="stat">
Active surveys
<b>{surveys}</b>
</div>

<div class="stat">
Active games
<b>{games}</b>
</div>

<div class="stat">
Active apps
<b>{apps}</b>
</div>

<div class="stat">
Unresolved fraud
<b>{fraud}</b>
</div>

<div class="stat">
Postbacks
<b>{postbacks}</b>
</div>

<div class="stat">
Transactions
<b>{transactions}</b>
</div>

<div class="stat">
Reward events
<b>{rewards}</b>
</div>

<div class="stat">
Administrators
<b>{admin_count}</b>
</div>

</div>

<div class="card">
<h2>Administration</h2>
<p>
Current account:
<b>{esc(u["email"])}</b>
&nbsp;
<span class="badge">{role_name(u)}</span>
</p>

<p>
All administrative actions require an authenticated user with
<b>is_admin=1</b>.
</p>

<p class="small">
Owner account: <b>{esc(OWNER_EMAIL)}</b>.
Only the Owner can change administrator privileges.
</p>

<p class="small">
Existing Supabase data is used directly. No data migration is performed by this panel.
</p>
</div>
"""

    return page("Dashboard", body, request)


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, q: str = ""):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    c = db()

    try:
        if q.strip():
            term = "%" + q.strip().lower() + "%"
            rows = c.execute(
                """
                SELECT *
                FROM users
                WHERE LOWER(email) LIKE ?
                   OR LOWER(COALESCE(username,'')) LIKE ?
                   OR LOWER(COALESCE(display_name,'')) LIKE ?
                ORDER BY id DESC
                LIMIT 200
                """,
                (term, term, term),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM users ORDER BY id DESC LIMIT 200"
            ).fetchall()
    finally:
        c.close()

    token = csrf_token(request)

    result = ""

    for x in rows:
        target_role = role_name(x)

        if target_role == "OWNER":
            role_html = '<span class="role-owner">OWNER</span>'
        elif target_role == "ADMIN":
            role_html = '<span class="role-admin">ADMIN</span>'
        else:
            role_html = "user"

        result += f"""
<tr>
<td>{x["id"]}</td>
<td>{esc(x["email"])}</td>
<td>{esc(x["username"])}</td>
<td>{esc(x["display_name"])}</td>
<td class="money">{money(x["balance"])}</td>
<td>{role_html}</td>
<td>{'yes' if int(x["email_verified"] or 0) else 'no'}</td>
<td class="actions">
<a href="/admin/users/{x["id"]}">Open</a>
</td>
</tr>
"""

    body = f"""
<h1>Users</h1>

<div class="card">
<form method="get" action="/admin/users">
<label>Search</label>
<input name="q" value="{esc(q)}" placeholder="Email, username or display name">
<button>Search</button>
</form>
</div>

<div class="card">
<h2>Create user</h2>

<form method="post" action="/admin/users/create">

<input type="hidden" name="csrf_token" value="{esc(token)}">

<div class="formgrid">

<div>
<label>Email</label>
<input name="email" type="email" required>
</div>

<div>
<label>Password</label>
<input name="password" type="password" required minlength="6">
</div>

<div>
<label>Username</label>
<input name="username">
</div>

<div>
<label>Display name</label>
<input name="display_name">
</div>

</div>

<button>Create user</button>

</form>
</div>

<div class="card">
<table>
<tr>
<th>ID</th>
<th>Email</th>
<th>Username</th>
<th>Name</th>
<th>Balance</th>
<th>Role</th>
<th>Verified</th>
<th>Action</th>
</tr>
{result or '<tr><td colspan="8">No users found.</td></tr>'}
</table>
</div>
"""

    return page("Users", body, request)


@router.post("/admin/users/create")
def admin_create_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    username: str = Form(""),
    display_name: str = Form(""),
    csrf_token_value: str = Form("", alias="csrf_token"),
):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    if not check_csrf(request, csrf_token_value):
        return redirect_admin("/admin/users")

    email = email.strip().lower()
    username = username.strip() or None
    display_name = display_name.strip() or None

    if not email or len(password) < 6:
        return redirect_admin("/admin/users")

    c = db()

    try:
        exists = c.execute(
            "SELECT id FROM users WHERE LOWER(email)=? LIMIT 1",
            (email,),
        ).fetchone()

        if exists:
            return redirect_admin("/admin/users")

        c.execute(
            """
            INSERT INTO users(
                email,
                password_hash,
                balance,
                is_admin,
                created_at,
                referral_code,
                referred_by,
                email_verified,
                username,
                display_name,
                avatar,
                language,
                notifications
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                email,
                hash_password(password),
                0,
                0,
                now(),
                None,
                None,
                1,
                username,
                display_name,
                None,
                "en",
                1,
            ),
        )

        c.commit()

    finally:
        c.close()

    return redirect_admin("/admin/users")


@router.get("/admin/users/{user_id}", response_class=HTMLResponse)
def admin_user_detail(request: Request, user_id: int):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    c = db()

    try:
        target = c.execute(
            "SELECT * FROM users WHERE id=?",
            (user_id,),
        ).fetchone()

        if not target:
            return redirect_admin("/admin/users")

        tx = c.execute(
            """
            SELECT *
            FROM transactions
            WHERE user_id=?
            ORDER BY id DESC
            LIMIT 50
            """,
            (user_id,),
        ).fetchall()

        activity = c.execute(
            """
            SELECT *
            FROM activity_log
            WHERE user_id=?
            ORDER BY id DESC
            LIMIT 50
            """,
            (user_id,),
        ).fetchall()

        payouts = c.execute(
            """
            SELECT *
            FROM payouts
            WHERE user_id=?
            ORDER BY id DESC
            LIMIT 30
            """,
            (user_id,),
        ).fetchall()

        fraud = c.execute(
            """
            SELECT *
            FROM fraud_events
            WHERE user_id=?
            ORDER BY id DESC
            LIMIT 30
            """,
            (user_id,),
        ).fetchall()

    finally:
        c.close()

    token = csrf_token(request)

    target_is_owner = is_owner(target)
    actor_is_owner = is_owner(u)

    tx_rows = "".join(
        f"""
<tr>
<td>{x["id"]}</td>
<td>{esc(x["kind"])}</td>
<td class="money">{money(x["amount"])}</td>
<td>{esc(x["description"])}</td>
<td>{x["created_at"]}</td>
</tr>
"""
        for x in tx
    )

    activity_rows = "".join(
        f"""
<tr>
<td>{x["id"]}</td>
<td>{esc(x["activity_type"])}</td>
<td>{esc(x["title"])}</td>
<td>{money(x["amount"])}</td>
<td>{esc(x["status"])}</td>
<td>{x["created_at"]}</td>
</tr>
"""
        for x in activity
    )

    payout_rows = "".join(
        f"""
<tr>
<td>{x["id"]}</td>
<td>{money(x["amount"])}</td>
<td>{esc(x["method"])}</td>
<td>{esc(x["account"])}</td>
<td>{esc(x["status"])}</td>
<td>{x["created_at"]}</td>
</tr>
"""
        for x in payouts
    )

    fraud_rows = "".join(
        f"""
<tr>
<td>{x["id"]}</td>
<td>{esc(x["event_type"])}</td>
<td>{esc(x["severity"])}</td>
<td>{esc(x["details"])}</td>
<td>{'resolved' if x["resolved"] else 'open'}</td>
</tr>
"""
        for x in fraud
    )

    if target_is_owner:
        role_section = """
<div class="protected">
<b>OWNER ACCOUNT PROTECTED</b>
<p class="small">
This account is the EasySurf Owner. Its Owner identity and administrator
status cannot be removed or changed through the admin panel.
</p>
</div>
"""
        admin_field = """
<div>
<label>Role</label>
<input value="OWNER" disabled>
</div>
"""
        email_field = f"""
<div>
<label>Email</label>
<input value="{esc(target["email"])}" disabled>
</div>
"""
    elif not actor_is_owner:
        role_section = """
<div class="protected">
<b>ADMIN PRIVILEGES</b>
<p class="small">
Only the Owner can change administrator privileges. Your current
administrator account cannot promote or demote other administrators.
</p>
</div>
"""
        admin_field = f"""
<div>
<label>Role</label>
<input value="{'ADMIN' if int(target["is_admin"] or 0) else 'USER'}" disabled>
<input type="hidden" name="is_admin" value="{1 if int(target["is_admin"] or 0) else 0}">
</div>
"""
        email_field = f"""
<div>
<label>Email</label>
<input name="email" type="email" value="{esc(target["email"])}" required>
</div>
"""
    else:
        role_section = """
<div class="small">
Owner can manage administrator privileges.
</div>
"""
        admin_field = f"""
<div>
<label>Role</label>
<select name="is_admin">
<option value="0" {'selected' if not int(target["is_admin"] or 0) else ""}>User</option>
<option value="1" {'selected' if int(target["is_admin"] or 0) else ""}>Admin</option>
</select>
</div>
"""
        email_field = f"""
<div>
<label>Email</label>
<input name="email" type="email" value="{esc(target["email"])}" required>
</div>
"""

    body = f"""
<h1>User #{target["id"]}</h1>

<div class="card">

<p>
Current role:
<b>{role_name(target)}</b>
</p>

{role_section}

<form method="post" action="/admin/users/{user_id}/update">

<input type="hidden" name="csrf_token" value="{esc(token)}">

<div class="formgrid">

{email_field}

<div>
<label>Username</label>
<input name="username" value="{esc(target["username"])}">
</div>

<div>
<label>Display name</label>
<input name="display_name" value="{esc(target["display_name"])}">
</div>

<div>
<label>Language</label>
<select name="language">
<option value="en" {'selected' if target["language"] == "en" else ""}>English</option>
<option value="ru" {'selected' if target["language"] == "ru" else ""}>Русский</option>
<option value="it" {'selected' if target["language"] == "it" else ""}>Italiano</option>
<option value="de" {'selected' if target["language"] == "de" else ""}>Deutsch</option>
<option value="ja" {'selected' if target["language"] == "ja" else ""}>日本語</option>
<option value="tr" {'selected' if target["language"] == "tr" else ""}>Türkçe</option>
</select>
</div>

<div>
<label>Notifications</label>
<select name="notifications">
<option value="1" {'selected' if int(target["notifications"] or 0) else ""}>Enabled</option>
<option value="0" {'selected' if not int(target["notifications"] or 0) else ""}>Disabled</option>
</select>
</div>

<div>
<label>Email verified</label>
<select name="email_verified">
<option value="1" {'selected' if int(target["email_verified"] or 0) else ""}>Yes</option>
<option value="0" {'selected' if not int(target["email_verified"] or 0) else ""}>No</option>
</select>
</div>

{admin_field}

</div>

<button>Save user</button>

</form>
</div>

<div class="card">
<h2>Balance adjustment</h2>

<form method="post" action="/admin/users/{user_id}/balance">
<input type="hidden" name="csrf_token" value="{esc(token)}">

<label>Amount in thousandths USD</label>
<input name="amount" type="number" required placeholder="100 = $0.100">

<label>Description</label>
<input name="description" maxlength="250" required>

<button>Apply balance adjustment</button>
</form>

<p class="small">
Positive amount adds balance. Negative amount subtracts balance.
</p>
</div>

<div class="card">
<h2>Current balance</h2>
<p class="money">{money(target["balance"])}</p>
</div>

<div class="card">
<h2>Transactions</h2>
<table>
<tr><th>ID</th><th>Kind</th><th>Amount</th><th>Description</th><th>Time</th></tr>
{tx_rows or '<tr><td colspan="5">No transactions.</td></tr>'}
</table>
</div>

<div class="card">
<h2>Activity</h2>
<table>
<tr><th>ID</th><th>Type</th><th>Title</th><th>Amount</th><th>Status</th><th>Time</th></tr>
{activity_rows or '<tr><td colspan="6">No activity.</td></tr>'}
</table>
</div>

<div class="card">
<h2>Payouts</h2>
<table>
<tr><th>ID</th><th>Amount</th><th>Method</th><th>Account</th><th>Status</th><th>Time</th></tr>
{payout_rows or '<tr><td colspan="6">No payouts.</td></tr>'}
</table>
</div>

<div class="card">
<h2>Fraud events</h2>
<table>
<tr><th>ID</th><th>Type</th><th>Severity</th><th>Details</th><th>Status</th></tr>
{fraud_rows or '<tr><td colspan="5">No fraud events.</td></tr>'}
</table>
</div>
"""

    return page("User", body, request)


@router.post("/admin/users/{user_id}/update")
def admin_update_user(
    request: Request,
    user_id: int,
    email: str = Form(...),
    username: str = Form(""),
    display_name: str = Form(""),
    language: str = Form("en"),
    notifications: int = Form(1),
    email_verified: int = Form(1),
    is_admin: int = Form(0),
    csrf_token_value: str = Form("", alias="csrf_token"),
):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    if not check_csrf(request, csrf_token_value):
        return redirect_admin(f"/admin/users/{user_id}")

    language = language if language in ("en", "ru", "it", "de", "ja", "tr") else "en"
    notifications = 1 if notifications else 0
    email_verified = 1 if email_verified else 0
    requested_is_admin = 1 if is_admin else 0

    c = db()

    try:
        target = c.execute(
            "SELECT * FROM users WHERE id=? LIMIT 1",
            (user_id,),
        ).fetchone()

        if not target:
            return redirect_admin("/admin/users")

        actor_is_owner = is_owner(u)
        target_is_owner = is_owner(target)

        # Owner cannot be modified into another role.
        if target_is_owner:
            final_email = OWNER_EMAIL
            final_is_admin = 1

        # Normal Admin cannot change administrator privileges.
        elif not actor_is_owner:
            final_email = email.strip().lower()
            final_is_admin = 1 if int(target["is_admin"] or 0) else 0

        # Owner can manage Admin privileges.
        else:
            final_email = email.strip().lower()
            final_is_admin = requested_is_admin

        if not final_email:
            return redirect_admin(f"/admin/users/{user_id}")

        duplicate = c.execute(
            """
            SELECT id
            FROM users
            WHERE LOWER(email)=?
              AND id<>?
            LIMIT 1
            """,
            (final_email, user_id),
        ).fetchone()

        if duplicate:
            return redirect_admin(f"/admin/users/{user_id}")

        c.execute(
            """
            UPDATE users
            SET email=?,
                username=?,
                display_name=?,
                language=?,
                notifications=?,
                email_verified=?,
                is_admin=?
            WHERE id=?
            """,
            (
                final_email,
                username.strip() or None,
                display_name.strip() or None,
                language,
                notifications,
                email_verified,
                final_is_admin,
                user_id,
            ),
        )

        c.commit()

    finally:
        c.close()

    return redirect_admin(f"/admin/users/{user_id}")


@router.post("/admin/users/{user_id}/balance")
def admin_adjust_balance(
    request: Request,
    user_id: int,
    amount: int = Form(...),
    description: str = Form(...),
    csrf_token_value: str = Form("", alias="csrf_token"),
):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    if not check_csrf(request, csrf_token_value):
        return redirect_admin(f"/admin/users/{user_id}")

    description = description.strip()

    if not description or amount == 0:
        return redirect_admin(f"/admin/users/{user_id}")

    c = db()

    try:
        target = c.execute(
            "SELECT balance FROM users WHERE id=?",
            (user_id,),
        ).fetchone()

        if not target:
            return redirect_admin("/admin/users")

        new_balance = int(target["balance"] or 0) + int(amount)

        if new_balance < 0:
            return redirect_admin(f"/admin/users/{user_id}")

        c.execute(
            "UPDATE users SET balance=? WHERE id=?",
            (new_balance, user_id),
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
                user_id,
                amount,
                "admin_adjustment",
                description,
                now(),
            ),
        )

        c.commit()

    finally:
        c.close()

    return redirect_admin(f"/admin/users/{user_id}")


@router.get("/admin/balances", response_class=HTMLResponse)
def admin_balances(request: Request):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    c = db()

    try:
        rows = c.execute(
            """
            SELECT t.*, u.email
            FROM transactions t
            JOIN users u ON u.id=t.user_id
            ORDER BY t.id DESC
            LIMIT 300
            """
        ).fetchall()
    finally:
        c.close()

    body_rows = "".join(
        f"""
<tr>
<td>{x["id"]}</td>
<td><a href="/admin/users/{x["user_id"]}">#{x["user_id"]}</a></td>
<td>{esc(x["email"])}</td>
<td>{esc(x["kind"])}</td>
<td class="money">{money(x["amount"])}</td>
<td>{esc(x["description"])}</td>
<td>{x["created_at"]}</td>
</tr>
"""
        for x in rows
    )

    body = f"""
<h1>Balances / Transactions</h1>
<div class="card">
<table>
<tr>
<th>ID</th>
<th>User</th>
<th>Email</th>
<th>Kind</th>
<th>Amount</th>
<th>Description</th>
<th>Time</th>
</tr>
{body_rows or '<tr><td colspan="7">No transactions.</td></tr>'}
</table>
</div>
"""

    return page("Balances", body, request)


@router.get("/admin/payouts", response_class=HTMLResponse)
def admin_payouts(request: Request):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    c = db()

    try:
        rows = c.execute(
            """
            SELECT p.*, u.email
            FROM payouts p
            JOIN users u ON u.id=p.user_id
            ORDER BY p.id DESC
            LIMIT 300
            """
        ).fetchall()
    finally:
        c.close()

    body_rows = "".join(
        f"""
<tr>
<td>{x["id"]}</td>
<td><a href="/admin/users/{x["user_id"]}">#{x["user_id"]}</a></td>
<td>{esc(x["email"])}</td>
<td class="money">{money(x["amount"])}</td>
<td>{esc(x["method"])}</td>
<td>{esc(x["account"])}</td>
<td><span class="badge">{esc(x["status"])}</span></td>
<td>{x["created_at"]}</td>
</tr>
"""
        for x in rows
    )

    body = f"""
<h1>Payouts</h1>
<div class="card">
<p class="small">
Existing payout processing remains unchanged. This page provides the full administrative view.
</p>
<table>
<tr>
<th>ID</th>
<th>User</th>
<th>Email</th>
<th>Amount</th>
<th>Method</th>
<th>Account</th>
<th>Status</th>
<th>Created</th>
</tr>
{body_rows or '<tr><td colspan="8">No payouts.</td></tr>'}
</table>
</div>
"""

    return page("Payouts", body, request)


@router.get("/admin/activity", response_class=HTMLResponse)
def admin_activity(request: Request):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    c = db()

    try:
        rows = c.execute(
            """
            SELECT a.*, u.email
            FROM activity_log a
            JOIN users u ON u.id=a.user_id
            ORDER BY a.id DESC
            LIMIT 500
            """
        ).fetchall()
    finally:
        c.close()

    body_rows = "".join(
        f"""
<tr>
<td>{x["id"]}</td>
<td><a href="/admin/users/{x["user_id"]}">#{x["user_id"]}</a></td>
<td>{esc(x["email"])}</td>
<td>{esc(x["activity_type"])}</td>
<td>{esc(x["title"])}</td>
<td>{money(x["amount"])}</td>
<td>{esc(x["status"])}</td>
<td>{x["created_at"]}</td>
</tr>
"""
        for x in rows
    )

    body = f"""
<h1>User Activity</h1>
<div class="card">
<table>
<tr>
<th>ID</th>
<th>User</th>
<th>Email</th>
<th>Type</th>
<th>Title</th>
<th>Amount</th>
<th>Status</th>
<th>Time</th>
</tr>
{body_rows or '<tr><td colspan="8">No activity.</td></tr>'}
</table>
</div>
"""

    return page("Activity", body, request)


def simple_table_page(
    request: Request,
    title: str,
    table_name: str,
    columns: list[str],
    limit: int = 300,
):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    allowed_tables = {
        "tasks",
        "offers",
        "surveys",
        "games",
        "apps",
        "providers",
        "fraud_events",
        "offerwall_postbacks",
        "reward_events",
        "achievements",
        "user_daily_stats",
    }

    if table_name not in allowed_tables:
        return redirect_admin()

    c = db()

    try:
        rows = c.execute(
            f"SELECT * FROM {table_name} ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        c.close()

    headers = "".join(f"<th>{esc(x)}</th>" for x in columns)

    data = ""

    for row in rows:
        cells = ""

        for column in columns:
            value = row[column]

            if column in (
                "reward",
                "amount",
                "balance",
                "earned",
                "goal",
                "payout_usd",
            ):
                value = money(value)

            cells += f"<td>{esc(value)}</td>"

        data += f"<tr>{cells}</tr>"

    body = f"""
<h1>{esc(title)}</h1>
<div class="card">
<table>
<tr>{headers}</tr>
{data or '<tr><td colspan="' + str(len(columns)) + '">No records.</td></tr>'}
</table>
</div>
"""

    return page(title, body, request)


@router.get("/admin/tasks", response_class=HTMLResponse)
def admin_tasks(request: Request):
    return simple_table_page(
        request,
        "Tasks",
        "tasks",
        [
            "id",
            "title",
            "url",
            "seconds",
            "reward",
            "active",
            "task_type",
            "budget",
            "spent",
            "created_at",
        ],
    )


@router.get("/admin/offers", response_class=HTMLResponse)
def admin_offers(request: Request):
    return simple_table_page(
        request,
        "Offers",
        "offers",
        [
            "id",
            "provider_id",
            "external_id",
            "title",
            "category",
            "reward",
            "status",
            "created_at",
            "expires_at",
        ],
    )


@router.get("/admin/surveys", response_class=HTMLResponse)
def admin_surveys(request: Request):
    return simple_table_page(
        request,
        "Surveys",
        "surveys",
        [
            "id",
            "provider_id",
            "external_id",
            "title",
            "seconds",
            "reward",
            "status",
            "created_at",
            "expires_at",
        ],
    )


@router.get("/admin/games", response_class=HTMLResponse)
def admin_games(request: Request):
    return simple_table_page(
        request,
        "Games",
        "games",
        [
            "id",
            "provider_id",
            "external_id",
            "title",
            "reward",
            "status",
            "created_at",
        ],
    )


@router.get("/admin/apps", response_class=HTMLResponse)
def admin_apps(request: Request):
    return simple_table_page(
        request,
        "Apps",
        "apps",
        [
            "id",
            "provider_id",
            "external_id",
            "title",
            "platform",
            "reward",
            "status",
            "created_at",
        ],
    )


@router.get("/admin/providers", response_class=HTMLResponse)
def admin_providers(request: Request):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    c = db()

    try:
        rows = c.execute(
            """
            SELECT
                id,
                name,
                provider_type,
                postback_url,
                active,
                created_at
            FROM providers
            ORDER BY id DESC
            """
        ).fetchall()
    finally:
        c.close()

    body_rows = "".join(
        f"""
<tr>
<td>{x["id"]}</td>
<td>{esc(x["name"])}</td>
<td>{esc(x["provider_type"])}</td>
<td>{esc(x["postback_url"])}</td>
<td>{'active' if int(x["active"] or 0) else 'inactive'}</td>
<td>{x["created_at"]}</td>
</tr>
"""
        for x in rows
    )

    body = f"""
<h1>Providers</h1>

<div class="card">
<p class="small">
Provider API keys and secrets are intentionally not displayed.
</p>

<table>
<tr>
<th>ID</th>
<th>Name</th>
<th>Type</th>
<th>Postback URL</th>
<th>Status</th>
<th>Created</th>
</tr>
{body_rows or '<tr><td colspan="6">No providers.</td></tr>'}
</table>
</div>
"""

    return page("Providers", body, request)


@router.get("/admin/fraud", response_class=HTMLResponse)
def admin_fraud(request: Request):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    c = db()

    try:
        rows = c.execute(
            """
            SELECT f.*, u.email
            FROM fraud_events f
            JOIN users u ON u.id=f.user_id
            ORDER BY f.id DESC
            LIMIT 500
            """
        ).fetchall()
    finally:
        c.close()

    body_rows = "".join(
        f"""
<tr>
<td>{x["id"]}</td>
<td><a href="/admin/users/{x["user_id"]}">#{x["user_id"]}</a></td>
<td>{esc(x["email"])}</td>
<td>{esc(x["event_type"])}</td>
<td>{esc(x["severity"])}</td>
<td>{esc(x["details"])}</td>
<td>{'resolved' if x["resolved"] else 'OPEN'}</td>
<td>{x["created_at"]}</td>
</tr>
"""
        for x in rows
    )

    body = f"""
<h1>Fraud / Suspicious Activity</h1>
<div class="card">
<table>
<tr>
<th>ID</th>
<th>User</th>
<th>Email</th>
<th>Type</th>
<th>Severity</th>
<th>Details</th>
<th>Status</th>
<th>Created</th>
</tr>
{body_rows or '<tr><td colspan="8">No fraud events.</td></tr>'}
</table>
</div>
"""

    return page("Fraud", body, request)


@router.get("/admin/postbacks", response_class=HTMLResponse)
def admin_postbacks(request: Request):
    return simple_table_page(
        request,
        "Offerwall Postbacks",
        "offerwall_postbacks",
        [
            "id",
            "transaction_id",
            "status",
            "user_id",
            "offer_id",
            "offer_name",
            "goal_id",
            "currency_amount",
            "amount",
            "currency_name",
            "payout_usd",
            "test",
            "provider_timestamp",
            "reversal_of_id",
            "created_at",
            "updated_at",
        ],
        500,
    )


@router.get("/admin/rewards", response_class=HTMLResponse)
def admin_rewards(request: Request):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    c = db()

    try:
        events = c.execute(
            """
            SELECT r.*, u.email
            FROM reward_events r
            JOIN users u ON u.id=r.user_id
            ORDER BY r.id DESC
            LIMIT 300
            """
        ).fetchall()

        achievements = c.execute(
            "SELECT * FROM achievements ORDER BY id DESC"
        ).fetchall()

        daily = c.execute(
            """
            SELECT d.*, u.email
            FROM daily_bonus_claims d
            JOIN users u ON u.id=d.user_id
            ORDER BY d.id DESC
            LIMIT 200
            """
        ).fetchall()
    finally:
        c.close()

    event_rows = "".join(
        f"""
<tr>
<td>{x["id"]}</td>
<td>{esc(x["email"])}</td>
<td>{esc(x["source_type"])}</td>
<td>{esc(x["external_id"])}</td>
<td>{money(x["amount"])}</td>
<td>{esc(x["status"])}</td>
<td>{x["created_at"]}</td>
</tr>
"""
        for x in events
    )

    achievement_rows = "".join(
        f"""
<tr>
<td>{x["id"]}</td>
<td>{esc(x["code"])}</td>
<td>{esc(x["title"])}</td>
<td>{esc(x["description"])}</td>
<td>{money(x["reward"])}</td>
<td>{'active' if x["active"] else 'inactive'}</td>
</tr>
"""
        for x in achievements
    )

    daily_rows = "".join(
        f"""
<tr>
<td>{x["id"]}</td>
<td>{esc(x["email"])}</td>
<td>{esc(x["day"])}</td>
<td>{x["streak_day"]}</td>
<td>{money(x["amount"])}</td>
<td>{x["created_at"]}</td>
</tr>
"""
        for x in daily
    )

    body = f"""
<h1>Rewards</h1>

<div class="card">
<h2>Reward Events</h2>
<table>
<tr>
<th>ID</th>
<th>User</th>
<th>Source</th>
<th>External ID</th>
<th>Amount</th>
<th>Status</th>
<th>Created</th>
</tr>
{event_rows or '<tr><td colspan="7">No reward events.</td></tr>'}
</table>
</div>

<div class="card">
<h2>Achievements</h2>
<table>
<tr>
<th>ID</th>
<th>Code</th>
<th>Title</th>
<th>Description</th>
<th>Reward</th>
<th>Status</th>
</tr>
{achievement_rows or '<tr><td colspan="6">No achievements.</td></tr>'}
</table>
</div>

<div class="card">
<h2>Daily Bonus Claims</h2>
<table>
<tr>
<th>ID</th>
<th>User</th>
<th>Day</th>
<th>Streak</th>
<th>Amount</th>
<th>Created</th>
</tr>
{daily_rows or '<tr><td colspan="6">No daily claims.</td></tr>'}
</table>
</div>
"""

    return page("Rewards", body, request)


@router.get("/admin/statistics", response_class=HTMLResponse)
def admin_statistics(request: Request):
    u, redirect = require_admin(request)

    if redirect:
        return redirect

    c = db()

    try:
        total_users = c.execute(
            "SELECT COUNT(*) AS n FROM users"
        ).fetchone()["n"]

        verified = c.execute(
            "SELECT COUNT(*) AS n FROM users WHERE email_verified=1"
        ).fetchone()["n"]

        admins = c.execute(
            "SELECT COUNT(*) AS n FROM users WHERE is_admin=1"
        ).fetchone()["n"]

        total_earned = c.execute(
            """
            SELECT COALESCE(SUM(amount),0) AS n
            FROM transactions
            WHERE amount > 0
            """
        ).fetchone()["n"]

        total_payouts = c.execute(
            """
            SELECT COALESCE(SUM(amount),0) AS n
            FROM payouts
            WHERE status IN ('approved','paid')
            """
        ).fetchone()["n"]

        referral_count = c.execute(
            "SELECT COUNT(*) AS n FROM referrals"
        ).fetchone()["n"]

        offer_completions = c.execute(
            "SELECT COUNT(*) AS n FROM offer_completions"
        ).fetchone()["n"]

        survey_completions = c.execute(
            "SELECT COUNT(*) AS n FROM survey_completions"
        ).fetchone()["n"]

    finally:
        c.close()

    body = f"""
<h1>Statistics</h1>

<div class="grid">

<div class="stat">
Users
<b>{total_users}</b>
</div>

<div class="stat">
Verified
<b>{verified}</b>
</div>

<div class="stat">
Admins
<b>{admins}</b>
</div>

<div class="stat">
Positive transactions
<b>{money(total_earned)}</b>
</div>

<div class="stat">
Approved / paid payouts
<b>{money(total_payouts)}</b>
</div>

<div class="stat">
Referrals
<b>{referral_count}</b>
</div>

<div class="stat">
Offer completions
<b>{offer_completions}</b>
</div>

<div class="stat">
Survey completions
<b>{survey_completions}</b>
</div>

</div>
"""

    return page("Statistics", body, request)