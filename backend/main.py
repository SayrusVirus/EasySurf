from services.auth import create_user, authenticate_user, hash_password
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.staticfiles import StaticFiles
from services.provider_core import (
    get_apps,
    get_offers,
    get_surveys,
    get_games,
    get_inventory_counts,
)
from services.offerwall_gg import OfferwallGG

from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
import os
import sqlite3, hashlib, secrets, time
import threading
from contextvars import ContextVar

from pathlib import Path
from html import escape
from urllib.parse import urlparse

from services.email_verification import (
    ensure_schema,
    create_token,
    verify_token,
    build_verification_url,
    send_verification_email,
)

BASE_DIR=Path(__file__).resolve().parent.parent; from services.db_config import DB_PATH
app=FastAPI(title='EasySurf',version='0.5.0')
CURRENT_LANGUAGE = ContextVar('current_language', default='en')
SUPPORTED_LANGUAGES = {
    "en": "English",
    "ru": "Русский",
}
app.mount("/static", StaticFiles(directory=BASE_DIR / "backend" / "static"), name="static")
AVATAR_DIR = BASE_DIR / "backend" / "static" / "uploads" / "avatars"
AVATAR_DIR.mkdir(parents=True, exist_ok=True)

APP_ENV = os.getenv("EASYSURF_ENV", "development").strip().lower()
SESSION_SECRET = os.getenv("EASYSURF_SESSION_SECRET", "").strip()

if APP_ENV == "production" and len(SESSION_SECRET) < 32:
    raise RuntimeError("EASYSURF_SESSION_SECRET must be at least 32 characters in production")

if not SESSION_SECRET:
    SESSION_SECRET = "LOCAL-DEVELOPMENT-ONLY-" + secrets.token_urlsafe(32)



class EasySurfSecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))

                security_headers = [
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"SAMEORIGIN"),
                    (b"referrer-policy", b"strict-origin-when-cross-origin"),
                    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    (b"cross-origin-opener-policy", b"same-origin"),
                ]

                existing = {k.lower() for k, _ in headers}

                for key, value in security_headers:
                    if key not in existing:
                        headers.append((key, value))

                if APP_ENV == "production":
                    if b"strict-transport-security" not in existing:
                        headers.append(
                            (
                                b"strict-transport-security",
                                b"max-age=31536000; includeSubDomains",
                            )
                        )

                message["headers"] = headers

            await send(message)

        await self.app(scope, receive, send_with_headers)


class EasySurfLanguageMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        language = request.session.get("language", "en")

        if language not in SUPPORTED_LANGUAGES:
            language = "en"

        token = CURRENT_LANGUAGE.set(language)

        try:
            await self.app(scope, receive, send)
        finally:
            CURRENT_LANGUAGE.reset(token)

app.add_middleware(EasySurfLanguageMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=604800,
    same_site="lax",
    https_only=(APP_ENV == "production"),
)
app.add_middleware(EasySurfSecurityHeadersMiddleware)

def db():
 c=sqlite3.connect(DB_PATH,timeout=10); c.row_factory=sqlite3.Row; c.execute('PRAGMA busy_timeout=10000'); return c
def now(): return int(time.time())
def hp(p,s=None):
 s=s or secrets.token_bytes(16); return s.hex()+':'+hashlib.scrypt(p.encode(),salt=s,n=2**14,r=8,p=1).hex()
def vp(p,x):
 try:
  s,d=x.split(':',1); return secrets.compare_digest(hashlib.scrypt(p.encode(),salt=bytes.fromhex(s),n=2**14,r=8,p=1).hex(),d)
 except: return False
def money(x): return f'${x/1000:.3f}'


def provider_card(title, description="", reward=0, url="", meta=""):
    title = escape(str(title or "Provider item"))
    description = escape(str(description or ""))
    meta = escape(str(meta or ""))

    if url:
        safe_url = escape(str(url), quote=True)
        action = (
            '<a class="btn" href="' + safe_url +
            '" target="_blank" rel="noopener noreferrer">Open</a>'
        )
    else:
        action = '<span class="muted">No link</span>'

    reward_text = money(int(reward or 0))

    return (
        '<div class="card" style="margin-bottom:16px;">'
        '<h3 style="margin-top:0;">' + title + '</h3>'
        '<p class="muted">' + description + '</p>'
        '<div style="display:flex;gap:12px;align-items:center;'
        'justify-content:space-between;flex-wrap:wrap;">'
        '<span><strong>Reward:</strong> ' + reward_text + '</span>'
        '<span class="muted">' + meta + '</span>'
        + action +
        '</div>'
        '</div>'
    )
def csrf(r):
 x=r.session.get('csrf')
 if not x: x=secrets.token_urlsafe(32); r.session['csrf']=x
 return x
def okcsrf(r,x):
 y=r.session.get('csrf'); return bool(y and x and secrets.compare_digest(y,x))
def normalizeurl(x):
 x=x.strip()
 if not x:
  return ''
 if '://' not in x:
  x='https://'+x
 return x

def validurl(x):
 try:
  x=normalizeurl(x)
  u=urlparse(x)
  return u.scheme in ('http','https') and bool(u.netloc)
 except:
  return False
def code(c):
 x=secrets.token_urlsafe(7).replace('-','').replace('_','').upper()[:8]
 while c.execute('SELECT 1 FROM users WHERE referral_code=?',(x,)).fetchone(): x=secrets.token_urlsafe(7).replace('-','').replace('_','').upper()[:8]
 return x
def user(r):
 uid=r.session.get('user_id');
 if not uid:return None
 c=db(); u=c.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone(); c.close(); return u

def init():
    c = db()

    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            balance INTEGER NOT NULL DEFAULT 0,
            is_admin INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            referral_code TEXT,
            referred_by INTEGER
        );

        CREATE TABLE IF NOT EXISTS tasks(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            url TEXT NOT NULL,
            seconds INTEGER NOT NULL,
            reward INTEGER NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            task_type TEXT NOT NULL DEFAULT 'visit',
            video_url TEXT,
            budget INTEGER NOT NULL DEFAULT 1000,
            spent INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS attempts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            task_id INTEGER NOT NULL,
            started_at INTEGER,
            completed_at INTEGER,
            rewarded INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS transactions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            kind TEXT NOT NULL,
            description TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS referrals(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            referrer_id INTEGER NOT NULL,
            referred_id INTEGER UNIQUE NOT NULL,
            bonus INTEGER NOT NULL,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS payouts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            amount INTEGER NOT NULL,
            method TEXT NOT NULL,
            account TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reward_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            source_type TEXT NOT NULL,
            amount INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS daily_bonus_claims(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            day TEXT NOT NULL,
            streak_day INTEGER NOT NULL DEFAULT 1,
            amount INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            UNIQUE(user_id, day)
        );

        CREATE TABLE IF NOT EXISTS activity_log(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            activity_type TEXT NOT NULL,
            title TEXT NOT NULL,
            amount INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'completed',
            created_at INTEGER NOT NULL
        );
        """
    )

    ensure_schema(c)

    # PROFILE SCHEMA MIGRATION
    # Required by /profile and /language for existing production databases.
    profile_columns = {x[1] for x in c.execute("PRAGMA table_info(users)")}

    if "username" not in profile_columns:
        c.execute("ALTER TABLE users ADD COLUMN username TEXT")

    if "display_name" not in profile_columns:
        c.execute("ALTER TABLE users ADD COLUMN display_name TEXT")

    if "avatar" not in profile_columns:
        c.execute("ALTER TABLE users ADD COLUMN avatar TEXT")

    if "language" not in profile_columns:
        c.execute("ALTER TABLE users ADD COLUMN language TEXT DEFAULT 'en'")

    if "notifications" not in profile_columns:
        c.execute("ALTER TABLE users ADD COLUMN notifications INTEGER NOT NULL DEFAULT 1")

    import re

    profile_rows = c.execute(
        "SELECT id,email,username,display_name,language,notifications FROM users"
    ).fetchall()

    for row in profile_rows:
        username = row["username"]

        if not username:
            base = re.sub(
                r"[^A-Za-z0-9_]+",
                "_",
                str(row["email"]).split("@", 1)[0]
            ).strip("_").lower()

            if len(base) < 3:
                base = "user" + str(row["id"])

            base = base[:24]
            candidate = base
            suffix = 1

            while c.execute(
                "SELECT 1 FROM users WHERE lower(username)=lower(?) AND id<>?",
                (candidate, row["id"])
            ).fetchone():
                tail = "_" + str(suffix)
                candidate = base[:30 - len(tail)] + tail
                suffix += 1

            username = candidate
            display_name = row["display_name"] or username

            c.execute(
                "UPDATE users SET username=?,display_name=? WHERE id=?",
                (username, display_name, row["id"])
            )

        if not row["display_name"]:
            c.execute(
                "UPDATE users SET display_name=? WHERE id=?",
                (username or ("user" + str(row["id"])), row["id"])
            )

    c.execute(
        "UPDATE users SET language='en' "
        "WHERE language IS NULL OR language NOT IN ('en','ru')"
    )

    c.execute(
        "UPDATE users SET notifications=1 WHERE notifications IS NULL"
    )


    uc = {x[1] for x in c.execute("PRAGMA table_info(users)")}
    if "referral_code" not in uc:
        c.execute("ALTER TABLE users ADD COLUMN referral_code TEXT")
    if "referred_by" not in uc:
        c.execute("ALTER TABLE users ADD COLUMN referred_by INTEGER")

    tc = {x[1] for x in c.execute("PRAGMA table_info(tasks)")}
    if "task_type" not in tc:
        c.execute("ALTER TABLE tasks ADD COLUMN task_type TEXT NOT NULL DEFAULT 'visit'")
    if "video_url" not in tc:
        c.execute("ALTER TABLE tasks ADD COLUMN video_url TEXT")
    if "budget" not in tc:
        c.execute("ALTER TABLE tasks ADD COLUMN budget INTEGER NOT NULL DEFAULT 1000")
    if "spent" not in tc:
        c.execute("ALTER TABLE tasks ADD COLUMN spent INTEGER NOT NULL DEFAULT 0")

    for u in c.execute(
        "SELECT id FROM users WHERE referral_code IS NULL OR referral_code=''"
    ).fetchall():
        c.execute(
            "UPDATE users SET referral_code=? WHERE id=?",
            (code(c), u["id"])
        )

    if not c.execute("SELECT id FROM tasks LIMIT 1").fetchone():
        c.execute(
            """
            INSERT INTO tasks(
                title,url,seconds,reward,created_at,task_type,budget,spent
            )
            VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                "Demo website visit",
                "https://example.com",
                20,
                5,
                now(),
                "visit",
                1000,
                0,
            )
        )

    # ADMIN BOOTSTRAP
    # Keeps the configured Render admin account available after a fresh
    # deployment or a new SQLite database.
    admin_email = os.getenv("EASYSURF_ADMIN_EMAIL", "").strip().lower()
    admin_password = os.getenv("EASYSURF_ADMIN_PASSWORD", "")

    if admin_email and len(admin_password) >= 8:
        admin_row = c.execute(
            "SELECT id FROM users WHERE lower(email)=lower(?)",
            (admin_email,)
        ).fetchone()

        if admin_row:
            c.execute(
                """
                UPDATE users
                SET password_hash=?,
                    is_admin=1,
                    email_verified=1
                WHERE id=?
                """,
                (
                    hash_password(admin_password),
                    int(admin_row["id"])
                )
            )
            print(
                "ADMIN BOOTSTRAP: updated",
                admin_email,
                "user_id=" + str(int(admin_row["id"])),
                flush=True
            )
        else:
            admin_username = admin_email.split("@", 1)[0]
            admin_username = "".join(
                ch if ch.isalnum() or ch == "_" else "_"
                for ch in admin_username.lower()
            ).strip("_")

            if len(admin_username) < 3:
                admin_username = "admin"

            admin_username = admin_username[:30]
            candidate = admin_username
            suffix = 1

            while c.execute(
                """
                SELECT 1
                FROM users
                WHERE lower(username)=lower(?)
                """,
                (candidate,)
            ).fetchone():
                suffix_text = "_" + str(suffix)
                candidate = (
                    admin_username[:30 - len(suffix_text)]
                    + suffix_text
                )
                suffix += 1

            admin_referral_code = code(c)

            cursor = c.execute(
                """
                INSERT INTO users(
                    email,
                    password_hash,
                    created_at,
                    referral_code,
                    referred_by,
                    email_verified,
                    is_admin,
                    username,
                    display_name,
                    language,
                    notifications
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    admin_email,
                    hash_password(admin_password),
                    now(),
                    admin_referral_code,
                    None,
                    1,
                    1,
                    candidate,
                    candidate,
                    "en",
                    1,
                )
            )

            print(
                "ADMIN BOOTSTRAP: created",
                admin_email,
                "user_id=" + str(int(cursor.lastrowid)),
                flush=True
            )
    elif admin_email:
        print(
            "ADMIN BOOTSTRAP: password missing or too short",
            flush=True
        )

    c.commit()
    c.close()
def startup():init()


# =========================================================
# EasySurf language system
# =========================================================

LANGUAGE_TRANSLATIONS = {
    "en": {
        "Dashboard": "Dashboard",
        "Profile": "Profile",
        "Earn": "Earn",
        "Rewards": "Rewards",
        "Activity": "Activity",
        "Leaderboard": "Leaderboard",
        "Referrals": "Referrals",
        "Withdraw": "Withdraw",
        "Payouts": "Payouts",
        "Offers": "Offers",
        "Games": "Games",
        "Apps": "Apps",
        "Tasks": "Tasks",
        "Microtasks": "Microtasks",
        "Login": "Login",
        "Register": "Register",
        "Get Started": "Get Started",
        "Logout": "Logout",

        "My Profile": "My Profile",
        "Personal information": "Personal information",
        "Display name": "Display name",
        "Username": "Username",
        "Email": "Email",
        "Language": "Language",
        "Notifications": "Notifications",
        "Receive notifications": "Receive notifications",
        "Avatar": "Avatar",
        "Save profile": "Save profile",
        "Save changes": "Save changes",

        "Account": "Account",
        "Balance": "Balance",
        "Total earned": "Total earned",
        "Total paid": "Total paid",
        "Referrals": "Referrals",
        "Referral code": "Referral code",
        "Account ID": "Account ID",
        "Admin": "Admin",
        "Yes": "Yes",
        "No": "No",

        "English": "English",
        "Russian": "Russian",
        "Italian": "Italian",
        "German": "German",
        "Japanese": "Japanese",
        "Turkish": "Turkish",

        "Русский": "Russian",
        "Italiano": "Italian",
        "Deutsch": "German",
        "日本語": "Japanese",
        "TГјrkГ§e": "Turkish",

        "Profile updated successfully.": "Profile updated successfully.",
        "Choose an earning method and get started.": "Choose an earning method and get started.",
        "Available offers from connected providers.": "Available offers from connected providers.",
        "Available games from connected providers.": "Available games from connected providers.",
        "Available apps from connected providers.": "Available apps from connected providers.",

        "Save": "Save",
        "Cancel": "Cancel",
        "Back": "Back",
        "Continue": "Continue",
        "Submit": "Submit",
        "Search": "Search",
        "Loading": "Loading",
        "Completed": "Completed",
        "Pending": "Pending",
        "Available": "Available",
        "Total": "Total",
        "Today": "Today",
        "Yesterday": "Вчера",
        "This week": "This week",
        "This month": "This month",

        "Welcome": "Welcome",
        "Welcome back": "Welcome back",
        "Your balance": "Your balance",
        "Start earning": "Start earning",
        "Earn money": "Earn money",
        "Earn more": "Earn more",
        "Your rewards": "Your rewards",
        "Your activity": "Your activity",
        "Your referrals": "Your referrals",

        "Your EasySurf Dashboard": "Your EasySurf Dashboard",
        "Earn now": "Earn now",
        "Available balance": "Available balance",
        "Earned today": "Earned today",
        "Pending rewards": "Pending rewards",
        "Tasks completed": "Tasks completed",
        "Daily target": "Daily target",
        "Today's earning goal": "Дневная цель заработка",
        "Keep completing available activities to grow your balance.": "Keep completing available activities to grow your balance.",
        "Quick access": "Quick access",
        "View all": "View all",
        "Surveys": "Surveys",
        "Paid research surveys when inventory is available.": "Paid research surveys when inventory is available.",
        "View surveys": "View surveys",
        "Offers": "Offers",
        "Advertiser offers and tracked activities.": "Advertiser offers and tracked activities.",
        "View offers": "View offers",
        "Games": "Games",
        "Play approved games and reach milestones.": "Play approved games and reach milestones.",
        "View games": "View games",
        "Apps": "Apps",
        "Discover tracked app opportunities.": "Discover tracked app opportunities.",
        "View apps": "View apps",
        "Available now": "Available now",
        "Website Tasks": "Website Tasks",
        "Browse earning options": "Browse earning options",
        "Your account": "Your account",
        "Recent Activity": "Recent Activity",
        "No activity yet. Start earning to see your transactions here.": "No activity yet. Start earning to see your transactions here.",
        "Activity": "Activity",
        "Amount": "Amount",
        "Goal": "Goal",
        "earned today": "earned today",

        "No data available": "No data available",
        "No offers available": "No offers available",
        "No games available": "No games available",
        "No apps available": "No apps available",
        "No tasks available": "No tasks available",

        "Sign in": "Sign in",
        "Sign up": "Sign up",
        "Password": "Password",
        "Confirm password": "Confirm password",
        "Remember me": "Remember me",
        "Forgot password?": "Forgot password?",
        "Don't have an account?": "Don't have an account?",
        "Already have an account?": "Already have an account?",

        "Invite friends": "Invite friends",
        "Referral program": "Referral program",
        "Your referral link": "Your referral link",
        "Copy": "Copy",
        "Copied": "Copied",

        "Request payout": "Request payout",
        "Payout history": "Payout history",
        "Minimum payout": "Minimum payout",
        "Payment method": "Payment method",

        "Home": "Home",
        "About": "About",
        "Contact": "Contact",
        "Privacy": "Privacy",
        "Terms": "Terms",
        "Help": "Help",
    },

    "ru": {
        "Dashboard": "Панель управления",
        "Profile": "Профиль",
        "Earn": "Заработок",
        "Rewards": "Награды",
        "Activity": "Активность",
        "Leaderboard": "Таблица лидеров",
"View activity": "Посмотреть активность",
"Today's reward": "Награда за сегодня",
"Daily Bonus": "Ежедневный бонус",
"One claim per day": "Одна награда в день",
"Bonus claimed today": "Бонус уже получен сегодня",
"Come back tomorrow to continue your streak and claim the next daily bonus.": "Вернитесь завтра, чтобы продолжить серию и получить следующий ежедневный бонус.",
"Your daily bonus is ready": "Ваш ежедневный бонус готов",
"Claim your bonus once today and keep your earning streak alive.": "Получите бонус сегодня и продолжайте свою серию заработка.",
"Claim Daily Bonus": "Получить ежедневный бонус",
"Rewards & Bonuses": "Награды и бонусы",
"Daily Goal": "Дневная цель",
"Reach today's target": "Достигните сегодняшней цели",
"progress": "прогресс",
"Your progress": "Ваш прогресс",
"Keep the momentum": "Продолжайте в том же духе",
"Earn every day to build your progress": "Зарабатывайте каждый день, чтобы увеличивать свой прогресс",
"Daily streak": "Ежедневная серия",
"Streak": "Серия",
"Keep earning every day to maintain your reward streak.": "Зарабатывайте каждый день, чтобы поддерживать серию наград.",
"View progress": "Посмотреть прогресс",
"Milestones": "Достижения",
"Achievements": "Достижения",
"Complete milestones and keep building your account progress.": "Выполняйте цели и продолжайте развивать свой аккаунт.",
"Community": "Сообщество",
"Open leaderboard": "Открыть таблицу лидеров",
"More ways to earn": "Больше способов заработать",
"Turn activity into rewards": "Превращайте активность в награды",
"Surveys": "Опросы",
"Offers": "Предложения",
"Games": "Р ВР С–РЎР‚РЎвЂ№",
"Apps": "Приложения",
"Videos": "Видео",
"No surveys available right now": "Сейчас нет доступных опросов",
"There are currently no active survey offers from connected providers.": "В настоящее время нет активных предложений опросов от подключённых провайдеров.",
"No offers available right now": "Сейчас нет доступных предложений",
"There are currently no active offers from connected providers.": "В настоящее время нет активных предложений от подключённых провайдеров.",
"No games available right now": "Сейчас нет доступных игр",
"There are currently no active game offers from connected providers.": "В настоящее время нет активных предложений игр от подключённых провайдеров.",
"No apps available right now": "Сейчас нет доступных приложений",
"There are currently no active app offers from connected providers.": "В настоящее время нет активных предложений приложений от подключённых провайдеров.",
"Today's reward": "Награда за сегодня",
"Daily Bonus": "Ежедневный бонус",
"One claim per day": "Одна награда в день",
"Bonus claimed today": "Бонус уже получен сегодня",
"Come back tomorrow to continue your streak and claim the next daily bonus.": "Вернитесь завтра, чтобы продолжить серию и получить следующий ежедневный бонус.",
"Daily Goal": "Дневная цель",
"Reach today's target": "Достигните сегодняшней цели",
"progress": "прогресс",
"Your progress": "Ваш прогресс",
"Keep the momentum": "Продолжайте в том же духе",
"Earn every day to build your progress": "Зарабатывайте каждый день, чтобы увеличивать свой прогресс",
"Daily streak": "Ежедневная серия",
"Streak": "Серия",
"Keep earning every day to maintain your reward streak.": "Зарабатывайте каждый день, чтобы поддерживать серию наград.",
"View activity →": "Посмотреть активность →",
"View progress →": "Посмотреть прогресс →",
"Milestones": "Достижения",
"Achievements": "Достижения",
"Complete milestones and keep building your account progress.": "Выполняйте цели и продолжайте развивать свой аккаунт.",
"Community": "Сообщество",
"Leaderboard": "Таблица лидеров",
"See how your total earnings compare with other EasySurf users.": "Сравните свой общий заработок с другими пользователями EasySurf.",
"Open leaderboard →": "РћС‚РєСЂС‹С‚СЊ С‚Р°Р±Р»РёС†Сѓ Р»РёРґРµСЂРѕРІ →",
"More ways to earn": "Больше способов заработать",
"Turn activity into rewards": "Превращайте активность в награды",
"Explore available tasks, surveys, offers, games and other earning sections.": "Р ВР В·РЎС“РЎвЂЎР В°Р в„–РЎвЂљР Вµ Р Т‘Р С•РЎРѓРЎвЂљРЎС“Р С—Р Р…РЎвЂ№Р Вµ Р В·Р В°Р Т‘Р В°Р Р…Р С‘РЎРЏ, Р С•Р С—РЎР‚Р С•РЎРѓРЎвЂ№, Р С—РЎР‚Р ВµР Т‘Р В»Р С•Р В¶Р ВµР Р…Р С‘РЎРЏ, Р С‘Р С–РЎР‚РЎвЂ№ Р С‘ Р Т‘РЎР‚РЎС“Р С–Р С‘Р Вµ РЎР‚Р В°Р В·Р Т‘Р ВµР В»РЎвЂ№ Р В·Р В°РЎР‚Р В°Р В±Р С•РЎвЂљР С”Р В°.",
"My Profile": "Мой профиль",
"Personal information": "Личная информация",
"Display name": "Отображаемое имя",
"Username": "Р ВР СРЎРЏ Р С—Р С•Р В»РЎРЉР В·Р С•Р Р†Р В°РЎвЂљР ВµР В»РЎРЏ",
"3–30 characters: letters, numbers and underscore.": "От 3 до 30 символов: буквы, цифры и символ подчёркивания.",
"Email": "Электронная почта",
"Language": "Язык",
"Receive notifications": "Получать уведомления",
"Avatar": "Аватар",
"JPG, PNG or WEBP. Maximum 2 MB.": "JPG, PNG или WEBP. Максимальный размер — 2 МБ.",
"Save profile": "Сохранить профиль",
"Account": "Аккаунт",
"Balance": "Баланс",
"Referral code": "Реферальный код",
"Account ID": "ID аккаунта",
"Admin": "Администратор",
"Pending Rewards": "Ожидающие награды",
"No pending rewards.": "Нет ожидающих наград.",
"Transaction History": "Р ВРЎРѓРЎвЂљР С•РЎР‚Р С‘РЎРЏ РЎвЂљРЎР‚Р В°Р Р…Р В·Р В°Р С”РЎвЂ Р С‘Р в„–",
"Description": "Описание",
"Type": "Тип",
"Amount": "Сумма",
"Top EasySurf earners.": "Лидеры по заработку EasySurf.",
"Rank": "Место",
"User": "Пользователь",
"Total earned": "Всего заработано",
"Your referral code": "Ваш реферальный код",
"Copy code": "Скопировать код",
"Give this code to a friend during registration.": "Передайте этот код другу при регистрации.",
"Referrals": "Рефералы",
"registered users": "зарегистрированных пользователей",
"Referral earnings": "Реферальный заработок",
"total referral bonuses": "общая сумма реферальных бонусов",
"Referral reward": "Реферальная награда",
"per successful signup": "за успешную регистрацию",
"Referral activity": "Реферальная активность",
"Your referrals": "Ваши рефералы",
"0 total": "Всего: 0",
"No referrals yet": "Пока нет рефералов",
"Share your referral code to start building your network.": "Поделитесь своим реферальным кодом, чтобы начать развивать свою сеть.",
"Grow your network": "Развивайте свою сеть",
"Invite more friends": "Приглашайте больше друзей",
"Share your referral code with people you know and earn the available referral bonus for successful registrations.": "Поделитесь своим реферальным кодом со знакомыми и получайте доступный реферальный бонус за успешные регистрации.",
        "Referrals": "Рефералы",
        "Withdraw": "Вывод средств",
        "Payouts": "Выплаты",
        "Offers": "Предложения",
        "Games": "Р ВР С–РЎР‚РЎвЂ№",
        "Apps": "Приложения",
        "Tasks": "Задания",
        "Microtasks": "Микрозадания",
        "Login": "Войти",
        "Register": "Регистрация",
        "Get Started": "Начать",
        "Logout": "Выйти",

        "My Profile": "Мой профиль",
        "Personal information": "Личная информация",
        "Display name": "Отображаемое имя",
        "Username": "Р ВР СРЎРЏ Р С—Р С•Р В»РЎРЉР В·Р С•Р Р†Р В°РЎвЂљР ВµР В»РЎРЏ",
        "Email": "Электронная почта",
        "Language": "Язык",
        "Notifications": "Уведомления",
        "Receive notifications": "Получать уведомления",
        "Avatar": "Аватар",
        "Save profile": "Сохранить профиль",
        "Save changes": "Сохранить изменения",

        "Account": "Аккаунт",
        "Balance": "Баланс",
        "Total earned": "Всего заработано",
        "Total paid": "Всего выплачено",
        "Referral code": "Реферальный код",
        "Account ID": "ID аккаунта",
        "Admin": "Администратор",
        "Yes": "Да",
        "No": "Нет",

        "English": "Английский",
        "Russian": "Русский",
        "Italian": "Р ВРЎвЂљР В°Р В»РЎРЉРЎРЏР Р…РЎРѓР С”Р С‘Р в„–",
        "German": "Немецкий",
        "Japanese": "Японский",
        "Turkish": "Турецкий",

        "Русский": "Русский",
        "Italiano": "Р ВРЎвЂљР В°Р В»РЎРЉРЎРЏР Р…РЎРѓР С”Р С‘Р в„–",
        "Deutsch": "Немецкий",
        "日本語": "Японский",
        "Türkçe": "Турецкий",

        "Profile updated successfully.": "Профиль успешно обновлён.",
        "Choose an earning method and get started.": "Выберите способ заработка и начните.",
        "Available offers from connected providers.": "Доступные предложения от подключённых провайдеров.",
        "Available games from connected providers.": "Доступные игры от подключённых провайдеров.",
        "Available apps from connected providers.": "Доступные приложения от подключённых провайдеров.",

        "Save": "Сохранить",
        "Cancel": "Отмена",
        "Back": "Назад",
        "Continue": "Продолжить",
        "Submit": "Отправить",
        "Search": "Поиск",
        "Loading": "Загрузка",
        "Completed": "Завершено",
        "Pending": "В ожидании",
    "No transactions yet.": "Транзакций пока нет.",
    "Track your completed and pending rewards.": "Отслеживайте выполненные и ожидающие награды.",
    "Status": "Статус",
        "Available": "Доступно",
"available": "доступно",
        "currently available": "доступно сейчас",
"Choose from available surveys, offers, games, apps, videos": "Выбирайте доступные опросы, предложения, игры, приложения и видео",
"and verified website tasks.": "и проверенные задания на сайтах.",
"Browse tasks": "Посмотреть задания",
"View rewards": "Посмотреть награды",
"Share your opinion through paid research surveys when inventory is available.": "Делитесь своим мнением в оплачиваемых исследовательских опросах при наличии доступных предложений.",
"Explore surveys": "Посмотреть опросы",
"Complete advertiser-approved activities and tracked offers.": "Выполняйте одобренные рекламодателями активности и отслеживаемые предложения.",
"Explore offers": "Посмотреть предложения",
"Explore games": "Посмотреть игры",
"Explore apps": "Посмотреть приложения",
"Watch approved video activities when available.": "Смотрите одобренные видео при наличии доступных активностей.",
"Explore videos": "Посмотреть видео",
"Micro Tasks": "Микрозадания",
"Explore rewards, referrals and other earning sections to see what is currently available.": "Р ВР В·РЎС“РЎвЂЎР В°Р в„–РЎвЂљР Вµ Р Р…Р В°Р С–РЎР‚Р В°Р Т‘РЎвЂ№, РЎР‚Р ВµРЎвЂћР ВµРЎР‚Р В°Р В»РЎРЉР Р…РЎС“РЎР‹ Р С—РЎР‚Р С•Р С–РЎР‚Р В°Р СР СРЎС“ Р С‘ Р Т‘РЎР‚РЎС“Р С–Р С‘Р Вµ РЎР‚Р В°Р В·Р Т‘Р ВµР В»РЎвЂ№ Р В·Р В°РЎР‚Р В°Р В±Р С•РЎвЂљР С”Р В°, РЎвЂЎРЎвЂљР С•Р В±РЎвЂ№ Р Р†Р С‘Р Т‘Р ВµРЎвЂљРЎРЉ Р Т‘Р С•РЎРѓРЎвЂљРЎС“Р С—Р Р…РЎвЂ№Р Вµ Р Р†Р С•Р В·Р СР С•Р В¶Р Р…Р С•РЎРѓРЎвЂљР С‘.",
        "Total": "Всего",
        "Today": "Сегодня",
        "Yesterday": "Вчера",
        "This week": "На этой неделе",
        "This month": "В этом месяце",

        "Welcome": "Добро пожаловать",
        "Welcome back": "С возвращением",
        "Your balance": "Ваш баланс",
        "Start earning": "Начать зарабатывать",
        "Earn money": "Зарабатывать деньги",
        "Earn more": "Зарабатывать больше",
        "Your rewards": "Ваши награды",
        "Your activity": "Ваша активность",
        "Your referrals": "Ваши рефералы",

        "Your EasySurf Dashboard": "Ваша панель EasySurf",
        "Earn now": "Заработать сейчас",
        "Available balance": "Доступный баланс",
        "Earned today": "Заработано сегодня",
        "Pending rewards": "Ожидающие награды",
        "Tasks completed": "Выполнено заданий",
        "Daily target": "Дневная цель",
        "Today's earning goal": "Дневная цель заработка",
        "Keep completing available activities to grow your balance.": "Продолжайте выполнять доступные задания, чтобы увеличить баланс.",
        "Quick access": "Быстрый доступ",
        "View all": "Посмотреть все",
        "Surveys": "Опросы",
        "Paid research surveys when inventory is available.": "Оплачиваемые исследовательские опросы при наличии доступных предложений.",
        "View surveys": "Посмотреть опросы",
        "Offers": "Предложения",
        "Advertiser offers and tracked activities.": "Предложения рекламодателей и отслеживаемые активности.",
        "View offers": "Посмотреть предложения",
        "Games": "Р ВР С–РЎР‚РЎвЂ№",
        "Play approved games and reach milestones.": "Р ВР С–РЎР‚Р В°Р в„–РЎвЂљР Вµ Р Р† Р С•Р Т‘Р С•Р В±РЎР‚Р ВµР Р…Р Р…РЎвЂ№Р Вµ Р С‘Р С–РЎР‚РЎвЂ№ Р С‘ Р Р†РЎвЂ№Р С—Р С•Р В»Р Р…РЎРЏР в„–РЎвЂљР Вµ РЎвЂ Р ВµР В»Р С‘.",
        "View games": "Посмотреть игры",
        "Apps": "Приложения",
        "Discover tracked app opportunities.": "Находите доступные предложения с отслеживанием приложений.",
        "View apps": "Посмотреть приложения",
        "Available now": "Доступно сейчас",
        "Website Tasks": "Задания на сайтах",
        "Browse earning options": "Просмотреть варианты заработка",
        "Your account": "Ваш аккаунт",
        "Recent Activity": "Последняя активность",
        "No activity yet. Start earning to see your transactions here.": "Активности пока нет. Начните зарабатывать, чтобы увидеть здесь свои операции.",
        "Activity": "Активность",
        "Amount": "Сумма",
        "Goal": "Цель",
        "earned today": "заработано сегодня",
"Today's earning goal": "Дневная цель заработка",
"No website tasks available": "Заданий на сайтах пока нет",
"New tasks may appear later. Explore other earning categories in the meantime.": "Новые задания могут появиться позже. А пока изучите другие категории заработка.",
"Explore Earn →": "Перейти к заработку →",
"Keep going": "Продолжайте",
"There are more ways to earn": "Есть и другие способы заработка",
"Explore all available earning categories and keep your activity growing.": "Р ВР В·РЎС“РЎвЂЎР С‘РЎвЂљР Вµ Р Р†РЎРѓР Вµ Р Т‘Р С•РЎРѓРЎвЂљРЎС“Р С—Р Р…РЎвЂ№Р Вµ Р С”Р В°РЎвЂљР ВµР С–Р С•РЎР‚Р С‘Р С‘ Р В·Р В°РЎР‚Р В°Р В±Р С•РЎвЂљР С”Р В° Р С‘ Р С—РЎР‚Р С•Р Т‘Р С•Р В»Р В¶Р В°Р в„–РЎвЂљР Вµ РЎС“Р Р†Р ВµР В»Р С‘РЎвЂЎР С‘Р Р†Р В°РЎвЂљРЎРЉ РЎРѓР Р†Р С•РЎР‹ Р В°Р С”РЎвЂљР С‘Р Р†Р Р…Р С•РЎРѓРЎвЂљРЎРЉ.",
"Explore earning": "Перейти к заработку",
"No website tasks available right now": "Заданий на сайтах сейчас нет",
"There are currently no available website tasks for your account.": "В настоящее время для вашего аккаунта нет доступных заданий на сайтах.",
"reach your daily goal and unlock more rewards.": "достигайте дневной цели и открывайте дополнительные награды.",
"Daily Goal": "Дневная цель",
"Keep completing eligible activities to increase your progress toward the daily earning goal.": "Продолжайте выполнять доступные задания, чтобы увеличивать прогресс к дневной цели заработка.",

        "No data available": "Нет доступных данных",
        "No offers available": "Нет доступных предложений",
        "Earn online. Your way.": "Зарабатывайте онлайн. По-своему.",
        "Complete surveys, offers, games, app activities and simple tasks from one modern rewards platform.": "Проходите опросы, выполняйте предложения, играйте, используйте приложения и выполняйте простые задания на одной современной платформе.",
        "Simple tasks": "Простые задания",
        "Daily rewards": "Ежедневные награды",
        "Referral bonuses": "Реферальные бонусы",
        "Platform": "Платформа",
        "Everything in one place": "Всё в одном месте",
        "Choose an earning method and get started.": "Выберите способ заработка и начните.",
        "Paid research surveys when real inventory is available.": "Оплачиваемые исследовательские опросы при наличии доступных предложений.",
        "Advertiser-approved offers and tracked activities.": "Предложения от рекламодателей и отслеживаемые активности.",
        "Game-based rewards through approved providers.": "Награды за игры через проверенных провайдеров.",
        "App-based earning opportunities.": "Возможности заработка через приложения.",
        "Watch approved video tasks and activities.": "Смотрите одобренные видео и выполняйте доступные активности.",
        "Complete verified website and microtasks.": "Выполняйте проверенные задания на сайтах и микрозадания.",
        "Ready when you are": "Готовы начать?",
        "Start building your rewards balance": "Начните увеличивать свой баланс наград",
        "Create free account →": "РЎРѕР·РґР°С‚СЊ Р±РµСЃРїР»Р°С‚РЅС‹Р№ Р°РєРєР°СѓРЅС‚ →",
        "Explore →": "Перейти →",
        "Start →": "РќР°С‡Р°С‚СЊ →",
        "Videos": "Видео",
        "Tasks": "Задания",
        "Watch approved video tasks and activities.": "Смотрите одобренные видео и выполняйте доступные активности.",
        "Complete verified website and microtasks.": "Выполняйте проверенные задания на сайтах и микрозадания.",
        "Home": "Главная",
        "Dashboard": "Панель управления",
        "Earn": "Заработок",
        "Rewards": "Награды",
        "Offers": "Предложения",
        "Surveys": "Опросы",
        "Videos": "Видео",
        "Company": "Компания",
        "Support": "Поддержка",
        "About Us": "О нас",
        "Contact": "Контакты",
        "Referrals": "Рефералы",
        "Payouts": "Вывод средств",
        "FAQ": "Частые вопросы",
        "Help Center": "Центр помощи",
        "Contact Support": "Связаться с поддержкой",
        "Terms of Service": "Условия использования",
        "Terms": "Условия",
        "All rights reserved.": "Все права защищены.",
        "Earn online by completing verified activities, offers, surveys, games and other available tasks.": "Зарабатывайте онлайн, выполняя проверенные активности, предложения, опросы, игры и другие доступные задания.",
        "No games available": "Нет доступных игр",
        "No apps available": "Нет доступных приложений",
        "No tasks available": "Нет доступных заданий",

        "Sign in": "Войти",
        "Sign up": "Зарегистрироваться",
        "Password": "Пароль",
        "Confirm password": "Подтвердите пароль",
        "Remember me": "Запомнить меня",
        "Forgot password?": "Забыли пароль?",
        "Don't have an account?": "Нет аккаунта?",
        "Already have an account?": "Уже есть аккаунт?",

        "Invite friends": "Пригласить друзей",
        "Referral program": "Реферальная программа",
        "Your referral link": "Ваша реферальная ссылка",
        "Copy": "Копировать",
        "Copied": "Скопировано",

        "Request payout": "Запросить выплату",
        "Payout history": "Р ВРЎРѓРЎвЂљР С•РЎР‚Р С‘РЎРЏ Р Р†РЎвЂ№Р С—Р В»Р В°РЎвЂљ",
        "Minimum payout": "Минимальная сумма выплаты",
        "Payment method": "Способ оплаты",

        "Home": "Главная",
        "About": "О нас",
        "Contact": "Контакты",
        "Privacy": "Конфиденциальность",
        "Terms": "Условия",
        "Help": "Помощь",
    },

    "it": {
        "Total earned": "Totale guadagnato",
        "Total paid": "Totale pagato",
        "Your EasySurf Dashboard": "La tua Dashboard EasySurf",
        "Earn now": "Guadagna ora",
        "Available balance": "Saldo disponibile",
        "Earned today": "Guadagnato oggi",
        "Pending rewards": "Ricompense in sospeso",
        "Tasks completed": "AttivitГ  completate",
        "Daily target": "Obiettivo giornaliero",
        "Today's earning goal": "Obiettivo di guadagno di oggi",
        "Keep completing available activities to grow your balance.": "Continua a completare le attivitГ  disponibili per aumentare il tuo saldo.",
        "Quick access": "Accesso rapido",
        "View all": "Visualizza tutto",
        "Surveys": "Sondaggi",
        "Paid research surveys when inventory is available.": "Sondaggi di ricerca retribuiti quando sono disponibili.",
        "View surveys": "Visualizza sondaggi",
        "Advertiser offers and tracked activities.": "Offerte degli inserzionisti e attivitГ  monitorate.",
        "View offers": "Visualizza offerte",
        "Play approved games and reach milestones.": "Gioca ai giochi approvati e raggiungi gli obiettivi.",
        "View games": "Visualizza giochi",
        "Discover tracked app opportunities.": "Scopri le opportunitГ  delle app monitorate.",
        "View apps": "Visualizza app",
        "Available now": "Disponibile ora",
        "Website Tasks": "AttivitГ  sul sito web",
        "Browse earning options": "Sfoglia le opzioni di guadagno",
        "Your account": "Il tuo account",
        "Recent Activity": "AttivitГ  recente",
        "No activity yet. Start earning to see your transactions here.": "Nessuna attivitГ  ancora. Inizia a guadagnare per vedere qui le tue transazioni.",
        "Amount": "Importo",
        "Goal": "Obiettivo",
        "earned today": "guadagnato oggi",
        "Dashboard": "Dashboard",
        "Profile": "Profilo",
        "Earn": "Guadagna",
        "Rewards": "Ricompense",
        "Activity": "AttivitГ ",
        "Leaderboard": "Classifica",
        "Referrals": "Referral",
        "Withdraw": "Prelievo",
        "Payouts": "Pagamenti",
        "Offers": "Offerte",
        "Games": "Giochi",
        "Apps": "App",
        "Tasks": "AttivitГ ",
        "Microtasks": "MicroattivitГ ",
        "Login": "Accedi",
        "Register": "Registrati",
        "Get Started": "Inizia",
        "Logout": "Esci",

        "My Profile": "Il mio profilo",
        "Personal information": "Informazioni personali",
        "Display name": "Nome visualizzato",
        "Username": "Nome utente",
        "Email": "Email",
        "Language": "Lingua",
        "Notifications": "Notifiche",
        "Receive notifications": "Ricevi notifiche",
        "Avatar": "Avatar",
        "Save profile": "Salva profilo",
        "Save changes": "Salva modifiche",

        "Account": "Account",
        "Balance": "Saldo",
        "Referral code": "Codice referral",
        "Account ID": "ID account",
        "Admin": "Amministratore",
        "Yes": "SГ¬",
        "No": "No",

        "English": "Inglese",
        "Russian": "Russo",
        "Italian": "Italiano",
        "German": "Tedesco",
        "Japanese": "Giapponese",
        "Turkish": "Turco",

        "Русский": "Russo",
        "Italiano": "Italiano",
        "Deutsch": "Tedesco",
        "日本語": "Giapponese",
        "TГјrkГ§e": "Turco",

        "Profile updated successfully.": "Profilo aggiornato con successo.",
        "Choose an earning method and get started.": "Scegli un metodo per guadagnare e inizia.",
        "Available offers from connected providers.": "Offerte disponibili dai provider collegati.",
        "Available games from connected providers.": "Giochi disponibili dai provider collegati.",
        "Available apps from connected providers.": "App disponibili dai provider collegati.",

        "Save": "Salva",
        "Cancel": "Annulla",
        "Back": "Indietro",
        "Continue": "Continua",
        "Submit": "Invia",
        "Search": "Cerca",
        "Loading": "Caricamento",
        "Completed": "Completato",
        "Pending": "In attesa",
        "Available": "Disponibile",
        "Total": "Totale",
        "Today": "Oggi",
        "Yesterday": "Ieri",
        "This week": "Questa settimana",
        "This month": "Questo mese",

        "Welcome": "Benvenuto",
        "Welcome back": "Bentornato",
        "Your balance": "Il tuo saldo",
        "Start earning": "Inizia a guadagnare",
        "Earn money": "Guadagna denaro",
        "Earn more": "Guadagna di piГ№",
        "Your rewards": "Le tue ricompense",
        "Your activity": "La tua attivitГ ",
        "Your referrals": "I tuoi referral",

        "No data available": "Nessun dato disponibile",
        "No offers available": "Nessuna offerta disponibile",
        "No games available": "Nessun gioco disponibile",
        "No apps available": "Nessuna app disponibile",
        "No tasks available": "Nessuna attivitГ  disponibile",

        "Sign in": "Accedi",
        "Sign up": "Registrati",
        "Password": "Password",
        "Confirm password": "Conferma password",
        "Remember me": "Ricordami",
        "Forgot password?": "Password dimenticata?",
        "Don't have an account?": "Non hai un account?",
        "Already have an account?": "Hai giГ  un account?",

        "Invite friends": "Invita amici",
        "Referral program": "Programma referral",
        "Your referral link": "Il tuo link referral",
        "Copy": "Copia",
        "Copied": "Copiato",

        "Request payout": "Richiedi pagamento",
        "Payout history": "Cronologia pagamenti",
        "Minimum payout": "Pagamento minimo",
        "Payment method": "Metodo di pagamento",

        "Home": "Home",
        "About": "Chi siamo",
        "Contact": "Contatti",
        "Privacy": "Privacy",
        "Terms": "Termini",
        "Help": "Aiuto",
    },

    "de": {
        "Total earned": "Insgesamt verdient",
        "Total paid": "Insgesamt ausgezahlt",
        "Your EasySurf Dashboard": "Dein EasySurf-Dashboard",
        "Earn now": "Jetzt verdienen",
        "Available balance": "VerfГјgbares Guthaben",
        "Earned today": "Heute verdient",
        "Pending rewards": "Ausstehende PrГ¤mien",
        "Tasks completed": "Aufgaben abgeschlossen",
        "Daily target": "Tagesziel",
        "Today's earning goal": "Heutiges Verdienstziel",
        "Keep completing available activities to grow your balance.": "Schließe weiterhin verfügbare Aktivitäten ab, um dein Guthaben zu erhöhen.",
        "Quick access": "Schnellzugriff",
        "View all": "Alle anzeigen",
        "Surveys": "Umfragen",
        "Paid research surveys when inventory is available.": "Bezahlte Forschungsumfragen, wenn verfГјgbar.",
        "View surveys": "Umfragen anzeigen",
        "Advertiser offers and tracked activities.": "Werbeangebote und erfasste AktivitГ¤ten.",
        "View offers": "Angebote anzeigen",
        "Play approved games and reach milestones.": "Spiele genehmigte Spiele und erreiche Meilensteine.",
        "View games": "Spiele anzeigen",
        "Discover tracked app opportunities.": "Entdecke erfasste App-MГ¶glichkeiten.",
        "View apps": "Apps anzeigen",
        "Available now": "Jetzt verfГјgbar",
        "Website Tasks": "Website-Aufgaben",
        "Browse earning options": "VerdienstmГ¶glichkeiten durchsuchen",
        "Your account": "Dein Konto",
        "Recent Activity": "Letzte AktivitГ¤ten",
        "No activity yet. Start earning to see your transactions here.": "Noch keine AktivitГ¤ten. Beginne zu verdienen, um deine Transaktionen hier zu sehen.",
        "Amount": "Betrag",
        "Goal": "Ziel",
        "earned today": "heute verdient",
        "Dashboard": "Dashboard",
        "Profile": "Profil",
        "Earn": "Verdienen",
        "Rewards": "Belohnungen",
        "Activity": "AktivitГ¤t",
        "Leaderboard": "Rangliste",
        "Referrals": "Empfehlungen",
        "Withdraw": "Auszahlung",
        "Payouts": "Zahlungen",
        "Offers": "Angebote",
        "Games": "Spiele",
        "Apps": "Apps",
        "Tasks": "Aufgaben",
        "Microtasks": "Mikroaufgaben",
        "Login": "Anmelden",
        "Register": "Registrieren",
        "Get Started": "Loslegen",
        "Logout": "Abmelden",

        "My Profile": "Mein Profil",
        "Personal information": "PersГ¶nliche Informationen",
        "Display name": "Anzeigename",
        "Username": "Benutzername",
        "Email": "E-Mail",
        "Language": "Sprache",
        "Notifications": "Benachrichtigungen",
        "Receive notifications": "Benachrichtigungen erhalten",
        "Avatar": "Avatar",
        "Save profile": "Profil speichern",
        "Save changes": "Г„nderungen speichern",

        "Account": "Konto",
        "Balance": "Guthaben",
        "Referral code": "Empfehlungscode",
        "Account ID": "Konto-ID",
        "Admin": "Administrator",
        "Yes": "Ja",
        "No": "Nein",

        "English": "Englisch",
        "Russian": "Russisch",
        "Italian": "Italienisch",
        "German": "Deutsch",
        "Japanese": "Japanisch",
        "Turkish": "TГјrkisch",

        "Русский": "Russisch",
        "Italiano": "Italienisch",
        "Deutsch": "Deutsch",
        "日本語": "Japanisch",
        "TГјrkГ§e": "TГјrkisch",

        "Profile updated successfully.": "Profil erfolgreich aktualisiert.",
        "Choose an earning method and get started.": "WГ¤hle eine Verdienstmethode und beginne.",
        "Available offers from connected providers.": "VerfГјgbare Angebote von verbundenen Anbietern.",
        "Available games from connected providers.": "VerfГјgbare Spiele von verbundenen Anbietern.",
        "Available apps from connected providers.": "VerfГјgbare Apps von verbundenen Anbietern.",

        "Save": "Speichern",
        "Cancel": "Abbrechen",
        "Back": "ZurГјck",
        "Continue": "Weiter",
        "Submit": "Absenden",
        "Search": "Suchen",
        "Loading": "Wird geladen",
        "Completed": "Abgeschlossen",
        "Pending": "Ausstehend",
        "Available": "VerfГјgbar",
        "Total": "Gesamt",
        "Today": "Heute",
        "Yesterday": "Gestern",
        "This week": "Diese Woche",
        "This month": "Diesen Monat",

        "Welcome": "Willkommen",
        "Welcome back": "Willkommen zurГјck",
        "Your balance": "Dein Guthaben",
        "Start earning": "Verdienen starten",
        "Earn money": "Geld verdienen",
        "Earn more": "Mehr verdienen",
        "Your rewards": "Deine Belohnungen",
        "Your activity": "Deine AktivitГ¤t",
        "Your referrals": "Deine Empfehlungen",

        "No data available": "Keine Daten verfГјgbar",
        "No offers available": "Keine Angebote verfГјgbar",
        "No games available": "Keine Spiele verfГјgbar",
        "No apps available": "Keine Apps verfГјgbar",
        "No tasks available": "Keine Aufgaben verfГјgbar",

        "Sign in": "Anmelden",
        "Sign up": "Registrieren",
        "Password": "Passwort",
        "Confirm password": "Passwort bestГ¤tigen",
        "Remember me": "Angemeldet bleiben",
        "Forgot password?": "Passwort vergessen?",
        "Don't have an account?": "Noch kein Konto?",
        "Already have an account?": "Bereits ein Konto?",

        "Invite friends": "Freunde einladen",
        "Referral program": "Empfehlungsprogramm",
        "Your referral link": "Dein Empfehlungslink",
        "Copy": "Kopieren",
        "Copied": "Kopiert",

        "Request payout": "Auszahlung anfordern",
        "Payout history": "Auszahlungsverlauf",
        "Minimum payout": "Mindestauszahlung",
        "Payment method": "Zahlungsmethode",

        "Home": "Startseite",
        "About": "Гњber uns",
        "Contact": "Kontakt",
        "Privacy": "Datenschutz",
        "Terms": "Bedingungen",
        "Help": "Hilfe",
    },

    "ja": {
        "Total earned": "зЌІеѕ—з·ЏйЎЌ",
        "Total paid": "ж”Їж‰•з·ЏйЎЌ",
        "Your EasySurf Dashboard": "РіРѓвЂљРіРѓР„РіРѓСџРіРѓВ®EasySurfРіС“Р‚РіС“С“РівЂљВ·РіС“ТђРіС“СљРіС“СРіС“вЂ°",
        "Earn now": "РґВ»Р‰РіРѓв„ўРіРѓС’Р·РЃСРіРѓС’",
        "Available balance": "Рµв‚¬В©Р·вЂќРЃРµРЏР‡РёС“Р…Р¶В®вЂ№Р№В«В",
        "Earned today": "д»Љж—ҐгЃ®зЌІеѕ—йЎЌ",
        "Pending rewards": "дїќз•™дё­гЃ®е ±й…¬",
        "Tasks completed": "е®Њдє†гЃ—гЃџг‚їг‚№г‚Ї",
        "Daily target": "1ж—ҐгЃ®з›®жЁ™",
        "Today's earning goal": "д»Љж—ҐгЃ®еЏЋз›Љз›®жЁ™",
        "Keep completing available activities to grow your balance.": "Рµв‚¬В©Р·вЂќРЃРµРЏР‡РёС“Р…РіРѓР„РівЂљСћРівЂљР‡РіС“вЂ РівЂљР€РіС“вЂњРіС“вЂ РівЂљР€РівЂљвЂ™Р·В¶С™РіРѓвЂРіРѓВ¦РµВ®РЉРґС”вЂ РіРѓвЂ”РіР‚РѓР¶В®вЂ№Р№В«ВРівЂљвЂ™РµСћвЂ”РівЂљвЂћРіРѓвЂ”РіРѓС•РіРѓвЂ”РівЂљвЂЎРіРѓвЂ РіР‚вЂљ",
        "Quick access": "г‚Їг‚¤гѓѓг‚Їг‚ўг‚Їг‚»г‚№",
        "View all": "гЃ™гЃ№гЃ¦иЎЁз¤є",
        "Surveys": "РівЂљСћРіС“С–РівЂљВ±РіС“СРіС“в‚¬",
        "Paid research surveys when inventory is available.": "Рµв‚¬В©Р·вЂќРЃРµРЏР‡РёС“Р…РіРѓР„РµВ Т‘РµС’в‚¬РіРѓВ«РµРЏвЂљРµР‰В РіРѓВ§РіРѓРЊРівЂљвЂ№Р¶СљвЂ°Р¶вЂ“в„ўРіС“Р„РівЂљВµРіС“СРіС“РѓРівЂљСћРіС“С–РівЂљВ±РіС“СРіС“в‚¬РіРѓВ§РіРѓв„ўРіР‚вЂљ",
        "View surveys": "РівЂљСћРіС“С–РівЂљВ±РіС“СРіС“в‚¬РівЂљвЂ™РёВ¦вЂ№РівЂљвЂ№",
        "Advertiser offers and tracked activities.": "РµС”С“РµвЂР‰РґС‘В»РіРѓВ®РівЂљР„РіС“вЂўРівЂљРЋРіС“СРіРѓРЃРёС—Р…РёВ·РЋРµР‡С•РёВ±РЋРіРѓВ®РівЂљСћРівЂљР‡РіС“вЂ РівЂљР€РіС“вЂњРіС“вЂ РівЂљР€РіР‚вЂљ",
        "View offers": "РівЂљР„РіС“вЂўРівЂљРЋРіС“СРівЂљвЂ™РёВ¦вЂ№РівЂљвЂ№",
        "Play approved games and reach milestones.": "Р¶вЂ°С—РёР„РЊРіРѓвЂўРівЂљРЉРіРѓСџРівЂљР†РіС“СРіС“В РівЂљвЂ™РіС“вЂ”РіС“В¬РівЂљВ¤РіРѓвЂ”РіРѓВ¦РіС“С›РівЂљВ¤РіС“В«РівЂљв„–РіС“в‚¬РіС“СРіС“С–РівЂљвЂ™Р№РѓвЂќР¶в‚¬С’РіРѓвЂ”РіРѓС•РіРѓвЂ”РівЂљвЂЎРіРѓвЂ РіР‚вЂљ",
        "View games": "РівЂљР†РіС“СРіС“В РівЂљвЂ™РёВ¦вЂ№РівЂљвЂ№",
        "Discover tracked app opportunities.": "РёС—Р…РёВ·РЋРµР‡С•РёВ±РЋРіРѓВ®РівЂљСћРіС“вЂ”РіС“Р„Р¶РЋв‚¬РґВ»В¶РівЂљвЂ™РёВ¦вЂ№РіРѓВ¤РіРѓвЂРіРѓС•РіРѓвЂ”РівЂљвЂЎРіРѓвЂ РіР‚вЂљ",
        "View apps": "г‚ўгѓ—гѓЄг‚’и¦‹г‚‹",
        "Available now": "зЏѕењЁе€©з”ЁеЏЇиѓЅ",
        "Website Tasks": "г‚¦г‚§гѓ–г‚µг‚¤гѓ€г‚їг‚№г‚Ї",
        "Browse earning options": "еЏЋз›Љг‚Єгѓ—г‚·гѓ§гѓіг‚’и¦‹г‚‹",
        "Your account": "гЃ‚гЃЄгЃџгЃ®г‚ўг‚«г‚¦гѓігѓ€",
        "Recent Activity": "Р¶СљР‚РёС—вЂРіРѓВ®РівЂљСћРівЂљР‡РіС“вЂ РівЂљР€РіС“вЂњРіС“вЂ РівЂљР€",
        "No activity yet. Start earning to see your transactions here.": "РіРѓС•РіРѓВ РівЂљСћРівЂљР‡РіС“вЂ РівЂљР€РіС“вЂњРіС“вЂ РівЂљР€РіРѓР‡РіРѓвЂљРівЂљР‰РіРѓС•РіРѓвЂєРівЂљвЂњРіР‚вЂљР·РЃСРіРѓР‹РµВ§вЂ№РівЂљРѓРівЂљвЂ№РіРѓРЃРіРѓвЂњРіРѓвЂњРіРѓВ«РµРЏвЂ“РµСвЂўРіРѓРЉРёРЋРЃР·В¤С”РіРѓвЂўРівЂљРЉРіРѓС•РіРѓв„ўРіР‚вЂљ",
        "Amount": "Р№вЂЎвЂР№РЋРЊ",
        "Goal": "з›®жЁ™",
        "earned today": "д»Љж—ҐгЃ®зЌІеѕ—йЎЌ",
        "Dashboard": "РіС“Р‚РіС“С“РівЂљВ·РіС“ТђРіС“СљРіС“СРіС“вЂ°",
        "Profile": "РіС“вЂ”РіС“В­РіС“вЂўРівЂљР€РіС“СРіС“В«",
        "Earn": "Р·РЃСРіРѓС’",
        "Rewards": "е ±й…¬",
        "Activity": "г‚ўг‚Їгѓ†г‚Јгѓ“гѓ†г‚Ј",
        "Leaderboard": "гѓ©гѓіг‚­гѓіг‚°",
        "Referrals": "зґ№д»‹",
        "Withdraw": "РµвЂЎС”Р№вЂЎвЂ",
        "Payouts": "ж”Їж‰•гЃ„",
        "Offers": "РівЂљР„РіС“вЂўРівЂљРЋРіС“С",
        "Games": "РівЂљР†РіС“СРіС“В ",
        "Apps": "г‚ўгѓ—гѓЄ",
        "Tasks": "г‚їг‚№г‚Ї",
        "Microtasks": "гѓћг‚¤г‚Їгѓ­г‚їг‚№г‚Ї",
        "Login": "гѓ­г‚°г‚¤гѓі",
        "Register": "з™»йЊІ",
        "Get Started": "е§‹г‚Ѓг‚‹",
        "Logout": "гѓ­г‚°г‚ўг‚¦гѓ€",

        "My Profile": "РіС“С›РівЂљВ¤РіС“вЂ”РіС“В­РіС“вЂўРівЂљР€РіС“СРіС“В«",
        "Personal information": "еЂ‹дєєжѓ…е ±",
        "Display name": "иЎЁз¤єеђЌ",
        "Username": "РіС“В¦РіС“СРівЂљВ¶РіС“СРµС’РЊ",
        "Email": "РіС“РЋРіС“СРіС“В«РівЂљСћРіС“вЂ°РіС“В¬РівЂљв„–",
        "Language": "言語",
        "Notifications": "йЂљзџҐ",
        "Receive notifications": "Р№Р‚С™Р·СџТђРівЂљвЂ™РµРЏвЂ”РіРѓвЂРµРЏвЂ“РівЂљвЂ№",
        "Avatar": "РівЂљСћРіС“С’РівЂљС—РіС“С",
        "Save profile": "РіС“вЂ”РіС“В­РіС“вЂўРівЂљР€РіС“СРіС“В«РівЂљвЂ™РґС—СњРµВ­В",
        "Save changes": "РµВ¤вЂ°Р¶вЂєТ‘РівЂљвЂ™РґС—СњРµВ­В",

        "Account": "г‚ўг‚«г‚¦гѓігѓ€",
        "Balance": "Р¶В®вЂ№Р№В«В",
        "Referral code": "Р·Т‘в„–РґВ»вЂ№РівЂљС–РіС“СРіС“вЂ°",
        "Account ID": "г‚ўг‚«г‚¦гѓігѓ€ID",
        "Admin": "з®Ўзђ†иЂ…",
        "Yes": "гЃЇгЃ„",
        "No": "гЃ„гЃ„гЃ€",

        "English": "英語",
        "Russian": "ロシア語",
        "Italian": "イタリア語",
        "German": "ドイツ語",
        "Japanese": "日本語",
        "Turkish": "トルコ語",

        "Русский": "ロシア語",
        "Italiano": "イタリア語",
        "Deutsch": "ドイツ語",
        "日本語": "日本語",
        "Türkçe": "トルコ語",

        "Profile updated successfully.": "РіС“вЂ”РіС“В­РіС“вЂўРівЂљР€РіС“СРіС“В«РівЂљвЂ™Р¶В­Р€РµС‘С‘РіРѓВ«Р¶вЂєТ‘Р¶вЂ“В°РіРѓвЂ”РіРѓС•РіРѓвЂ”РіРѓСџРіР‚вЂљ",
        "Choose an earning method and get started.": "еЏЋз›Љж–№жі•г‚’йЃёжЉћгЃ—гЃ¦е§‹г‚ЃгЃѕгЃ—г‚‡гЃ†гЂ‚",
        "Available offers from connected providers.": "Р¶Р‹ТђР·В¶С™РіРѓвЂўРівЂљРЉРіРѓСџРіС“вЂ”РіС“В­РіС“С’РівЂљВ¤РіС“Р‚РіС“СРіРѓвЂ№РівЂљвЂ°Рµв‚¬В©Р·вЂќРЃРµРЏР‡РёС“Р…РіРѓР„РівЂљР„РіС“вЂўРівЂљРЋРіС“СРіР‚вЂљ",
        "Available games from connected providers.": "Р¶Р‹ТђР·В¶С™РіРѓвЂўРівЂљРЉРіРѓСџРіС“вЂ”РіС“В­РіС“С’РівЂљВ¤РіС“Р‚РіС“СРіРѓвЂ№РівЂљвЂ°Рµв‚¬В©Р·вЂќРЃРµРЏР‡РёС“Р…РіРѓР„РівЂљР†РіС“СРіС“В РіР‚вЂљ",
        "Available apps from connected providers.": "Р¶Р‹ТђР·В¶С™РіРѓвЂўРівЂљРЉРіРѓСџРіС“вЂ”РіС“В­РіС“С’РівЂљВ¤РіС“Р‚РіС“СРіРѓвЂ№РівЂљвЂ°Рµв‚¬В©Р·вЂќРЃРµРЏР‡РёС“Р…РіРѓР„РівЂљСћРіС“вЂ”РіС“Р„РіР‚вЂљ",

        "Save": "РґС—СњРµВ­В",
        "Cancel": "г‚­гѓЈгѓіг‚»гѓ«",
        "Back": "ж€»г‚‹",
        "Continue": "з¶љиЎЊ",
        "Submit": "йЂЃдїЎ",
        "Search": "ж¤њзґў",
        "Loading": "РёР„В­РіРѓС—РёС•СРіРѓС—РґС‘В­",
        "Completed": "е®Њдє†",
        "Pending": "дїќз•™дё­",
        "Available": "е€©з”ЁеЏЇиѓЅ",
        "Total": "еђ€иЁ€",
        "Today": "д»Љж—Ґ",
        "Yesterday": "Вчера",
        "This week": "д»ЉйЂ±",
        "This month": "д»Љжњ€",

        "Welcome": "г‚€гЃ†гЃ“гЃќ",
        "Welcome back": "гЃЉгЃ‹гЃ€г‚ЉгЃЄгЃ•гЃ„",
        "Your balance": "РіРѓвЂљРіРѓР„РіРѓСџРіРѓВ®Р¶В®вЂ№Р№В«В",
        "Start earning": "еЏЋз›Љг‚’й–‹е§‹",
        "Earn money": "РіРѓР‰Р№вЂЎвЂРівЂљвЂ™Р·РЃСРіРѓС’",
        "Earn more": "РівЂљвЂљРіРѓР€РіРѓРЃР·РЃСРіРѓС’",
        "Your rewards": "гЃ‚гЃЄгЃџгЃ®е ±й…¬",
        "Your activity": "гЃ‚гЃЄгЃџгЃ®г‚ўг‚Їгѓ†г‚Јгѓ“гѓ†г‚Ј",
        "Your referrals": "гЃ‚гЃЄгЃџгЃ®зґ№д»‹",

        "No data available": "Рµв‚¬В©Р·вЂќРЃРµРЏР‡РёС“Р…РіРѓР„РіС“вЂЎРіС“СРівЂљС—РіРѓР‡РіРѓвЂљРівЂљР‰РіРѓС•РіРѓвЂєРівЂљвЂњ",
        "No offers available": "Рµв‚¬В©Р·вЂќРЃРµРЏР‡РёС“Р…РіРѓР„РівЂљР„РіС“вЂўРівЂљРЋРіС“СРіРѓР‡РіРѓвЂљРівЂљР‰РіРѓС•РіРѓвЂєРівЂљвЂњ",
        "No games available": "Рµв‚¬В©Р·вЂќРЃРµРЏР‡РёС“Р…РіРѓР„РівЂљР†РіС“СРіС“В РіРѓР‡РіРѓвЂљРівЂљР‰РіРѓС•РіРѓвЂєРівЂљвЂњ",
        "No apps available": "е€©з”ЁеЏЇиѓЅгЃЄг‚ўгѓ—гѓЄгЃЇгЃ‚г‚ЉгЃѕгЃ›г‚“",
        "No tasks available": "е€©з”ЁеЏЇиѓЅгЃЄг‚їг‚№г‚ЇгЃЇгЃ‚г‚ЉгЃѕгЃ›г‚“",

        "Sign in": "гѓ­г‚°г‚¤гѓі",
        "Sign up": "з™»йЊІгЃ™г‚‹",
        "Password": "РіС“вЂРівЂљв„–РіС“Р‡РіС“СРіС“вЂ°",
        "Confirm password": "РіС“вЂРівЂљв„–РіС“Р‡РіС“СРіС“вЂ°РівЂљвЂ™Р·СћС”РёР„РЊ",
        "Remember me": "гѓ­г‚°г‚¤гѓізЉ¶ж…‹г‚’дїќжЊЃ",
        "Forgot password?": "РіС“вЂРівЂљв„–РіС“Р‡РіС“СРіС“вЂ°РівЂљвЂ™РµС—ВРівЂљРЉРіРѓС•РіРѓвЂ”РіРѓСџРіРѓвЂ№РїССџ",
        "Don't have an account?": "РівЂљСћРівЂљВ«РівЂљВ¦РіС“С–РіС“в‚¬РівЂљвЂ™РіРѓР‰Р¶РЉРѓРіРѓРЋРіРѓВ§РіРѓР„РіРѓвЂћРіРѓВ§РіРѓв„ўРіРѓвЂ№РїССџ",
        "Already have an account?": "РіРѓв„ўРіРѓВ§РіРѓВ«РівЂљСћРівЂљВ«РівЂљВ¦РіС“С–РіС“в‚¬РівЂљвЂ™РіРѓР‰Р¶РЉРѓРіРѓРЋРіРѓВ§РіРѓв„ўРіРѓвЂ№РїССџ",

        "Invite friends": "еЏ‹йЃ”г‚’ж‹›еѕ…",
        "Referral program": "зґ№д»‹гѓ—гѓ­г‚°гѓ©гѓ ",
        "Your referral link": "гЃ‚гЃЄгЃџгЃ®зґ№д»‹гѓЄгѓіг‚Ї",
        "Copy": "РівЂљС–РіС“вЂќРіС“С",
        "Copied": "РівЂљС–РіС“вЂќРіС“СРіРѓвЂ”РіРѓС•РіРѓвЂ”РіРѓСџ",

        "Request payout": "ж”Їж‰•гЃ„г‚’з”іи«‹",
        "Payout history": "ж”Їж‰•гЃ„е±Ґж­ґ",
        "Minimum payout": "жњЂдЅЋж”Їж‰•йЎЌ",
        "Payment method": "ж”Їж‰•гЃ„ж–№жі•",

        "Home": "РіС“вЂєРіС“СРіС“В ",
        "About": "ж¦‚и¦Ѓ",
        "Contact": "гЃЉе•ЏгЃ„еђ€г‚ЏгЃ›",
        "Privacy": "РіС“вЂ”РіС“В©РівЂљВ¤РіС“С’РівЂљВ·РіС“С",
        "Terms": "е€©з”Ёи¦Џзґ„",
        "Help": "РіС“ВРіС“В«РіС“вЂ”",
    },

    "tr": {
        "Total earned": "Toplam kazanГ§",
        "Total paid": "Toplam Г¶deme",
        "Your EasySurf Dashboard": "EasySurf Kontrol Paneliniz",
        "Earn now": "Ећimdi kazan",
        "Available balance": "KullanД±labilir bakiye",
        "Earned today": "BugГјn kazanД±lan",
        "Pending rewards": "Bekleyen Г¶dГјller",
        "Tasks completed": "Tamamlanan gГ¶revler",
        "Daily target": "GГјnlГјk hedef",
        "Today's earning goal": "BugГјnГјn kazanГ§ hedefi",
        "Keep completing available activities to grow your balance.": "Bakiyenizi artД±rmak iГ§in mevcut etkinlikleri tamamlamaya devam edin.",
        "Quick access": "HД±zlД± eriЕџim",
        "View all": "TГјmГјnГј gГ¶rГјntГјle",
        "Surveys": "Anketler",
        "Paid research surveys when inventory is available.": "Kontenjan olduğunda ücretli araştırma anketleri.",
        "View surveys": "Anketleri gГ¶rГјntГјle",
        "Advertiser offers and tracked activities.": "Reklamveren teklifleri ve takip edilen etkinlikler.",
        "View offers": "Teklifleri gГ¶rГјntГјle",
        "Play approved games and reach milestones.": "OnaylД± oyunlarД± oynayД±n ve kilometre taЕџlarД±na ulaЕџД±n.",
        "View games": "OyunlarД± gГ¶rГјntГјle",
        "Discover tracked app opportunities.": "Takip edilen uygulama fД±rsatlarД±nД± keЕџfedin.",
        "View apps": "UygulamalarД± gГ¶rГјntГјle",
        "Available now": "Ећimdi mevcut",
        "Website Tasks": "Web Sitesi GГ¶revleri",
        "Browse earning options": "KazanГ§ seГ§eneklerine gГ¶z at",
        "Your account": "HesabД±nД±z",
        "Recent Activity": "Son Etkinlikler",
        "No activity yet. Start earning to see your transactions here.": "Henüz etkinlik yok. İşlem geçmişinizi burada görmek için kazanmaya başlayın.",
        "Amount": "Tutar",
        "Goal": "Hedef",
        "earned today": "bugГјn kazanД±lan",
        "Dashboard": "Kontrol Paneli",
        "Profile": "Profil",
        "Earn": "Kazan",
        "Rewards": "Г–dГјller",
        "Activity": "Aktivite",
        "Leaderboard": "Liderlik Tablosu",
        "Referrals": "Referanslar",
        "Withdraw": "Para Г‡ekme",
        "Payouts": "Г–demeler",
        "Offers": "Teklifler",
        "Games": "Oyunlar",
        "Apps": "Uygulamalar",
        "Tasks": "GГ¶revler",
        "Microtasks": "Mikro GГ¶revler",
        "Login": "GiriЕџ Yap",
        "Register": "KayД±t Ol",
        "Get Started": "BaЕџla",
        "Logout": "Г‡Д±kД±Еџ Yap",

        "My Profile": "Profilim",
        "Personal information": "KiЕџisel bilgiler",
        "Display name": "GГ¶rГјnen ad",
        "Username": "KullanД±cД± adД±",
        "Email": "E-posta",
        "Language": "Dil",
        "Notifications": "Bildirimler",
        "Receive notifications": "Bildirimleri al",
        "Avatar": "Avatar",
        "Save profile": "Profili kaydet",
        "Save changes": "DeДџiЕџiklikleri kaydet",

        "Account": "Hesap",
        "Balance": "Bakiye",
        "Referral code": "Referans kodu",
        "Account ID": "Hesap ID",
        "Admin": "YГ¶netici",
        "Yes": "Evet",
        "No": "HayД±r",

        "English": "Д°ngilizce",
        "Russian": "RusГ§a",
        "Italian": "Д°talyanca",
        "German": "Almanca",
        "Japanese": "Japonca",
        "Turkish": "TГјrkГ§e",

        "Русский": "Rusça",
        "Italiano": "Д°talyanca",
        "Deutsch": "Almanca",
        "日本語": "Japonca",
        "TГјrkГ§e": "TГјrkГ§e",

        "Profile updated successfully.": "Profil başarıyla güncellendi.",
        "Choose an earning method and get started.": "Bir kazanç yöntemi seçin ve başlayın.",
        "Available offers from connected providers.": "BaДџlД± saДџlayД±cД±lardan mevcut teklifler.",
        "Available games from connected providers.": "BaДџlД± saДџlayД±cД±lardan mevcut oyunlar.",
        "Available apps from connected providers.": "BaДџlД± saДџlayД±cД±lardan mevcut uygulamalar.",

        "Save": "Kaydet",
        "Cancel": "Д°ptal",
        "Back": "Geri",
        "Continue": "Devam Et",
        "Submit": "GГ¶nder",
        "Search": "Ara",
        "Loading": "YГјkleniyor",
        "Completed": "TamamlandД±",
        "Pending": "Beklemede",
        "Available": "Mevcut",
        "Total": "Toplam",
        "Today": "BugГјn",
        "Yesterday": "DГјn",
        "This week": "Bu hafta",
        "This month": "Bu ay",

        "Welcome": "HoЕџ geldiniz",
        "Welcome back": "Tekrar hoЕџ geldiniz",
        "Your balance": "Bakiyeniz",
        "Start earning": "Kazanmaya baЕџla",
        "Earn money": "Para kazan",
        "Earn more": "Daha fazla kazan",
        "Your rewards": "Г–dГјlleriniz",
        "Your activity": "Aktiviteleriniz",
        "Your referrals": "ReferanslarД±nД±z",

        "No data available": "Veri bulunamadД±",
        "No offers available": "Teklif bulunamadД±",
        "No games available": "Oyun bulunamadД±",
        "No apps available": "Uygulama bulunamadД±",
        "No tasks available": "GГ¶rev bulunamadД±",

        "Sign in": "GiriЕџ Yap",
        "Sign up": "KayД±t Ol",
        "Password": "Ећifre",
        "Confirm password": "Ећifreyi onayla",
        "Remember me": "Beni hatД±rla",
        "Forgot password?": "Ећifrenizi mi unuttunuz?",
        "Don't have an account?": "HesabД±nД±z yok mu?",
        "Already have an account?": "Zaten hesabД±nД±z var mД±?",

        "Invite friends": "ArkadaЕџlarД±nД± davet et",
        "Referral program": "Referans programД±",
        "Your referral link": "Referans baДџlantД±nД±z",
        "Copy": "Kopyala",
        "Copied": "KopyalandД±",

        "Request payout": "Г–deme talep et",
        "Payout history": "Ödeme geçmişi",
        "Minimum payout": "Minimum Г¶deme",
        "Payment method": "Г–deme yГ¶ntemi",

        "Home": "Ana Sayfa",
        "About": "HakkД±mД±zda",
        "Contact": "Д°letiЕџim",
        "Privacy": "Gizlilik",
        "Terms": "KoЕџullar",
        "Help": "YardД±m",
    },
}





# Initialize the database schema immediately when the application module is loaded.
init()

def get_language(u=None):
    language = CURRENT_LANGUAGE.get()

    if language in SUPPORTED_LANGUAGES:
        return language

    try:
        if u is not None:
            language = u["language"]
            if language in SUPPORTED_LANGUAGES:
                return language
    except Exception:
        pass

    return "en"

def tr(text, u=None):
    language = get_language(u)

    translations = LANGUAGE_TRANSLATIONS.get(language, {})

    if text in translations:
        return translations[text]

    english = LANGUAGE_TRANSLATIONS.get("en", {})

    if text in english:
        return english[text]

    return text

def esc_attr(value):
    return str(value).replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;").replace(">", "&gt;")



def layout(title, body, u=None):
    language = get_language(u)
    language_options = "".join(
        '<option value="' + code + '"' + (' selected' if code == language else '') + '>' + label + '</option>'
        for code, label in SUPPORTED_LANGUAGES.items()
    )
    current_path = "/"
    if u is not None:
        current_path = "/dashboard"

    language_form = (
        '<div class="language-switcher" style="display:flex;align-items:center;gap:8px;font-size:14px;font-weight:600;position:relative;z-index:1000;">'
        '<a href="/language?language=en&amp;next=' + current_path + '" style="display:inline-block;position:relative;z-index:1001;padding:4px 2px;color:' + ('#ffffff' if language == 'en' else '#94a3b8') + ';text-decoration:none;cursor:pointer;">English</a>'
        '<span style="opacity:.45;position:relative;z-index:1001;">|</span>'
        '<a href="/language?language=ru&amp;next=' + current_path + '" style="display:inline-block;position:relative;z-index:1001;padding:4px 2px;color:' + ('#ffffff' if language == 'ru' else '#94a3b8') + ';text-decoration:none;cursor:pointer;">Русский</a>'
        '</div>'
    )
    if not u:
        nav = (
            '<a href="/">' + tr('Home', u) + '</a>'
            '<a href="/login">' + tr('Login', u) + '</a>'
            '<a class="nav-btn" href="/register">' + tr('Get Started', u) + '</a>'
        )
    else:
        admin_link = '<a href="/admin">' + tr('Admin', u) + '</a>' if u["is_admin"] else ''
        nav = (
            '<a href="/dashboard">' + tr('Dashboard', u) + '</a>'
            '<a href="/profile">' + tr('Profile', u) + '</a>'
            '<a href="/earn">' + tr('Earn', u) + '</a>'
            '<a href="/rewards">' + tr('Rewards', u) + '</a>'
            '<a href="/activity">' + tr('Activity', u) + '</a>'
            '<a href="/leaderboard">' + tr('Leaderboard', u) + '</a>'
            '<a href="/referrals">' + tr('Referrals', u) + '</a>'
            '<a href="/payouts">' + tr('Withdraw', u) + '</a>'
            + admin_link +
            '<span class="balance-pill">&#128176; ' + money(u["balance"]) + '</span>'
            '<a href="/logout">' + tr('Logout', u) + '</a>' + language_form
        )
    return f"""<!doctype html>

<html lang="{language}">
<head><link rel="icon" type="image/png" href="/static/images/favicon.png">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} В· EasySurf</title>

<style>
*{{box-sizing:border-box}}.language-form{{display:inline-flex;align-items:center;margin:0 8px 0 0}}.language-form select{{display:block}}.language-selector{{appearance:none;-webkit-appearance:none;background:#111f33;color:#fff;border:1px solid rgba(255,255,255,.16);border-radius:10px;padding:8px 34px 8px 12px;min-width:135px;font-size:14px;font-weight:600;cursor:pointer;outline:none;margin-right:10px}}.language-selector:hover{{border-color:rgba(255,255,255,.35);background-color:#162942}}.language-selector:focus{{border-color:#4da3ff;box-shadow:0 0 0 3px rgba(77,163,255,.15)}}.language-selector option{{background:#111f33;color:#fff}}

:root{{
 --bg:#07111f;
 --bg2:#0b1728;
 --card:rgba(15,31,52,.88);
 --card2:#10233b;
 --text:#f8fafc;
 --muted:#94a3b8;
 --border:rgba(148,163,184,.16);
 --primary:#38bdf8;
 --primary2:#2563eb;
 --green:#22c55e;
 --orange:#f59e0b;
 --purple:#a78bfa;
 --danger:#fb7185;
 --shadow:0 20px 60px rgba(0,0,0,.28);
}}

html{{
 scroll-behavior:smooth;
}}

.auth-card{{
 width:min(100%,520px);
 margin:40px auto;
 padding:34px 38px;
 border-radius:24px;
 background:linear-gradient(145deg,rgba(16,35,59,.98),rgba(9,24,41,.98));
 border:1px solid var(--border);
 box-shadow:0 20px 55px rgba(0,0,0,.24);
}}

.auth-card h2{{
 margin:0 0 26px;
 font-size:30px;
 line-height:1.2;
 text-align:center;
}}

.auth-card form{{
 display:flex;
 flex-direction:column;
 gap:0;
}}

.auth-card label{{
 display:block;
 margin:0 0 8px;
 font-size:14px;
 font-weight:600;
 color:#dbeafe;
}}

.auth-card input{{
 width:100%;
 box-sizing:border-box;
 min-height:48px;
 margin:0 0 18px;
 padding:0 15px;
 border-radius:12px;
 border:1px solid rgba(148,163,184,.22);
 background:rgba(15,23,42,.72);
 color:#f8fafc;
 font-size:15px;
 outline:none;
 transition:border-color .2s,box-shadow .2s,background .2s;
}}

.auth-card input:focus{{
 border-color:rgba(96,165,250,.65);
 box-shadow:0 0 0 3px rgba(59,130,246,.12);
 background:rgba(15,23,42,.9);
}}

.auth-card button{{
 width:100%;
 min-height:50px;
 margin-top:4px;
 border:0;
 border-radius:12px;
 font-size:16px;
 font-weight:700;
 cursor:pointer;
}}

@media (max-width:640px){{
 .auth-card{{
  width:auto;
  margin:24px 12px;
  padding:26px 20px;
  border-radius:20px;
 }}
 .auth-card h2{{
  font-size:26px;
 }}
}}
body{{
 margin:0;
 min-height:100vh;
 background:
   radial-gradient(circle at 10% 0%,rgba(37,99,235,.20),transparent 32%),
   radial-gradient(circle at 90% 10%,rgba(56,189,248,.13),transparent 28%),
   linear-gradient(180deg,var(--bg),#050b14 100%);
 color:var(--text);
 font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;
 line-height:1.55;
}}

body::before{{
 content:"";
 position:fixed;
 inset:0;
 pointer-events:none;
 background-image:
   linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),
   linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px);
 background-size:48px 48px;
 mask-image:linear-gradient(to bottom,black,transparent 80%);
}}

header{{
 position:sticky;
 top:0;
 z-index:100;
 min-height:72px;
 padding:0 28px;
 display:flex;
 align-items:center;
 justify-content:space-between;
 gap:20px;
 background:rgba(5,13,25,.82);
 border-bottom:1px solid var(--border);
 backdrop-filter:blur(18px);
 -webkit-backdrop-filter:blur(18px);
}}

.brand{{
 display:flex;
 align-items:center;
 gap:10px;
 color:#fff;
 font-size:24px;
 font-weight:950;
 letter-spacing:-.7px;
 text-decoration:none;
 white-space:nowrap;
}}

.brand::before{{
 content:"⚡";
 width:38px;
 height:38px;
 display:grid;
 place-items:center;
 border-radius:12px;
 background:linear-gradient(135deg,var(--primary),var(--primary2));
 box-shadow:0 8px 25px rgba(37,99,235,.35);
 font-size:20px;
}}

nav{{
 display:flex;
 align-items:center;
 justify-content:flex-end;
 gap:4px;
 flex-wrap:nowrap;
 white-space:nowrap;
 min-width:0;
}}

.language-switcher{{
 display:inline-flex !important;
 align-items:center;
 justify-content:center;
 gap:8px;
 flex:0 0 auto;
 white-space:nowrap;
 margin-left:6px;
}}

@media (max-width:1100px){{
 nav{{
  flex-wrap:wrap;
  justify-content:flex-end;
 }}
}}

@media (max-width:700px){{
 header{{
  padding:0 16px;
  flex-wrap:wrap;
 }}

 nav{{
  width:100%;
  justify-content:flex-start;
  padding-bottom:10px;
  overflow-x:auto;
  flex-wrap:nowrap;
 }}
}}
nav a{{
 color:#cbd5e1;
 text-decoration:none;
 padding:9px 11px;
 border-radius:10px;
 font-size:13px;
 font-weight:700;
 transition:.2s ease;
}}

nav a:hover{{
 color:#fff;
 background:rgba(255,255,255,.07);
 transform:translateY(-1px);
}}

nav .nav-btn{{
 color:#fff;
 padding:10px 16px;
 background:linear-gradient(135deg,var(--primary2),#0ea5e9);
 box-shadow:0 8px 24px rgba(37,99,235,.30);
}}

nav .nav-btn:hover{{
 background:linear-gradient(135deg,#1d4ed8,#0284c7);
}}

.balance-pill{{
 display:inline-flex;
 align-items:center;
 gap:5px;
 color:#bbf7d0;
 background:rgba(34,197,94,.10);
 border:1px solid rgba(34,197,94,.22);
 padding:8px 12px;
 border-radius:999px;
 font-weight:900;
 margin-left:5px;
 white-space:nowrap;
}}

main{{
 position:relative;
 z-index:1;
 width:100%;
 max-width:1220px;
 margin:0 auto;
 padding:36px 22px 70px;
}}

.hero{{
 position:relative;
 overflow:hidden;
 background:
   radial-gradient(circle at 85% 20%,rgba(56,189,248,.22),transparent 28%),
   linear-gradient(135deg,#0f2747,#102b5f 52%,#0b3b63);
 color:#fff;
 border:1px solid rgba(125,211,252,.16);
 border-radius:26px;
 padding:42px;
 margin-bottom:24px;
 box-shadow:var(--shadow);
}}

.hero::after{{
 content:"";
 position:absolute;
 width:280px;
 height:280px;
 right:-100px;
 bottom:-140px;
 border-radius:50%;
 background:rgba(56,189,248,.12);
}}

.hero h1{{
 position:relative;
 z-index:1;
 margin:0 0 10px;
 font-size:clamp(30px,5vw,48px);
 line-height:1.08;
 letter-spacing:-1.5px;
}}

.hero p{{
 position:relative;
 z-index:1;
 max-width:720px;
 color:#dbeafe;
 font-size:16px;
}}

.grid{{
 display:grid;
 grid-template-columns:repeat(auto-fit,minmax(220px,1fr));
 gap:18px;
}}

.card{{
 position:relative;
 overflow:hidden;
 background:linear-gradient(145deg,rgba(16,35,59,.94),rgba(9,24,41,.94));
 border:1px solid var(--border);
 border-radius:20px;
 padding:22px;
 margin-bottom:18px;
 box-shadow:0 12px 35px rgba(0,0,0,.16);
 transition:transform .2s ease,border-color .2s ease,box-shadow .2s ease;
}}

.card:hover{{
 transform:translateY(-2px);
 border-color:rgba(56,189,248,.24);
 box-shadow:0 18px 45px rgba(0,0,0,.24);
}}

.card h2,.card h3{{
 margin-top:0;
 color:#fff;
}}

.metric{{
 font-size:32px;
 font-weight:950;
 letter-spacing:-1px;
 margin-top:7px;
}}

.muted{{
 color:var(--muted);
}}

.btn{{
 display:inline-flex;
 align-items:center;
 justify-content:center;
 gap:7px;
 border:0;
 border-radius:12px;
 background:linear-gradient(135deg,var(--primary2),#0ea5e9);
 color:#fff;
 padding:12px 18px;
 font-weight:850;
 text-decoration:none;
 cursor:pointer;
 box-shadow:0 9px 25px rgba(37,99,235,.25);
 transition:.2s ease;
}}

.btn:hover{{
 transform:translateY(-1px);
 box-shadow:0 12px 30px rgba(37,99,235,.35);
}}

.secondary{{
 background:#334155;
 box-shadow:none;
}}

.green{{
 color:var(--green);
}}

.orange{{
 color:var(--orange);
}}

.earn-card{{
 min-height:180px;
 display:flex;
 flex-direction:column;
 justify-content:space-between;
}}

.earn-icon{{
 width:54px;
 height:54px;
 display:grid;
 place-items:center;
 border-radius:16px;
 background:rgba(56,189,248,.10);
 border:1px solid rgba(56,189,248,.18);
 font-size:29px;
 margin-bottom:12px;
}}

.progress{{
 height:12px;
 background:#17263a;
 border:1px solid rgba(148,163,184,.10);
 border-radius:999px;
 overflow:hidden;
}}

.progress-bar{{
 height:100%;
 background:linear-gradient(90deg,#2563eb,#38bdf8);
 border-radius:999px;
 box-shadow:0 0 18px rgba(56,189,248,.35);
}}

.notice{{
 padding:15px 17px;
 background:rgba(37,99,235,.10);
 border:1px solid rgba(96,165,250,.20);
 border-radius:14px;
 margin-bottom:17px;
}}

.success{{
 background:rgba(34,197,94,.09);
 border-color:rgba(34,197,94,.20);
}}

.empty{{
 text-align:center;
 padding:48px 20px;
 color:var(--muted);
}}

.timer{{
 font-size:54px;
 text-align:center;
 font-weight:950;
 color:#38bdf8;
 margin:22px;
 text-shadow:0 0 25px rgba(56,189,248,.22);
}}

table{{
 width:100%;
 border-collapse:collapse;
 overflow:hidden;
}}

th,td{{
 padding:13px 12px;
 border-bottom:1px solid rgba(148,163,184,.11);
 text-align:left;
}}

th{{
 color:#94a3b8;
 font-size:12px;
 text-transform:uppercase;
 letter-spacing:.06em;
}}

input,select{{
 width:100%;
 padding:12px 13px;
 color:#f8fafc;
 background:#0b1a2d;
 border:1px solid rgba(148,163,184,.20);
 border-radius:11px;
 outline:none;
}}

input:focus,select:focus{{
 border-color:#38bdf8;
 box-shadow:0 0 0 3px rgba(56,189,248,.10);
}}

option{{
 background:#0b1a2d;
 color:#fff;
}}

form{{
 display:grid;
 gap:12px;
}}

footer{{
 position:relative;
 z-index:1;
 text-align:center;
 color:#64748b;
 padding:34px 20px;
 border-top:1px solid var(--border);
 background:rgba(3,9,17,.55);
}}

@media(max-width:1050px){{
 header{{
  padding:12px 18px;
  align-items:center;
 }}

 nav{{
  max-width:760px;
 }}

 nav a{{
  font-size:12px;
  padding:7px 8px;
 }}
}}

@media(max-width:700px){{
 header{{
  position:relative;
  flex-direction:column;
  align-items:stretch;
  padding:14px;
 }}

 .brand{{
  justify-content:center;
 }}

 nav{{
  justify-content:center;
  gap:4px;
 }}

 nav a{{
  font-size:12px;
  padding:7px 8px;
 }}

 .balance-pill{{
  margin-left:0;
 }}

 main{{
  padding:22px 13px 50px;
 }}

 .hero{{
  padding:28px 21px;
  border-radius:21px;
 }}

 .hero h1{{
  font-size:30px;
 }}

 .card{{
  border-radius:17px;
  padding:18px;
 }}

 .metric{{
  font-size:28px;
 }}

 table{{
  display:block;
  overflow-x:auto;
  white-space:nowrap;
 }}
}}

@media(max-width:430px){{
 nav a{{
  font-size:11px;
  padding:6px;
 }}

 .hero h1{{
  font-size:27px;
 }}

 .btn{{
  width:100%;
 }}

 .grid{{
  grid-template-columns:1fr;
 }}
}}

/* ===== EasySurf Modern Footer ===== */

.footer-wrap{{
  width:100%;
  max-width:1200px;
  margin:0 auto;
}}

.footer-grid{{
  display:grid;
  grid-template-columns:2fr repeat(4,1fr);
  gap:42px;
  max-width:1200px;
  margin:0 auto;
  text-align:left;
}}

.footer-brand{{
  padding-right:25px;
}}

.footer-logo{{
  display:inline-flex;
  align-items:center;
  gap:11px;
  color:#f8fafc;
  text-decoration:none;
  font-size:22px;
  font-weight:800;
  letter-spacing:-.4px;
}}

.footer-logo:hover{{
  color:#ffffff;
  text-decoration:none;
}}

.footer-logo-mark{{
  width:36px;
  height:36px;
  display:inline-flex;
  align-items:center;
  justify-content:center;
  border-radius:11px;
  background:linear-gradient(135deg,#38bdf8,#6366f1);
  color:#ffffff;
  font-size:18px;
  font-weight:900;
  box-shadow:0 8px 24px rgba(56,189,248,.18);
}}

.footer-description{{
  margin:17px 0 0;
  max-width:330px;
  color:#94a3b8;
  font-size:14px;
  line-height:1.7;
}}

.footer-heading{{
  margin:3px 0 16px;
  color:#f8fafc;
  font-size:14px;
  font-weight:800;
  letter-spacing:.2px;
}}

.footer-links{{
  display:flex;
  flex-direction:column;
  gap:10px;
}}

.footer-links a{{
  width:max-content;
  color:#94a3b8;
  text-decoration:none;
  font-size:13px;
  line-height:1.4;
  transition:color .18s ease,transform .18s ease;
}}

.footer-links a:hover{{
  color:#38bdf8;
  text-decoration:none;
  transform:translateX(3px);
}}

.footer-divider{{
  height:1px;
  margin:38px 0 22px;
  background:linear-gradient(
    90deg,
    transparent,
    rgba(148,163,184,.20),
    transparent
  );
}}

.footer-bottom{{
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:20px;
  color:#64748b;
  font-size:12px;
}}

.footer-bottom-links{{
  display:flex;
  align-items:center;
  justify-content:flex-end;
  flex-wrap:wrap;
  gap:18px;
}}

.footer-bottom-links a{{
  color:#64748b;
  text-decoration:none;
  transition:color .18s ease;
}}

.footer-bottom-links a:hover{{
  color:#94a3b8;
  text-decoration:none;
}}

.footer-status{{
  display:inline-flex;
  align-items:center;
  gap:7px;
  color:#94a3b8;
  white-space:nowrap;
}}

.footer-status-dot{{
  width:7px;
  height:7px;
  border-radius:50%;
  background:#22c55e;
  box-shadow:0 0 0 4px rgba(34,197,94,.10);
}}

/* Tablet */

@media (max-width:900px){{

  .footer-grid{{
    grid-template-columns:repeat(3,1fr);
    gap:30px 25px;
  }}

  .footer-brand{{
    grid-column:1 / -1;
    padding-right:0;
  }}

  .footer-description{{
    max-width:600px;
  }}

}}

/* Mobile */

@media (max-width:600px){{

  footer{{
    padding:30px 18px;
  }}

  .footer-grid{{
    grid-template-columns:repeat(2,1fr);
    gap:28px 22px;
  }}

  .footer-brand{{
    grid-column:1 / -1;
  }}

  .footer-bottom{{
    flex-direction:column;
    align-items:flex-start;
  }}

  .footer-bottom-links{{
    justify-content:flex-start;
    gap:13px 18px;
  }}

}}

/* Small phones */

@media (max-width:400px){{

  .footer-grid{{
    grid-template-columns:1fr;
  }}

  .footer-brand{{
    grid-column:auto;
  }}

  .footer-bottom-links{{
    flex-direction:column;
    align-items:flex-start;
  }}

}}

</style>
</head>

<body>

<header>
<a class="brand" href="/">EasySurf</a>
<nav>{nav}</nav>
</header>

<main>
{body}
</main>

<footer>
<div class="footer-wrap">

  <div class="footer-grid">

    <div class="footer-brand">
      <a class="footer-logo" href="/">
        <span class="footer-logo-mark">E</span>
        EasySurf
      </a>

      <p class="footer-description">
        {tr('Earn online by completing verified activities, offers, surveys, games and other available tasks.', u)}

      </p>
    </div>

    <div>
      <div class="footer-heading">EasySurf</div>
      <div class="footer-links">
        <a href="/">{tr('Home', u)}</a>
        <a href="/dashboard">{tr('Dashboard', u)}</a>
        <a href="/earn">{tr('Earn', u)}</a>
        <a href="/rewards">{tr('Rewards', u)}</a>
        <a href="/leaderboard">{tr('Leaderboard', u)}</a>
      </div>
    </div>

    <div>
      <div class="footer-heading">{tr('Earn', u)}</div>
      <div class="footer-links">
        <a href="/earn">{tr('Tasks', u)}</a>
        <a href="/offers">{tr('Offers', u)}</a>
        <a href="/surveys">{tr('Surveys', u)}</a>
        <a href="/games">{tr('Games', u)}</a>
        <a href="/apps">{tr('Apps', u)}</a>
        <a href="/videos">{tr('Videos', u)}</a>
      </div>
    </div>

    <div>
      <div class="footer-heading">{tr('Company', u)}</div>
      <div class="footer-links">
        <a href="/about">{tr('About Us', u)}</a>
        <a href="/contact">{tr('Contact', u)}</a>
        <a href="/referrals">{tr('Referrals', u)}</a>
        <a href="/payouts">{tr('Payouts', u)}</a>
      </div>
    </div>

    <div>
      <div class="footer-heading">{tr('Support', u)}</div>
      <div class="footer-links">
        <a href="/faq">{tr('FAQ', u)}</a>
        <a href="/help">{tr('Help Center', u)}</a>
        <a href="/contact">{tr('Contact Support', u)}</a>
        <a href="/terms">{tr('Terms of Service', u)}</a>
      </div>
    </div>

  </div>

  <div class="footer-divider"></div>

  <div class="footer-bottom">
    <div>
      В© 2026 EasySurf. {tr('All rights reserved.', u)}
    </div>

    <div class="footer-bottom-links">
      <a href="/terms">{tr('Terms', u)}</a>

      <span class="footer-status">
        <span class="footer-status-dot"></span>
        {tr('Platform online', u)}
      </span>
    </div>
  </div>

</div>
</footer>

</body>
</html>"""


# ============================================================
# SECURITY V2 вЂ” AUTHENTICATION RATE LIMITING
# ============================================================

_LOGIN_WINDOW_SECONDS = 300
_LOGIN_MAX_FAILURES = 10

_REGISTER_WINDOW_SECONDS = 1800
_REGISTER_MAX_ATTEMPTS = 5
_RESEND_VERIFICATION_WINDOW_SECONDS=10*60
_RESEND_VERIFICATION_MAX_ATTEMPTS=3

_login_failures = {}
_register_attempts = {}
_resend_verification_attempts={}

_rate_limit_lock = threading.Lock()


def _client_ip(r):
    try:
        if r.client and r.client.host:
            return str(r.client.host)
    except Exception:
        pass
    return "unknown"


def _cleanup_rate_events(store,key,window_seconds,current_time):
    events=store.get(key,[])
    events=[x for x in events if current_time-x < window_seconds]

    if events:
        store[key]=events
    else:
        store.pop(key,None)

    return events


def _rate_allowed(store,key,window_seconds,max_events):
    current_time=time.time()

    with _rate_limit_lock:
        events=_cleanup_rate_events(
            store,
            key,
            window_seconds,
            current_time
        )

        if len(events)>=max_events:
            retry_after=max(
                1,
                int(window_seconds-(current_time-events[0]))+1
            )
            return False,retry_after

    return True,0


def _rate_record(store,key,window_seconds,max_events):
    current_time=time.time()

    with _rate_limit_lock:
        events=_cleanup_rate_events(
            store,
            key,
            window_seconds,
            current_time
        )

        events.append(current_time)

        if len(events)>max_events:
            events=events[-max_events:]

        store[key]=events


def _rate_reset(store,key):
    with _rate_limit_lock:
        store.pop(key,None)


def _rate_limited_response(retry_after):
    return HTMLResponse(
        "<h1>Too many requests</h1>"
        "<p>Please wait before trying again.</p>",
        status_code=429,
        headers={"Retry-After":str(max(1,int(retry_after)))}
    )

# ============================================================
# END SECURITY V2
# ============================================================

@app.get('/',response_class=HTMLResponse)
def home(r:Request):
    u=user(r)

    body=f"""
    <section class="hero" style="position:relative;overflow:hidden;background-image:linear-gradient(90deg,rgba(15,23,42,.96) 0%,rgba(15,23,42,.82) 48%,rgba(15,23,42,.35) 100%),url('/static/images/hero-banner.png');background-size:cover;background-position:center;min-height:460px;display:flex;align-items:center;">
        <div style="position:relative;z-index:2;max-width:760px;">
            <div style="display:inline-flex;align-items:center;gap:8px;padding:7px 13px;border:1px solid rgba(96,165,250,.25);border-radius:999px;background:rgba(59,130,246,.10);font-size:13px;color:#93c5fd;margin-bottom:18px;">
                ⚡ EasySurf Rewards Platform
            </div>

            <h1 style="font-size:clamp(38px,6vw,68px);line-height:1.02;margin:0 0 18px;">
                Earn online.<br>
                <span style="color:#60a5fa;">Your way.</span>
            </h1>

            <p class="muted" style="font-size:18px;line-height:1.7;max-width:650px;margin:0;">
                {tr('Complete surveys, offers, games, app activities and simple tasks from one modern rewards platform.', u)}

            </p>

            <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:28px;">
                <a class="btn" href="/register">🚀 {tr('Start earning', u)}</a>
                <a class="btn secondary" href="/login">Login</a>
            </div>

            <div style="display:flex;gap:28px;flex-wrap:wrap;margin-top:30px;color:#94a3b8;font-size:13px;">
                <span>✓ {tr('Simple tasks', u)}</span>
                <span>✓ {tr('Daily rewards', u)}</span>
                <span>✓ {tr('Referral bonuses', u)}</span>
            </div>
        </div>

        <div style="position:absolute;right:-80px;top:-120px;width:360px;height:360px;border-radius:50%;background:rgba(59,130,246,.12);filter:blur(10px);"></div>
        <div style="position:absolute;right:80px;bottom:-180px;width:300px;height:300px;border-radius:50%;background:rgba(34,197,94,.08);filter:blur(20px);"></div>
    </section>

    <section style="margin-top:26px;">
        <div style="display:flex;align-items:end;justify-content:space-between;gap:16px;margin-bottom:16px;flex-wrap:wrap;">
            <div>
                <div class="muted" style="font-size:13px;text-transform:uppercase;letter-spacing:.08em;">{tr('Platform', u)}</div>
                <h2 style="margin:5px 0 0;">{tr('Everything in one place', u)}</h2>
            </div>
            <div class="muted" style="font-size:14px;">{tr('Choose an earning method and get started.', u)}</div>
        </div>

        <div class="grid">

            <div class="card earn-card" style="min-height:190px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">📋</div>
                    <h3>{tr('Surveys', u)}</h3>
                    <p class="muted">
                        {tr('Paid research surveys when real inventory is available.', u)}
                    </p>
                </div>
                <a href="/surveys">{tr('Explore →', u)}</a>
            </div>

            <div class="card earn-card" style="min-height:190px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">🎁</div>
                    <h3>{tr('Offers', u)}</h3>
                    <p class="muted">
                        {tr('Advertiser-approved offers and tracked activities.', u)}
                    </p>
                </div>
                <a href="/offers">{tr('Explore →', u)}</a>
            </div>

            <div class="card earn-card" style="min-height:190px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">🎮</div>
                    <h3>{tr('Games', u)}</h3>
                    <p class="muted">
                        {tr('Game-based rewards through approved providers.', u)}
                    </p>
                </div>
                <a href="/games">{tr('Explore →', u)}</a>
            </div>

            <div class="card earn-card" style="min-height:190px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">📱</div>
                    <h3>{tr('Apps', u)}</h3>
                    <p class="muted">
                        {tr('App-based earning opportunities.', u)}
                    </p>
                </div>
                <a href="/apps">{tr('Explore →', u)}</a>
            </div>

            <div class="card earn-card" style="min-height:190px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">▶️</div>
                    <h3>{tr('Videos', u)}</h3>
                    <p class="muted">
                        {tr('Watch approved video tasks and activities.', u)}
                    </p>
                </div>
                <a href="/videos">{tr('Explore →', u)}</a>
            </div>

            <div class="card earn-card" style="min-height:190px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">🌐</div>
                    <h3>{tr('Tasks', u)}</h3>
                    <p class="muted">
                        {tr('Complete verified website and microtasks.', u)}
                    </p>
                </div>
                <a href="/earn">Start →</a>
            </div>

        </div>
    </section>

    <section class="card" style="margin-top:26px;padding:28px;position:relative;overflow:hidden;">
        <div style="position:relative;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:24px;flex-wrap:wrap;">
            <div>
                <div style="font-size:13px;color:#60a5fa;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                    {tr('Ready when you are', u)}
                </div>
                <h2 style="margin:7px 0 8px;">{tr('Start building your rewards balance', u)}</h2>
                <p class="muted" style="margin:0;max-width:620px;">
                    {tr('Create your free account, explore available opportunities,', u)}
                    {tr('collect rewards and track your activity from your dashboard.', u)}
                </p>
            </div>

            <a class="btn" href="/register" style="white-space:nowrap;">
                {tr('Create free account →', u)}
            </a>
        </div>

        <div style="position:absolute;right:-90px;top:-90px;width:240px;height:240px;border-radius:50%;background:rgba(59,130,246,.10);"></div>
    </section>
    """

    return layout("Home",body,u)
@app.get('/register',response_class=HTMLResponse)
def regp(r:Request):
    if user(r):
        return RedirectResponse(
            '/dashboard',
            303
        )

    t=csrf(r)

    status=r.query_params.get(
        'email',
        ''
    ).strip().lower()

    message=''

    if status=='exists':
        message=(
            '<div class="alert">'
            'An account with this email already exists. '
            '<a href="/login">Log in instead.</a>'
            '</div>'
        )

    elif status=='mismatch':
        message=(
            '<div class="alert">'
            'Passwords do not match.'
            '</div>'
        )

    elif status=='short':
        message=(
            '<div class="alert">'
            'Password must be at least 8 characters.'
            '</div>'
        )

    elif status=='long':
        message=(
            '<div class="alert">'
            'Password cannot exceed 64 characters.'
            '</div>'
        )

    elif status=='invalid':
        message=(
            '<div class="alert">'
            'Please enter a valid email address.'
            '</div>'
        )

    elif status=='registered':
        message=(
            '<div class="alert">'
            'Account created successfully. '
            'You can now log in.'
            '</div>'
        )

    elif status=='error':
        message=(
            '<div class="alert">'
            'Registration could not be completed. '
            'Please try again.'
            '</div>'
        )

    body=(
        '<div class="center card auth-card" '
        'style="max-width:560px;margin:30px auto;">'
        '<h2>Create account</h2>'
        '<p class="muted">'
        'Start earning with EasySurf.'
        '</p>'
        + message +
        '<form method="post" action="/register">'
        '<input type="hidden" '
        'name="csrf_token" value="' + t + '">'
        '<label>Email</label>'
        '<input name="email" '
        'type="email" '
        'required '
        'autocomplete="email" '
        'maxlength="320">'
        '<label>Password</label>'
        '<input name="password" '
        'type="password" '
        'required '
        'minlength="8" '
        'maxlength="64" '
        'autocomplete="new-password">'
        '<p class="muted" style="font-size:12px;">'
        'Minimum 8, maximum 64 characters.'
        '</p>'
        '<label>Confirm password</label>'
        '<input name="password_confirm" '
        'type="password" '
        'required '
        'minlength="8" '
        'maxlength="64" '
        'autocomplete="new-password">'
        '<button type="submit">'
        'Sign Up Now'
        '</button>'
        '</form>'
        '<p class="muted" style="margin-top:16px;">'
        'By signing up, you agree to the '
        '<a href="/terms">Terms</a> and '
        '<a href="/privacy">Privacy</a>.'
        '</p>'
        '<p style="margin-top:18px;">'
        'Already have an account? '
        '<a href="/login">Log in</a>'
        '</p>'
        '</div>'
    )

    return layout(
        'Register',
        body
    )

@app.post('/register')
def reg(
    r:Request,
    email:str=Form(...),
    password:str=Form(...),
    password_confirm:str=Form(...),
    csrf_token:str=Form(...),
    ref:str=Form('')
):
    ip=_client_ip(r)
    rate_key=f"ip:{ip}"

    allowed,retry=_rate_allowed(
        _register_attempts,
        rate_key,
        _REGISTER_WINDOW_SECONDS,
        _REGISTER_MAX_ATTEMPTS
    )

    if not allowed:
        return _rate_limited_response(retry)

    _rate_record(
        _register_attempts,
        rate_key,
        _REGISTER_WINDOW_SECONDS,
        _REGISTER_MAX_ATTEMPTS
    )

    if not okcsrf(r,csrf_token):
        return RedirectResponse(
            '/register?email=error',
            303
        )

    email=email.strip().lower()
    ref=ref.strip().upper()

    if not email or len(email)>320 or '@' not in email:
        return RedirectResponse(
            '/register?email=invalid',
            303
        )

    if len(password)<8:
        return RedirectResponse(
            '/register?email=short',
            303
        )

    if len(password)>64:
        return RedirectResponse(
            '/register?email=long',
            303
        )

    if password!=password_confirm:
        return RedirectResponse(
            '/register?email=mismatch',
            303
        )

    c=db()

    try:
        c.execute('BEGIN IMMEDIATE')

        result=create_user(
            c,
            email,
            password,
            now(),
            ref
        )

        if not result.ok:
            c.rollback()
            c.close()

            return RedirectResponse(
                '/register?email='
                + (
                    'exists'
                    if result.reason=='exists'
                    else 'error'
                ),
                303
            )

        c.commit()

    except Exception as e:
        try:
            c.rollback()
        except Exception:
            pass

        c.close()

        print(
            f"REGISTER AUTH ERROR: "
            f"{type(e).__name__}: {e}",
            flush=True
        )

        return RedirectResponse(
            '/register?email=error',
            303
        )

    c.close()

    print(
        "REGISTER RESULT: success",
        email,
        "user_id=" + str(result.user_id),
        "is_admin=" + str(int(result.is_admin)),
        flush=True
    )

    return RedirectResponse(
        '/login?registered=1',
        303
    )

@app.get('/verify-email',response_class=HTMLResponse)
def verify_email(r:Request,token:str=''):
 token=token.strip()

 if not token:
  return layout(
   'Email verification',
   '<div class="center card"><h2>Verification link is invalid</h2><p class="muted">The verification token is missing.</p><p><a href="/register">Create an account</a></p></div>'
  )

 c=db()

 try:
  c.execute('BEGIN IMMEDIATE')

  uid=verify_token(c,token)

  if not uid:
   c.rollback()
   c.close()

   return layout(
    'Email verification',
    '<div class="center card"><h2>Verification link is invalid or expired</h2><p class="muted">The link may have expired or already been used.</p><p><a href="/login">Go to login</a></p></div>'
   )

  updated=c.execute(
   'UPDATE users SET email_verified=1 WHERE id=? AND email_verified=0',
   (uid,)
  ).rowcount

  if updated != 1:
   c.rollback()
   c.close()

   return layout(
    'Email verification',
    '<div class="center card"><h2>Email already verified</h2><p class="muted">This email address has already been verified.</p><p><a href="/login">Go to login</a></p></div>'
   )

  c.commit()

 except Exception:
  try:
   c.rollback()
  except Exception:
   pass

  c.close()

  return layout(
   'Email verification',
   '<div class="center card"><h2>Verification failed</h2><p class="muted">Please try the verification link again.</p><p><a href="/login">Go to login</a></p></div>'
  )

 c.close()

 return layout(
  'Email verified',
  '<div class="center card"><h2>Email verified successfully</h2><p class="muted">Your email address has been confirmed. You can now log in.</p><p><a href="/login">Continue to login</a></p></div>'
 )

@app.get('/resend-verification',response_class=HTMLResponse)
def resend_verification_page(r:Request):
 if user(r):
  return RedirectResponse('/dashboard',303)

 t=csrf(r)

 return layout(
  'Resend verification',
  f'<div class="center card"><h2>Resend verification email</h2><form method="post"><input type="hidden" name="csrf_token" value="{t}"><label>{tr("Email")}</label><input name="email" type="email" required><button>Send verification email</button></form><p class="muted"><a href="/login">Back to login</a></p></div>'
 )

@app.post('/resend-verification')
def resend_verification(
 r:Request,
 email:str=Form(...),
 csrf_token:str=Form(...)
):
 ip=_client_ip(r)
 normalized_email=email.strip().lower()

 rate_key=f"{ip}:{normalized_email}"

 allowed,retry=_rate_allowed(
  _resend_verification_attempts,
  rate_key,
  _RESEND_VERIFICATION_WINDOW_SECONDS,
  _RESEND_VERIFICATION_MAX_ATTEMPTS
 )

 if not allowed:
  return _rate_limited_response(retry)

 _rate_record(
  _resend_verification_attempts,
  rate_key,
  _RESEND_VERIFICATION_WINDOW_SECONDS,
  _RESEND_VERIFICATION_MAX_ATTEMPTS
 )

 if not okcsrf(r,csrf_token):
  return RedirectResponse('/resend-verification',303)

 public_url=os.getenv(
  'EASYSURF_PUBLIC_URL',
  'http://127.0.0.1:8000'
 ).strip().rstrip('/')

 c=db()

 try:
  c.execute('BEGIN IMMEDIATE')

  u=c.execute(
   'SELECT id,email,email_verified FROM users WHERE email=?',
   (normalized_email,)
  ).fetchone()

  if u and int(u['email_verified']) == 0:

   token=create_token(
    c,
    u['id']
   )

   verification_url=build_verification_url(
    public_url,
    token
   )

   c.commit()

   try:
    send_verification_email(
     normalized_email,
     verification_url
    )
   except Exception:
    pass

  else:
   c.commit()

 except Exception:
  try:
   c.rollback()
  except Exception:
   pass

 finally:
  c.close()

 return RedirectResponse(
  '/login?verification=resent',
  303
 )

@app.get('/login',response_class=HTMLResponse)
def loginp(r:Request):
    if user(r):
        return RedirectResponse(
            '/dashboard',
            303
        )

    t=csrf(r)

    status=r.query_params.get(
        'registered',
        ''
    ).strip()

    error=r.query_params.get(
        'error',
        ''
    ).strip().lower()

    message=''

    if status=='1':
        message=(
            '<div class="alert">'
            'Account created successfully. '
            'You can now log in.'
            '</div>'
        )

    elif error=='invalid':
        message=(
            '<div class="alert">'
            'Invalid email or password.'
            '</div>'
        )

    elif error=='server':
        message=(
            '<div class="alert">'
            'Login temporarily failed. '
            'Please try again.'
            '</div>'
        )

    body=(
        '<div class="center card auth-card" '
        'style="max-width:560px;margin:30px auto;">'
        '<h2>Welcome back</h2>'
        '<p class="muted">'
        'Sign in to continue with EasySurf.'
        '</p>'
        + message +
        '<form method="post" action="/login">'
        '<input type="hidden" '
        'name="csrf_token" value="' + t + '">'
        '<label>Email</label>'
        '<input name="email" '
        'type="email" '
        'required '
        'autocomplete="email">'
        '<label>Password</label>'
        '<input name="password" '
        'type="password" '
        'required '
        'autocomplete="current-password">'
        '<button type="submit">'
        'Log In'
        '</button>'
        '</form>'
        '<p style="margin-top:18px;">'
        'Don\'t have an account? '
        '<a href="/register">Sign up</a>'
        '</p>'
        '</div>'
    )

    return layout(
        'Login',
        body
    )
@app.post('/login')
def login(
    r:Request,
    email:str=Form(...),
    password:str=Form(...),
    csrf_token:str=Form(...)
):
    ip=_client_ip(r)
    normalized_email=email.strip().lower()

    ip_key=f"ip:{ip}"
    email_key=f"email:{normalized_email}"

    allowed,retry=_rate_allowed(
        _login_failures,
        ip_key,
        _LOGIN_WINDOW_SECONDS,
        _LOGIN_MAX_FAILURES
    )

    if not allowed:
        return _rate_limited_response(retry)

    allowed,retry=_rate_allowed(
        _login_failures,
        email_key,
        _LOGIN_WINDOW_SECONDS,
        _LOGIN_MAX_FAILURES
    )

    if not allowed:
        return _rate_limited_response(retry)

    if not okcsrf(r,csrf_token):
        return RedirectResponse(
            '/login?error=server',
            303
        )

    c=db()

    try:
        c.execute('BEGIN IMMEDIATE')

        result=authenticate_user(
            c,
            normalized_email,
            password
        )

        if not result.ok:
            c.rollback()
            c.close()

            _rate_record(
                _login_failures,
                ip_key,
                _LOGIN_WINDOW_SECONDS,
                _LOGIN_MAX_FAILURES
            )

            _rate_record(
                _login_failures,
                email_key,
                _LOGIN_WINDOW_SECONDS,
                _LOGIN_MAX_FAILURES
            )

            print(
                "LOGIN RESULT: invalid",
                normalized_email,
                flush=True
            )

            return RedirectResponse(
                '/login?error=invalid',
                303
            )

        c.commit()

    except Exception as e:
        try:
            c.rollback()
        except Exception:
            pass

        c.close()

        print(
            f"LOGIN AUTH ERROR: "
            f"{type(e).__name__}: {e}",
            flush=True
        )

        return RedirectResponse(
            '/login?error=server',
            303
        )

    c.close()

    _rate_reset(
        _login_failures,
        ip_key
    )

    _rate_reset(
        _login_failures,
        email_key
    )

    r.session.clear()
    r.session['user_id']=result.user_id
    r.session['csrf']=secrets.token_urlsafe(32)

    print(
        "LOGIN RESULT: success",
        normalized_email,
        "user_id=" + str(result.user_id),
        "is_admin=" + str(int(result.is_admin)),
        flush=True
    )

    return RedirectResponse(
        '/dashboard',
        303
    )

@app.get('/profile',response_class=HTMLResponse)
def profile_page(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',status_code=303)

    conn=db()

    row=conn.execute(
        "SELECT id,email,balance,is_admin,created_at,referral_code,username,display_name,avatar,language,notifications FROM users WHERE id=?",
        (u["id"],)
    ).fetchone()

    conn.close()

    if not row:
        return RedirectResponse('/login',status_code=303)

    username=str(row["username"] or "")
    display_name=str(row["display_name"] or username)
    avatar=str(row["avatar"] or "")
    language=str(row["language"] or "en")
    notifications=int(row["notifications"] or 0)

    if avatar:
        avatar_html=(
            '<img src="/static/uploads/avatars/' + avatar + '" '
            'alt="Avatar" '
            'style="width:96px;height:96px;border-radius:50%;object-fit:cover;'
            'border:4px solid rgba(255,255,255,.15);">'
        )
    else:
        initial=(display_name[:1].upper() if display_name else "?")
        avatar_html=(
            '<div style="width:96px;height:96px;border-radius:50%;'
            'background:linear-gradient(135deg,#2563eb,#7c3aed);'
            'display:flex;align-items:center;justify-content:center;'
            'font-size:38px;font-weight:800;color:white;">'
            + initial +
            '</div>'
        )

    saved=str(r.query_params.get("saved") or "")

    saved_html=""

    if saved=="1":
        saved_html=(
            '<div class="card" style="border-left:4px solid #22c55e;margin-bottom:18px;">'
            '<strong>Profile updated successfully.</strong>'
            '</div>'
        )

    body=(
        saved_html

        + '<div class="card" style="margin-bottom:20px;">'
        + '<div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap;">'
        + avatar_html
        + '<div>'
        + f'<h1 style="margin:0 0 5px 0;">{tr('My Profile', u)}</h1>'
        + '<div class="muted">@' + username + '</div>'
        + '</div>'
        + '</div>'
        + '</div>'

        + '<div class="card">'
        + f'<h2>{tr('Personal information', u)}</h2>'

        + '<form method="post" action="/profile" enctype="multipart/form-data">'

        + f'<label>{tr('Display name', u)}</label>'
        + '<input name="display_name" value="' + display_name.replace('"','&quot;') + '" maxlength="50" required>'

        + f'<label>{tr('Username', u)}</label>'
        + '<input name="username" value="' + username.replace('"','&quot;') + '" maxlength="30" required>'

        + '<div class="muted" style="margin-bottom:12px;">'
        + f'{tr('3вЂ“30 characters: letters, numbers and underscore.', u)}'
        + '</div>'

        + f'<label>{tr("Email")}</label>'
        + '<input value="' + str(row["email"]).replace('"','&quot;') + '" disabled>'

        + f'<label>{tr('Language', u)}</label>'
        + '<select name="language">'
        + '<option value="en"' + (' selected' if language=="en" else '') + '>English</option>'
        + '<option value="ru"' + (' selected' if language=="ru" else '') + '>Русский</option>'
        + '<option value="uz"' + (' selected' if language=="uz" else '') + '>' + tr('OРІР‚Вzbekcha', u) + '</option>'
        + '</select>'

        + '<label style="display:flex;align-items:center;gap:10px;margin-top:14px;">'
        + '<input type="checkbox" name="notifications" value="1"'
        + (' checked' if notifications else '')
        + ' style="width:auto;">'
        + tr('Receive notifications', u)
        + '</label>'

        + f'<label style="margin-top:18px;">{tr('Avatar', u)}</label>'
        + '<input type="file" name="avatar_file" accept=".jpg,.jpeg,.png,.webp,image/jpeg,image/png,image/webp">'

        + '<div class="muted" style="margin-top:6px;">'
        + f'{tr('JPG, PNG or WEBP. Maximum 2 MB.', u)}'
        + '</div>'

        + '<button type="submit" style="margin-top:18px;">'
        + tr('Save profile', u)
        + '</button>'

        + '</form>'
        + '</div>'

        + '<div class="card" style="margin-top:20px;">'
        + f'<h2>{tr('Account', u)}</h2>'
        + f'<p><strong>{tr('Balance', u)}:</strong> ' + str(int(row["balance"] or 0)) + '</p>'
        + f'<p><strong>{tr('Referral code', u)}:</strong> ' + str(row["referral_code"] or "вЂ”") + '</p>'
        + f'<p><strong>{tr('Account ID', u)}:</strong> ' + str(int(row["id"])) + '</p>'
        + f'<p><strong>{tr('Admin', u)}:</strong> ' + ('Yes' if int(row["is_admin"] or 0) else 'No') + '</p>'
        + '</div>'
    )

    return layout("Profile",body,row)


@app.post('/profile')
async def profile_update(
    r:Request,
    display_name:str=Form(...),
    username:str=Form(...),
    language:str=Form("en"),
    notifications:str|None=Form(None),
    avatar_file:UploadFile|None=File(None)
):
    u=user(r)

    if not u:
        return RedirectResponse('/login',status_code=303)

    import re

    display_name=display_name.strip()
    username=username.strip().lower()

    if len(display_name)<1 or len(display_name)>50:
        return HTMLResponse("Invalid display name",status_code=400)

    if not (3<=len(username)<=30):
        return HTMLResponse("Invalid username",status_code=400)

    if not re.fullmatch(r"[a-zA-Z0-9_]+",username):
        return HTMLResponse(
            "Username may contain only letters, numbers and underscore.",
            status_code=400
        )

    if language not in ("en","ru","uz"):
        language="en"

    conn=db()

    existing=conn.execute(
        "SELECT id FROM users WHERE lower(username)=lower(?) AND id<>?",
        (username,u["id"])
    ).fetchone()

    if existing:
        conn.close()
        return HTMLResponse("Username is already taken.",status_code=409)

    avatar_name=None

    if avatar_file and avatar_file.filename:

        filename=str(avatar_file.filename)
        suffix=Path(filename).suffix.lower()

        allowed={".jpg",".jpeg",".png",".webp"}

        if suffix not in allowed:
            conn.close()
            return HTMLResponse(
                "Avatar must be JPG, PNG or WEBP.",
                status_code=400
            )

        content=await avatar_file.read()

        if len(content)>2*1024*1024:
            conn.close()
            return HTMLResponse(
                "Avatar is too large. Maximum size is 2 MB.",
                status_code=400
            )

        valid=False

        if suffix in (".jpg",".jpeg"):
            valid=content.startswith(b"\xff\xd8\xff")

        elif suffix==".png":
            valid=content.startswith(b"\x89PNG\r\n\x1a\n")

        elif suffix==".webp":
            valid=(
                len(content)>=12
                and content[0:4]==b"RIFF"
                and content[8:12]==b"WEBP"
            )

        if not valid:
            conn.close()
            return HTMLResponse(
                "Invalid image file.",
                status_code=400
            )

        avatar_name="user_" + str(u["id"]) + suffix
        avatar_path=AVATAR_DIR / avatar_name
        avatar_path.write_bytes(content)

    if avatar_name:
        conn.execute(
            "UPDATE users SET username=?,display_name=?,language=?,notifications=?,avatar=? WHERE id=?",
            (
                username,
                display_name,
                language,
                1 if notifications else 0,
                avatar_name,
                u["id"]
            )
        )
    else:
        conn.execute(
            "UPDATE users SET username=?,display_name=?,language=?,notifications=? WHERE id=?",
            (
                username,
                display_name,
                language,
                1 if notifications else 0,
                u["id"]
            )
        )

    conn.commit()
    conn.close()

    return RedirectResponse('/profile?saved=1',status_code=303)



@app.get('/language')
def change_language(r: Request):
    language = (r.query_params.get('language') or 'en').lower()
    next_path = r.query_params.get('next') or '/'

    if language not in SUPPORTED_LANGUAGES:
        language = 'en'

    if not next_path.startswith('/') or next_path.startswith('//'):
        next_path = '/'

    user_id = r.session.get('user_id')

    if user_id:
        conn = db()
        try:
            conn.execute(
                "UPDATE users SET language=? WHERE id=?",
                (language, int(user_id))
            )
            conn.commit()
        finally:
            conn.close()

    r.session['language'] = language
    return RedirectResponse(next_path, status_code=303)
@app.get('/logout')
def logout(r:Request):r.session.clear();return RedirectResponse('/',303)

@app.get('/dashboard',response_class=HTMLResponse)
def dash(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',303)

    c=db()

    today_start=(now()//86400)*86400

    today_earned=c.execute(
        "SELECT COALESCE(SUM(amount),0) n "
        "FROM transactions "
        "WHERE user_id=? AND amount>0 AND created_at>=?",
        (u["id"],today_start)
    ).fetchone()["n"]

    pending=c.execute(
        "SELECT COALESCE(SUM(amount),0) n "
        "FROM reward_events "
        "WHERE user_id=? AND status='pending'",
        (u["id"],)
    ).fetchone()["n"]

    done=c.execute(
        "SELECT COUNT(*) n "
        "FROM attempts "
        "WHERE user_id=? AND rewarded=1",
        (u["id"],)
    ).fetchone()["n"]

    refs=c.execute(
        "SELECT COUNT(*) n "
        "FROM referrals "
        "WHERE referrer_id=?",
        (u["id"],)
    ).fetchone()["n"]

    earned=c.execute(
        "SELECT COALESCE(SUM(amount),0) n "
        "FROM transactions "
        "WHERE user_id=? AND amount>0",
        (u["id"],)
    ).fetchone()["n"]

    paid=c.execute(
        "SELECT COALESCE(SUM(amount),0) n "
        "FROM payouts "
        "WHERE user_id=? AND status='paid'",
        (u["id"],)
    ).fetchone()["n"]

    tasks=c.execute(
        """
        SELECT t.*
        FROM tasks t
        WHERE t.active=1
        AND t.spent+t.reward<=t.budget
        AND NOT EXISTS(
            SELECT 1
            FROM attempts a
            WHERE a.user_id=?
            AND a.task_id=t.id
            AND a.rewarded=1
        )
        ORDER BY t.id DESC
        """,
        (u["id"],)
    ).fetchall()

    recent=c.execute(
        "SELECT * FROM transactions "
        "WHERE user_id=? ORDER BY id DESC LIMIT 5",
        (u["id"],)
    ).fetchall()

    c.close()

    goal=100
    percent=min(100,int(today_earned*100/goal)) if goal else 0

    task_cards="".join(
        f"""
        <div class="card earn-card" style="min-height:190px;">
            <div>
                <div class="earn-icon" style="font-size:32px;">🌐</div>
                <div style="display:inline-flex;padding:5px 9px;border-radius:999px;background:rgba(59,130,246,.10);color:#93c5fd;font-size:11px;margin-bottom:8px;">
                    Website Task
                </div>
                <h3 style="margin:4px 0 8px;">{escape(x["title"])}</h3>
                <p class="muted">
                    вЏ± {x["seconds"]} sec
                    &nbsp;В·&nbsp;
                    💰 {money(x["reward"])}
                </p>
            </div>
            <a class="btn" href="/task/{x["id"]}">Start task →</a>
        </div>
        """
        for x in tasks[:6]
    )

    if not task_cards:
        task_cards=f"""
        <div class="card empty" style="grid-column:1/-1;text-align:center;padding:36px;">
            <div class="earn-icon" style="font-size:38px;">🔎</div>
            <h3>{tr('No website tasks available', u)}</h3>
            <p class="muted">
                {tr('New tasks may appear later. Explore other earning categories in the meantime.', u)}
            </p>
            <a class="btn" href="/earn">{tr('Explore Earn →', u)}</a>
        </div>
        """

    activity="".join(
        f"""
        <tr>
            <td>
                <div style="font-weight:600;">{escape(x["description"])}</div>
                <div class="muted" style="font-size:12px;margin-top:3px;">
                    {time.strftime("%Y-%m-%d %H:%M",time.localtime(x["created_at"]))}
                </div>
            </td>
            <td class="green" style="font-weight:700;white-space:nowrap;">
                {"+" if x["amount"]>=0 else ""}{money(x["amount"])}
            </td>
        </tr>
        """
        for x in recent
    )

    if not activity:
        activity="""
        <tr>
            <td colspan="2" class="muted" style="text-align:center;padding:24px;">
                No activity yet. {tr('Start earning', u)} to see your transactions here.
            </td>
        </tr>
        """

    body=f"""
    <section class="hero" style="position:relative;overflow:hidden;background-image:linear-gradient(90deg,rgba(15,23,42,.96) 0%,rgba(15,23,42,.82) 48%,rgba(15,23,42,.35) 100%),url('/static/images/hero-banner.png');background-size:cover;background-position:center;min-height:460px;display:flex;align-items:center;">
        <div style="position:relative;z-index:2;">
            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(96,165,250,.25);border-radius:999px;background:rgba(59,130,246,.10);font-size:12px;color:#93c5fd;margin-bottom:14px;">
                ⚡ {tr('Your EasySurf Dashboard', u)}
            </div>

            <h1 style="margin:0 0 8px;">
                {tr('Welcome back', u)}
            </h1>

            <p class="muted" style="margin:0;font-size:15px;">
                {escape(u["email"])}
            </p>

            <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:22px;">
                <a class="btn" href="/earn">🚀 {tr('Earn now', u)}</a>
                <a class="btn secondary" href="/rewards">🎁 {tr('Rewards', u)}</a>
            </div>
        </div>

        <div style="position:absolute;right:-80px;top:-130px;width:340px;height:340px;border-radius:50%;background:rgba(59,130,246,.11);filter:blur(8px);"></div>
        <div style="position:absolute;right:100px;bottom:-190px;width:280px;height:280px;border-radius:50%;background:rgba(34,197,94,.07);filter:blur(14px);"></div>
    </section>

    <section style="margin-top:22px;">
        <div class="grid">

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:30px;">💰</div>
                <div class="muted">{tr('Available balance', u)}</div>
                <div class="metric" style="font-size:32px;margin-top:5px;">{money(u["balance"])}</div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:30px;">📈</div>
                <div class="muted">{tr('Earned today', u)}</div>
                <div class="metric" style="font-size:32px;margin-top:5px;">{money(today_earned)}</div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:30px;">вЏі</div>
                <div class="muted">{tr('Pending rewards', u)}</div>
                <div class="metric" style="font-size:32px;margin-top:5px;">{money(pending)}</div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:30px;">🔥</div>
                <div class="muted">{tr('Tasks completed', u)}</div>
                <div class="metric" style="font-size:32px;margin-top:5px;">{done}</div>
            </div>

        </div>
    </section>

    <section class="card" style="margin-top:22px;">
        <div style="display:flex;justify-content:space-between;align-items:end;gap:15px;flex-wrap:wrap;">
            <div>
                <div style="font-size:12px;color:#60a5fa;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                    {tr('Daily target', u)}
                </div>
                <h2 style="margin:5px 0 4px;">{tr("Today's earning goal", u)}</h2>
                <p class="muted" style="margin:0;">
                    {tr('Keep completing available activities to grow your balance.', u)}
                </p>
            </div>

            <div style="font-size:20px;font-weight:800;">
                {percent}%
            </div>
        </div>

        <div class="progress" style="margin-top:20px;">
            <div class="progress-bar" style="width:{percent}%"></div>
        </div>

        <div style="display:flex;justify-content:space-between;gap:10px;margin-top:10px;font-size:13px;">
            <span><b>{money(today_earned)}</b> {tr('earned today', u)}</span>
            <span class="muted">{tr('Goal', u)}: {money(goal)}</span>
        </div>
    </section>

    <section style="margin-top:28px;">
        <div style="display:flex;align-items:end;justify-content:space-between;gap:15px;flex-wrap:wrap;margin-bottom:15px;">
            <div>
                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.08em;">
                    {tr('Quick access', u)}
                </div>
                <h2 style="margin:5px 0 0;">{tr('Start earning', u)}</h2>
            </div>
            <a href="/earn" class="muted">{tr('View all', u)} →</a>
        </div>

        <div class="grid">

            <div class="card earn-card" style="min-height:175px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">📋</div>
                    <h3>{tr('Surveys', u)}</h3>
                    <p class="muted">{tr('Paid research surveys when inventory is available.', u)}</p>
                </div>
                <a href="/surveys">{tr('View surveys', u)} →</a>
            </div>

            <div class="card earn-card" style="min-height:175px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">🎁</div>
                    <h3>{tr('Offers', u)}</h3>
                    <p class="muted">{tr('Advertiser offers and tracked activities.', u)}</p>
                </div>
                <a href="/offers">{tr('View offers', u)} →</a>
            </div>

            <div class="card earn-card" style="min-height:175px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">🎮</div>
                    <h3>{tr('Games', u)}</h3>
                    <p class="muted">{tr('Play approved games and reach milestones.', u)}</p>
                </div>
                <a href="/games">{tr('View games', u)} →</a>
            </div>

            <div class="card earn-card" style="min-height:175px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">📱</div>
                    <h3>{tr('Apps', u)}</h3>
                    <p class="muted">{tr('Discover tracked app opportunities.', u)}</p>
                </div>
                <a href="/apps">{tr('View apps', u)} →</a>
            </div>

        </div>
    </section>

    <section style="margin-top:28px;">
        <div style="display:flex;align-items:end;justify-content:space-between;gap:15px;flex-wrap:wrap;margin-bottom:15px;">
            <div>
                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.08em;">
                    {tr('Available now', u)}
                </div>
                <h2 style="margin:5px 0 0;">{tr('Website Tasks', u)}</h2>
            </div>
            <a href="/earn" class="muted">{tr('Browse earning options', u)} →</a>
        </div>

        <div class="grid">
            {task_cards}
        </div>
    </section>

    <section class="card" style="margin-top:28px;">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap;margin-bottom:14px;">
            <div>
                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.08em;">
                    {tr('Your account', u)}
                </div>
                <h2 style="margin:5px 0 0;">{tr('Recent Activity', u)}</h2>
            </div>
            <a href="/activity" class="muted">{tr('View all', u)} →</a>
        </div>

        <table>
            <tr>
                <th>{tr('Activity', u)}</th>
                <th>{tr('Amount', u)}</th>
            </tr>
            {activity}
        </table>
    </section>

    <section style="margin-top:22px;">
        <div class="grid">

            <div class="card">
                <div class="muted">{tr('Total earned', u)}</div>
                <div class="metric" style="font-size:28px;margin-top:5px;">{money(earned)}</div>
            </div>

            <div class="card">
                <div class="muted">{tr('Total paid', u)}</div>
                <div class="metric" style="font-size:28px;margin-top:5px;">{money(paid)}</div>
            </div>

            <div class="card">
                <div class="muted">{tr('Referrals', u)}</div>
                <div class="metric" style="font-size:28px;margin-top:5px;">{refs}</div>
            </div>

        </div>
    </section>

    <section class="card" style="margin-top:22px;padding:26px;position:relative;overflow:hidden;">
        <div style="position:relative;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;">
            <div>
                <div style="font-size:12px;color:#60a5fa;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                    {tr('Keep going', u)}
                </div>
                <h2 style="margin:6px 0 7px;">{tr('There are more ways to earn', u)}</h2>
                <p class="muted" style="margin:0;max-width:600px;">
                    {tr('Explore all available earning categories and keep your activity growing.', u)}
                </p>
            </div>

            <a class="btn" href="/earn">{tr('Explore Earn →', u)}</a>
        </div>

        <div style="position:absolute;right:-80px;top:-100px;width:240px;height:240px;border-radius:50%;background:rgba(59,130,246,.08);"></div>
    </section>
    """

    return layout("Dashboard",body,u)
@app.get('/task/{tid}',response_class=HTMLResponse)
def task(r:Request,tid:int):
 u=user(r)
 if not u:return RedirectResponse('/login',303)
 if u['is_admin']:return layout('Admin','<div class="card"><h2>Admin account</h2><p class="muted">Admin accounts cannot earn task rewards.</p></div>',u)
 c=db();t=c.execute('SELECT * FROM tasks WHERE id=? AND active=1',(tid,)).fetchone();
 if not t:c.close();return HTMLResponse(layout('Not found','<div class="card">Task not found.</div>',u),404)
 if c.execute('SELECT id FROM attempts WHERE user_id=? AND task_id=? AND rewarded=1',(u['id'],tid)).fetchone():c.close();return layout('Completed','<div class="card">You already completed this task.</div>',u)
 a=c.execute('SELECT * FROM attempts WHERE user_id=? AND task_id=? AND rewarded=0 ORDER BY id DESC LIMIT 1',(u['id'],tid)).fetchone()
 if not a:
  cur=c.execute('INSERT INTO attempts(user_id,task_id,started_at) VALUES(?,?,NULL)',(u['id'],tid));aid=cur.lastrowid;c.commit()
 else:
  aid=a['id']
 c.close()
 ct=csrf(r)
 target=escape(t['video_url'] or t['url'])
 label='Watch video' if t['task_type']=='video' else 'Open website'
 body=f'''<div class="card"><h2>{escape(t["title"])}</h2>
 <p class="muted">Click the button below to open the advertiser page. The timer starts only after you open it.</p>
 <button class="btn secondary" id="openBtn" onclick="startTask()">{label}</button>
 <div id="status" class="notice" style="margin-top:15px">Waiting for advertiser page...</div>
 <div id="timer" class="timer">--</div>
 <form method="post" action="/complete/{aid}" id="completeForm">
 <input type="hidden" name="csrf_token" value="{ct}">
 <button id="completeBtn" disabled>Complete task</button>
 </form></div>
 <script>
 let n={t["seconds"]};
 let started=false;
 const timer=document.getElementById("timer");
 const openBtn=document.getElementById("openBtn");
 const completeBtn=document.getElementById("completeBtn");
 const status=document.getElementById("status");

 function startTask(){{
   if(started)return;
   started=true;
   window.open("{target}","_blank","noopener,noreferrer");
   fetch("/start/{aid}",{{
     method:"POST",
     headers:{{"Content-Type":"application/x-www-form-urlencoded"}},
     body:"csrf_token="+encodeURIComponent("{ct}")
   }}).then(()=>{{
     openBtn.disabled=true;
     status.textContent="Advertiser page opened. Timer is running.";
     runTimer();
   }});
 }}

 function runTimer(){{
   timer.textContent=n;
   if(n<=0){{
     timer.textContent="✓ Completed";
     completeBtn.disabled=false;
     status.textContent="Time completed. You can now claim your reward.";
     return;
   }}
   n--;
   setTimeout(runTimer,1000);
 }}
 </script>'''
 return layout('Task',body,u)
@app.post('/start/{aid}')
def start_task(r:Request,aid:int,csrf_token:str=Form(...)):
 u=user(r)
 if not u:return RedirectResponse('/login',303)
 if not okcsrf(r,csrf_token):return RedirectResponse('/dashboard',303)
 c=db()
 try:
  c.execute('BEGIN IMMEDIATE')
  a=c.execute('SELECT a.*,t.active FROM attempts a JOIN tasks t ON t.id=a.task_id WHERE a.id=? AND a.user_id=?',(aid,u['id'])).fetchone()
  if not a or not a['active'] or a['rewarded']:
   c.rollback()
   return RedirectResponse('/dashboard',303)
  if a['started_at'] is None:
   c.execute('UPDATE attempts SET started_at=? WHERE id=? AND started_at IS NULL',(now(),aid))
  c.commit()
 finally:
  c.close()
 return RedirectResponse(f'/task/{a["task_id"]}',303)

@app.post('/complete/{aid}')
def complete(r:Request,aid:int,csrf_token:str=Form(...)):
 u=user(r)
 if not u:return RedirectResponse('/login',303)
 if u['is_admin']:return RedirectResponse('/admin',303)
 if not okcsrf(r,csrf_token):return RedirectResponse('/dashboard',303)
 c=db()
 try:
  c.execute('BEGIN IMMEDIATE')
  a=c.execute('SELECT a.*,t.title,t.seconds,t.reward,t.active,t.budget,t.spent FROM attempts a JOIN tasks t ON t.id=a.task_id WHERE a.id=? AND a.user_id=?',(aid,u['id'])).fetchone()
  if not a or not a['active'] or a['rewarded'] or a['started_at'] is None or now()-a['started_at']<a['seconds']:
   c.rollback()
   return RedirectResponse(f'/task/{a["task_id"]}' if a else '/dashboard',303)

  if c.execute('SELECT id FROM attempts WHERE user_id=? AND task_id=? AND rewarded=1',(u['id'],a['task_id'])).fetchone():
   c.rollback()
   return RedirectResponse('/dashboard',303)

  updated=c.execute('UPDATE tasks SET spent=spent+? WHERE id=? AND active=1 AND spent+?<=budget',(a['reward'],a['task_id'],a['reward'])).rowcount
  if updated!=1:
   c.rollback()
   return RedirectResponse('/dashboard',303)

  ts=now()
  c.execute('UPDATE attempts SET completed_at=?,rewarded=1 WHERE id=? AND rewarded=0',(ts,aid))
  c.execute('UPDATE users SET balance=balance+? WHERE id=?',(a['reward'],u['id']))
  c.execute('INSERT INTO transactions(user_id,amount,kind,description,created_at) VALUES(?,?,?,?,?)',(u['id'],a['reward'],'task_reward',a['title'],ts))
  c.execute('UPDATE tasks SET active=0 WHERE id=? AND spent>=budget',(a['task_id'],))
  c.commit()
 finally:
  c.close()
 return RedirectResponse('/dashboard',303)
@app.get('/history',response_class=HTMLResponse)
def history(r:Request):
 u=user(r)
 if not u:return RedirectResponse('/login',303)
 c=db();rows=c.execute('SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC',(u['id'],)).fetchall();c.close();trs=''.join(f'<tr><td>{escape(x["kind"])}</td><td>{escape(x["description"])}</td><td>{money(x["amount"])}</td></tr>' for x in rows);return layout('History',f'<div class="card"><h2>History</h2><table><tr><th>{tr('Type', u)}</th><th>{tr('Description', u)}</th><th>{tr('Amount', u)}</th></tr>{trs or "<tr><td colspan=3>No transactions.</td></tr>"}</table></div>',u)
@app.get('/referrals',response_class=HTMLResponse)
def referrals(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',303)

    c=db()

    rows=c.execute(
        """
        SELECT r.*,u.email
        FROM referrals r
        JOIN users u ON u.id=r.referred_id
        WHERE r.referrer_id=?
        ORDER BY r.id DESC
        """,
        (u["id"],)
    ).fetchall()

    total_bonus=sum(int(x["bonus"] or 0) for x in rows)
    referral_count=len(rows)

    c.close()

    referral_code=escape(u["referral_code"] or "")

    trs="".join(
        f"""
        <tr>
            <td>
                <div style="font-weight:600;">
                    {escape(x["email"])}
                </div>
            </td>

            <td>
                <span style="display:inline-flex;padding:5px 9px;border-radius:999px;background:rgba(34,197,94,.10);color:#86efac;">
                    +{money(x["bonus"])}
                </span>
            </td>
        </tr>
        """
        for x in rows
    )

    if not trs:
        trs="""
        <tr>
            <td colspan="2" style="padding:35px 15px;text-align:center;">
                <div style="font-size:32px;margin-bottom:8px;">👥</div>
                <strong>{tr('No referrals yet', u)}</strong>
                <div class="muted" style="margin-top:6px;">
                    {tr('Share your referral code to start building your network.', u)}
                </div>
            </td>
        </tr>
        """

    body=f"""
    <section class="hero" style="position:relative;overflow:hidden;background-image:linear-gradient(90deg,rgba(15,23,42,.96) 0%,rgba(15,23,42,.82) 48%,rgba(15,23,42,.35) 100%),url('/static/images/hero-banner.png');background-size:cover;background-position:center;min-height:460px;display:flex;align-items:center;">
        <div style="position:relative;z-index:2;">

            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(34,197,94,.25);border-radius:999px;background:rgba(34,197,94,.09);font-size:12px;color:#86efac;margin-bottom:14px;">
                🤝 EasySurf Referral Program
            </div>

            <h1 style="margin:0 0 10px;">
                Invite friends & earn
            </h1>

            <p class="muted" style="max-width:720px;font-size:16px;line-height:1.7;margin:0;">
                {tr('Share your referral code with friends and receive a referral bonus', u)}
                when a new user registers through your code.
            </p>

            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:22px;">
                <a class="btn" href="/earn">
                    ⚡ {tr('Start earning', u)}
                </a>

                <a class="btn secondary" href="/activity">
                    📊 {tr('View activity', u)}
                </a>
            </div>

        </div>

        <div style="position:absolute;right:-100px;top:-140px;width:390px;height:390px;border-radius:50%;background:rgba(34,197,94,.09);filter:blur(10px);"></div>

        <div style="position:absolute;right:160px;bottom:-210px;width:300px;height:300px;border-radius:50%;background:rgba(59,130,246,.07);filter:blur(12px);"></div>
    </section>

    <section style="margin-top:25px;">

        <div class="card" style="position:relative;overflow:hidden;padding:28px;border-color:rgba(59,130,246,.25);background:linear-gradient(135deg,rgba(59,130,246,.11),rgba(15,23,42,.88));">

            <div style="position:relative;z-index:2;">

                <div style="font-size:12px;color:#60a5fa;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                    Your referral code
                </div>

                <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-top:10px;">

                    <div id="referral-code"
                         style="font-size:28px;font-weight:800;letter-spacing:.08em;padding:12px 18px;border-radius:14px;background:rgba(15,23,42,.65);border:1px solid rgba(148,163,184,.15);">
                        {referral_code}
                    </div>

                    <button type="button"
                            class="btn secondary"
                            onclick="copyReferralCode()">
                        📋 {tr('Copy code', u)}
                    </button>

                </div>

                <p class="muted" style="margin:13px 0 0;line-height:1.6;">
                    {tr('Give this code to a friend during registration.', u)}
                </p>

                <div id="copy-message"
                     style="display:none;margin-top:10px;color:#86efac;font-size:13px;">
                    ✓ Referral code copied
                </div>

            </div>

            <div style="position:absolute;right:-80px;top:-90px;width:250px;height:250px;border-radius:50%;background:rgba(59,130,246,.08);"></div>

        </div>

    </section>

    <section style="margin-top:25px;">

        <div class="grid">

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:34px;">👥</div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    Referrals
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;">
                    {referral_count}
                </div>

                <div class="muted" style="font-size:13px;">
                    {tr('registered users', u)}
                </div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:34px;">💰</div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    {tr('Referral earnings', u)}
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;color:#86efac;">
                    {money(total_bonus)}
                </div>

                <div class="muted" style="font-size:13px;">
                    {tr('total referral bonuses', u)}
                </div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:34px;">🎁</div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    {tr('Referral reward', u)}
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;">
                    {money(50)}
                </div>

                <div class="muted" style="font-size:13px;">
                    {tr('per successful signup', u)}
                </div>
            </div>

        </div>

    </section>

    <section style="margin-top:28px;">

        <div class="card" style="padding:0;overflow:hidden;">

            <div style="padding:22px 24px;border-bottom:1px solid rgba(148,163,184,.10);display:flex;align-items:center;justify-content:space-between;gap:15px;flex-wrap:wrap;">

                <div>
                    <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.08em;">
                        {tr('Referral activity', u)}
                    </div>

                    <h2 style="margin:5px 0 0;">
                        Your referrals
                    </h2>
                </div>

                <div class="muted" style="font-size:13px;">
                    {referral_count} total
                </div>

            </div>

            <div style="overflow-x:auto;">
                <table style="margin:0;">
                    <tr>
                        <th>{tr('User', u)}</th>
                        <th>Bonus</th>
                    </tr>

                    {trs}
                </table>
            </div>

        </div>

    </section>

    <section class="card" style="margin-top:28px;padding:26px;position:relative;overflow:hidden;">

        <div style="position:relative;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;">

            <div>
                <div style="font-size:12px;color:#86efac;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                    {tr('Grow your network', u)}
                </div>

                <h2 style="margin:6px 0 7px;">
                    {tr('Invite more friends', u)}
                </h2>

                <p class="muted" style="margin:0;max-width:620px;line-height:1.6;">
                    {tr('Share your referral code with people you know and earn the available referral bonus for successful registrations.', u)}
                </p>
            </div>

            <div style="display:flex;gap:10px;flex-wrap:wrap;">
                <button type="button"
                        class="btn"
                        onclick="copyReferralCode()">
                    📋 Copy referral code
                </button>

                <a class="btn secondary" href="/earn">
                    {tr('Explore earning', u)}
                </a>
            </div>

        </div>

        <div style="position:absolute;right:-90px;top:-100px;width:260px;height:260px;border-radius:50%;background:rgba(34,197,94,.07);"></div>

    </section>

    <script>
    function copyReferralCode() {{
        const code = document.getElementById("referral-code").innerText.trim();
        const message = document.getElementById("copy-message");

        if (navigator.clipboard && navigator.clipboard.writeText) {{
            navigator.clipboard.writeText(code).then(function() {{
                if (message) {{
                    message.style.display = "block";
                    setTimeout(function() {{
                        message.style.display = "none";
                    }}, 1800);
                }}
            }});
        }} else {{
            const area = document.createElement("textarea");
            area.value = code;
            document.body.appendChild(area);
            area.select();
            document.execCommand("copy");
            document.body.removeChild(area);

            if (message) {{
                message.style.display = "block";
                setTimeout(function() {{
                    message.style.display = "none";
                }}, 1800);
            }}
        }}
    }}
    </script>
    """

    return layout("Referrals",body,u)
@app.get('/payouts',response_class=HTMLResponse)
def payouts_page(r:Request):
 u=user(r)
 if not u:return RedirectResponse('/login',303)
 c=db(); rows=c.execute('SELECT * FROM payouts WHERE user_id=? ORDER BY id DESC',(u['id'],)).fetchall(); c.close()
 token=csrf(r)
 trs=''.join(f'<tr><td>#{x["id"]}</td><td>{money(x["amount"])}</td><td>{escape(x["method"])}</td><td>{escape(x["account"])}</td><td>{escape(x["status"])}</td></tr>' for x in rows) or '<tr><td colspan="5">No payout requests.</td></tr>'
 body=f'''<div class="grid"><div class="card"><h2>Withdraw</h2><p>{tr('Available balance', u)}: <b>{money(u["balance"])}</b></p><p class="muted">Minimum withdrawal: {money(5000)}</p><form method="post" action="/payouts"><input type="hidden" name="csrf_token" value="{token}"><label>{tr('Amount', u)} (thousandths USD)</label><input name="amount" type="number" min="5000" step="1" required><label>Method</label><select name="method"><option value="PayPal">PayPal</option><option value="USDT TRC20">USDT TRC20</option><option value="Other">Other</option></select><label>Account / wallet</label><input name="account" maxlength="200" required><button>Request payout</button></form></div><div class="card"><h2>Rules</h2><p class="muted">Payouts are processed manually in this local MVP. No real payment is sent automatically.</p></div></div><div class="card"><h2>Payout history</h2><table><tr><th>ID</th><th>{tr('Amount', u)}</th><th>Method</th><th>Account</th><th>Status</th></tr>{trs}</table></div>'''
 return layout('Payouts',body,u)

@app.post('/payouts')
def create_payout(r:Request,amount:int=Form(...),method:str=Form(...),account:str=Form(...),csrf_token:str=Form(...)):
 u=user(r)
 if not u:return RedirectResponse('/login',303)
 if not okcsrf(r,csrf_token):return RedirectResponse('/payouts',303)
 if amount<5000 or method not in ('PayPal','USDT TRC20','Other') or not account.strip() or len(account.strip())>200:return RedirectResponse('/payouts',303)
 c=db()
 try:
  c.execute('BEGIN IMMEDIATE')
  fresh=c.execute('SELECT balance FROM users WHERE id=?',(u['id'],)).fetchone()
  if not fresh or fresh['balance']<amount:
   c.rollback(); return RedirectResponse('/payouts',303)
  ts=now()
  reserved=c.execute(
   'UPDATE users SET balance=balance-? WHERE id=? AND balance>=?',
   (amount,u['id'],amount)
  ).rowcount

  if reserved!=1:
   c.rollback()
   return RedirectResponse('/payouts',303)
  cur=c.execute('INSERT INTO payouts(user_id,amount,method,account,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',(u['id'],amount,method,account.strip(),'pending',ts,ts))
  c.execute('INSERT INTO transactions(user_id,amount,kind,description,created_at) VALUES(?,?,?,?,?)',(u['id'],-amount,'payout_request',f'Payout #{cur.lastrowid} reserved',ts))
  c.commit()
 finally:c.close()
 return RedirectResponse('/payouts',303)

@app.post('/admin/payout/{pid}')
def update_payout(r:Request,pid:int,status:str=Form(...),csrf_token:str=Form(...)):
 u=user(r)

 if not u or not u['is_admin']:
  return RedirectResponse('/login',303)

 if not okcsrf(r,csrf_token):
  return RedirectResponse('/admin',303)

 if status not in ('approved','paid','rejected'):
  return RedirectResponse('/admin',303)

 c=db()

 try:
  c.execute('BEGIN IMMEDIATE')

  p=c.execute(
   'SELECT * FROM payouts WHERE id=?',
   (pid,)
  ).fetchone()

  if not p:
   c.rollback()
   return RedirectResponse('/admin',303)

  current=str(p['status'] or '').strip().lower()
  target=str(status).strip().lower()

  # Explicit payout state machine:
  #
  # pending  -> approved
  # pending  -> rejected
  # approved -> paid
  # approved -> rejected
  #
  # paid     -> terminal
  # rejected -> terminal

  allowed={
   'pending':('approved','rejected'),
   'approved':('paid','rejected'),
   'paid':(),
   'rejected':(),
  }

  if target not in allowed.get(current,()):
   c.rollback()
   return RedirectResponse('/admin',303)

  amount=int(p['amount'] or 0)

  if amount<=0:
   c.rollback()
   return RedirectResponse('/admin',303)

  ts=now()

  # The payout amount was already reserved when the request
  # was created. A rejection returns that reservation.
  if target=='rejected':
   refunded=c.execute(
    'UPDATE users SET balance=balance+? WHERE id=?',
    (amount,p['user_id'])
   ).rowcount

   if refunded!=1:
    c.rollback()
    return RedirectResponse('/admin',303)

   c.execute(
    '''
    INSERT INTO transactions
    (user_id,amount,kind,description,created_at)
    VALUES(?,?,?,?,?)
    ''',
    (
     p['user_id'],
     amount,
     'payout_refund',
     f'Payout #{pid} rejected and refunded',
     ts
    )
   )

  # The amount was already reserved at payout_request time.
  # approved and paid therefore do not modify balance.
  updated=c.execute(
   '''
   UPDATE payouts
   SET status=?,updated_at=?
   WHERE id=? AND status=?
   ''',
   (target,ts,pid,current)
  ).rowcount

  if updated!=1:
   c.rollback()
   return RedirectResponse('/admin',303)

  if target=='approved':
   c.execute(
    '''
    INSERT INTO transactions
    (user_id,amount,kind,description,created_at)
    VALUES(?,?,?,?,?)
    ''',
    (
     p['user_id'],
     0,
     'payout_approved',
     f'Payout #{pid} approved for processing',
     ts
    )
   )

  elif target=='paid':
   c.execute(
    '''
    INSERT INTO transactions
    (user_id,amount,kind,description,created_at)
    VALUES(?,?,?,?,?)
    ''',
    (
     p['user_id'],
     0,
     'payout_paid',
     f'Payout #{pid} marked as paid',
     ts
    )
   )

  c.commit()

 except Exception:
  try:
   c.rollback()
  except Exception:
   pass
  raise

 finally:
  c.close()

 return RedirectResponse('/admin',303)
 
@app.get('/admin',response_class=HTMLResponse)
def admin(r:Request):
 u=user(r)
 if not u or not u['is_admin']:return RedirectResponse('/login',303)
 c=db();ts=c.execute('SELECT * FROM tasks ORDER BY id DESC').fetchall();us=c.execute('SELECT email,balance FROM users ORDER BY id DESC').fetchall();ps=c.execute('SELECT p.*,u.email FROM payouts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC').fetchall();c.close();token=csrf(r);rows=''.join(f'<tr><td>{x["id"]}</td><td>{escape(x["title"])}</td><td>{escape(x["task_type"])}</td><td>{x["seconds"]}s</td><td>{money(x["reward"])}</td><td>{money(x["budget"])}</td><td>{money(x["spent"])}</td><td>{money(max(0,x["budget"]-x["spent"]))}</td></tr>' for x in ts);users=''.join(f'<tr><td>{escape(x["email"])}</td><td>{money(x["balance"])}</td></tr>' for x in us)
 payouts=''.join(f'<tr><td>#{x["id"]}</td><td>{escape(x["email"])}</td><td>{money(x["amount"])}</td><td>{escape(x["method"])}</td><td>{escape(x["status"])}</td><td><form method="post" action="/admin/payout/{x["id"]}"><input type="hidden" name="csrf_token" value="{token}"><select name="status"><option value="approved">approved</option><option value="paid">paid</option><option value="rejected">rejected</option></select><button>Update</button></form></td></tr>' for x in ps) or '<tr><td colspan=6>No payout requests.</td></tr>'
 body=f'''<h1>Admin</h1><div class="card"><h2>Create task</h2><form method="post" action="/admin/task"><input type="hidden" name="csrf_token" value="{token}"><label>Title</label><input name="title" required maxlength="120"><label>Destination URL</label><input name="url" type="url" required><label>Seconds</label><input name="seconds" type="number" min="5" max="86400" value="20" required><label>Reward (thousandths USD)</label><input name="reward" type="number" min="1" value="5" required><label>Budget (thousandths USD)</label><input name="budget" type="number" min="1" value="1000" required><label>{tr('Type', u)}</label><select name="task_type"><option value="visit">Website visit</option><option value="video">Video</option></select><label>Video URL</label><input name="video_url" type="url"><button>Create task</button></form></div><div class="card"><h2>Tasks</h2><table><tr><th>ID</th><th>Title</th><th>{tr('Type', u)}</th><th>Time</th><th>Reward</th><th>Budget</th><th>Spent</th><th>Remaining</th></tr>{rows}</table></div><div class="card"><h2>Users</h2><table><tr><th>{tr("Email")}</th><th>Balance</th></tr>{users}</table></div><div class="card"><h2>Payouts</h2><table><tr><th>ID</th><th>{tr('User', u)}</th><th>{tr('Amount', u)}</th><th>Method</th><th>Status</th><th>Action</th></tr>{payouts}</table></div>''';return layout('Admin',body,u)
@app.post('/admin/task')
def create_task(r:Request,title:str=Form(...),url:str=Form(...),seconds:int=Form(...),reward:int=Form(...),budget:int=Form(...),task_type:str=Form(...),video_url:str=Form(''),csrf_token:str=Form(...)):
 u=user(r)
 if not u or not u['is_admin']:return RedirectResponse('/login',303)
 url=normalizeurl(url)
 video_url=normalizeurl(video_url) if video_url.strip() else ''
 if not okcsrf(r,csrf_token) or not title.strip() or not validurl(url) or task_type not in ('visit','video') or seconds<5 or seconds>86400 or reward<1 or budget<reward or (video_url and not validurl(video_url)):return RedirectResponse('/admin',303)
 c=db()
 c.execute('INSERT INTO tasks(title,url,seconds,reward,created_at,task_type,video_url,budget,spent) VALUES(?,?,?,?,?,?,?,?,?)',(title.strip(),url,seconds,reward,now(),task_type,video_url or None,budget,0))
 c.commit()
 c.close()
 return RedirectResponse('/admin',303)



# ============================================================
# EasySurf GPT v1.0
# ============================================================

def empty_gpt_page(r:Request, title, icon, description):
    u=user(r)

    if not u:
        return RedirectResponse('/login',303)

    body=f"""
    <section class="hero">
        <h1>{icon} {escape(title)}</h1>
        <p class="muted">{escape(description)}</p>
    </section>

    <div class="card empty">
        <div class="earn-icon">{icon}</div>
        <h2>No offers available yet</h2>
        <p class="muted">
            This category is ready for real provider inventory.
            EasySurf does not create fake offers or fake rewards.
        </p>
        <a class="btn" href="/earn">Back to Earn</a>
    </div>
    """

    return layout(title,body,u)


@app.get('/earn',response_class=HTMLResponse)
def earn(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',303)

    c=db()

    tasks=c.execute(
        """
        SELECT t.*
        FROM tasks t
        WHERE t.active=1
        AND t.spent+t.reward<=t.budget
        AND NOT EXISTS(
            SELECT 1
            FROM attempts a
            WHERE a.user_id=?
            AND a.task_id=t.id
            AND a.rewarded=1
        )
        ORDER BY t.id DESC
        """,
        (u["id"],)
    ).fetchall()

    c.close()

    cards="".join(
        f"""
        <div class="card earn-card" style="min-height:205px;">
            <div>
                <div class="earn-icon" style="font-size:34px;">🌐</div>

                <div style="display:inline-flex;align-items:center;padding:5px 9px;border-radius:999px;background:rgba(59,130,246,.10);color:#93c5fd;font-size:11px;margin-bottom:8px;">
                    Website Task
                </div>

                <h3 style="margin:4px 0 8px;">{escape(x["title"])}</h3>

                <div style="display:flex;gap:8px;flex-wrap:wrap;font-size:13px;">
                    <span style="padding:5px 9px;border-radius:8px;background:rgba(148,163,184,.08);">
                        вЏ± {x["seconds"]} sec
                    </span>
                    <span style="padding:5px 9px;border-radius:8px;background:rgba(34,197,94,.09);color:#86efac;">
                        💰 {money(x["reward"])}
                    </span>
                </div>
            </div>

            <a class="btn" href="/task/{x["id"]}">
                Start task →
            </a>
        </div>
        """
        for x in tasks
    )

    if not cards:
        cards="""
        <div class="card empty" style="grid-column:1/-1;text-align:center;padding:42px;">
            <div class="earn-icon" style="font-size:42px;">🔎</div>
            <h3>{tr('No website tasks available right now', u)}</h3>
            <p class="muted" style="max-width:560px;margin:8px auto 20px;">
                {tr('There are currently no available website tasks for your account.', u)}
                Check back later or explore another earning category.
            </p>
            <div style="display:flex;justify-content:center;gap:10px;flex-wrap:wrap;">
                <a class="btn" href="/earn">Refresh</a>
                <a class="btn secondary" href="/surveys">Explore surveys</a>
            </div>
        </div>
        """

    body=f"""
    <section class="hero" style="position:relative;overflow:hidden;background-image:linear-gradient(90deg,rgba(15,23,42,.96) 0%,rgba(15,23,42,.82) 48%,rgba(15,23,42,.35) 100%),url('/static/images/hero-banner.png');background-size:cover;background-position:center;min-height:460px;display:flex;align-items:center;">
        <div style="position:relative;z-index:2;">
            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(96,165,250,.25);border-radius:999px;background:rgba(59,130,246,.10);font-size:12px;color:#93c5fd;margin-bottom:14px;">
                ⚡ EasySurf Earning Center
            </div>

            <h1 style="margin:0 0 10px;">
                Earn more, your way
            </h1>

            <p class="muted" style="max-width:700px;font-size:16px;line-height:1.7;margin:0;">
                {tr('Choose from available surveys, offers, games, apps, videos', u)}
                {tr('and verified website tasks.', u)}
            </p>

            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:24px;">
                <a class="btn" href="#tasks">🌐 {tr('Browse tasks', u)}</a>
                <a class="btn secondary" href="/rewards">🎁 {tr('View rewards', u)}</a>
            </div>
        </div>

        <div style="position:absolute;right:-80px;top:-120px;width:350px;height:350px;border-radius:50%;background:rgba(59,130,246,.11);filter:blur(8px);"></div>
        <div style="position:absolute;right:120px;bottom:-190px;width:280px;height:280px;border-radius:50%;background:rgba(34,197,94,.07);filter:blur(14px);"></div>
    </section>

    <section style="margin-top:25px;">
        <div style="display:flex;align-items:end;justify-content:space-between;gap:15px;flex-wrap:wrap;margin-bottom:15px;">
            <div>
                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.08em;">
                    Earning methods
                </div>
                <h2 style="margin:5px 0 0;">Choose an activity</h2>
            </div>

            <div class="muted" style="font-size:13px;">
                Multiple ways to grow your balance
            </div>
        </div>

        <div class="grid">

            <div class="card earn-card" style="min-height:185px;">
                <div>
                    <div class="earn-icon" style="font-size:34px;">📋</div>
                    <h3>{tr('Surveys', u)}</h3>
                    <p class="muted">
                        {tr('Share your opinion through paid research surveys when inventory is available.', u)}
                    </p>
                </div>
                <a href="/surveys">{tr('Explore surveys', u)} →</a>
            </div>

            <div class="card earn-card" style="min-height:185px;">
                <div>
                    <div class="earn-icon" style="font-size:34px;">🎁</div>
                    <h3>{tr('Offers', u)}</h3>
                    <p class="muted">
                        {tr('Complete advertiser-approved activities and tracked offers.', u)}
                    </p>
                </div>
                <a href="/offers">{tr('Explore offers', u)} →</a>
            </div>

            <div class="card earn-card" style="min-height:185px;">
                <div>
                    <div class="earn-icon" style="font-size:34px;">🎮</div>
                    <h3>{tr('Games', u)}</h3>
                    <p class="muted">
                        Discover game-based opportunities and milestone rewards.
                    </p>
                </div>
                <a href="/games">{tr('Explore games', u)} →</a>
            </div>

            <div class="card earn-card" style="min-height:185px;">
                <div>
                    <div class="earn-icon" style="font-size:34px;">📱</div>
                    <h3>{tr('Apps', u)}</h3>
                    <p class="muted">
                        Find tracked app activities and approved earning opportunities.
                    </p>
                </div>
                <a href="/apps">{tr('Explore apps', u)} →</a>
            </div>

            <div class="card earn-card" style="min-height:185px;">
                <div>
                    <div class="earn-icon" style="font-size:34px;">▶️</div>
                    <h3>{tr('Videos', u)}</h3>
                    <p class="muted">
                        {tr('Watch approved video activities when available.', u)}
                    </p>
                </div>
                <a href="/videos">{tr('Explore videos', u)} →</a>
            </div>

            <div class="card earn-card" style="min-height:185px;">
                <div>
                    <div class="earn-icon" style="font-size:34px;">🧩</div>
                    <h3>{tr('Micro Tasks', u)}</h3>
                    <p class="muted">
                        Complete small verified activities and simple tasks.
                    </p>
                </div>
                <a href="/microtasks">Explore tasks →</a>
            </div>

        </div>
    </section>

    <section id="tasks" style="margin-top:30px;">
        <div style="display:flex;align-items:end;justify-content:space-between;gap:15px;flex-wrap:wrap;margin-bottom:15px;">
            <div>
                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.08em;">
                    {tr('Available now', u)}
                </div>
                <h2 style="margin:5px 0 0;">{tr('Website Tasks', u)}</h2>
            </div>

            <div style="display:flex;align-items:center;gap:8px;font-size:13px;">
                <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;"></span>
                <span class="muted">{len(tasks)} {tr('available', u)}</span>
            </div>
        </div>

        <div class="grid">
            {cards}
        </div>
    </section>

    <section class="card" style="margin-top:25px;padding:25px;position:relative;overflow:hidden;">
        <div style="position:relative;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;">
            <div>
                <div style="font-size:12px;color:#60a5fa;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                    Keep earning
                </div>
                <h2 style="margin:6px 0 7px;">Don't stop at one category</h2>
                <p class="muted" style="margin:0;max-width:620px;">
                    {tr("Explore rewards, referrals and other earning sections to see what is currently available.", u)}
                </p>
            </div>

            <div style="display:flex;gap:10px;flex-wrap:wrap;">
                <a class="btn" href="/rewards">Rewards →</a>
                <a class="btn secondary" href="/referrals">Referrals →</a>
            </div>
        </div>

        <div style="position:absolute;right:-90px;top:-100px;width:250px;height:250px;border-radius:50%;background:rgba(59,130,246,.08);"></div>
    </section>
    """

    return layout("Earn",body,u)
@app.get('/surveys',response_class=HTMLResponse)
def surveys(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',status_code=303)

    rows=get_surveys()

    cards=[]

    for row in rows:
        cards.append(
            provider_card(
                row["title"],
                row["description"],
                row["reward"],
                row["url"],
                "Estimated time: " + str(row["seconds"] or 0) + " sec"
            )
        )

    if cards:
        body=(
            f'<h1>{tr('Surveys', u)}</h1>'
            '<p class="muted">Available surveys from connected providers.</p>'
            + ''.join(cards)
        )
    else:
        body=(
            f'<h1>{tr('Surveys', u)}</h1>'
            '<div class="card">'
            f'<h3>{tr('No surveys available right now', u)}</h3>'
            '<p class="muted">'
            f'{tr('There are currently no active survey offers from connected providers.', u)}'
            '</p>'
            '</div>'
        )

    return layout("Surveys",body,u)

@app.get('/games',response_class=HTMLResponse)
def games_page(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',status_code=303)

    rows=get_games()

    cards=[]

    for row in rows:
        cards.append(
            provider_card(
                row["title"],
                row["description"],
                row["reward"],
                row["url"],
                "Game"
            )
        )

    hero = """
    <section class="hero" style="position:relative;overflow:hidden;background-image:linear-gradient(90deg,rgba(15,23,42,.96) 0%,rgba(15,23,42,.78) 48%,rgba(15,23,42,.28) 100%),url('/static/images/hero-banner.png');background-size:cover;background-position:center;min-height:360px;display:flex;align-items:center;margin-bottom:24px;">
        <div style="position:relative;z-index:2;max-width:760px;">
            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(139,92,246,.35);border-radius:999px;background:rgba(139,92,246,.10);font-size:12px;color:#c4b5fd;margin-bottom:14px;">
                🎮 EasySurf Games
            </div>
            <h1 style="margin:0 0 10px;">
                """ + tr("Games", u) + """
            </h1>
            <p class="muted" style="max-width:680px;font-size:16px;line-height:1.7;margin:0;">
                Discover available games, complete activities and earn rewards.
            </p>
        </div>
    </section>
    """

    if cards:
        body = hero + ''.join(cards)
    else:
        body = hero + """
        <div class="card">
            <h3>""" + tr("No games available right now", u) + """</h3>
            <p class="muted">
                """ + tr("There are currently no active game offers from connected providers.", u) + """
            </p>
        </div>
        """

    return layout("Games",body,u)
@app.get('/offers',response_class=HTMLResponse)
def offers_page(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',status_code=303)

    rows=get_offers()

    cards=[]

    for row in rows:
        category=str(row["category"] or "Offer")

        cards.append(
            provider_card(
                row["title"],
                row["description"],
                row["reward"],
                row["url"],
                category
            )
        )

    hero = """
    <section class="hero" style="position:relative;overflow:hidden;background-image:linear-gradient(90deg,rgba(15,23,42,.96) 0%,rgba(15,23,42,.78) 48%,rgba(15,23,42,.28) 100%),url('/static/images/offers-banner.png');background-size:cover;background-position:center;min-height:360px;display:flex;align-items:center;margin-bottom:24px;">
        <div style="position:relative;z-index:2;max-width:760px;">
            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(245,158,11,.35);border-radius:999px;background:rgba(245,158,11,.10);font-size:12px;color:#fcd34d;margin-bottom:14px;">
                💰 EasySurf Offers
            </div>
            <h1 style="margin:0 0 10px;">
                """ + tr("Offers", u) + """
            </h1>
            <p class="muted" style="max-width:680px;font-size:16px;line-height:1.7;margin:0;">
                Explore available offers and complete partner activities to earn rewards.
            </p>
        </div>
    </section>
    """

    if cards:
        body = hero + ''.join(cards)
    else:
        body = hero + """
        <div class="card">
            <h3>""" + tr("No offers available right now", u) + """</h3>
            <p class="muted">
                """ + tr("There are currently no active offers from connected providers.", u) + """
            </p>
        </div>
        """

    return layout("Offers",body,u)
@app.get('/microtasks',response_class=HTMLResponse)
def microtasks_page(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',303)

    body=f"""
    <section class="hero" style="position:relative;overflow:hidden;background-image:linear-gradient(90deg,rgba(15,23,42,.96) 0%,rgba(15,23,42,.82) 48%,rgba(15,23,42,.35) 100%),url('/static/images/hero-banner.png');background-size:cover;background-position:center;min-height:460px;display:flex;align-items:center;">
        <div style="position:relative;z-index:2;">

            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(245,158,11,.28);border-radius:999px;background:rgba(245,158,11,.09);font-size:12px;color:#fcd34d;margin-bottom:14px;">
                🧩 {tr('EasySurf Microtasks', u)}
            </div>

            <h1 style="margin:0 0 10px;">
                {tr('Complete small tasks. Earn rewards.', u)}
            </h1>

            <p class="muted" style="max-width:720px;font-size:16px;line-height:1.7;margin:0;">
                {tr('Microtasks are short activities designed to be simple, Clear and easy to complete when real task inventory is available.', u)}

            </p>

            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:22px;">
                <a class="btn" href="/earn">
                    ⚡ {tr('Browse all tasks', u)}
                </a>

                <a class="btn secondary" href="/activity">
                    📊 {tr('View activity', u)}
                </a>
            </div>

        </div>

        <div style="position:absolute;right:-100px;top:-140px;width:390px;height:390px;border-radius:50%;background:rgba(245,158,11,.09);filter:blur(12px);"></div>

        <div style="position:absolute;right:180px;bottom:-200px;width:300px;height:300px;border-radius:50%;background:rgba(59,130,246,.06);filter:blur(12px);"></div>
    </section>

    <section style="margin-top:25px;">

        <div class="grid">

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:34px;">🧩</div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    {tr('Microtasks', u)}
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;">
                    0
                </div>

                <div class="muted" style="font-size:13px;">
                    {tr('currently available', u)}
                </div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:34px;">⏱️</div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    {tr('Task style', u)}
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;">
                    {tr('Short', u)}
                </div>

                <div class="muted" style="font-size:13px;">
                    {tr('focused activities', u)}
                </div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:34px;">🛡️</div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    {tr('Rewards', u)}
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;color:#86efac;">
                    {tr('Verified', u)}
                </div>

                <div class="muted" style="font-size:13px;">
                    {tr('after valid completion', u)}
                </div>
            </div>

        </div>

    </section>

    <section style="margin-top:28px;">

        <div class="card" style="position:relative;overflow:hidden;padding:38px;text-align:center;">

            <div style="position:relative;z-index:2;max-width:720px;margin:0 auto;">

                <div style="width:78px;height:78px;margin:0 auto 18px;border-radius:24px;display:flex;align-items:center;justify-content:center;font-size:40px;background:linear-gradient(135deg,rgba(245,158,11,.18),rgba(59,130,246,.10));border:1px solid rgba(245,158,11,.25);box-shadow:0 15px 45px rgba(0,0,0,.18);">
                    🧩
                </div>

                <div style="font-size:12px;color:#fbbf24;text-transform:uppercase;letter-spacing:.09em;font-weight:700;">
                    {tr('Microtask inventory', u)}
                </div>

                <h2 style="margin:7px 0 10px;">
                    {tr('No microtasks available yet', u)}
                </h2>

                <p class="muted" style="max-width:620px;margin:0 auto;line-height:1.7;">
                    {tr('This section is ready for real microtask providers. EasySurf does not generate fake tasks, fake completions, or artificial rewards.', u)}


                </p>

                <div style="display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin-top:22px;">
                    <a class="btn" href="/earn">
                        ⚡ {tr('Browse earning tasks', u)}
                    </a>

                    <a class="btn secondary" href="/offers">
                        💎 {tr('Explore offers', u)}
                    </a>
                </div>

            </div>

            <div style="position:absolute;left:-110px;top:-110px;width:280px;height:280px;border-radius:50%;background:rgba(245,158,11,.06);filter:blur(15px);"></div>

            <div style="position:absolute;right:-100px;bottom:-120px;width:300px;height:300px;border-radius:50%;background:rgba(59,130,246,.06);filter:blur(15px);"></div>

        </div>

    </section>

    <section style="margin-top:28px;">

        <div class="grid">

            <div class="card">
                <div style="font-size:28px;margin-bottom:10px;">🔎</div>

                <h3 style="margin:0 0 7px;">
                    {tr('Choose a task', u)}
                </h3>

                <p class="muted" style="margin:0;line-height:1.6;font-size:13px;">
                    {tr('Select an available microtask and read its requirements carefully.', u)}
                </p>
            </div>

            <div class="card">
                <div style="font-size:28px;margin-bottom:10px;">✍️</div>

                <h3 style="margin:0 0 7px;">
                    {tr('Complete it', u)}
                </h3>

                <p class="muted" style="margin:0;line-height:1.6;font-size:13px;">
                    {tr('Follow the instructions and submit only valid work.', u)}
                </p>
            </div>

            <div class="card">
                <div style="font-size:28px;margin-bottom:10px;">💰</div>

                <h3 style="margin:0 0 7px;">
                    {tr('Get credited', u)}
                </h3>

                <p class="muted" style="margin:0;line-height:1.6;font-size:13px;">
                    {tr('A reward is credited after the completion is accepted or verified.', u)}
                </p>
            </div>

        </div>

    </section>
    """

    return layout("Microtasks",body,u)
@app.get('/videos',response_class=HTMLResponse)
def videos_page(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',303)

    c=db()

    rows=c.execute(
        """
        SELECT *
        FROM tasks
        WHERE active=1
          AND task_type='video'
          AND spent + reward <= budget
        ORDER BY id DESC
        """
    ).fetchall()

    c.close()

    cards="".join(
        f"""
        <div class="card" style="position:relative;overflow:hidden;">

            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:15px;">

                <div>
                    <div style="width:52px;height:52px;border-radius:16px;display:flex;align-items:center;justify-content:center;font-size:27px;background:rgba(239,68,68,.10);border:1px solid rgba(239,68,68,.18);margin-bottom:14px;">
                        ▶️
                    </div>

                    <h3 style="margin:0 0 7px;">
                        {escape(x["title"])}
                    </h3>

                    <p class="muted" style="margin:0;line-height:1.6;font-size:13px;">
                        Watch the available video and complete the task requirements.
                    </p>
                </div>

                <div style="white-space:nowrap;padding:7px 10px;border-radius:999px;background:rgba(34,197,94,.10);color:#86efac;font-weight:700;font-size:13px;">
                    +{money(x["reward"])}
                </div>

            </div>

            <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:18px;">

                <span style="padding:6px 9px;border-radius:999px;background:rgba(148,163,184,.08);color:#cbd5e1;font-size:12px;">
                    ⏱️ {int(x["seconds"])} sec
                </span>

                <span style="padding:6px 9px;border-radius:999px;background:rgba(148,163,184,.08);color:#cbd5e1;font-size:12px;">
                    🎥 Video
                </span>

                <span style="padding:6px 9px;border-radius:999px;background:rgba(59,130,246,.08);color:#93c5fd;font-size:12px;">
                    ✓ Available
                </span>

            </div>

            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:20px;">

                <a class="btn" href="/complete/{int(x["id"])}">
                    ▶️ Start video
                </a>

            </div>

        </div>
        """
        for x in rows
    )

    if not cards:
        cards="""
        <div class="card" style="position:relative;overflow:hidden;padding:38px;text-align:center;">

            <div style="position:relative;z-index:2;max-width:720px;margin:0 auto;">

                <div style="width:78px;height:78px;margin:0 auto 18px;border-radius:24px;display:flex;align-items:center;justify-content:center;font-size:40px;background:linear-gradient(135deg,rgba(239,68,68,.16),rgba(59,130,246,.10));border:1px solid rgba(239,68,68,.22);box-shadow:0 15px 45px rgba(0,0,0,.18);">
                    ▶️
                </div>

                <div style="font-size:12px;color:#fca5a5;text-transform:uppercase;letter-spacing:.09em;font-weight:700;">
                    Video inventory
                </div>

                <h2 style="margin:7px 0 10px;">
                    No video tasks available
                </h2>

                <p class="muted" style="max-width:620px;margin:0 auto;line-height:1.7;">
                    New video tasks will appear here when real campaigns are available.
                    EasySurf does not create fake video views {tr('or artificial rewards.', u)}
                </p>

                <div style="display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin-top:22px;">

                    <a class="btn" href="/earn">
                        ⚡ {tr('Browse earning tasks', u)}
                    </a>

                    <a class="btn secondary" href="/games">
                        🎮 Explore games
                    </a>

                </div>

            </div>

            <div style="position:absolute;left:-110px;top:-110px;width:280px;height:280px;border-radius:50%;background:rgba(239,68,68,.06);filter:blur(15px);"></div>

            <div style="position:absolute;right:-100px;bottom:-120px;width:300px;height:300px;border-radius:50%;background:rgba(59,130,246,.06);filter:blur(15px);"></div>

        </div>
        """

    body=f"""
    <section class="hero" style="position:relative;overflow:hidden;background-image:linear-gradient(90deg,rgba(15,23,42,.96) 0%,rgba(15,23,42,.82) 48%,rgba(15,23,42,.35) 100%),url('/static/images/hero-banner.png');background-size:cover;background-position:center;min-height:460px;display:flex;align-items:center;">

        <div style="position:relative;z-index:2;">

            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(239,68,68,.28);border-radius:999px;background:rgba(239,68,68,.09);font-size:12px;color:#fca5a5;margin-bottom:14px;">
                🎥 EasySurf Videos
            </div>

            <h1 style="margin:0 0 10px;">
                Watch. Complete. Earn.
            </h1>

            <p class="muted" style="max-width:720px;font-size:16px;line-height:1.7;margin:0;">
                Watch eligible video tasks and receive the listed reward
                after the task is completed and accepted.
            </p>

            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:22px;">

                <a class="btn" href="/earn">
                    ⚡ {tr('Browse all tasks', u)}
                </a>

                <a class="btn secondary" href="/activity">
                    📊 {tr('View activity', u)}
                </a>

            </div>

        </div>

        <div style="position:absolute;right:-100px;top:-140px;width:390px;height:390px;border-radius:50%;background:rgba(239,68,68,.08);filter:blur(12px);"></div>

        <div style="position:absolute;right:180px;bottom:-200px;width:300px;height:300px;border-radius:50%;background:rgba(59,130,246,.06);filter:blur(12px);"></div>

    </section>

    <section style="margin-top:25px;">

        <div class="grid">

            <div class="card" style="min-height:150px;">

                <div class="earn-icon" style="font-size:34px;">
                    🎥
                </div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    Video tasks
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;">
                    {len(rows)}
                </div>

                <div class="muted" style="font-size:13px;">
                    {tr('currently available', u)}
                </div>

            </div>

            <div class="card" style="min-height:150px;">

                <div class="earn-icon" style="font-size:34px;">
                    ⏱️
                </div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    Format
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;">
                    {tr('Short', u)}
                </div>

                <div class="muted" style="font-size:13px;">
                    watch-based activities
                </div>

            </div>

            <div class="card" style="min-height:150px;">

                <div class="earn-icon" style="font-size:34px;">
                    💰
                </div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    Reward
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;color:#86efac;">
                    {tr('Verified', u)}
                </div>

                <div class="muted" style="font-size:13px;">
                    {tr('after valid completion', u)}
                </div>

            </div>

        </div>

    </section>

    <section style="margin-top:28px;">

        <div class="grid">

            {cards}

        </div>

    </section>

    <section class="card" style="margin-top:28px;padding:26px;">

        <div style="display:flex;align-items:center;gap:15px;">

            <div style="width:48px;height:48px;border-radius:15px;display:flex;align-items:center;justify-content:center;font-size:24px;background:rgba(59,130,246,.10);">
                ℹ️
            </div>

            <div>

                <h3 style="margin:0 0 5px;">
                    How video rewards work
                </h3>

                <p class="muted" style="margin:0;line-height:1.6;font-size:13px;">
                    Only active video tasks with remaining campaign budget are shown.
                    Completing a task does not guarantee payment until the required validation is passed.
                </p>

            </div>

        </div>

    </section>
    """

    return layout("Videos",body,u)





@app.get('/about',response_class=HTMLResponse)
def about_page(r:Request):
    u=user(r)
    body="""
    <section class="hero">
      <div class="eyebrow">ABOUT EASYSURF</div>
      <h1>Simple online rewards.</h1>
      <p>
        EasySurf brings available online activities into one simple
        rewards dashboard.
      </p>
    </section>

    <section class="grid">
      <div class="card">
        <h2>What is EasySurf?</h2>
        <p class="muted">
          EasySurf organizes available tasks, videos, surveys, offers,
          games and app activities in one place.
        </p>
      </div>

      <div class="card">
        <h2>How rewards work</h2>
        <p class="muted">
          Each activity has its own requirements, duration and reward.
          Completed activities are recorded in your account.
        </p>
      </div>

      <div class="card">
        <h2>Transparency</h2>
        <p class="muted">
          {tr('Activity', u)} availability and reward amounts depend on the tasks
          {tr('currently available', u)} on the platform.
        </p>
      </div>
    </section>
    """
    return layout("About",body,u)


@app.get('/contact',response_class=HTMLResponse)
def contact_page(r:Request):
    u=user(r)
    body="""
    <section class="hero">
      <div class="eyebrow">CONTACT</div>
      <h1>Contact EasySurf.</h1>
      <p>
        Have a question about your account, an activity or a payout?
        Use the support information available through your account.
      </p>
    </section>

    <section class="grid">
      <div class="card">
        <h2>Account support</h2>
        <p class="muted">
          Include your registered email address and a clear description
          of the problem.
        </p>
      </div>

      <div class="card">
        <h2>Task problems</h2>
        <p class="muted">
          Include the task name or identifier and describe what happened.
        </p>
      </div>

      <div class="card">
        <h2>Payout questions</h2>
        <p class="muted">
          Include the relevant payout request information.
          Never send your password.
        </p>
      </div>
    </section>
    """
    return layout("Contact",body,u)


@app.get('/faq',response_class=HTMLResponse)
def faq_page(r:Request):
    u=user(r)
    body="""
    <section class="hero">
      <div class="eyebrow">FAQ</div>
      <h1>Frequently asked questions.</h1>
      <p>
        Common questions about EasySurf activities and rewards.
      </p>
    </section>

    <section class="grid">

      <div class="card">
        <h2>How do I earn?</h2>
        <p class="muted">
          Open the Earn section, select an available activity and
          complete its requirements.
        </p>
      </div>

      <div class="card">
        <h2>Why are there no offers?</h2>
        <p class="muted">
          Available activities depend on the current task inventory
          and connected providers.
        </p>
      </div>

      <div class="card">
        <h2>When is a task rewarded?</h2>
        <p class="muted">
          The configured completion requirements must be satisfied
          before a reward is recorded.
        </p>
      </div>

      <div class="card">
        <h2>Can I have multiple accounts?</h2>
        <p class="muted">
          Use your account according to the platform rules.
          Multiple accounts used to bypass restrictions may be restricted.
        </p>
      </div>

      <div class="card">
        <h2>Can rewards change?</h2>
        <p class="muted">
          Yes. Task availability, budgets, rewards and requirements
          may change.
        </p>
      </div>

      <div class="card">
        <h2>Is income guaranteed?</h2>
        <p class="muted">
          No. EasySurf does not guarantee a fixed amount of income.
        </p>
      </div>

    </section>
    """
    return layout("FAQ",body,u)


@app.get('/help',response_class=HTMLResponse)
def help_page(r:Request):
    u=user(r)
    body="""
    <section class="hero">
      <div class="eyebrow">HELP CENTER</div>
      <h1>How can we help?</h1>
      <p>
        Find the EasySurf section you need below.
      </p>
    </section>

    <section class="grid">

      <a class="card" href="/earn" style="text-decoration:none;color:inherit;">
        <h2>Earn</h2>
        <p class="muted">
          Browse available tasks and earning activities.
        </p>
      </a>

      <a class="card" href="/rewards" style="text-decoration:none;color:inherit;">
        <h2>Rewards</h2>
        <p class="muted">
          Review available reward features.
        </p>
      </a>

      <a class="card" href="/payouts" style="text-decoration:none;color:inherit;">
        <h2>Payouts</h2>
        <p class="muted">
          Review withdrawal requests and payout information.
        </p>
      </a>

      <a class="card" href="/activity" style="text-decoration:none;color:inherit;">
        <h2>{tr('Activity', u)}</h2>
        <p class="muted">
          Review recorded account activity.
        </p>
      </a>

    </section>
    """
    return layout("Help Center",body,u)


@app.get('/privacy',response_class=HTMLResponse)
def privacy_page(r:Request):
    u=user(r)
    body="""
    <section class="hero">
      <div class="eyebrow">PRIVACY</div>
      <h1>Privacy Policy.</h1>
      <p>
        Information about account data and platform operation.
      </p>
    </section>

    <section class="card legal-card">
      <h2>Information we use</h2>
      <p class="muted">
        EasySurf may store account information such as email address,
        account identifier, balance, activity history, rewards and
        payout information required to operate the platform.
      </p>

      <h2>Security</h2>
      <p class="muted">
        Keep your login credentials private and never send your password
        to support.
      </p>

      <h2>{tr('Activity', u)} records</h2>
      <p class="muted">
        {tr('Activity', u)} and transaction records may be retained to calculate
        rewards, prevent duplicate completions and investigate suspicious
        activity.
      </p>

      <h2>Third-party services</h2>
      <p class="muted">
        If external providers are connected, information required for
        a specific activity may be processed according to the provider's
        applicable terms and privacy policy.
      </p>
    </section>
    """
    return layout("Privacy Policy",body,u)


@app.get('/terms',response_class=HTMLResponse)
def terms_page(r:Request):
    u=user(r)
    body="""
    <section class="hero">
      <div class="eyebrow">TERMS</div>
      <h1>Terms of Service.</h1>
      <p>
        General rules for using the EasySurf platform.
      </p>
    </section>

    <section class="card legal-card">
      <h2>Account use</h2>
      <p class="muted">
        You are responsible for activity performed through your account
        and for keeping your credentials secure.
      </p>

      <h2>Fair participation</h2>
      <p class="muted">
        Do not manipulate task completion, duplicate rewards, exploit
        platform errors or interfere with EasySurf.
      </p>

      <h2>Rewards</h2>
      <p class="muted">
        Rewards are associated with individual activities and their
        configured requirements. Availability may change.
      </p>

      <h2>Account restrictions</h2>
      <p class="muted">
        Suspicious, abusive or fraudulent activity may result in
        appropriate account restrictions.
      </p>
    </section>
    """
    return layout("Terms of Service",body,u)


@app.get('/cookies',response_class=HTMLResponse)
def cookies_page(r:Request):
    u=user(r)
    body="""
    <section class="hero">
      <div class="eyebrow">COOKIES</div>
      <h1>Cookie Policy.</h1>
      <p>
        Information about cookies and browser storage used by EasySurf.
      </p>
    </section>

    <section class="card legal-card">
      <h2>Session cookies</h2>
      <p class="muted">
        Session information allows EasySurf to recognize your account
        while you move between pages.
      </p>

      <h2>Essential functionality</h2>
      <p class="muted">
        Essential browser storage may be used for authentication,
        security and core platform functions.
      </p>

      <h2>Third-party cookies</h2>
      <p class="muted">
        If third-party services are integrated, those services may
        use cookies according to their own policies.
      </p>

      <h2>Browser controls</h2>
      <p class="muted">
        You can control cookies through your browser settings.
        Disabling essential cookies may prevent some functions from working.
      </p>
    </section>
    """
    return layout("Cookie Policy",body,u)



@app.get('/apps',response_class=HTMLResponse)
def apps_page(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',status_code=303)

    rows=get_apps()

    cards=[]

    for row in rows:
        platform=str(row["platform"] or "android")

        cards.append(
            provider_card(
                row["title"],
                row["description"],
                row["reward"],
                row["url"],
                platform
            )
        )

    hero = """
    <section class="hero" style="position:relative;overflow:hidden;background-image:linear-gradient(90deg,rgba(15,23,42,.96) 0%,rgba(15,23,42,.78) 48%,rgba(15,23,42,.28) 100%),url('/static/images/apps-banner.png');background-size:cover;background-position:center;min-height:360px;display:flex;align-items:center;margin-bottom:24px;">
        <div style="position:relative;z-index:2;max-width:760px;">
            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(59,130,246,.35);border-radius:999px;background:rgba(59,130,246,.10);font-size:12px;color:#93c5fd;margin-bottom:14px;">
                📱 EasySurf Apps
            </div>
            <h1 style="margin:0 0 10px;">
                """ + tr("Apps", u) + """
            </h1>
            <p class="muted" style="max-width:680px;font-size:16px;line-height:1.7;margin:0;">
                Discover available applications from connected providers and earn rewards.
            </p>
        </div>
    </section>
    """

    if cards:
        body = hero + ''.join(cards)
    else:
        body = hero + """
        <div class="card">
            <h3>""" + tr("No apps available right now", u) + """</h3>
            <p class="muted">
                """ + tr("There are currently no active app offers from connected providers.", u) + """
            </p>
        </div>
        """

    return layout("Apps",body,u)
@app.get('/rewards',response_class=HTMLResponse)
def rewards(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',303)

    c=db()

    day_key=str(now()//86400)

    today_start=(now()//86400)*86400

    today=c.execute(
        """
        SELECT COALESCE(SUM(amount),0) n
        FROM transactions
        WHERE user_id=? AND amount>0 AND created_at>=?
        """,
        (u["id"],today_start)
    ).fetchone()["n"]

    claim=c.execute(
        """
        SELECT id
        FROM daily_bonus_claims
        WHERE user_id=? AND day=?
        """,
        (u["id"],day_key)
    ).fetchone()

    c.close()

    goal=100
    percent=min(100,int(today*100/goal)) if goal else 0

    if claim:
        bonus=f"""
        <div class="card" style="border-color:rgba(34,197,94,.25);background:linear-gradient(135deg,rgba(34,197,94,.10),rgba(15,23,42,.82));">
            <div style="display:flex;align-items:flex-start;gap:16px;">
                <div style="width:54px;height:54px;min-width:54px;border-radius:16px;display:flex;align-items:center;justify-content:center;background:rgba(34,197,94,.14);font-size:28px;">
                    ✓
                </div>

                <div>
                    <div style="font-size:12px;color:#86efac;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                        {tr('Daily Bonus', u)}
                    </div>

                    <h2 style="margin:5px 0 7px;">
                        {tr('Bonus claimed today', u)}
                    </h2>

                    <p class="muted" style="margin:0;line-height:1.6;">
                        {tr('Come back tomorrow to continue your streak and claim the next daily bonus.', u)}
                    </p>
                </div>
            </div>
        </div>
        """
    else:
        token=csrf(r)

        bonus=f"""
        <div class="card" style="position:relative;overflow:hidden;border-color:rgba(59,130,246,.28);background:linear-gradient(135deg,rgba(59,130,246,.12),rgba(15,23,42,.88));">
            <div style="position:relative;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:24px;flex-wrap:wrap;">

                <div style="display:flex;align-items:flex-start;gap:16px;">
                    <div style="width:58px;height:58px;min-width:58px;border-radius:18px;display:flex;align-items:center;justify-content:center;background:rgba(59,130,246,.16);font-size:30px;">
                        🎁
                    </div>

                    <div>
                        <div style="font-size:12px;color:#60a5fa;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                            Daily Reward
                        </div>

                        <h2 style="margin:5px 0 7px;">
                            {tr('Your daily bonus is ready', u)}
                        </h2>

                        <p class="muted" style="margin:0;line-height:1.6;">
                            {tr('Claim your bonus once today and keep your earning streak alive.', u)}
                        </p>
                    </div>
                </div>

                <form method="post" action="/rewards/daily" style="margin:0;">
                    <input type="hidden"
                           name="csrf_token"
                           value="{token}">

                    <button class="btn" style="min-width:190px;">
                        🎁 Claim {tr('Daily Bonus', u)}
                    </button>
                </form>

            </div>

            <div style="position:absolute;right:-80px;top:-120px;width:300px;height:300px;border-radius:50%;background:rgba(59,130,246,.09);filter:blur(10px);"></div>
        </div>
        """

    body=f"""
    <section class="hero" style="position:relative;overflow:hidden;background-image:linear-gradient(90deg,rgba(15,23,42,.96) 0%,rgba(15,23,42,.82) 48%,rgba(15,23,42,.35) 100%),url('/static/images/hero-banner.png');background-size:cover;background-position:center;min-height:460px;display:flex;align-items:center;">
        <div style="position:relative;z-index:2;">

            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(168,85,247,.25);border-radius:999px;background:rgba(168,85,247,.10);font-size:12px;color:#c4b5fd;margin-bottom:14px;">
                ✨ EasySurf Rewards Center
            </div>

            <h1 style="margin:0 0 10px;">
                Rewards & Bonuses
            </h1>

            <p class="muted" style="max-width:720px;font-size:16px;line-height:1.7;margin:0;">
                {tr('Claim your daily bonus, build your earning streak,', u)}
                {tr('reach your daily goal and unlock more rewards.', u)}
            </p>

            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:22px;">
                <a class="btn" href="/earn">
                    ⚡ {tr('Start earning', u)}
                </a>

                <a class="btn secondary" href="/activity">
                    📊 {tr('View activity', u)}
                </a>
            </div>

        </div>

        <div style="position:absolute;right:-100px;top:-140px;width:390px;height:390px;border-radius:50%;background:rgba(168,85,247,.10);filter:blur(10px);"></div>

        <div style="position:absolute;right:160px;bottom:-210px;width:300px;height:300px;border-radius:50%;background:rgba(59,130,246,.08);filter:blur(12px);"></div>
    </section>

    <section style="margin-top:25px;">

        <div style="display:flex;align-items:end;justify-content:space-between;gap:15px;flex-wrap:wrap;margin-bottom:15px;">
            <div>
                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.08em;">
                    {tr("Today's reward", u)}
                </div>

                <h2 style="margin:5px 0 0;">
                    {tr('Daily Bonus', u)}
                </h2>
            </div>

            <div style="font-size:13px;" class="muted">
                {tr('One claim per day', u)}
            </div>
        </div>

        {bonus}

    </section>

    <section style="margin-top:28px;">

        <div class="card" style="padding:26px;position:relative;overflow:hidden;">

            <div style="position:relative;z-index:2;">

                <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:20px;flex-wrap:wrap;">

                    <div>
                        <div style="font-size:12px;color:#60a5fa;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                            {tr('Daily Goal', u)}
                        </div>

                        <h2 style="margin:6px 0 7px;">
                            {tr("Reach today's target", u)}
                        </h2>

                        <p class="muted" style="margin:0;max-width:580px;line-height:1.6;">
                            {tr('Keep completing eligible activities to increase your progress toward the daily earning goal.', u)}
                        </p>
                    </div>

                    <div style="text-align:right;">
                        <div style="font-size:30px;font-weight:800;">
                            {percent}%
                        </div>

                        <div class="muted" style="font-size:12px;">
                            progress
                        </div>
                    </div>

                </div>

                <div class="progress" style="height:14px;margin-top:22px;">
                    <div class="progress-bar"
                         style="width:{percent}%;"></div>
                </div>

                <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:12px;flex-wrap:wrap;">
                    <span class="muted" style="font-size:13px;">
                        {tr('Earned today', u)}
                    </span>

                    <strong style="font-size:16px;">
                        {money(today)} <span class="muted">/ {money(goal)}</span>
                    </strong>
                </div>

            </div>

            <div style="position:absolute;right:-100px;bottom:-160px;width:300px;height:300px;border-radius:50%;background:rgba(34,197,94,.06);"></div>

        </div>

    </section>

    <section style="margin-top:28px;">

        <div style="display:flex;align-items:end;justify-content:space-between;gap:15px;flex-wrap:wrap;margin-bottom:15px;">

            <div>
                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.08em;">
                    {tr('Your progress', u)}
                </div>

                <h2 style="margin:5px 0 0;">
                    {tr('Keep the momentum', u)}
                </h2>
            </div>

            <div class="muted" style="font-size:13px;">
                {tr('Earn every day to build your progress', u)}
            </div>

        </div>

        <div class="grid">

            <div class="card earn-card" style="min-height:205px;">
                <div>
                    <div class="earn-icon" style="font-size:38px;">🔥</div>

                    <div style="display:inline-flex;padding:5px 9px;border-radius:999px;background:rgba(249,115,22,.10);color:#fdba74;font-size:11px;margin-bottom:8px;">
                        {tr('Daily streak', u)}
                    </div>

                    <h3 style="margin:4px 0 7px;">
                        {tr('Streak', u)}
                    </h3>

                    <p class="muted" style="line-height:1.6;">
                        {tr('Keep earning every day to maintain your reward streak.', u)}
                    </p>
                </div>

                <a href="/activity">
                    {tr('View activity →', u)}
                </a>
            </div>

            <div class="card earn-card" style="min-height:205px;">
                <div>
                    <div class="earn-icon" style="font-size:38px;">🏆</div>

                    <div style="display:inline-flex;padding:5px 9px;border-radius:999px;background:rgba(168,85,247,.10);color:#c4b5fd;font-size:11px;margin-bottom:8px;">
                        {tr('Milestones', u)}
                    </div>

                    <h3 style="margin:4px 0 7px;">
                        {tr('Achievements', u)}
                    </h3>

                    <p class="muted" style="line-height:1.6;">
                        {tr('Complete milestones and keep building your account progress.', u)}
                    </p>
                </div>

                <a href="/activity">
                    View progress →
                </a>
            </div>

            <div class="card earn-card" style="min-height:205px;">
                <div>
                    <div class="earn-icon" style="font-size:38px;">🥇</div>

                    <div style="display:inline-flex;padding:5px 9px;border-radius:999px;background:rgba(234,179,8,.10);color:#fde68a;font-size:11px;margin-bottom:8px;">
                        {tr('Community', u)}
                    </div>

                    <h3 style="margin:4px 0 7px;">
                        Leaderboard
                    </h3>

                    <p class="muted" style="line-height:1.6;">
                        {tr('See how your total earnings compare with other EasySurf users.', u)}
                    </p>
                </div>

                <a href="/leaderboard">
                    {tr('Open leaderboard →', u)}
                </a>
            </div>

        </div>

    </section>

    <section class="card" style="margin-top:28px;padding:26px;position:relative;overflow:hidden;">

        <div style="position:relative;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;">

            <div>
                <div style="font-size:12px;color:#60a5fa;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                    {tr('More ways to earn', u)}
                </div>

                <h2 style="margin:6px 0 7px;">
                    {tr('Turn activity into rewards', u)}
                </h2>

                <p class="muted" style="margin:0;max-width:620px;line-height:1.6;">
                    Explore available tasks, surveys, offers, games and other earning sections.
                </p>
            </div>

            <div style="display:flex;gap:10px;flex-wrap:wrap;">
                <a class="btn" href="/earn">
                    {tr('Explore earning', u)}
                </a>

                <a class="btn secondary" href="/referrals">
                    Invite friends
                </a>
            </div>

        </div>

        <div style="position:absolute;right:-90px;top:-100px;width:260px;height:260px;border-radius:50%;background:rgba(168,85,247,.07);"></div>

    </section>
    """

    return layout("Rewards",body,u)
@app.post('/rewards/daily')
def claim_daily_bonus(r:Request,csrf_token:str=Form(...)):
    u=user(r)

    if not u:
        return RedirectResponse('/login',303)

    if u["is_admin"]:
        return RedirectResponse('/rewards',303)

    if not okcsrf(r,csrf_token):
        return RedirectResponse('/rewards',303)

    c=db()

    try:
        c.execute("BEGIN IMMEDIATE")

        day=now()//86400
        day_key=str(day)

        existing=c.execute(
            """
            SELECT id
            FROM daily_bonus_claims
            WHERE user_id=? AND day=?
            """,
            (u["id"],day_key)
        ).fetchone()

        if existing:
            c.rollback()
            return RedirectResponse('/rewards',303)

        previous=c.execute(
            """
            SELECT streak_day
            FROM daily_bonus_claims
            WHERE user_id=? AND day=?
            """,
            (u["id"],str(day-1))
        ).fetchone()

        streak=(previous["streak_day"]+1) if previous else 1

        schedule=[1,2,3,4,5,6,10]
        amount=schedule[min(streak,7)-1]

        ts=now()

        c.execute(
            """
            INSERT INTO daily_bonus_claims
            (user_id,day,streak_day,amount,created_at)
            VALUES(?,?,?,?,?)
            """,
            (u["id"],day_key,streak,amount,ts)
        )

        c.execute(
            "UPDATE users SET balance=balance+? WHERE id=?",
            (amount,u["id"])
        )

        c.execute(
            """
            INSERT INTO transactions
            (user_id,amount,kind,description,created_at)
            VALUES(?,?,?,?,?)
            """,
            (
                u["id"],
                amount,
                "daily_bonus",
                f"Daily Bonus - Day {streak}",
                ts
            )
        )

        c.execute(
            """
            INSERT INTO activity_log
            (user_id,activity_type,title,amount,status,created_at)
            VALUES(?,?,?,?,?,?)
            """,
            (
                u["id"],
                "daily_bonus",
                f"Daily Bonus - Day {streak}",
                amount,
                "completed",
                ts
            )
        )

        c.commit()

    finally:
        c.close()

    return RedirectResponse('/rewards',303)


@app.get('/activity',response_class=HTMLResponse)
def activity(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',303)

    c=db()

    rows=c.execute(
        """
        SELECT *
        FROM transactions
        WHERE user_id=?
        ORDER BY id DESC
        LIMIT 100
        """,
        (u["id"],)
    ).fetchall()

    pending=c.execute(
        """
        SELECT *
        FROM reward_events
        WHERE user_id=? AND status='pending'
        ORDER BY id DESC
        """,
        (u["id"],)
    ).fetchall()

    c.close()

    transactions="".join(
        f"""
        <tr>
            <td>{escape(x["description"])}</td>
            <td>{escape(x["kind"])}</td>
            <td class="green">
                +{money(x["amount"])}
            </td>
        </tr>
        """
        for x in rows
    )

    if not transactions:
        transactions=f"""
        <tr>
            <td colspan="3" class="muted">
                {tr('No transactions yet.', u)}
            </td>
        </tr>
        """

    pending_rows="".join(
        f"""
        <tr>
            <td>{escape(x["source_type"])}</td>
            <td>{money(x["amount"])}</td>
            <td class="orange">{tr('Pending', u)}</td>
        </tr>
        """
        for x in pending
    )

    if not pending_rows:
        pending_rows=f"""
        <tr>
            <td colspan="3" class="muted">
                {tr('No pending rewards.', u)}
            </td>
        </tr>
        """

    body=f"""
    <section class="hero">
        <h1>📊 {tr('Activity', u)}</h1>
        <p class="muted">
            {tr('Track your completed and pending rewards.', u)}
        </p>
    </section>

    <div class="card">
        <h2>{tr('Pending Rewards', u)}</h2>

        <table>
            <tr>
                <th>{tr('Source', u)}</th>
                <th>{tr('Amount', u)}</th>
                <th>{tr('Status', u)}</th>
            </tr>

            {pending_rows}
        </table>
    </div>

    <div class="card">
        <h2>{tr('Transaction History', u)}</h2>

        <table>
            <tr>
                <th>{tr('Description', u)}</th>
                <th>{tr('Type', u)}</th>
                <th>{tr('Amount', u)}</th>
            </tr>

            {transactions}
        </table>
    </div>
    """

    return layout("Activity",body,u)


@app.get('/leaderboard',response_class=HTMLResponse)
def leaderboard(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',303)

    c=db()

    rows=c.execute(
        """
        SELECT
            u.email,
            COALESCE(SUM(t.amount),0) AS earned
        FROM users u
        LEFT JOIN transactions t
            ON t.user_id=u.id
            AND t.amount>0
        WHERE u.is_admin=0
        GROUP BY u.id
        ORDER BY earned DESC
        LIMIT 25
        """
    ).fetchall()

    c.close()

    table=""

    for i,x in enumerate(rows,1):
        email=x["email"]
        name=email.split("@")[0]

        if len(name)>4:
            name=name[:2]+"***"+name[-1:]

        table+=f"""
        <tr>
            <td><b>#{i}</b></td>
            <td>{escape(name)}</td>
            <td>{money(x["earned"])}</td>
        </tr>
        """

    if not table:
        table="""
        <tr>
            <td colspan="3">
                {tr('No rankings yet.', u)}
            </td>
        </tr>
        """

    body=f"""
    <section class="hero">
        <h1>🏆 {tr('Leaderboard', u)}</h1>
        <p class="muted">
            {tr('Top EasySurf earners.', u)}
        </p>
    </section>

    <div class="card">
        <table>
            <tr>
                <th>{tr('Rank', u)}</th>
                <th>{tr('User', u)}</th>
                <th>{tr('Total earned', u)}</th>
            </tr>

            {table}
        </table>
    </div>
    """

    return layout("Leaderboard",body,u)


# ============================================================
# SECURITY V4 вЂ” OFFERWALL.GG SECURE POSTBACK
# ============================================================

def _init_offerwall_v4():
    c = db()

    try:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS offerwall_postbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transaction_id TEXT NOT NULL,
                status TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                offer_id TEXT,
                offer_name TEXT,
                goal_id TEXT,
                currency_amount TEXT NOT NULL,
                amount INTEGER NOT NULL DEFAULT 0,
                currency_name TEXT,
                payout_usd TEXT,
                test INTEGER NOT NULL DEFAULT 0,
                provider_timestamp INTEGER,
                signature TEXT,
                reversal_of_id INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )

        c.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS
            ux_offerwall_postbacks_transaction_status
            ON offerwall_postbacks(transaction_id,status)
            """
        )

        c.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_offerwall_postbacks_user
            ON offerwall_postbacks(user_id,created_at)
            """
        )

        c.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_offerwall_postbacks_transaction
            ON offerwall_postbacks(transaction_id)
            """
        )

        c.commit()

    finally:
        c.close()


def _offerwall_amount_to_points(value):
    from decimal import Decimal, InvalidOperation, ROUND_FLOOR

    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError):
        return None

    if not amount.is_finite():
        return None

    if amount == 0:
        return 0

    # EasySurf balances are integer points.
    # Floor positive credits and use the same magnitude
    # for reversals.
    if amount > 0:
        return int(
            amount.to_integral_value(
                rounding=ROUND_FLOOR
            )
        )

    return -int(
        (-amount).to_integral_value(
            rounding=ROUND_FLOOR
        )
    )


def _offerwall_value(r, name, default=""):
    value = r.query_params.get(name)

    if value is not None:
        return str(value)

    return str(default)


async def _offerwall_params(r):
    data = {}

    for key in (
        "userId",
        "transactionId",
        "offerId",
        "offerName",
        "goalId",
        "currencyAmount",
        "currencyName",
        "payoutUsd",
        "status",
        "test",
        "timestamp",
        "signature",
    ):
        value = r.query_params.get(key)

        if value is not None:
            data[key] = str(value)

    if r.method.upper() == "POST":
        try:
            form = await r.form()

            for key in (
                "userId",
                "transactionId",
                "offerId",
                "offerName",
                "goalId",
                "currencyAmount",
                "currencyName",
                "payoutUsd",
                "status",
                "test",
                "timestamp",
                "signature",
            ):
                if key not in data and key in form:
                    data[key] = str(form[key])
        except Exception:
            pass

    return data


@app.api_route(
    '/offerwall/callback',
    methods=['GET', 'POST']
)
async def offerwall_callback(r:Request):

    data = await _offerwall_params(r)

    user_id_raw = str(data.get("userId", "")).strip()
    transaction_id = str(
        data.get("transactionId", "")
    ).strip()
    currency_amount = str(
        data.get("currencyAmount", "")
    ).strip()
    signature = str(
        data.get("signature", "")
    ).strip()

    status = str(
        data.get("status", "credited")
    ).strip().lower()

    test_value = str(
        data.get("test", "0")
    ).strip()

    if not user_id_raw:
        return HTMLResponse(
            "INVALID_USER",
            status_code=400
        )

    if not transaction_id:
        return HTMLResponse(
            "INVALID_TRANSACTION",
            status_code=400
        )

    if len(transaction_id) > 200:
        return HTMLResponse(
            "INVALID_TRANSACTION",
            status_code=400
        )

    if not currency_amount:
        return HTMLResponse(
            "INVALID_AMOUNT",
            status_code=400
        )

    if status not in ("credited", "reversed"):
        return HTMLResponse(
            "INVALID_STATUS",
            status_code=400
        )

    if not signature:
        return HTMLResponse(
            "FORBIDDEN",
            status_code=403
        )

    if not OfferwallGG.verify_postback_signature(
        user_id_raw,
        transaction_id,
        currency_amount,
        signature
    ):
        return HTMLResponse(
            "FORBIDDEN",
            status_code=403
        )

    amount = _offerwall_amount_to_points(
        currency_amount
    )

    if amount is None:
        return HTMLResponse(
            "INVALID_AMOUNT",
            status_code=400
        )

    # A credited conversion must carry a positive amount.
    if status == "credited" and amount <= 0:
        return HTMLResponse(
            "INVALID_AMOUNT",
            status_code=400
        )

    # A reversal must carry a negative amount according
    # to the provider contract.
    if status == "reversed" and amount >= 0:
        return HTMLResponse(
            "INVALID_REVERSAL",
            status_code=400
        )

    try:
        user_id = int(user_id_raw)
    except (ValueError, TypeError):
        return HTMLResponse(
            "INVALID_USER",
            status_code=400
        )

    test = 1 if test_value == "1" else 0

    # Dashboard test callbacks are signed and must be accepted,
    # but they must never touch a user balance.
    if test == 1:
        return HTMLResponse(
            "OK",
            status_code=200
        )

    c = db()

    try:
        c.execute("BEGIN IMMEDIATE")

        # ----------------------------------------------------
        # Verify EasySurf user
        # ----------------------------------------------------

        u = c.execute(
            """
            SELECT id
            FROM users
            WHERE id=?
            """,
            (user_id,)
        ).fetchone()

        if not u:
            c.rollback()

            # The callback is authentic, but the user does not
            # exist in EasySurf. Do not credit an unknown account.
            return HTMLResponse(
                "UNKNOWN_USER",
                status_code=200
            )

        # ----------------------------------------------------
        # REVERSAL MUST BE HANDLED BEFORE NORMAL DEDUPE
        # ----------------------------------------------------

        if status == "reversed":

            original = c.execute(
                """
                SELECT *
                FROM offerwall_postbacks
                WHERE transaction_id=?
                  AND status='credited'
                LIMIT 1
                """,
                (transaction_id,)
            ).fetchone()

            if not original:
                c.rollback()

                # Returning a retryable response is safer than
                # silently accepting a reversal for which the
                # original credit is unknown.
                return HTMLResponse(
                    "ORIGINAL_NOT_FOUND",
                    status_code=409
                )

            # Already reversed?
            existing_reversal = c.execute(
                """
                SELECT id
                FROM offerwall_postbacks
                WHERE transaction_id=?
                  AND status='reversed'
                LIMIT 1
                """,
                (transaction_id,)
            ).fetchone()

            if existing_reversal:
                c.rollback()
                return HTMLResponse(
                    "OK",
                    status_code=200
                )

            original_amount = int(
                original["amount"] or 0
            )

            if original_amount <= 0:
                c.rollback()

                return HTMLResponse(
                    "INVALID_ORIGINAL",
                    status_code=409
                )

            ts = now()

            # Provider sends a negative amount.
            # We reverse exactly the originally credited
            # integer amount, not a separately rounded value.
            reversal_amount = -original_amount

            c.execute(
                """
                INSERT INTO offerwall_postbacks
                (
                    transaction_id,
                    status,
                    user_id,
                    offer_id,
                    offer_name,
                    goal_id,
                    currency_amount,
                    amount,
                    currency_name,
                    payout_usd,
                    test,
                    provider_timestamp,
                    signature,
                    reversal_of_id,
                    created_at,
                    updated_at
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    transaction_id,
                    "reversed",
                    user_id,
                    data.get("offerId"),
                    data.get("offerName"),
                    data.get("goalId"),
                    currency_amount,
                    reversal_amount,
                    data.get("currencyName"),
                    data.get("payoutUsd"),
                    test,
                    int(data["timestamp"])
                    if str(data.get("timestamp","")).isdigit()
                    else None,
                    signature,
                    original["id"],
                    ts,
                    ts
                )
            )

            c.execute(
                """
                UPDATE users
                SET balance=balance+?
                WHERE id=?
                """,
                (
                    reversal_amount,
                    user_id
                )
            )

            c.execute(
                """
                INSERT INTO transactions
                (
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
                    reversal_amount,
                    "offerwall_reversal",
                    f"Offerwall.GG reversal #{transaction_id}",
                    ts
                )
            )

            c.execute(
                """
                INSERT INTO activity_log
                (
                    user_id,
                    activity_type,
                    title,
                    amount,
                    status,
                    created_at
                )
                VALUES(?,?,?,?,?,?)
                """,
                (
                    user_id,
                    "offerwall_reversal",
                    "Offerwall.GG conversion reversed",
                    reversal_amount,
                    "reversed",
                    ts
                )
            )

            c.commit()

            return HTMLResponse(
                "OK",
                status_code=200
            )

        # ----------------------------------------------------
        # CREDITED вЂ” DATABASE UNIQUE CONSTRAINT IS THE
        # CONCURRENCY-SAFE IDEMPOTENCY CHECK
        # ----------------------------------------------------

        existing = c.execute(
            """
            SELECT id
            FROM offerwall_postbacks
            WHERE transaction_id=?
              AND status='credited'
            LIMIT 1
            """,
            (transaction_id,)
        ).fetchone()

        if existing:
            c.rollback()

            return HTMLResponse(
                "OK",
                status_code=200
            )

        ts = now()

        try:
            c.execute(
                """
                INSERT INTO offerwall_postbacks
                (
                    transaction_id,
                    status,
                    user_id,
                    offer_id,
                    offer_name,
                    goal_id,
                    currency_amount,
                    amount,
                    currency_name,
                    payout_usd,
                    test,
                    provider_timestamp,
                    signature,
                    reversal_of_id,
                    created_at,
                    updated_at
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    transaction_id,
                    "credited",
                    user_id,
                    data.get("offerId"),
                    data.get("offerName"),
                    data.get("goalId"),
                    currency_amount,
                    amount,
                    data.get("currencyName"),
                    data.get("payoutUsd"),
                    test,
                    int(data["timestamp"])
                    if str(data.get("timestamp","")).isdigit()
                    else None,
                    signature,
                    None,
                    ts,
                    ts
                )
            )

        except sqlite3.IntegrityError:
            c.rollback()

            return HTMLResponse(
                "OK",
                status_code=200
            )

        c.execute(
            """
            UPDATE users
            SET balance=balance+?
            WHERE id=?
            """,
            (
                amount,
                user_id
            )
        )

        c.execute(
            """
            INSERT INTO transactions
            (
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
                "offerwall_reward",
                f"Offerwall.GG conversion #{transaction_id}",
                ts
            )
        )

        c.execute(
            """
            INSERT INTO activity_log
            (
                user_id,
                activity_type,
                title,
                amount,
                status,
                created_at
            )
            VALUES(?,?,?,?,?,?)
            """,
            (
                user_id,
                "offerwall_reward",
                "Offerwall.GG conversion completed",
                amount,
                "completed",
                ts
            )
        )

        c.commit()

    except Exception:
        try:
            c.rollback()
        except Exception:
            pass

        return HTMLResponse(
            "ERROR",
            status_code=500
        )

    finally:
        c.close()

    return HTMLResponse(
        "OK",
        status_code=200
    )


# Create the V4 ledger/indexes during application import.
_init_offerwall_v4()

# ============================================================
# END SECURITY V4
# ============================================================
