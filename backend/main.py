from fastapi import FastAPI, Request, Form
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

BASE_DIR=Path(__file__).resolve().parent.parent; DB_PATH=BASE_DIR/'easysurf.db'
app=FastAPI(title='EasySurf',version='0.5.0')
APP_ENV = os.getenv("EASYSURF_ENV", "development").strip().lower()
SESSION_SECRET = os.getenv("EASYSURF_SESSION_SECRET", "").strip()

if APP_ENV == "production" and len(SESSION_SECRET) < 32:
    raise RuntimeError("EASYSURF_SESSION_SECRET must be at least 32 characters in production")

if not SESSION_SECRET:
    SESSION_SECRET = "LOCAL-DEVELOPMENT-ONLY-" + secrets.token_urlsafe(32)

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=604800,
    same_site="lax",
    https_only=(APP_ENV == "production"),
)

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
 c=db()
 ensure_schema(c)
 c.executescript('''CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,balance INTEGER NOT NULL DEFAULT 0,is_admin INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL,referral_code TEXT,referred_by INTEGER);CREATE TABLE IF NOT EXISTS tasks(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,url TEXT NOT NULL,seconds INTEGER NOT NULL,reward INTEGER NOT NULL,active INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL,task_type TEXT NOT NULL DEFAULT 'visit',video_url TEXT);CREATE TABLE IF NOT EXISTS attempts(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,task_id INTEGER NOT NULL,started_at INTEGER NOT NULL,completed_at INTEGER,rewarded INTEGER NOT NULL DEFAULT 0);CREATE TABLE IF NOT EXISTS transactions(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,amount INTEGER NOT NULL,kind TEXT NOT NULL,description TEXT NOT NULL,created_at INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS referrals(id INTEGER PRIMARY KEY AUTOINCREMENT,referrer_id INTEGER NOT NULL,referred_id INTEGER UNIQUE NOT NULL,bonus INTEGER NOT NULL,created_at INTEGER NOT NULL);CREATE TABLE IF NOT EXISTS payouts(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,amount INTEGER NOT NULL,method TEXT NOT NULL,account TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'pending',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);''')
 uc={x[1] for x in c.execute('PRAGMA table_info(users)')}
 if 'referral_code' not in uc:c.execute('ALTER TABLE users ADD COLUMN referral_code TEXT')
 if 'referred_by' not in uc:c.execute('ALTER TABLE users ADD COLUMN referred_by INTEGER')
 tc={x[1] for x in c.execute('PRAGMA table_info(tasks)')}
 if 'task_type' not in tc:c.execute("ALTER TABLE tasks ADD COLUMN task_type TEXT NOT NULL DEFAULT 'visit'")
 if 'video_url' not in tc:c.execute('ALTER TABLE tasks ADD COLUMN video_url TEXT')
 for u in c.execute("SELECT id FROM users WHERE referral_code IS NULL OR referral_code='' ").fetchall(): c.execute('UPDATE users SET referral_code=? WHERE id=?',(code(c),u['id']))
 if not c.execute('SELECT id FROM tasks LIMIT 1').fetchone(): c.execute('INSERT INTO tasks(title,url,seconds,reward,created_at,task_type) VALUES(?,?,?,?,?,?)',('Demo website visit','https://example.com',20,5,now(),'visit'))
 c.commit()
 c.close()

def startup():init()

def layout(title, body, u=None):
    if not u:
        nav = (
            '<a href="/">Home</a>'
            '<a href="/login">Login</a>'
            '<a class="nav-btn" href="/register">Get Started</a>'
        )
    else:
        admin_link = '<a href="/admin">Admin</a>' if u["is_admin"] else ''
        nav = (
            '<a href="/dashboard">Dashboard</a>'
            '<a href="/earn">Earn</a>'
            '<a href="/rewards">Rewards</a>'
            '<a href="/activity">Activity</a>'
            '<a href="/leaderboard">Leaderboard</a>'
            '<a href="/referrals">Referrals</a>'
            '<a href="/payouts">Withdraw</a>'
            + admin_link +
            '<span class="balance-pill">💰 ' + money(u["balance"]) + '</span>'
            '<a href="/logout">Logout</a>'
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} · EasySurf</title>

<style>
*{{box-sizing:border-box}}

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
 flex-wrap:wrap;
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
        Earn online by completing verified activities, offers, surveys,
        games and other available tasks.
      </p>
    </div>

    <div>
      <div class="footer-heading">EasySurf</div>
      <div class="footer-links">
        <a href="/">Home</a>
        <a href="/dashboard">Dashboard</a>
        <a href="/earn">Earn</a>
        <a href="/rewards">Rewards</a>
        <a href="/leaderboard">Leaderboard</a>
      </div>
    </div>

    <div>
      <div class="footer-heading">Earn</div>
      <div class="footer-links">
        <a href="/earn">Tasks</a>
        <a href="/offers">Offers</a>
        <a href="/surveys">Surveys</a>
        <a href="/games">Games</a>
        <a href="/apps">Apps</a>
        <a href="/videos">Videos</a>
      </div>
    </div>

    <div>
      <div class="footer-heading">Company</div>
      <div class="footer-links">
        <a href="/about">About Us</a>
        <a href="/contact">Contact</a>
        <a href="/referrals">Referrals</a>
        <a href="/payouts">Payouts</a>
      </div>
    </div>

    <div>
      <div class="footer-heading">Support</div>
      <div class="footer-links">
        <a href="/faq">FAQ</a>
        <a href="/help">Help Center</a>
        <a href="/contact">Contact Support</a>
        <a href="/terms">Terms of Service</a>
      </div>
    </div>

  </div>

  <div class="footer-divider"></div>

  <div class="footer-bottom">
    <div>
      ? 2026 EasySurf. All rights reserved.
    </div>

    <div class="footer-bottom-links">
      <a href="/terms">Terms</a>

      <span class="footer-status">
        <span class="footer-status-dot"></span>
        Platform online
      </span>
    </div>
  </div>

</div>
</footer>

</body>
</html>"""


# ============================================================
# SECURITY V2 — AUTHENTICATION RATE LIMITING
# ============================================================

_LOGIN_WINDOW_SECONDS = 600
_LOGIN_MAX_FAILURES = 5

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

    body="""
    <section class="hero" style="position:relative;overflow:hidden;">
        <div style="position:relative;z-index:2;max-width:760px;">
            <div style="display:inline-flex;align-items:center;gap:8px;padding:7px 13px;border:1px solid rgba(96,165,250,.25);border-radius:999px;background:rgba(59,130,246,.10);font-size:13px;color:#93c5fd;margin-bottom:18px;">
                ⚡ EasySurf Rewards Platform
            </div>

            <h1 style="font-size:clamp(38px,6vw,68px);line-height:1.02;margin:0 0 18px;">
                Earn online.<br>
                <span style="color:#60a5fa;">Your way.</span>
            </h1>

            <p class="muted" style="font-size:18px;line-height:1.7;max-width:650px;margin:0;">
                Complete surveys, offers, games, app activities and simple tasks
                from one modern rewards platform.
            </p>

            <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:28px;">
                <a class="btn" href="/register">🚀 Start earning</a>
                <a class="btn secondary" href="/login">Login</a>
            </div>

            <div style="display:flex;gap:28px;flex-wrap:wrap;margin-top:30px;color:#94a3b8;font-size:13px;">
                <span>✓ Simple tasks</span>
                <span>✓ Daily rewards</span>
                <span>✓ Referral bonuses</span>
            </div>
        </div>

        <div style="position:absolute;right:-80px;top:-120px;width:360px;height:360px;border-radius:50%;background:rgba(59,130,246,.12);filter:blur(10px);"></div>
        <div style="position:absolute;right:80px;bottom:-180px;width:300px;height:300px;border-radius:50%;background:rgba(34,197,94,.08);filter:blur(20px);"></div>
    </section>

    <section style="margin-top:26px;">
        <div style="display:flex;align-items:end;justify-content:space-between;gap:16px;margin-bottom:16px;flex-wrap:wrap;">
            <div>
                <div class="muted" style="font-size:13px;text-transform:uppercase;letter-spacing:.08em;">Platform</div>
                <h2 style="margin:5px 0 0;">Everything in one place</h2>
            </div>
            <div class="muted" style="font-size:14px;">Choose an earning method and get started.</div>
        </div>

        <div class="grid">

            <div class="card earn-card" style="min-height:190px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">📋</div>
                    <h3>Surveys</h3>
                    <p class="muted">
                        Paid research surveys when real inventory is available.
                    </p>
                </div>
                <a href="/surveys">Explore →</a>
            </div>

            <div class="card earn-card" style="min-height:190px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">🎁</div>
                    <h3>Offers</h3>
                    <p class="muted">
                        Advertiser-approved offers and tracked activities.
                    </p>
                </div>
                <a href="/offers">Explore →</a>
            </div>

            <div class="card earn-card" style="min-height:190px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">🎮</div>
                    <h3>Games</h3>
                    <p class="muted">
                        Game-based rewards through approved providers.
                    </p>
                </div>
                <a href="/games">Explore →</a>
            </div>

            <div class="card earn-card" style="min-height:190px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">📱</div>
                    <h3>Apps</h3>
                    <p class="muted">
                        App-based earning opportunities.
                    </p>
                </div>
                <a href="/apps">Explore →</a>
            </div>

            <div class="card earn-card" style="min-height:190px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">▶️</div>
                    <h3>Videos</h3>
                    <p class="muted">
                        Watch approved video tasks and activities.
                    </p>
                </div>
                <a href="/videos">Explore →</a>
            </div>

            <div class="card earn-card" style="min-height:190px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">🌐</div>
                    <h3>Tasks</h3>
                    <p class="muted">
                        Complete verified website and microtasks.
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
                    Ready when you are
                </div>
                <h2 style="margin:7px 0 8px;">Start building your rewards balance</h2>
                <p class="muted" style="margin:0;max-width:620px;">
                    Create your free account, explore available opportunities,
                    collect rewards and track your activity from your dashboard.
                </p>
            </div>

            <a class="btn" href="/register" style="white-space:nowrap;">
                Create free account →
            </a>
        </div>

        <div style="position:absolute;right:-90px;top:-90px;width:240px;height:240px;border-radius:50%;background:rgba(59,130,246,.10);"></div>
    </section>
    """

    return layout("Home",body,u)
@app.get('/register',response_class=HTMLResponse)
def regp(r:Request):
 if user(r):
  return RedirectResponse('/dashboard',303)
 t=csrf(r)
 verification=r.query_params.get('verification','').strip().lower()
 email_status=r.query_params.get('email','').strip().lower()
 message=''
 if verification=='sent':
  message='<div class="alert">Verification email sent. Please check your inbox to verify your email.</div>'
 elif email_status=='failed':
  message='<div class="alert">Registration succeeded, but the verification email could not be sent. Please use the resend option after registration.</div>'
 return layout('Register',f'<div class="center card"><h2>Create account</h2>{message}<form method="post"><input type="hidden" name="csrf_token" value="{t}"><label>Email</label><input name="email" type="email" required><label>Password</label><input name="password" type="password" required minlength="6"><button>Register</button></form></div>')
@app.post('/register')
@app.post('/register')
def reg(r:Request,email:str=Form(...),password:str=Form(...),csrf_token:str=Form(...),ref:str=Form('')):
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
  return RedirectResponse('/register',303)

 email=email.strip().lower()
 ref=ref.strip().upper()

 if len(email)>320 or len(password)<6:
  return RedirectResponse('/register',303)

 public_url=os.getenv(
  'EASYSURF_PUBLIC_URL',
  'http://127.0.0.1:8000'
 ).strip().rstrip('/')

 c=db()

 try:
  c.execute('BEGIN IMMEDIATE')

  rr=c.execute(
   'SELECT id FROM users WHERE referral_code=?',
   (ref,)
  ).fetchone() if ref else None

  cur=c.execute(
   'INSERT INTO users(email,password_hash,created_at,referral_code,referred_by,email_verified) VALUES(?,?,?,?,?,?)',
   (
    email,
    hp(password),
    now(),
    code(c),
    rr['id'] if rr else None,
    0
   )
  )

  nid=cur.lastrowid

  token=create_token(c,nid)

  verification_url=build_verification_url(
   public_url,
   token
  )

  if rr:
   bonus=50

   c.execute(
    'UPDATE users SET balance=balance+? WHERE id=?',
    (bonus,rr['id'])
   )

   c.execute(
    'INSERT INTO transactions(user_id,amount,kind,description,created_at) VALUES(?,?,?,?,?)',
    (
     rr['id'],
     bonus,
     'referral_bonus',
     'Referral signup bonus',
     now()
    )
   )

   c.execute(
    'INSERT INTO referrals(referrer_id,referred_id,bonus,created_at) VALUES(?,?,?,?)',
    (
     rr['id'],
     nid,
     bonus,
     now()
    )
   )

  c.commit()

 except sqlite3.IntegrityError:
  try:
   c.rollback()
  except Exception:
   pass

  c.close()
  return RedirectResponse('/register',303)

 except Exception:
  try:
   c.rollback()
  except Exception:
   pass

  c.close()
  return RedirectResponse('/register',303)

 c.close()

 try:
  send_verification_email(
   email,
   verification_url
  )
 except Exception:
  return RedirectResponse('/register?email=failed',303)

 return RedirectResponse('/login?verification=sent',303)

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
  f'<div class="center card"><h2>Resend verification email</h2><form method="post"><input type="hidden" name="csrf_token" value="{t}"><label>Email</label><input name="email" type="email" required><button>Send verification email</button></form><p class="muted"><a href="/login">Back to login</a></p></div>'
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

def loginp(r:Request):
 if user(r):
  return RedirectResponse('/dashboard',303)
 t=csrf(r)
 verification=r.query_params.get('verification','').strip().lower()
 message=''
 if verification=='required':
  message='<div class="alert">Email verification required. Please verify your email before logging in.</div>'
 elif verification=='resent':
  message='<div class="alert">Verification email sent. Please check your inbox.</div>'
 elif verification=='failed':
  message='<div class="alert">We could not send the verification email. Please try again later.</div>'
 resend='<p style="margin-top:12px"><a href="/resend-verification">Resend verification email</a></p>'
 return layout('Login',f'<div class="center card"><h2>Login</h2>{message}<form method="post"><input type="hidden" name="csrf_token" value="{t}"><label>Email</label><input name="email" type="email" required><label>Password</label><input name="password" type="password" required><button>Login</button></form>{resend}</div>')
@app.post('/login')
def login(r:Request,email:str=Form(...),password:str=Form(...),csrf_token:str=Form(...)):
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

 if not okcsrf(r,csrf_token):return RedirectResponse('/login',303)

 c=db();u=c.execute('SELECT * FROM users WHERE email=?',(normalized_email,)).fetchone();c.close()

 if not u or not vp(password,u['password_hash']):
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

  return RedirectResponse('/login',303)

 _rate_reset(_login_failures,ip_key)
 _rate_reset(_login_failures,email_key)

 if not int(u['email_verified'] or 0):
  return RedirectResponse('/login?verification=required',303)
 r.session.clear();r.session['user_id']=u['id'];r.session['csrf']=secrets.token_urlsafe(32);return RedirectResponse('/dashboard',303)
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
                    ⏱ {x["seconds"]} sec
                    &nbsp;·&nbsp;
                    💰 {money(x["reward"])}
                </p>
            </div>
            <a class="btn" href="/task/{x["id"]}">Start task →</a>
        </div>
        """
        for x in tasks[:6]
    )

    if not task_cards:
        task_cards="""
        <div class="card empty" style="grid-column:1/-1;text-align:center;padding:36px;">
            <div class="earn-icon" style="font-size:38px;">🔎</div>
            <h3>No website tasks available</h3>
            <p class="muted">
                New tasks may appear later. Explore other earning categories in the meantime.
            </p>
            <a class="btn" href="/earn">Explore Earn →</a>
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
                No activity yet. Start earning to see your transactions here.
            </td>
        </tr>
        """

    body=f"""
    <section class="hero" style="position:relative;overflow:hidden;">
        <div style="position:relative;z-index:2;">
            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(96,165,250,.25);border-radius:999px;background:rgba(59,130,246,.10);font-size:12px;color:#93c5fd;margin-bottom:14px;">
                ⚡ Your EasySurf Dashboard
            </div>

            <h1 style="margin:0 0 8px;">
                Welcome back
            </h1>

            <p class="muted" style="margin:0;font-size:15px;">
                {escape(u["email"])}
            </p>

            <div style="display:flex;gap:12px;flex-wrap:wrap;margin-top:22px;">
                <a class="btn" href="/earn">🚀 Earn now</a>
                <a class="btn secondary" href="/rewards">🎁 Rewards</a>
            </div>
        </div>

        <div style="position:absolute;right:-80px;top:-130px;width:340px;height:340px;border-radius:50%;background:rgba(59,130,246,.11);filter:blur(8px);"></div>
        <div style="position:absolute;right:100px;bottom:-190px;width:280px;height:280px;border-radius:50%;background:rgba(34,197,94,.07);filter:blur(14px);"></div>
    </section>

    <section style="margin-top:22px;">
        <div class="grid">

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:30px;">💰</div>
                <div class="muted">Available balance</div>
                <div class="metric" style="font-size:32px;margin-top:5px;">{money(u["balance"])}</div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:30px;">📈</div>
                <div class="muted">Earned today</div>
                <div class="metric" style="font-size:32px;margin-top:5px;">{money(today_earned)}</div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:30px;">⏳</div>
                <div class="muted">Pending rewards</div>
                <div class="metric" style="font-size:32px;margin-top:5px;">{money(pending)}</div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:30px;">🔥</div>
                <div class="muted">Tasks completed</div>
                <div class="metric" style="font-size:32px;margin-top:5px;">{done}</div>
            </div>

        </div>
    </section>

    <section class="card" style="margin-top:22px;">
        <div style="display:flex;justify-content:space-between;align-items:end;gap:15px;flex-wrap:wrap;">
            <div>
                <div style="font-size:12px;color:#60a5fa;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                    Daily target
                </div>
                <h2 style="margin:5px 0 4px;">Today's earning goal</h2>
                <p class="muted" style="margin:0;">
                    Keep completing available activities to grow your balance.
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
            <span><b>{money(today_earned)}</b> earned today</span>
            <span class="muted">Goal: {money(goal)}</span>
        </div>
    </section>

    <section style="margin-top:28px;">
        <div style="display:flex;align-items:end;justify-content:space-between;gap:15px;flex-wrap:wrap;margin-bottom:15px;">
            <div>
                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.08em;">
                    Quick access
                </div>
                <h2 style="margin:5px 0 0;">Start earning</h2>
            </div>
            <a href="/earn" class="muted">View all →</a>
        </div>

        <div class="grid">

            <div class="card earn-card" style="min-height:175px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">📋</div>
                    <h3>Surveys</h3>
                    <p class="muted">Paid research surveys when inventory is available.</p>
                </div>
                <a href="/surveys">View surveys →</a>
            </div>

            <div class="card earn-card" style="min-height:175px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">🎁</div>
                    <h3>Offers</h3>
                    <p class="muted">Advertiser offers and tracked activities.</p>
                </div>
                <a href="/offers">View offers →</a>
            </div>

            <div class="card earn-card" style="min-height:175px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">🎮</div>
                    <h3>Games</h3>
                    <p class="muted">Play approved games and reach milestones.</p>
                </div>
                <a href="/games">View games →</a>
            </div>

            <div class="card earn-card" style="min-height:175px;">
                <div>
                    <div class="earn-icon" style="font-size:32px;">📱</div>
                    <h3>Apps</h3>
                    <p class="muted">Discover tracked app opportunities.</p>
                </div>
                <a href="/apps">View apps →</a>
            </div>

        </div>
    </section>

    <section style="margin-top:28px;">
        <div style="display:flex;align-items:end;justify-content:space-between;gap:15px;flex-wrap:wrap;margin-bottom:15px;">
            <div>
                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.08em;">
                    Available now
                </div>
                <h2 style="margin:5px 0 0;">Website Tasks</h2>
            </div>
            <a href="/earn" class="muted">Browse earning options →</a>
        </div>

        <div class="grid">
            {task_cards}
        </div>
    </section>

    <section class="card" style="margin-top:28px;">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap;margin-bottom:14px;">
            <div>
                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.08em;">
                    Your account
                </div>
                <h2 style="margin:5px 0 0;">Recent Activity</h2>
            </div>
            <a href="/activity" class="muted">View all →</a>
        </div>

        <table>
            <tr>
                <th>Activity</th>
                <th>Amount</th>
            </tr>
            {activity}
        </table>
    </section>

    <section style="margin-top:22px;">
        <div class="grid">

            <div class="card">
                <div class="muted">Total earned</div>
                <div class="metric" style="font-size:28px;margin-top:5px;">{money(earned)}</div>
            </div>

            <div class="card">
                <div class="muted">Total paid</div>
                <div class="metric" style="font-size:28px;margin-top:5px;">{money(paid)}</div>
            </div>

            <div class="card">
                <div class="muted">Referrals</div>
                <div class="metric" style="font-size:28px;margin-top:5px;">{refs}</div>
            </div>

        </div>
    </section>

    <section class="card" style="margin-top:22px;padding:26px;position:relative;overflow:hidden;">
        <div style="position:relative;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;">
            <div>
                <div style="font-size:12px;color:#60a5fa;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                    Keep going
                </div>
                <h2 style="margin:6px 0 7px;">There are more ways to earn</h2>
                <p class="muted" style="margin:0;max-width:600px;">
                    Explore all available earning categories and keep your activity growing.
                </p>
            </div>

            <a class="btn" href="/earn">Explore Earn →</a>
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
 c=db();rows=c.execute('SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC',(u['id'],)).fetchall();c.close();trs=''.join(f'<tr><td>{escape(x["kind"])}</td><td>{escape(x["description"])}</td><td>{money(x["amount"])}</td></tr>' for x in rows);return layout('History',f'<div class="card"><h2>History</h2><table><tr><th>Type</th><th>Description</th><th>Amount</th></tr>{trs or "<tr><td colspan=3>No transactions.</td></tr>"}</table></div>',u)
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
                <strong>No referrals yet</strong>
                <div class="muted" style="margin-top:6px;">
                    Share your referral code to start building your network.
                </div>
            </td>
        </tr>
        """

    body=f"""
    <section class="hero" style="position:relative;overflow:hidden;">
        <div style="position:relative;z-index:2;">

            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(34,197,94,.25);border-radius:999px;background:rgba(34,197,94,.09);font-size:12px;color:#86efac;margin-bottom:14px;">
                🤝 EasySurf Referral Program
            </div>

            <h1 style="margin:0 0 10px;">
                Invite friends & earn
            </h1>

            <p class="muted" style="max-width:720px;font-size:16px;line-height:1.7;margin:0;">
                Share your referral code with friends and receive a referral bonus
                when a new user registers through your code.
            </p>

            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:22px;">
                <a class="btn" href="/earn">
                    ⚡ Start earning
                </a>

                <a class="btn secondary" href="/activity">
                    📊 View activity
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
                        📋 Copy code
                    </button>

                </div>

                <p class="muted" style="margin:13px 0 0;line-height:1.6;">
                    Give this code to a friend during registration.
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
                    registered users
                </div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:34px;">💰</div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    Referral earnings
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;color:#86efac;">
                    {money(total_bonus)}
                </div>

                <div class="muted" style="font-size:13px;">
                    total referral bonuses
                </div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:34px;">🎁</div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    Referral reward
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;">
                    {money(50)}
                </div>

                <div class="muted" style="font-size:13px;">
                    per successful signup
                </div>
            </div>

        </div>

    </section>

    <section style="margin-top:28px;">

        <div class="card" style="padding:0;overflow:hidden;">

            <div style="padding:22px 24px;border-bottom:1px solid rgba(148,163,184,.10);display:flex;align-items:center;justify-content:space-between;gap:15px;flex-wrap:wrap;">

                <div>
                    <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.08em;">
                        Referral activity
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
                        <th>User</th>
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
                    Grow your network
                </div>

                <h2 style="margin:6px 0 7px;">
                    Invite more friends
                </h2>

                <p class="muted" style="margin:0;max-width:620px;line-height:1.6;">
                    Share your referral code with people you know and earn the available referral bonus for successful registrations.
                </p>
            </div>

            <div style="display:flex;gap:10px;flex-wrap:wrap;">
                <button type="button"
                        class="btn"
                        onclick="copyReferralCode()">
                    📋 Copy referral code
                </button>

                <a class="btn secondary" href="/earn">
                    Explore earning
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
 body=f'''<div class="grid"><div class="card"><h2>Withdraw</h2><p>Available balance: <b>{money(u["balance"])}</b></p><p class="muted">Minimum withdrawal: {money(5000)}</p><form method="post" action="/payouts"><input type="hidden" name="csrf_token" value="{token}"><label>Amount (thousandths USD)</label><input name="amount" type="number" min="5000" step="1" required><label>Method</label><select name="method"><option value="PayPal">PayPal</option><option value="USDT TRC20">USDT TRC20</option><option value="Other">Other</option></select><label>Account / wallet</label><input name="account" maxlength="200" required><button>Request payout</button></form></div><div class="card"><h2>Rules</h2><p class="muted">Payouts are processed manually in this local MVP. No real payment is sent automatically.</p></div></div><div class="card"><h2>Payout history</h2><table><tr><th>ID</th><th>Amount</th><th>Method</th><th>Account</th><th>Status</th></tr>{trs}</table></div>'''
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
  c.execute('UPDATE users SET balance=balance-? WHERE id=? AND balance>=?',(amount,u['id'],amount))
  cur=c.execute('INSERT INTO payouts(user_id,amount,method,account,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',(u['id'],amount,method,account.strip(),'pending',ts,ts))
  c.execute('INSERT INTO transactions(user_id,amount,kind,description,created_at) VALUES(?,?,?,?,?)',(u['id'],-amount,'payout_request',f'Payout #{cur.lastrowid} reserved',ts))
  c.commit()
 finally:c.close()
 return RedirectResponse('/payouts',303)

@app.post('/admin/payout/{pid}')
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

  # Explicit payout state machine.
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

  if target=='rejected':
   updated=c.execute(
    'UPDATE users SET balance=balance+? WHERE id=?',
    (amount,p['user_id'])
   ).rowcount

   if updated!=1:
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

  c.commit()

 finally:
  c.close()

 return RedirectResponse('/admin',303)
@app.get('/admin',response_class=HTMLResponse)
def admin(r:Request):
 u=user(r)
 if not u or not u['is_admin']:return RedirectResponse('/login',303)
 c=db();ts=c.execute('SELECT * FROM tasks ORDER BY id DESC').fetchall();us=c.execute('SELECT email,balance FROM users ORDER BY id DESC').fetchall();ps=c.execute('SELECT p.*,u.email FROM payouts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC').fetchall();c.close();token=csrf(r);rows=''.join(f'<tr><td>{x["id"]}</td><td>{escape(x["title"])}</td><td>{escape(x["task_type"])}</td><td>{x["seconds"]}s</td><td>{money(x["reward"])}</td><td>{money(x["budget"])}</td><td>{money(x["spent"])}</td><td>{money(max(0,x["budget"]-x["spent"]))}</td></tr>' for x in ts);users=''.join(f'<tr><td>{escape(x["email"])}</td><td>{money(x["balance"])}</td></tr>' for x in us)
 payouts=''.join(f'<tr><td>#{x["id"]}</td><td>{escape(x["email"])}</td><td>{money(x["amount"])}</td><td>{escape(x["method"])}</td><td>{escape(x["status"])}</td><td><form method="post" action="/admin/payout/{x["id"]}"><input type="hidden" name="csrf_token" value="{token}"><select name="status"><option value="approved">approved</option><option value="paid">paid</option><option value="rejected">rejected</option></select><button>Update</button></form></td></tr>' for x in ps) or '<tr><td colspan=6>No payout requests.</td></tr>'
 body=f'''<h1>Admin</h1><div class="card"><h2>Create task</h2><form method="post" action="/admin/task"><input type="hidden" name="csrf_token" value="{token}"><label>Title</label><input name="title" required maxlength="120"><label>Destination URL</label><input name="url" type="url" required><label>Seconds</label><input name="seconds" type="number" min="5" max="86400" value="20" required><label>Reward (thousandths USD)</label><input name="reward" type="number" min="1" value="5" required><label>Budget (thousandths USD)</label><input name="budget" type="number" min="1" value="1000" required><label>Type</label><select name="task_type"><option value="visit">Website visit</option><option value="video">Video</option></select><label>Video URL</label><input name="video_url" type="url"><button>Create task</button></form></div><div class="card"><h2>Tasks</h2><table><tr><th>ID</th><th>Title</th><th>Type</th><th>Time</th><th>Reward</th><th>Budget</th><th>Spent</th><th>Remaining</th></tr>{rows}</table></div><div class="card"><h2>Users</h2><table><tr><th>Email</th><th>Balance</th></tr>{users}</table></div><div class="card"><h2>Payouts</h2><table><tr><th>ID</th><th>User</th><th>Amount</th><th>Method</th><th>Status</th><th>Action</th></tr>{payouts}</table></div>''';return layout('Admin',body,u)
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
                        ⏱ {x["seconds"]} sec
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
            <h3>No website tasks available right now</h3>
            <p class="muted" style="max-width:560px;margin:8px auto 20px;">
                There are currently no available website tasks for your account.
                Check back later or explore another earning category.
            </p>
            <div style="display:flex;justify-content:center;gap:10px;flex-wrap:wrap;">
                <a class="btn" href="/earn">Refresh</a>
                <a class="btn secondary" href="/surveys">Explore surveys</a>
            </div>
        </div>
        """

    body=f"""
    <section class="hero" style="position:relative;overflow:hidden;">
        <div style="position:relative;z-index:2;">
            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(96,165,250,.25);border-radius:999px;background:rgba(59,130,246,.10);font-size:12px;color:#93c5fd;margin-bottom:14px;">
                ⚡ EasySurf Earning Center
            </div>

            <h1 style="margin:0 0 10px;">
                Earn more, your way
            </h1>

            <p class="muted" style="max-width:700px;font-size:16px;line-height:1.7;margin:0;">
                Choose from available surveys, offers, games, apps, videos
                and verified website tasks.
            </p>

            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:24px;">
                <a class="btn" href="#tasks">🌐 Browse tasks</a>
                <a class="btn secondary" href="/rewards">🎁 View rewards</a>
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
                    <h3>Surveys</h3>
                    <p class="muted">
                        Share your opinion through paid research surveys when inventory is available.
                    </p>
                </div>
                <a href="/surveys">Explore surveys →</a>
            </div>

            <div class="card earn-card" style="min-height:185px;">
                <div>
                    <div class="earn-icon" style="font-size:34px;">🎁</div>
                    <h3>Offers</h3>
                    <p class="muted">
                        Complete advertiser-approved activities and tracked offers.
                    </p>
                </div>
                <a href="/offers">Explore offers →</a>
            </div>

            <div class="card earn-card" style="min-height:185px;">
                <div>
                    <div class="earn-icon" style="font-size:34px;">🎮</div>
                    <h3>Games</h3>
                    <p class="muted">
                        Discover game-based opportunities and milestone rewards.
                    </p>
                </div>
                <a href="/games">Explore games →</a>
            </div>

            <div class="card earn-card" style="min-height:185px;">
                <div>
                    <div class="earn-icon" style="font-size:34px;">📱</div>
                    <h3>Apps</h3>
                    <p class="muted">
                        Find tracked app activities and approved earning opportunities.
                    </p>
                </div>
                <a href="/apps">Explore apps →</a>
            </div>

            <div class="card earn-card" style="min-height:185px;">
                <div>
                    <div class="earn-icon" style="font-size:34px;">▶️</div>
                    <h3>Videos</h3>
                    <p class="muted">
                        Watch approved video activities when available.
                    </p>
                </div>
                <a href="/videos">Explore videos →</a>
            </div>

            <div class="card earn-card" style="min-height:185px;">
                <div>
                    <div class="earn-icon" style="font-size:34px;">🧩</div>
                    <h3>Micro Tasks</h3>
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
                    Available now
                </div>
                <h2 style="margin:5px 0 0;">Website Tasks</h2>
            </div>

            <div style="display:flex;align-items:center;gap:8px;font-size:13px;">
                <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#22c55e;"></span>
                <span class="muted">{len(tasks)} available</span>
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
                    Explore rewards, referrals and other earning sections to see what is currently available.
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
            '<h1>Surveys</h1>'
            '<p class="muted">Available surveys from connected providers.</p>'
            + ''.join(cards)
        )
    else:
        body=(
            '<h1>Surveys</h1>'
            '<div class="card">'
            '<h3>No surveys available right now</h3>'
            '<p class="muted">'
            'There are currently no active survey offers from connected providers.'
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

    if cards:
        body=(
            '<h1>Games</h1>'
            '<p class="muted">Available games from connected providers.</p>'
            + ''.join(cards)
        )
    else:
        body=(
            '<h1>Games</h1>'
            '<div class="card">'
            '<h3>No games available right now</h3>'
            '<p class="muted">'
            'There are currently no active game offers from connected providers.'
            '</p>'
            '</div>'
        )

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

    if cards:
        body=(
            '<h1>Offers</h1>'
            '<p class="muted">Available offers from connected providers.</p>'
            + ''.join(cards)
        )
    else:
        body=(
            '<h1>Offers</h1>'
            '<div class="card">'
            '<h3>No offers available right now</h3>'
            '<p class="muted">'
            'There are currently no active offers from connected providers.'
            '</p>'
            '</div>'
        )

    return layout("Offers",body,u)

@app.get('/microtasks',response_class=HTMLResponse)
def microtasks_page(r:Request):
    u=user(r)

    if not u:
        return RedirectResponse('/login',303)

    body=f"""
    <section class="hero" style="position:relative;overflow:hidden;">
        <div style="position:relative;z-index:2;">

            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(245,158,11,.28);border-radius:999px;background:rgba(245,158,11,.09);font-size:12px;color:#fcd34d;margin-bottom:14px;">
                🧩 EasySurf Microtasks
            </div>

            <h1 style="margin:0 0 10px;">
                Complete small tasks. Earn rewards.
            </h1>

            <p class="muted" style="max-width:720px;font-size:16px;line-height:1.7;margin:0;">
                Microtasks are short activities designed to be simple,
                clear and easy to complete when real task inventory is available.
            </p>

            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:22px;">
                <a class="btn" href="/earn">
                    ⚡ Browse all tasks
                </a>

                <a class="btn secondary" href="/activity">
                    📊 View activity
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
                    Microtasks
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;">
                    0
                </div>

                <div class="muted" style="font-size:13px;">
                    currently available
                </div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:34px;">⏱️</div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    Task style
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;">
                    Short
                </div>

                <div class="muted" style="font-size:13px;">
                    focused activities
                </div>
            </div>

            <div class="card" style="min-height:150px;">
                <div class="earn-icon" style="font-size:34px;">🛡️</div>

                <div class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.07em;">
                    Rewards
                </div>

                <div style="font-size:28px;font-weight:800;margin-top:4px;color:#86efac;">
                    Verified
                </div>

                <div class="muted" style="font-size:13px;">
                    after valid completion
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
                    Microtask inventory
                </div>

                <h2 style="margin:7px 0 10px;">
                    No microtasks available yet
                </h2>

                <p class="muted" style="max-width:620px;margin:0 auto;line-height:1.7;">
                    This section is ready for real microtask providers.
                    EasySurf does not generate fake tasks, fake completions,
                    or artificial rewards.
                </p>

                <div style="display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin-top:22px;">
                    <a class="btn" href="/earn">
                        ⚡ Browse earning tasks
                    </a>

                    <a class="btn secondary" href="/offers">
                        💎 Explore offers
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
                    Choose a task
                </h3>

                <p class="muted" style="margin:0;line-height:1.6;font-size:13px;">
                    Select an available microtask and read its requirements carefully.
                </p>
            </div>

            <div class="card">
                <div style="font-size:28px;margin-bottom:10px;">✍️</div>

                <h3 style="margin:0 0 7px;">
                    Complete it
                </h3>

                <p class="muted" style="margin:0;line-height:1.6;font-size:13px;">
                    Follow the instructions and submit only valid work.
                </p>
            </div>

            <div class="card">
                <div style="font-size:28px;margin-bottom:10px;">💰</div>

                <h3 style="margin:0 0 7px;">
                    Get credited
                </h3>

                <p class="muted" style="margin:0;line-height:1.6;font-size:13px;">
                    A reward is credited after the completion is accepted or verified.
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
                    EasySurf does not create fake video views or artificial rewards.
                </p>

                <div style="display:flex;justify-content:center;gap:10px;flex-wrap:wrap;margin-top:22px;">

                    <a class="btn" href="/earn">
                        ⚡ Browse earning tasks
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
    <section class="hero" style="position:relative;overflow:hidden;">

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
                    ⚡ Browse all tasks
                </a>

                <a class="btn secondary" href="/activity">
                    📊 View activity
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
                    currently available
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
                    Short
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
                    Verified
                </div>

                <div class="muted" style="font-size:13px;">
                    after valid completion
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
          Activity availability and reward amounts depend on the tasks
          currently available on the platform.
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
        <h2>Activity</h2>
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

      <h2>Activity records</h2>
      <p class="muted">
        Activity and transaction records may be retained to calculate
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

    if cards:
        body=(
            '<h1>Apps</h1>'
            '<p class="muted">Available applications from connected providers.</p>'
            + ''.join(cards)
        )
    else:
        body=(
            '<h1>Apps</h1>'
            '<div class="card">'
            '<h3>No apps available right now</h3>'
            '<p class="muted">'
            'There are currently no active app offers from connected providers.'
            '</p>'
            '</div>'
        )

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
                        Daily Bonus
                    </div>

                    <h2 style="margin:5px 0 7px;">
                        Bonus claimed today
                    </h2>

                    <p class="muted" style="margin:0;line-height:1.6;">
                        Come back tomorrow to continue your streak and claim the next daily bonus.
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
                            Your daily bonus is ready
                        </h2>

                        <p class="muted" style="margin:0;line-height:1.6;">
                            Claim your bonus once today and keep your earning streak alive.
                        </p>
                    </div>
                </div>

                <form method="post" action="/rewards/daily" style="margin:0;">
                    <input type="hidden"
                           name="csrf_token"
                           value="{token}">

                    <button class="btn" style="min-width:190px;">
                        🎁 Claim Daily Bonus
                    </button>
                </form>

            </div>

            <div style="position:absolute;right:-80px;top:-120px;width:300px;height:300px;border-radius:50%;background:rgba(59,130,246,.09);filter:blur(10px);"></div>
        </div>
        """

    body=f"""
    <section class="hero" style="position:relative;overflow:hidden;">
        <div style="position:relative;z-index:2;">

            <div style="display:inline-flex;align-items:center;gap:8px;padding:6px 12px;border:1px solid rgba(168,85,247,.25);border-radius:999px;background:rgba(168,85,247,.10);font-size:12px;color:#c4b5fd;margin-bottom:14px;">
                ✨ EasySurf Rewards Center
            </div>

            <h1 style="margin:0 0 10px;">
                Rewards & Bonuses
            </h1>

            <p class="muted" style="max-width:720px;font-size:16px;line-height:1.7;margin:0;">
                Claim your daily bonus, build your earning streak,
                reach your daily goal and unlock more rewards.
            </p>

            <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:22px;">
                <a class="btn" href="/earn">
                    ⚡ Start earning
                </a>

                <a class="btn secondary" href="/activity">
                    📊 View activity
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
                    Today's reward
                </div>

                <h2 style="margin:5px 0 0;">
                    Daily Bonus
                </h2>
            </div>

            <div style="font-size:13px;" class="muted">
                One claim per day
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
                            Daily Goal
                        </div>

                        <h2 style="margin:6px 0 7px;">
                            Reach today's target
                        </h2>

                        <p class="muted" style="margin:0;max-width:580px;line-height:1.6;">
                            Keep completing eligible activities to increase your progress toward the daily earning goal.
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
                        Earned today
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
                    Your progress
                </div>

                <h2 style="margin:5px 0 0;">
                    Keep the momentum
                </h2>
            </div>

            <div class="muted" style="font-size:13px;">
                Earn every day to build your progress
            </div>

        </div>

        <div class="grid">

            <div class="card earn-card" style="min-height:205px;">
                <div>
                    <div class="earn-icon" style="font-size:38px;">🔥</div>

                    <div style="display:inline-flex;padding:5px 9px;border-radius:999px;background:rgba(249,115,22,.10);color:#fdba74;font-size:11px;margin-bottom:8px;">
                        Daily streak
                    </div>

                    <h3 style="margin:4px 0 7px;">
                        Streak
                    </h3>

                    <p class="muted" style="line-height:1.6;">
                        Keep earning every day to maintain your reward streak.
                    </p>
                </div>

                <a href="/activity">
                    View activity →
                </a>
            </div>

            <div class="card earn-card" style="min-height:205px;">
                <div>
                    <div class="earn-icon" style="font-size:38px;">🏆</div>

                    <div style="display:inline-flex;padding:5px 9px;border-radius:999px;background:rgba(168,85,247,.10);color:#c4b5fd;font-size:11px;margin-bottom:8px;">
                        Milestones
                    </div>

                    <h3 style="margin:4px 0 7px;">
                        Achievements
                    </h3>

                    <p class="muted" style="line-height:1.6;">
                        Complete milestones and keep building your account progress.
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
                        Community
                    </div>

                    <h3 style="margin:4px 0 7px;">
                        Leaderboard
                    </h3>

                    <p class="muted" style="line-height:1.6;">
                        See how your total earnings compare with other EasySurf users.
                    </p>
                </div>

                <a href="/leaderboard">
                    Open leaderboard →
                </a>
            </div>

        </div>

    </section>

    <section class="card" style="margin-top:28px;padding:26px;position:relative;overflow:hidden;">

        <div style="position:relative;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;">

            <div>
                <div style="font-size:12px;color:#60a5fa;text-transform:uppercase;letter-spacing:.08em;font-weight:700;">
                    More ways to earn
                </div>

                <h2 style="margin:6px 0 7px;">
                    Turn activity into rewards
                </h2>

                <p class="muted" style="margin:0;max-width:620px;line-height:1.6;">
                    Explore available tasks, surveys, offers, games and other earning sections.
                </p>
            </div>

            <div style="display:flex;gap:10px;flex-wrap:wrap;">
                <a class="btn" href="/earn">
                    Explore earning
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
        transactions="""
        <tr>
            <td colspan="3" class="muted">
                No transactions yet.
            </td>
        </tr>
        """

    pending_rows="".join(
        f"""
        <tr>
            <td>{escape(x["source_type"])}</td>
            <td>{money(x["amount"])}</td>
            <td class="orange">Pending</td>
        </tr>
        """
        for x in pending
    )

    if not pending_rows:
        pending_rows="""
        <tr>
            <td colspan="3" class="muted">
                No pending rewards.
            </td>
        </tr>
        """

    body=f"""
    <section class="hero">
        <h1>📊 Activity</h1>
        <p class="muted">
            Track your completed and pending rewards.
        </p>
    </section>

    <div class="card">
        <h2>Pending Rewards</h2>

        <table>
            <tr>
                <th>Source</th>
                <th>Amount</th>
                <th>Status</th>
            </tr>

            {pending_rows}
        </table>
    </div>

    <div class="card">
        <h2>Transaction History</h2>

        <table>
            <tr>
                <th>Description</th>
                <th>Type</th>
                <th>Amount</th>
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
                No rankings yet.
            </td>
        </tr>
        """

    body=f"""
    <section class="hero">
        <h1>🏆 Leaderboard</h1>
        <p class="muted">
            Top EasySurf earners.
        </p>
    </section>

    <div class="card">
        <table>
            <tr>
                <th>Rank</th>
                <th>User</th>
                <th>Total earned</th>
            </tr>

            {table}
        </table>
    </div>
    """

    return layout("Leaderboard",body,u)


# ============================================================
# SECURITY V4 — OFFERWALL.GG SECURE POSTBACK
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
        # CREDITED — DATABASE UNIQUE CONSTRAINT IS THE
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


