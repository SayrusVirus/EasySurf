from __future__ import annotations

import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

_default_db = BASE_DIR.parent / "easysurf.db"
_db_value = os.getenv("EASYSURF_DB_PATH", "").strip()

DB_PATH = Path(_db_value).expanduser() if _db_value else _default_db

if not DB_PATH.is_absolute():
    DB_PATH = (BASE_DIR.parent / DB_PATH).resolve()
else:
    DB_PATH = DB_PATH.resolve()
