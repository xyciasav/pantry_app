from __future__ import annotations

import os
import sqlite3
import json
import re
import base64
import binascii
import hashlib
import hmac
import io
import secrets
import shutil
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from contextlib import closing
from datetime import date, datetime, timedelta
from pathlib import Path

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Security, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("PANTRY_DATA_DIR", BASE_DIR.parent / "data"))
DB_PATH = DATA_DIR / "pantry.db"
APP_VERSION = os.getenv("APP_VERSION", "1.9.2")
AUTH_USERNAME = os.getenv("PANTRY_USERNAME", "")
AUTH_PASSWORD = os.getenv("PANTRY_PASSWORD", "")
AUTH_SECRET = os.getenv("PANTRY_SECRET_KEY", "")
API_KEY = os.getenv("PANTRY_API_KEY", "")
LLM_URL = os.getenv("PANTRY_LLM_URL", "").strip().rstrip("/")
LLM_MODEL = os.getenv("PANTRY_LLM_MODEL", "").strip()
LLM_API_KEY = os.getenv("PANTRY_LLM_API_KEY", "").strip()
COOKIE_SECURE_MODE = os.getenv("PANTRY_COOKIE_SECURE", "auto").strip().lower()
SESSION_SECONDS = int(float(os.getenv("PANTRY_SESSION_HOURS", "12")) * 3600)
COOKIE_NAME = "pantry_session"
LEGACY_COOKIE_NAME = "__Host-pantry_session"
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

CATEGORIES = {
    "produce": ("Produce", "🥬"),
    "dairy": ("Dairy", "🥛"),
    "meat": ("Meat & seafood", "🥩"),
    "frozen": ("Frozen", "🧊"),
    "pantry": ("Pantry", "🥫"),
    "bakery": ("Bakery", "🍞"),
    "drinks": ("Drinks", "🧃"),
    "other": ("Other", "🛒"),
}

DEFAULT_CATEGORIES = CATEGORIES.copy()

ITEM_ART = {
    "onion": ("onion", "onions", "shallot", "shallots"),
    "garlic": ("garlic",),
    "tomato": ("tomato", "tomatoes"),
    "broccoli": ("broccoli",),
    "pepper": ("pepper", "peppers", "capsicum", "capsicums"),
    "apple": ("apple", "apples"),
    "banana": ("banana", "bananas"),
    "carrot": ("carrot", "carrots"),
    "potato": ("potato", "potatoes", "spud", "spuds"),
    "milk": ("milk", "cream", "half and half"),
    "egg": ("egg", "eggs"),
    "cheese": ("cheese", "cheddar", "mozzarella", "parmesan"),
    "bread": ("bread", "loaf", "bagel", "buns", "rolls"),
    "canned-food": ("can", "canned", "tin", "beans"),
    "pasta": ("pasta", "noodles", "spaghetti", "macaroni"),
    "chicken": ("chicken", "poultry", "turkey"),
    "frozen-food": ("frozen", "ice cream", "pizza"),
}

app = FastAPI(title="Shelf Life", description="Read Shelf Life pantry inventory through the authenticated inventory endpoint.", version=APP_VERSION)
api_bearer = HTTPBearer(auto_error=False, description="Enter the PANTRY_API_KEY configured in Portainer.")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")
templates = Environment(
    loader=FileSystemLoader(BASE_DIR / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)


def auth_config_valid() -> None:
    missing = [name for name, value in (("PANTRY_USERNAME", AUTH_USERNAME), ("PANTRY_PASSWORD", AUTH_PASSWORD), ("PANTRY_SECRET_KEY", AUTH_SECRET)) if not value]
    if missing:
        raise RuntimeError(f"Authentication is required. Set: {', '.join(missing)}")
    if len(AUTH_SECRET) < 32:
        raise RuntimeError("PANTRY_SECRET_KEY must be at least 32 characters")


def create_session_token() -> str:
    password_version = hashlib.sha256(AUTH_PASSWORD.encode()).hexdigest()[:16]
    payload = f"{AUTH_USERNAME}|{password_version}|{int(time.time()) + SESSION_SECONDS}|{secrets.token_urlsafe(16)}"
    signature = hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{signature}".encode()).decode()


def valid_session_token(token: str | None) -> bool:
    if not token:
        return False
    try:
        decoded = base64.urlsafe_b64decode(token.encode()).decode()
        username, password_version, expires, nonce, signature = decoded.rsplit("|", 4)
        payload = f"{username}|{password_version}|{expires}|{nonce}"
        expected = hmac.new(AUTH_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        current_password_version = hashlib.sha256(AUTH_PASSWORD.encode()).hexdigest()[:16]
        return username == AUTH_USERNAME and hmac.compare_digest(password_version, current_password_version) and int(expires) >= int(time.time()) and hmac.compare_digest(signature, expected)
    except (ValueError, UnicodeDecodeError, binascii.Error):
        return False


def request_uses_https(request: Request) -> bool:
    if COOKIE_SECURE_MODE in {"1", "true", "yes"}:
        return True
    if COOKIE_SECURE_MODE in {"0", "false", "no"}:
        return False
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip().lower()
    return request.url.scheme == "https" or forwarded_proto == "https"


def prevent_browser_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


def valid_api_key(request: Request) -> bool:
    if not API_KEY:
        return False
    authorization = request.headers.get("authorization", "")
    supplied = authorization[7:] if authorization.lower().startswith("bearer ") else ""
    return bool(supplied) and hmac.compare_digest(supplied, API_KEY)


def require_api_key(credentials: HTTPAuthorizationCredentials | None = Security(api_bearer)) -> None:
    supplied = credentials.credentials if credentials and credentials.scheme.lower() == "bearer" else ""
    if not API_KEY or not supplied or not hmac.compare_digest(supplied, API_KEY):
        raise HTTPException(401, "A valid PANTRY_API_KEY Bearer token is required", headers={"WWW-Authenticate": "Bearer"})


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    public = path in {"/login", "/health", "/docs", "/openapi.json", "/manifest.webmanifest", "/sw.js"} or path.startswith("/static/")
    session_token = request.cookies.get(COOKIE_NAME) or request.cookies.get(LEGACY_COOKIE_NAME)
    api_access = path == "/api/inventory" and valid_api_key(request)
    if not public and not api_access and not valid_session_token(session_token):
        if path.startswith("/api/"):
            return prevent_browser_cache(JSONResponse({"detail": "Authentication required"}, status_code=401))
        next_path = urllib.parse.quote(path if path.startswith("/") else "/", safe="/")
        return prevent_browser_cache(RedirectResponse(f"/login?next={next_path}", status_code=303))
    response = await call_next(request)
    if not path.startswith("/static/"):
        prevent_browser_cache(response)
    return response


def db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with closing(db()) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                category TEXT NOT NULL DEFAULT 'other',
                location TEXT NOT NULL DEFAULT 'pantry',
                quantity REAL NOT NULL DEFAULT 1,
                unit TEXT NOT NULL DEFAULT 'item',
                low_at REAL NOT NULL DEFAULT 1,
                bought_on TEXT,
                expires_on TEXT,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS item_stocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                location_id INTEGER NOT NULL REFERENCES locations(id),
                quantity REAL NOT NULL DEFAULT 0 CHECK(quantity >= 0),
                opened REAL NOT NULL DEFAULT 0 CHECK(opened >= 0 AND opened <= quantity),
                updated_at TEXT NOT NULL,
                UNIQUE(item_id, location_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL DEFAULT 'pantry',
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS product_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS categories (
                key TEXT PRIMARY KEY,
                label TEXT NOT NULL UNIQUE,
                icon TEXT NOT NULL DEFAULT '•',
                custom INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS inventory_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                delta REAL NOT NULL,
                event_type TEXT NOT NULL,
                created_at TEXT NOT NULL
            )"""
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS shopping_list (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL UNIQUE REFERENCES items(id) ON DELETE CASCADE,
                reason TEXT NOT NULL DEFAULT '',
                automatic INTEGER NOT NULL DEFAULT 0,
                added_at TEXT NOT NULL
            )"""
        )
        conn.execute("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('shopping_mode', 'analysis')")
        conn.execute("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('analysis_days', '7')")
        conn.execute("INSERT OR IGNORE INTO app_settings (key, value) VALUES ('analysis_started_at', ?)", (datetime.now().isoformat(timespec="seconds"),))
        for key, (label, icon) in DEFAULT_CATEGORIES.items():
            conn.execute("INSERT OR IGNORE INTO categories (key, label, icon, custom) VALUES (?, ?, ?, 0)", (key, label, icon))
        columns = {row[1] for row in conn.execute("PRAGMA table_info(items)")}
        for name, definition in {
            "location_id": "INTEGER REFERENCES locations(id)",
            "barcode": "TEXT",
            "image_url": "TEXT",
            "ingredients": "TEXT NOT NULL DEFAULT ''",
            "group_id": "INTEGER REFERENCES product_groups(id) ON DELETE SET NULL",
            "opened_low": "INTEGER NOT NULL DEFAULT 0",
            "essential": "INTEGER NOT NULL DEFAULT 0",
        }.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE items ADD COLUMN {name} {definition}")
        now = datetime.now().isoformat(timespec="seconds")
        for name, kind in (("Main Pantry", "pantry"), ("Kitchen Fridge", "fridge"), ("Kitchen Freezer", "freezer")):
            conn.execute("INSERT OR IGNORE INTO locations (name, kind, created_at) VALUES (?, ?, ?)", (name, kind, now))
        conn.execute(
            """UPDATE items SET location_id = (
                SELECT id FROM locations
                WHERE locations.kind = items.location
                ORDER BY id LIMIT 1
            ) WHERE location_id IS NULL"""
        )
        conn.execute(
            """INSERT OR IGNORE INTO item_stocks (item_id, location_id, quantity, opened, updated_at)
               SELECT id, location_id, quantity, 0, ? FROM items WHERE location_id IS NOT NULL""",
            (now,),
        )
        conn.execute(
            """CREATE TABLE IF NOT EXISTS stock_batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                location_id INTEGER NOT NULL REFERENCES locations(id),
                quantity REAL NOT NULL DEFAULT 0 CHECK(quantity >= 0),
                opened REAL NOT NULL DEFAULT 0 CHECK(opened >= 0 AND opened <= quantity),
                bought_on TEXT,
                expires_on TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        conn.execute(
            """INSERT INTO stock_batches (item_id, location_id, quantity, opened, bought_on, expires_on, created_at, updated_at)
               SELECT s.item_id, s.location_id, s.quantity, s.opened, i.bought_on, i.expires_on, ?, ?
               FROM item_stocks s JOIN items i ON i.id=s.item_id
               WHERE s.quantity > 0 AND NOT EXISTS (SELECT 1 FROM stock_batches b WHERE b.item_id=s.item_id)""",
            (now, now),
        )
        conn.commit()
        CATEGORIES.clear()
        CATEGORIES.update({row["key"]: (row["label"], row["icon"]) for row in conn.execute("SELECT * FROM categories ORDER BY label")})


def get_locations(conn: sqlite3.Connection | None = None) -> list[dict]:
    owns_connection = conn is None
    conn = conn or db()
    try:
        return [dict(row) for row in conn.execute("SELECT * FROM locations ORDER BY kind, name")]
    finally:
        if owns_connection:
            conn.close()


@app.on_event("startup")
def startup() -> None:
    auth_config_valid()
    init_db()


def normalize_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise HTTPException(400, "Invalid date") from exc


def refresh_stock_from_batches(conn: sqlite3.Connection, item_id: int) -> float:
    """Keep the legacy per-location totals and item summary in sync with dated lots."""
    now = datetime.now().isoformat(timespec="seconds")
    conn.execute("DELETE FROM item_stocks WHERE item_id=?", (item_id,))
    conn.execute(
        """INSERT INTO item_stocks (item_id, location_id, quantity, opened, updated_at)
           SELECT item_id, location_id, SUM(quantity), SUM(opened), ?
           FROM stock_batches WHERE item_id=? AND quantity > 0 GROUP BY item_id, location_id""",
        (now, item_id),
    )
    summary = conn.execute(
        """SELECT COALESCE(SUM(quantity),0) AS total,
                  MIN(CASE WHEN quantity > 0 THEN expires_on END) AS next_expiry,
                  MAX(CASE WHEN quantity > 0 THEN bought_on END) AS latest_purchase
           FROM stock_batches WHERE item_id=?""",
        (item_id,),
    ).fetchone()
    conn.execute(
        "UPDATE items SET quantity=?, expires_on=?, bought_on=COALESCE(?, bought_on), updated_at=? WHERE id=?",
        (summary["total"], summary["next_expiry"], summary["latest_purchase"], now, item_id),
    )
    conn.execute("UPDATE items SET opened_low=0 WHERE id=? AND NOT EXISTS (SELECT 1 FROM stock_batches WHERE item_id=? AND opened>0 AND quantity>0)", (item_id, item_id))
    return float(summary["total"])


def consume_batches(conn: sqlite3.Connection, item_id: int, amount: float) -> None:
    """Consume opened lots first, then earliest-expiring unopened lots."""
    remaining = amount
    rows = conn.execute(
        """SELECT * FROM stock_batches WHERE item_id=? AND quantity > 0
           ORDER BY CASE WHEN opened > 0 THEN 0 ELSE 1 END,
                    CASE WHEN expires_on IS NULL THEN 1 ELSE 0 END, expires_on, created_at""",
        (item_id,),
    ).fetchall()
    for batch in rows:
        if remaining <= 0:
            break
        used = min(remaining, batch["quantity"])
        new_quantity = batch["quantity"] - used
        new_opened = min(batch["opened"], new_quantity)
        conn.execute("UPDATE stock_batches SET quantity=?, opened=?, updated_at=? WHERE id=?", (new_quantity, new_opened, datetime.now().isoformat(timespec="seconds"), batch["id"]))
        remaining -= used


def safe_return_path(value: str | None, fallback: str = "/") -> str:
    return value if value and value.startswith("/") and not value.startswith("//") else fallback


def shopping_settings(conn: sqlite3.Connection) -> dict:
    values = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM app_settings")}
    return {"mode": values.get("shopping_mode", "analysis"), "days": int(values.get("analysis_days", "7")), "started_at": values.get("analysis_started_at", datetime.now().isoformat(timespec="seconds"))}


def dinner_inventory(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """SELECT items.name, items.unit, items.category, items.ingredients,
                  COALESCE((SELECT SUM(s.quantity) FROM item_stocks s WHERE s.item_id=items.id),0) AS total_quantity,
                  COALESCE((SELECT SUM(s.opened) FROM item_stocks s WHERE s.item_id=items.id),0) AS opened_quantity,
                  MIN(CASE WHEN stock_batches.quantity > 0 THEN stock_batches.expires_on END) AS nearest_expiry
           FROM items LEFT JOIN stock_batches ON stock_batches.item_id=items.id
           GROUP BY items.id HAVING total_quantity > 0 ORDER BY items.name"""
    ).fetchall()
    return [{"name": row["name"], "category": row["category"], "unit": row["unit"], "total": row["total_quantity"], "open": row["opened_quantity"], "nearest_expiry": row["nearest_expiry"], "ingredients": row["ingredients"] or ""} for row in rows]


def parse_llm_json(content: str) -> dict:
    cleaned = content.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    decoder = json.JSONDecoder()
    candidates = []
    for match in re.finditer(r"\{", cleaned):
        try:
            value, _ = decoder.raw_decode(cleaned[match.start():])
            if isinstance(value, dict):
                candidates.append(value)
        except json.JSONDecodeError:
            continue
    if not candidates:
        raise ValueError("the model did not return valid JSON")
    meal_candidates = [candidate for candidate in candidates if isinstance(candidate.get("meals"), list)]
    for candidate in reversed(meal_candidates):
        names = [str(meal.get("name", "")).strip() for meal in candidate["meals"] if isinstance(meal, dict)]
        if names and any(name not in {"", "..."} for name in names):
            return candidate
    if meal_candidates:
        return meal_candidates[-1]
    for candidate in reversed(candidates):
        if isinstance(candidate.get("steps"), list) and isinstance(candidate.get("ingredients"), list):
            return candidate
    return candidates[-1]


def compact_dinner_inventory(inventory: list[dict]) -> list[str]:
    """Keep the LLM prompt small while retaining the facts needed to choose meals."""
    lines = []
    for item in inventory:
        line = f"{item['name']}: {item['total']:g} {item['unit']}"
        if item["open"]:
            line += f", {item['open']:g} open"
        if item["nearest_expiry"]:
            line += f", expires {item['nearest_expiry']}"
        lines.append(line)
    return lines


def call_dinner_llm(system: str, user_data: dict, temperature: float = 0.7, max_tokens: int = 800) -> dict:
    if not LLM_URL or not LLM_MODEL:
        raise RuntimeError("Dinner Assistant is not configured. Set PANTRY_LLM_URL and PANTRY_LLM_MODEL in Portainer.")
    user = "/no_think\n" + json.dumps(user_data, ensure_ascii=False, separators=(",", ":"))
    payload = json.dumps({
        "model": LLM_MODEL, "temperature": temperature, "max_tokens": max_tokens,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "system", "content": system + " Do not reason aloud. /no_think"}, {"role": "user", "content": user}],
    }).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if LLM_API_KEY:
        headers["Authorization"] = f"Bearer {LLM_API_KEY}"
    request = urllib.request.Request(f"{LLM_URL}/chat/completions", data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=90) as response:
            response_data = json.load(response)
        return parse_llm_json(response_data["choices"][0]["message"]["content"])
    except urllib.error.HTTPError as exc:
        detail = exc.read(500).decode("utf-8", "replace")
        raise RuntimeError(f"The LLM proxy returned HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Shelf Life could not reach the LLM proxy: {exc}") from exc
    except (KeyError, IndexError, TypeError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(f"The LLM response could not be read: {exc}") from exc


def ask_dinner_picks(inventory: list[dict]) -> list[dict]:
    result = call_dinner_llm(
        "Use your configured household food profile and the supplied pantry inventory. Pick up to three distinct dinner ideas. "
        "Prefer opened and soon-expiring food. Do not write recipes yet. Return JSON only as "
        "{\"meals\":[{\"name\":\"...\",\"summary\":\"one short sentence\"}]}. Do not add other keys.",
        {"inventory": compact_dinner_inventory(inventory)}, 0.8, 500,
    )
    meals = result.get("meals")
    if not isinstance(meals, list) or not meals:
        raise RuntimeError("The LLM returned no dinner choices.")
    picks = []
    for meal in meals[:3]:
        if isinstance(meal, dict) and str(meal.get("name", "")).strip():
            picks.append({"name": str(meal["name"]).strip()[:160], "summary": str(meal.get("summary", "")).strip()[:300]})
    if not picks:
        raise RuntimeError("The LLM returned dinner choices in an unreadable format.")
    return picks


def ask_dinner_recipe(inventory: list[dict], meal_name: str) -> dict:
    result = call_dinner_llm(
        "Use your configured household food profile. Write a practical recipe for the selected meal using the supplied inventory. "
        "Clearly distinguish pantry items from missing items. Return JSON only with name, summary, time_minutes, servings, "
        "ingredients (array of objects with item, amount, have), steps (array of short strings), and missing_items (array of strings).",
        {"selected_meal": meal_name, "inventory": compact_dinner_inventory(inventory)}, 0.4, 1400,
    )
    if not isinstance(result, dict) or not isinstance(result.get("steps"), list) or not isinstance(result.get("ingredients"), list):
        raise RuntimeError("The LLM returned the recipe in an unreadable format.")
    result["name"] = str(result.get("name") or meal_name)
    result["missing_items"] = result.get("missing_items") if isinstance(result.get("missing_items"), list) else []
    return result


def record_inventory_event(conn: sqlite3.Connection, item_id: int, delta: float, event_type: str) -> None:
    if abs(delta) > 0.0001:
        conn.execute("INSERT INTO inventory_events (item_id, delta, event_type, created_at) VALUES (?, ?, ?, ?)", (item_id, delta, event_type, datetime.now().isoformat(timespec="seconds")))


def shopping_analysis(conn: sqlite3.Connection, item: dict, settings: dict) -> dict:
    since = (datetime.now() - timedelta(days=settings["days"])).isoformat(timespec="seconds")
    usage = conn.execute(
        """SELECT COALESCE(SUM(CASE WHEN delta < 0 THEN -delta ELSE 0 END), 0) AS used,
                  COUNT(CASE WHEN delta < 0 THEN 1 END) AS uses,
                  MIN(created_at) AS first_event
           FROM inventory_events WHERE item_id=? AND created_at>=?""",
        (item["id"], since),
    ).fetchone()
    daily_use = usage["used"] / settings["days"] if settings["days"] else 0
    days_left = item["unopened_quantity"] / daily_use if daily_use > 0 else None
    observed_days = max(0, (datetime.now() - datetime.fromisoformat(settings["started_at"])).days)
    enough_history = observed_days >= settings["days"] and usage["uses"] >= 2
    should_buy = item["state"] in {"out", "low"} or (enough_history and days_left is not None and days_left <= 3)
    if item["opened_low"]:
        reason = "Opened package marked getting low" + (" · essential" if item["essential"] else "")
    elif item["state"] == "out":
        reason = "Out of stock" + (" · essential" if item["essential"] else "")
    elif item["state"] == "low":
        reason = f"{item['unopened_quantity']:g} unopened; low alert is {item['low_at']:g}"
    elif enough_history and days_left is not None:
        reason = f"About {days_left:.1f} days left based on {settings['days']}-day usage"
    else:
        remaining_days = max(0, settings["days"] - observed_days)
        reason = f"Learning usage ({usage['uses']} decrease{'s' if usage['uses'] != 1 else ''} recorded; {remaining_days} day{'s' if remaining_days != 1 else ''} left)"
    confidence = "high" if usage["uses"] >= 5 else "medium" if usage["uses"] >= 2 else "learning"
    return {"should_buy": should_buy, "reason": reason, "daily_use": daily_use, "days_left": days_left, "confidence": confidence}


def maybe_auto_add_shopping(conn: sqlite3.Connection, item_id: int) -> None:
    settings = shopping_settings(conn)
    if settings["mode"] != "assistant":
        return
    row = conn.execute(
        """SELECT items.*, COALESCE(SUM(item_stocks.quantity),0) AS total_quantity,
                  COALESCE(SUM(item_stocks.opened),0) AS opened_quantity
           FROM items LEFT JOIN item_stocks ON item_stocks.item_id=items.id
           WHERE items.id=? GROUP BY items.id""",
        (item_id,),
    ).fetchone()
    if not row:
        return
    item = view_item(row)
    analysis = shopping_analysis(conn, item, settings)
    if analysis["should_buy"]:
        conn.execute(
            """INSERT INTO shopping_list (item_id, reason, automatic, added_at) VALUES (?, ?, 1, ?)
               ON CONFLICT(item_id) DO UPDATE SET reason=excluded.reason""",
            (item_id, analysis["reason"], datetime.now().isoformat(timespec="seconds")),
        )


def item_art_url(name: str, category: str) -> str | None:
    words = set(re.findall(r"[a-z]+", name.lower()))
    normalized = " ".join(re.findall(r"[a-z]+", name.lower()))
    for artwork, aliases in ITEM_ART.items():
        if any((" " in alias and alias in normalized) or alias in words for alias in aliases):
            return f"/static/items/{artwork}.webp"
    return None


def view_item(row: sqlite3.Row) -> dict:
    item = dict(row)
    item["quantity"] = item.get("total_quantity", item.get("quantity", 0))
    item["opened_quantity"] = item.get("opened_quantity", 0)
    item["unopened_quantity"] = max(0, item["quantity"] - item["opened_quantity"])
    today = date.today()
    expires = date.fromisoformat(item["expires_on"]) if item["expires_on"] else None
    days_left = (expires - today).days if expires else None
    item["opened_low"] = bool(item.get("opened_low", 0) and item["opened_quantity"] > 0)
    item["essential"] = bool(item.get("essential", 0))
    if item["quantity"] <= 0:
        state = "out"
    elif item["opened_low"]:
        state = "low"
    elif item["unopened_quantity"] > 0 and item["unopened_quantity"] <= item["low_at"]:
        state = "low"
    elif days_left is not None and days_left < 0:
        state = "expired"
    elif days_left is not None and days_left <= 3:
        state = "expiring"
    else:
        state = "good"
    item.update(
        category_label=CATEGORIES.get(item["category"], CATEGORIES["other"])[0],
        icon=CATEGORIES.get(item["category"], CATEGORIES["other"])[1],
        days_left=days_left,
        state=state,
        critical=item["essential"] and state in {"out", "low"},
    )
    item["image_url"] = item.get("image_url") or item_art_url(item["name"], item["category"])
    return item


def render(request: Request, name: str, **context) -> HTMLResponse:
    template = templates.get_template(name)
    generic_images = [{"url": f"/static/items/{path.name}", "label": path.stem.replace("-", " ").title()} for path in sorted((BASE_DIR / "static" / "items").glob("*.webp"))]
    with closing(db()) as conn:
        shopping_count = conn.execute("SELECT COUNT(*) FROM shopping_list").fetchone()[0]
    return HTMLResponse(template.render(request=request, categories=CATEGORIES, locations=get_locations(), generic_images=generic_images, shopping_count=shopping_count, app_version=APP_VERSION, **context))


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, next: str = "/", error: str = ""):
    if valid_session_token(request.cookies.get(COOKIE_NAME) or request.cookies.get(LEGACY_COOKIE_NAME)):
        return RedirectResponse("/", status_code=303)
    safe_next = next if next.startswith("/") and not next.startswith("//") else "/"
    return render(request, "login.html", next_path=safe_next, error=error)


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form("/")):
    client = request.client.host if request.client else "unknown"
    now = time.monotonic()
    recent = [attempt for attempt in LOGIN_ATTEMPTS.get(client, []) if now - attempt < 600]
    if len(recent) >= 5:
        return RedirectResponse("/login?error=Too+many+attempts.+Try+again+in+10+minutes.", status_code=303)
    username_ok = hmac.compare_digest(username.encode(), AUTH_USERNAME.encode())
    password_ok = hmac.compare_digest(password.encode(), AUTH_PASSWORD.encode())
    if not (username_ok and password_ok):
        recent.append(now)
        LOGIN_ATTEMPTS[client] = recent
        return RedirectResponse("/login?error=Incorrect+username+or+password.", status_code=303)
    LOGIN_ATTEMPTS.pop(client, None)
    destination = next if next.startswith("/") and not next.startswith("//") else "/"
    response = RedirectResponse(destination, status_code=303)
    response.set_cookie(COOKIE_NAME, create_session_token(), httponly=True, secure=request_uses_https(request), samesite="lax", path="/")
    response.delete_cookie(LEGACY_COOKIE_NAME, path="/", secure=True, httponly=True, samesite="strict")
    prevent_browser_cache(response)
    return response


@app.post("/logout")
def logout(request: Request):
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/", secure=request_uses_https(request), httponly=True, samesite="lax")
    response.delete_cookie(LEGACY_COOKIE_NAME, path="/", secure=True, httponly=True, samesite="strict")
    prevent_browser_cache(response)
    return response


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": APP_VERSION}


@app.get("/manifest.webmanifest")
def pwa_manifest():
    return Response((BASE_DIR / "static" / "manifest.webmanifest").read_text(encoding="utf-8"), media_type="application/manifest+json")


@app.get("/sw.js")
def service_worker():
    return Response((BASE_DIR / "static" / "sw.js").read_text(encoding="utf-8"), media_type="application/javascript", headers={"Service-Worker-Allowed": "/", "Cache-Control": "no-cache"})


@app.get("/", response_class=HTMLResponse)
def home(request: Request, location: str = "all", category: str = "all", q: str = ""):
    clauses, params = [], []
    if location != "all":
        clauses.append("EXISTS (SELECT 1 FROM item_stocks filtered_stock WHERE filtered_stock.item_id = items.id AND filtered_stock.location_id = ? AND filtered_stock.quantity > 0)")
        params.append(int(location))
    if category != "all":
        clauses.append("items.category = ?")
        params.append(category)
    if q.strip():
        clauses.append("(items.name LIKE ? OR EXISTS (SELECT 1 FROM product_groups search_group WHERE search_group.id = items.group_id AND search_group.name LIKE ?))")
        params.extend((f"%{q.strip()}%", f"%{q.strip()}%"))
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with closing(db()) as conn:
        rows = conn.execute(
            f"""SELECT items.*,
                       COALESCE(SUM(item_stocks.quantity), 0) AS total_quantity,
                       COALESCE(SUM(item_stocks.opened), 0) AS opened_quantity,
                       COUNT(CASE WHEN item_stocks.quantity > 0 THEN 1 END) AS active_locations,
                       MIN(CASE WHEN item_stocks.quantity > 0 THEN locations.name END) AS location_name
                FROM items
                LEFT JOIN item_stocks ON item_stocks.item_id = items.id
                LEFT JOIN locations ON locations.id = item_stocks.location_id
                {where}
                GROUP BY items.id
                ORDER BY CASE WHEN items.expires_on IS NULL THEN 1 ELSE 0 END, items.expires_on, items.name""",
            params,
        ).fetchall()
        stock_rows = conn.execute(
            """SELECT item_stocks.item_id, locations.name, item_stocks.quantity, item_stocks.opened
               FROM item_stocks JOIN locations ON locations.id = item_stocks.location_id
               WHERE item_stocks.quantity > 0 ORDER BY locations.name"""
        ).fetchall()
        groups = [dict(row) for row in conn.execute("SELECT * FROM product_groups ORDER BY name").fetchall()]
    breakdowns: dict[int, list[dict]] = {}
    for stock in stock_rows:
        stock_view = dict(stock)
        stock_view["unopened"] = max(0, stock_view["quantity"] - stock_view["opened"])
        breakdowns.setdefault(stock["item_id"], []).append(stock_view)
    items = [view_item(row) for row in rows]
    for item in items:
        item["stocks"] = breakdowns.get(item["id"], [])
        item["card_type"] = "item"
    grouped_items: dict[int, list[dict]] = {}
    for item in items:
        if item.get("group_id"):
            grouped_items.setdefault(item["group_id"], []).append(item)
    visible_items = [item for item in items if not item.get("group_id")]
    for group in groups:
        variants = grouped_items.get(group["id"], [])
        if not variants:
            continue
        total = sum(item["quantity"] for item in variants)
        opened = sum(item["opened_quantity"] for item in variants)
        unopened = sum(item["unopened_quantity"] for item in variants)
        active_locations = len({stock["name"] for item in variants for stock in item["stocks"]})
        expiry_variants = [item for item in variants if item["expires_on"] and item["quantity"] > 0]
        earliest = min(expiry_variants, key=lambda item: item["expires_on"]) if expiry_variants else None
        state = "out" if total <= 0 else (earliest["state"] if earliest and earliest["state"] in {"expired", "expiring"} else "low" if unopened <= sum(item["low_at"] for item in variants) else "good")
        visible_items.append({
            "id": group["id"], "card_type": "group", "name": group["name"], "category": variants[0]["category"],
            "category_label": variants[0]["category_label"], "icon": variants[0]["icon"], "image_url": variants[0]["image_url"],
            "quantity": total, "opened_quantity": opened, "unopened_quantity": unopened, "active_locations": active_locations,
            "state": state, "days_left": earliest["days_left"] if earliest else None, "expires_on": earliest["expires_on"] if earliest else None,
            "variants": variants,
        })
    items = sorted(visible_items, key=lambda item: (not bool(item.get("critical")), item["expires_on"] is None, item["expires_on"] or "", item["name"].lower()))
    category_sections = []
    for category_key, (category_label, category_icon) in CATEGORIES.items():
        category_items = [item for item in items if item["category"] == category_key]
        if category_items:
            category_sections.append({
                "key": category_key,
                "label": category_label,
                "icon": category_icon,
                "items": category_items,
            })
    counts = {
        "all": len(items),
        "attention": sum(i["state"] in {"out", "low", "expired", "expiring"} for i in items),
        "expiring": sum(i["state"] in {"expired", "expiring"} for i in items),
        "low": sum(i["state"] in {"out", "low"} for i in items),
        "critical": sum(bool(i.get("critical")) for i in items),
    }
    return render(request, "index.html", items=items, category_sections=category_sections, counts=counts, filters={"location": location, "category": category, "q": q}, return_to=str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""))


@app.get("/items/new", response_class=HTMLResponse)
def new_item(request: Request, name: str = "", barcode: str = "", image_url: str = "", category: str = "other", unit: str = "item", ingredients: str = ""):
    item = {"name": name, "barcode": barcode, "image_url": image_url, "category": category, "unit": unit, "ingredients": ingredients} if any((name, barcode, image_url, ingredients)) else None
    return render(request, "form.html", item=item, is_new=True, today=date.today().isoformat())


@app.get("/items/{item_id}", response_class=HTMLResponse)
def item_detail(request: Request, item_id: int, return_to: str = "/"):
    with closing(db()) as conn:
        row = conn.execute(
            """SELECT items.*, COALESCE(SUM(item_stocks.quantity), 0) AS total_quantity,
                      COALESCE(SUM(item_stocks.opened), 0) AS opened_quantity
               FROM items LEFT JOIN item_stocks ON item_stocks.item_id=items.id
               WHERE items.id=? GROUP BY items.id""",
            (item_id,),
        ).fetchone()
        if not row:
            raise HTTPException(404)
        stocks = [dict(stock) for stock in conn.execute(
            """SELECT locations.name, locations.kind, item_stocks.quantity, item_stocks.opened
               FROM item_stocks JOIN locations ON locations.id=item_stocks.location_id
               WHERE item_stocks.item_id=? AND item_stocks.quantity > 0 ORDER BY locations.name""",
            (item_id,),
        )]
        batches = [dict(batch) for batch in conn.execute(
            """SELECT stock_batches.*, locations.name AS location_name
               FROM stock_batches JOIN locations ON locations.id=stock_batches.location_id
               WHERE stock_batches.item_id=? AND stock_batches.quantity > 0
               ORDER BY CASE WHEN expires_on IS NULL THEN 1 ELSE 0 END, expires_on, created_at""", (item_id,))]
    item = view_item(row)
    for stock in stocks:
        stock["unopened"] = max(0, stock["quantity"] - stock["opened"])
    return render(request, "detail.html", item=item, stocks=stocks, batches=batches, return_to=safe_return_path(return_to))


@app.get("/items/{item_id}/edit", response_class=HTMLResponse)
def edit_item(request: Request, item_id: int, return_to: str = "/"):
    with closing(db()) as conn:
        row = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if not row:
        raise HTTPException(404)
    return render(request, "form.html", item=dict(row), is_new=False, today=date.today().isoformat(), return_to=safe_return_path(return_to))


@app.post("/items/{item_id}/flags")
def update_item_flags(item_id: int, essential: str | None = Form(None), opened_low: str | None = Form(None), return_to: str = Form("/")):
    with closing(db()) as conn:
        item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not item:
            raise HTTPException(404)
        has_open_stock = conn.execute("SELECT COALESCE(SUM(opened),0) FROM item_stocks WHERE item_id=?", (item_id,)).fetchone()[0] > 0
        conn.execute("UPDATE items SET essential=?, opened_low=?, updated_at=? WHERE id=?", (1 if essential else 0, 1 if opened_low and has_open_stock else 0, datetime.now().isoformat(timespec="seconds"), item_id))
        maybe_auto_add_shopping(conn, item_id)
        conn.commit()
    return RedirectResponse(safe_return_path(return_to, f"/items/{item_id}"), status_code=303)


@app.post("/items/save")
async def save_item(
    item_id: int | None = Form(None),
    name: str = Form(...),
    category: str = Form("other"),
    location_id: int | None = Form(None),
    unopened: float | None = Form(None),
    quantity: float | None = Form(None),
    opened: float = Form(0),
    unit: str = Form("item"),
    low_at: float = Form(1),
    bought_on: str | None = Form(None),
    expires_on: str | None = Form(None),
    notes: str = Form(""),
    ingredients: str = Form(""),
    barcode: str = Form(""),
    image_url: str = Form(""),
    generic_image: str = Form(""),
    photo: UploadFile | None = File(None),
    return_to: str = Form("/"),
):
    starting_unopened = unopened if unopened is not None else quantity
    if not name.strip() or low_at < 0 or (starting_unopened is not None and starting_unopened < 0) or opened < 0:
        raise HTTPException(400, "Name is required and quantities cannot be negative")
    now = datetime.now().isoformat(timespec="seconds")
    saved_image_url = image_url.strip()
    valid_generic_images = {f"/static/items/{path.name}" for path in (BASE_DIR / "static" / "items").glob("*.webp")}
    if generic_image:
        if generic_image not in valid_generic_images:
            raise HTTPException(400, "Choose a valid built-in image")
        saved_image_url = generic_image
    if photo and photo.filename:
        allowed = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "image/heic": ".heic", "image/heif": ".heif"}
        extension = allowed.get((photo.content_type or "").lower())
        if not extension:
            raise HTTPException(400, "Upload a JPG, PNG, WebP, or HEIC photo")
        content = await photo.read(10 * 1024 * 1024 + 1)
        if len(content) > 10 * 1024 * 1024:
            raise HTTPException(400, "Photo must be 10 MB or smaller")
        filename = f"{secrets.token_hex(16)}{extension}"
        (UPLOAD_DIR / filename).write_bytes(content)
        saved_image_url = f"/uploads/{filename}"
    with closing(db()) as conn:
        if item_id:
            conn.execute(
                "UPDATE items SET name=?, category=?, unit=?, low_at=?, bought_on=?, expires_on=?, notes=?, ingredients=?, barcode=?, image_url=?, updated_at=? WHERE id=?",
                (name.strip(), category if category in CATEGORIES else "other", unit.strip() or "item", low_at, normalize_date(bought_on), normalize_date(expires_on), notes.strip(), ingredients.strip(), barcode.strip(), saved_image_url, now, item_id),
            )
        else:
            if location_id is None or starting_unopened is None:
                raise HTTPException(400, "Choose a location and enter unopened and open quantities")
            total_quantity = starting_unopened + opened
            location_row = conn.execute("SELECT kind FROM locations WHERE id = ?", (location_id,)).fetchone()
            if not location_row:
                raise HTTPException(400, "Invalid storage location")
            cursor = conn.execute(
                "INSERT INTO items (name, category, location, location_id, quantity, unit, low_at, bought_on, expires_on, notes, ingredients, barcode, image_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name.strip(), category if category in CATEGORIES else "other", location_row["kind"], location_id, total_quantity, unit.strip() or "item", low_at, normalize_date(bought_on), normalize_date(expires_on), notes.strip(), ingredients.strip(), barcode.strip(), saved_image_url, now, now),
            )
            new_item_id = cursor.lastrowid
            conn.execute("INSERT INTO stock_batches (item_id, location_id, quantity, opened, bought_on, expires_on, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (new_item_id, location_id, total_quantity, opened, normalize_date(bought_on), normalize_date(expires_on), now, now))
            refresh_stock_from_batches(conn, new_item_id)
            record_inventory_event(conn, new_item_id, total_quantity, "purchase")
        conn.commit()
    return RedirectResponse(safe_return_path(return_to), status_code=303)


@app.post("/items/{item_id}/quantity")
def change_quantity(item_id: int, delta: float = Form(...), return_to: str = Form("/")):
    with closing(db()) as conn:
        now = datetime.now().isoformat(timespec="seconds")
        previous_total = conn.execute("SELECT COALESCE(SUM(quantity), 0) FROM item_stocks WHERE item_id = ?", (item_id,)).fetchone()[0]
        item = conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not item:
            raise HTTPException(404)
        if delta < 0:
            consume_batches(conn, item_id, min(-delta, previous_total))
        elif delta > 0:
            location_id = item["location_id"] or conn.execute("SELECT id FROM locations ORDER BY id LIMIT 1").fetchone()[0]
            conn.execute("INSERT INTO stock_batches (item_id, location_id, quantity, opened, bought_on, expires_on, created_at, updated_at) VALUES (?, ?, ?, 0, ?, NULL, ?, ?)", (item_id, location_id, delta, date.today().isoformat(), now, now))
        total = refresh_stock_from_batches(conn, item_id)
        record_inventory_event(conn, item_id, total - previous_total, "restock" if total > previous_total else "use")
        maybe_auto_add_shopping(conn, item_id)
        conn.commit()
    destination = return_to if return_to.startswith("/") and not return_to.startswith("//") else "/"
    return RedirectResponse(destination, status_code=303)


@app.get("/items/{item_id}/stock", response_class=HTMLResponse)
def item_stock_page(request: Request, item_id: int, return_to: str = "/"):
    with closing(db()) as conn:
        item = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not item:
            raise HTTPException(404)
        stocks = [
            dict(row)
            for row in conn.execute(
                """SELECT locations.*, COALESCE(item_stocks.quantity, 0) AS quantity,
                          COALESCE(item_stocks.opened, 0) AS opened
                   FROM locations LEFT JOIN item_stocks
                     ON item_stocks.location_id = locations.id AND item_stocks.item_id = ?
                   ORDER BY locations.kind, locations.name""",
                (item_id,),
            )
        ]
        batches = [dict(row) for row in conn.execute(
            """SELECT stock_batches.*, locations.name AS location_name, locations.kind
               FROM stock_batches JOIN locations ON locations.id=stock_batches.location_id
               WHERE stock_batches.item_id=? AND stock_batches.quantity > 0
               ORDER BY CASE WHEN expires_on IS NULL THEN 1 ELSE 0 END, expires_on, created_at""", (item_id,))]
    return render(request, "stock.html", item=dict(item), stocks=stocks, batches=batches, today=date.today().isoformat(), return_to=safe_return_path(return_to))


@app.get("/items/{item_id}/group", response_class=HTMLResponse)
def group_item_page(request: Request, item_id: int):
    with closing(db()) as conn:
        item = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        if not item:
            raise HTTPException(404)
        candidates = [
            dict(row)
            for row in conn.execute(
                """SELECT items.*, COALESCE(SUM(item_stocks.quantity), 0) AS total_quantity,
                          COALESCE(SUM(item_stocks.opened), 0) AS opened_quantity
                   FROM items LEFT JOIN item_stocks ON item_stocks.item_id = items.id
                   WHERE items.id != ? AND (items.group_id IS NULL OR items.group_id = ?)
                   GROUP BY items.id
                   ORDER BY CASE WHEN items.category = ? THEN 0 ELSE 1 END, items.name""",
                (item_id, item["group_id"], item["category"]),
            )
        ]
        current_group = conn.execute("SELECT * FROM product_groups WHERE id = ?", (item["group_id"],)).fetchone() if item["group_id"] else None
    return render(request, "merge.html", item=dict(item), candidates=candidates, current_group=dict(current_group) if current_group else None)


@app.get("/items/{item_id}/merge")
def old_merge_redirect(item_id: int):
    return RedirectResponse(f"/items/{item_id}/group", status_code=303)


@app.post("/items/{item_id}/group")
def group_item(item_id: int, source_id: int = Form(...), group_name: str = Form(...)):
    if item_id == source_id:
        raise HTTPException(400, "An item cannot be combined with itself")
    now = datetime.now().isoformat(timespec="seconds")
    with closing(db()) as conn:
        target = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        source = conn.execute("SELECT * FROM items WHERE id = ?", (source_id,)).fetchone()
        if not target or not source:
            raise HTTPException(404)
        name = group_name.strip()
        if not name:
            raise HTTPException(400, "A group name is required")
        group_id = target["group_id"] or source["group_id"]
        if group_id:
            conn.execute("UPDATE product_groups SET name = ? WHERE id = ?", (name, group_id))
        else:
            group_id = conn.execute("INSERT INTO product_groups (name, created_at) VALUES (?, ?)", (name, now)).lastrowid
        conn.execute("UPDATE items SET group_id=?, updated_at=? WHERE id IN (?, ?)", (group_id, now, item_id, source_id))
        conn.commit()
    return RedirectResponse(f"/groups/{group_id}", status_code=303)


@app.get("/groups/{group_id}", response_class=HTMLResponse)
def group_detail(request: Request, group_id: int):
    with closing(db()) as conn:
        group = conn.execute("SELECT * FROM product_groups WHERE id = ?", (group_id,)).fetchone()
        if not group:
            raise HTTPException(404)
        rows = conn.execute(
            """SELECT items.*, COALESCE(SUM(item_stocks.quantity), 0) AS total_quantity,
                      COALESCE(SUM(item_stocks.opened), 0) AS opened_quantity
               FROM items LEFT JOIN item_stocks ON item_stocks.item_id = items.id
               WHERE items.group_id = ? GROUP BY items.id
               ORDER BY CASE WHEN items.expires_on IS NULL THEN 1 ELSE 0 END, items.expires_on, items.name""",
            (group_id,),
        ).fetchall()
    return render(request, "group.html", group=dict(group), variants=[view_item(row) for row in rows])


@app.post("/groups/{group_id}/rename")
def rename_group(group_id: int, name: str = Form(...)):
    clean_name = name.strip()
    if not clean_name:
        raise HTTPException(400, "Enter a group name")
    with closing(db()) as conn:
        cursor = conn.execute("UPDATE product_groups SET name=? WHERE id=?", (clean_name, group_id))
        conn.commit()
    if not cursor.rowcount:
        raise HTTPException(404)
    return RedirectResponse(f"/groups/{group_id}", status_code=303)


@app.post("/items/{item_id}/ungroup")
def ungroup_item(item_id: int):
    with closing(db()) as conn:
        item = conn.execute("SELECT group_id FROM items WHERE id = ?", (item_id,)).fetchone()
        if not item:
            raise HTTPException(404)
        group_id = item["group_id"]
        conn.execute("UPDATE items SET group_id=NULL WHERE id=?", (item_id,))
        if group_id and conn.execute("SELECT COUNT(*) FROM items WHERE group_id=?", (group_id,)).fetchone()[0] < 2:
            conn.execute("UPDATE items SET group_id=NULL WHERE group_id=?", (group_id,))
            conn.execute("DELETE FROM product_groups WHERE id=?", (group_id,))
        conn.commit()
    return RedirectResponse("/", status_code=303)


@app.get("/inventory", response_class=HTMLResponse)
def inventory_list(request: Request, q: str = "", status: str = "all"):
    params: list[str] = []
    where = ""
    if q.strip():
        where = "WHERE items.name LIKE ? OR product_groups.name LIKE ?"
        params.extend((f"%{q.strip()}%", f"%{q.strip()}%"))
    with closing(db()) as conn:
        rows = conn.execute(
            f"""SELECT items.*, product_groups.name AS group_name,
                       COALESCE(SUM(item_stocks.quantity), 0) AS total_quantity,
                       COALESCE(SUM(item_stocks.opened), 0) AS opened_quantity
                FROM items
                LEFT JOIN product_groups ON product_groups.id=items.group_id
                LEFT JOIN item_stocks ON item_stocks.item_id=items.id
                {where}
                GROUP BY items.id""",
            params,
        ).fetchall()
        stock_rows = conn.execute(
            """SELECT item_stocks.item_id, locations.name, item_stocks.quantity, item_stocks.opened
               FROM item_stocks JOIN locations ON locations.id=item_stocks.location_id
               WHERE item_stocks.quantity > 0 ORDER BY locations.name"""
        ).fetchall()
    stocks: dict[int, list[dict]] = {}
    for row in stock_rows:
        stock = dict(row)
        stock["unopened"] = stock["quantity"] - stock["opened"]
        stocks.setdefault(stock.pop("item_id"), []).append(stock)
    items = [view_item(row) for row in rows]
    state_order = {"out": 0, "expired": 1, "low": 2, "expiring": 3, "good": 4}
    for item in items:
        item["stocks"] = stocks.get(item["id"], [])
    if status == "low":
        items = [item for item in items if item["state"] in {"out", "low"}]
    elif status == "critical":
        items = [item for item in items if item["critical"]]
    elif status == "expiring":
        items = [item for item in items if item["state"] in {"expired", "expiring"}]
    elif status != "all":
        raise HTTPException(400, "Invalid inventory status filter")
    items.sort(key=lambda item: (not item["critical"], state_order[item["state"]], item["unopened_quantity"], item["expires_on"] is None, item["expires_on"] or "", item["name"].lower()))
    return render(request, "list.html", items=items, q=q, status=status, return_to=str(request.url.path) + (f"?{request.url.query}" if request.url.query else ""))


@app.post("/items/{item_id}/stock")
async def update_item_stock(item_id: int, request: Request):
    form = await request.form()
    return_to = safe_return_path(str(form.get("return_to", "/")))
    now = datetime.now().isoformat(timespec="seconds")
    with closing(db()) as conn:
        if not conn.execute("SELECT 1 FROM items WHERE id = ?", (item_id,)).fetchone():
            raise HTTPException(404)
        previous_total = conn.execute("SELECT COALESCE(SUM(quantity), 0) FROM item_stocks WHERE item_id = ?", (item_id,)).fetchone()[0]
        location_ids = [row[0] for row in conn.execute("SELECT id FROM locations")]
        for location_id in location_ids:
            try:
                unopened = float(form.get(f"unopened_{location_id}", 0))
                opened = float(form.get(f"opened_{location_id}", 0))
            except (TypeError, ValueError) as exc:
                raise HTTPException(400, "Enter valid stock quantities") from exc
            if unopened < 0 or opened < 0:
                raise HTTPException(400, "Unopened and open quantities cannot be negative")
            conn.execute(
                """INSERT INTO item_stocks (item_id, location_id, quantity, opened, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(item_id, location_id) DO UPDATE SET quantity=excluded.quantity, opened=excluded.opened, updated_at=excluded.updated_at""",
                (item_id, location_id, unopened + opened, opened, now),
            )
        total = conn.execute("SELECT COALESCE(SUM(quantity), 0) FROM item_stocks WHERE item_id = ?", (item_id,)).fetchone()[0]
        conn.execute("UPDATE items SET quantity=?, updated_at=? WHERE id=?", (total, now, item_id))
        record_inventory_event(conn, item_id, total - previous_total, "restock" if total > previous_total else "use")
        maybe_auto_add_shopping(conn, item_id)
        conn.commit()
    return RedirectResponse(return_to, status_code=303)


@app.post("/items/{item_id}/batches")
def add_stock_batch(item_id: int, location_id: int = Form(...), quantity: float = Form(...), opened: float = Form(0), bought_on: str | None = Form(None), expires_on: str | None = Form(None), return_to: str = Form("/")):
    if quantity <= 0 or opened < 0 or opened > quantity:
        raise HTTPException(400, "Enter a positive quantity and a valid opened amount")
    now = datetime.now().isoformat(timespec="seconds")
    with closing(db()) as conn:
        if not conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone() or not conn.execute("SELECT 1 FROM locations WHERE id=?", (location_id,)).fetchone():
            raise HTTPException(404)
        before = conn.execute("SELECT COALESCE(SUM(quantity),0) FROM item_stocks WHERE item_id=?", (item_id,)).fetchone()[0]
        conn.execute("INSERT INTO stock_batches (item_id, location_id, quantity, opened, bought_on, expires_on, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (item_id, location_id, quantity, opened, normalize_date(bought_on), normalize_date(expires_on), now, now))
        total = refresh_stock_from_batches(conn, item_id)
        record_inventory_event(conn, item_id, total - before, "purchase")
        conn.commit()
    return RedirectResponse(f"/items/{item_id}/stock?return_to={urllib.parse.quote(safe_return_path(return_to), safe='/')}", status_code=303)


@app.post("/items/{item_id}/batches/save")
async def save_stock_batches(item_id: int, request: Request):
    form = await request.form()
    return_to = safe_return_path(str(form.get("return_to", "/")))
    now = datetime.now().isoformat(timespec="seconds")
    with closing(db()) as conn:
        before = conn.execute("SELECT COALESCE(SUM(quantity),0) FROM item_stocks WHERE item_id=?", (item_id,)).fetchone()[0]
        batch_ids = [row[0] for row in conn.execute("SELECT id FROM stock_batches WHERE item_id=?", (item_id,))]
        for batch_id in batch_ids:
            try:
                location_id = int(form.get(f"location_{batch_id}"))
                quantity = float(form.get(f"quantity_{batch_id}"))
                opened = float(form.get(f"opened_{batch_id}"))
            except (TypeError, ValueError) as exc:
                raise HTTPException(400, "Enter valid batch values") from exc
            if quantity < 0 or opened < 0 or opened > quantity:
                raise HTTPException(400, "Opened stock cannot exceed the batch total")
            conn.execute("UPDATE stock_batches SET location_id=?, quantity=?, opened=?, bought_on=?, expires_on=?, updated_at=? WHERE id=? AND item_id=?", (location_id, quantity, opened, normalize_date(str(form.get(f"bought_{batch_id}", ""))), normalize_date(str(form.get(f"expires_{batch_id}", ""))), now, batch_id, item_id))
        total = refresh_stock_from_batches(conn, item_id)
        record_inventory_event(conn, item_id, total - before, "restock" if total > before else "use")
        maybe_auto_add_shopping(conn, item_id)
        conn.commit()
    return RedirectResponse(f"/items/{item_id}/stock?return_to={urllib.parse.quote(return_to, safe='/')}", status_code=303)


@app.post("/items/{item_id}/batches/{batch_id}")
def update_stock_batch(item_id: int, batch_id: int, quantity: float = Form(...), opened: float = Form(0), location_id: int = Form(...), bought_on: str | None = Form(None), expires_on: str | None = Form(None), return_to: str = Form("/")):
    if quantity < 0 or opened < 0 or opened > quantity:
        raise HTTPException(400, "Enter valid batch quantities")
    now = datetime.now().isoformat(timespec="seconds")
    with closing(db()) as conn:
        before = conn.execute("SELECT COALESCE(SUM(quantity),0) FROM item_stocks WHERE item_id=?", (item_id,)).fetchone()[0]
        cursor = conn.execute("UPDATE stock_batches SET location_id=?, quantity=?, opened=?, bought_on=?, expires_on=?, updated_at=? WHERE id=? AND item_id=?", (location_id, quantity, opened, normalize_date(bought_on), normalize_date(expires_on), now, batch_id, item_id))
        if not cursor.rowcount:
            raise HTTPException(404)
        total = refresh_stock_from_batches(conn, item_id)
        record_inventory_event(conn, item_id, total - before, "restock" if total > before else "use")
        maybe_auto_add_shopping(conn, item_id)
        conn.commit()
    return RedirectResponse(f"/items/{item_id}/stock?return_to={urllib.parse.quote(safe_return_path(return_to), safe='/')}", status_code=303)


@app.post("/items/{item_id}/delete")
def delete_item(item_id: int, return_to: str = Form("/")):
    with closing(db()) as conn:
        conn.execute("DELETE FROM item_stocks WHERE item_id = ?", (item_id,))
        conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
        conn.commit()
    return RedirectResponse(safe_return_path(return_to), status_code=303)


@app.get("/locations", response_class=HTMLResponse)
def locations_page(request: Request):
    with closing(db()) as conn:
        locations = [
            dict(row)
            for row in conn.execute(
                """SELECT locations.*, COUNT(DISTINCT CASE WHEN item_stocks.quantity > 0 THEN item_stocks.item_id END) AS item_count
                   FROM locations LEFT JOIN item_stocks ON item_stocks.location_id = locations.id
                   GROUP BY locations.id ORDER BY locations.kind, locations.name"""
            )
        ]
    return render(request, "locations.html", managed_locations=locations)


@app.post("/locations")
def add_location(name: str = Form(...), kind: str = Form("pantry")):
    if not name.strip() or kind not in {"pantry", "fridge", "freezer"}:
        raise HTTPException(400, "A valid name and location type are required")
    try:
        with closing(db()) as conn:
            conn.execute(
                "INSERT INTO locations (name, kind, created_at) VALUES (?, ?, ?)",
                (name.strip(), kind, datetime.now().isoformat(timespec="seconds")),
            )
            conn.commit()
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "A location with that name already exists") from exc
    return RedirectResponse("/locations", status_code=303)


@app.post("/locations/{location_id}/delete")
def delete_location(location_id: int):
    with closing(db()) as conn:
        count = conn.execute("SELECT COUNT(*) FROM item_stocks WHERE location_id = ? AND quantity > 0", (location_id,)).fetchone()[0]
        if count:
            raise HTTPException(409, "Move the items in this location before deleting it")
        conn.execute("DELETE FROM item_stocks WHERE location_id = ?", (location_id,))
        conn.execute("UPDATE items SET location_id = NULL WHERE location_id = ?", (location_id,))
        conn.execute("DELETE FROM locations WHERE id = ?", (location_id,))
        conn.commit()
    return RedirectResponse("/locations", status_code=303)


@app.get("/manage", response_class=HTMLResponse)
def manage_page(request: Request, restored: str = ""):
    with closing(db()) as conn:
        managed_categories = [dict(row) for row in conn.execute(
            """SELECT categories.*, COUNT(items.id) AS item_count
               FROM categories LEFT JOIN items ON items.category = categories.key
               GROUP BY categories.key ORDER BY categories.label"""
        )]
        shop_settings = shopping_settings(conn)
    return render(request, "manage.html", managed_categories=managed_categories, restored=restored, api_enabled=bool(API_KEY), shop_settings=shop_settings, llm_enabled=bool(LLM_URL and LLM_MODEL), llm_model=LLM_MODEL)


@app.get("/dinner", response_class=HTMLResponse)
def dinner_page(request: Request):
    with closing(db()) as conn:
        inventory_count = len(dinner_inventory(conn))
    return render(request, "dinner.html", inventory_count=inventory_count, meals=[], error="", llm_enabled=bool(LLM_URL and LLM_MODEL))


@app.get("/dinner/generate")
def dinner_generate_get():
    return RedirectResponse("/dinner", status_code=303)


@app.post("/dinner/generate", response_class=HTMLResponse)
def generate_dinner(request: Request):
    with closing(db()) as conn:
        inventory = dinner_inventory(conn)
    if not inventory:
        return render(request, "dinner.html", inventory_count=0, meals=[], error="Add some in-stock items before asking for dinner ideas.", llm_enabled=bool(LLM_URL and LLM_MODEL))
    try:
        meals = ask_dinner_picks(inventory)
        error = ""
    except RuntimeError as exc:
        meals, error = [], str(exc)
    return render(request, "dinner.html", inventory_count=len(inventory), meals=meals, error=error, llm_enabled=bool(LLM_URL and LLM_MODEL))


@app.post("/dinner/recipe", response_class=HTMLResponse)
def generate_recipe(request: Request, meal_name: str = Form(...)):
    meal_name = meal_name.strip()[:160]
    if not meal_name:
        return RedirectResponse("/dinner", status_code=303)
    with closing(db()) as conn:
        inventory = dinner_inventory(conn)
    try:
        recipe = ask_dinner_recipe(inventory, meal_name)
        error = ""
    except RuntimeError as exc:
        recipe, error = None, str(exc)
    return render(request, "recipe.html", recipe=recipe, meal_name=meal_name, error=error)


@app.get("/shopping", response_class=HTMLResponse)
def shopping_page(request: Request):
    with closing(db()) as conn:
        settings = shopping_settings(conn)
        rows = conn.execute(
            """SELECT items.*, shopping_list.reason, shopping_list.automatic, shopping_list.added_at,
                      COALESCE(SUM(item_stocks.quantity),0) AS total_quantity,
                      COALESCE(SUM(item_stocks.opened),0) AS opened_quantity
               FROM shopping_list JOIN items ON items.id=shopping_list.item_id
               LEFT JOIN item_stocks ON item_stocks.item_id=items.id
               GROUP BY items.id ORDER BY shopping_list.added_at DESC"""
        ).fetchall()
        listed = []
        listed_ids = set()
        for row in rows:
            item = view_item(row)
            item.update(reason=row["reason"], automatic=bool(row["automatic"]), added_at=row["added_at"])
            listed.append(item)
            listed_ids.add(item["id"])
        inventory_rows = conn.execute(
            """SELECT items.*, COALESCE(SUM(item_stocks.quantity),0) AS total_quantity,
                      COALESCE(SUM(item_stocks.opened),0) AS opened_quantity
               FROM items LEFT JOIN item_stocks ON item_stocks.item_id=items.id GROUP BY items.id"""
        ).fetchall()
        recommendations = []
        learning = []
        for row in inventory_rows:
            item = view_item(row)
            analysis = shopping_analysis(conn, item, settings)
            item.update(analysis)
            if item["id"] not in listed_ids and analysis["should_buy"]:
                recommendations.append(item)
            elif analysis["confidence"] == "learning":
                learning.append(item)
    recommendations.sort(key=lambda item: (item["unopened_quantity"], item["name"].lower()))
    return render(request, "shopping.html", listed=listed, recommendations=recommendations, learning_count=len(learning), shop_settings=settings)


@app.post("/shopping/{item_id}/add")
def add_to_shopping(item_id: int, return_to: str = Form("/shopping")):
    with closing(db()) as conn:
        row = conn.execute("SELECT name FROM items WHERE id=?", (item_id,)).fetchone()
        if not row:
            raise HTTPException(404)
        conn.execute(
            """INSERT INTO shopping_list (item_id, reason, automatic, added_at) VALUES (?, 'Added manually', 0, ?)
               ON CONFLICT(item_id) DO UPDATE SET reason='Added manually', automatic=0""",
            (item_id, datetime.now().isoformat(timespec="seconds")),
        )
        conn.commit()
    return RedirectResponse(safe_return_path(return_to, "/shopping"), status_code=303)


@app.post("/shopping/{item_id}/remove")
def remove_from_shopping(item_id: int):
    with closing(db()) as conn:
        conn.execute("DELETE FROM shopping_list WHERE item_id=?", (item_id,))
        conn.commit()
    return RedirectResponse("/shopping", status_code=303)


@app.post("/shopping/{item_id}/buy")
def buy_shopping_item(item_id: int, quantity: float = Form(...), location_id: int = Form(...), bought_on: str | None = Form(None), expires_on: str | None = Form(None)):
    if quantity <= 0:
        raise HTTPException(400, "Purchased quantity must be greater than zero")
    with closing(db()) as conn:
        item = conn.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone()
        location = conn.execute("SELECT id FROM locations WHERE id=?", (location_id,)).fetchone()
        if not item or not location:
            raise HTTPException(404, "Item or location not found")
        now = datetime.now().isoformat(timespec="seconds")
        conn.execute("INSERT INTO stock_batches (item_id, location_id, quantity, opened, bought_on, expires_on, created_at, updated_at) VALUES (?, ?, ?, 0, ?, ?, ?, ?)", (item_id, location_id, quantity, normalize_date(bought_on) or date.today().isoformat(), normalize_date(expires_on), now, now))
        refresh_stock_from_batches(conn, item_id)
        conn.execute("UPDATE items SET location_id=COALESCE(location_id, ?) WHERE id=?", (location_id, item_id))
        record_inventory_event(conn, item_id, quantity, "purchase")
        conn.execute("DELETE FROM shopping_list WHERE item_id=?", (item_id,))
        conn.commit()
    return RedirectResponse("/shopping?bought=1", status_code=303)


@app.post("/shopping/settings")
def update_shopping_settings(mode: str = Form(...), analysis_days: int = Form(7)):
    if mode not in {"analysis", "assistant"} or analysis_days not in {7, 14, 30, 60}:
        raise HTTPException(400, "Choose a valid shopping mode and analysis window")
    with closing(db()) as conn:
        conn.execute("INSERT INTO app_settings (key,value) VALUES ('shopping_mode',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (mode,))
        conn.execute("INSERT INTO app_settings (key,value) VALUES ('analysis_days',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(analysis_days),))
        if mode == "assistant":
            item_ids = [row[0] for row in conn.execute("SELECT id FROM items")]
            for item_id in item_ids:
                maybe_auto_add_shopping(conn, item_id)
        conn.commit()
    return RedirectResponse("/shopping", status_code=303)


@app.post("/categories")
def add_category(label: str = Form(...), icon: str = Form("•")):
    clean_label = label.strip()
    key = re.sub(r"[^a-z0-9]+", "-", clean_label.lower()).strip("-")
    if not clean_label or not key:
        raise HTTPException(400, "Enter a category name")
    try:
        with closing(db()) as conn:
            conn.execute("INSERT INTO categories (key, label, icon, custom) VALUES (?, ?, ?, 1)", (key, clean_label, icon.strip() or "•"))
            conn.commit()
            CATEGORIES[key] = (clean_label, icon.strip() or "•")
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "That category already exists") from exc
    return RedirectResponse("/manage", status_code=303)


@app.post("/categories/{key}/delete")
def delete_category(key: str):
    with closing(db()) as conn:
        category = conn.execute("SELECT custom FROM categories WHERE key=?", (key,)).fetchone()
        if not category or not category["custom"]:
            raise HTTPException(400, "Built-in categories cannot be removed")
        if conn.execute("SELECT COUNT(*) FROM items WHERE category=?", (key,)).fetchone()[0]:
            raise HTTPException(409, "Move items out of this category before removing it")
        conn.execute("DELETE FROM categories WHERE key=?", (key,))
        conn.commit()
        CATEGORIES.pop(key, None)
    return RedirectResponse("/manage", status_code=303)


@app.post("/categories/{key}")
def edit_category(key: str, label: str = Form(...), icon: str = Form("•")):
    clean_label = label.strip()
    clean_icon = icon.strip() or "•"
    if not clean_label:
        raise HTTPException(400, "Enter a category name")
    try:
        with closing(db()) as conn:
            cursor = conn.execute("UPDATE categories SET label=?, icon=? WHERE key=?", (clean_label, clean_icon, key))
            if not cursor.rowcount:
                raise HTTPException(404, "Category not found")
            conn.commit()
            CATEGORIES[key] = (clean_label, clean_icon)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(409, "That category name already exists") from exc
    return RedirectResponse("/manage", status_code=303)


@app.get("/backup")
def download_backup():
    backup_path = DATA_DIR / f"backup-{secrets.token_hex(8)}.db"
    try:
        with closing(db()) as source, closing(sqlite3.connect(backup_path)) as destination:
            source.backup(destination)
        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.write(backup_path, "pantry.db")
            for photo in UPLOAD_DIR.iterdir():
                if photo.is_file():
                    archive.write(photo, f"uploads/{photo.name}")
        content = bundle.getvalue()
    finally:
        backup_path.unlink(missing_ok=True)
    filename = f"shelf-life-{date.today().isoformat()}.zip"
    return Response(content, media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.post("/backup/restore")
async def restore_backup(backup: UploadFile = File(...)):
    content = await backup.read(100 * 1024 * 1024 + 1)
    if len(content) > 100 * 1024 * 1024:
        raise HTTPException(400, "Backup must be 100 MB or smaller")
    candidate = DATA_DIR / f"restore-{secrets.token_hex(8)}.db"
    safety_copy = DATA_DIR / "pantry-before-restore.db"
    restored_photos: list[tuple[str, bytes]] = []
    if content.startswith(b"PK"):
        try:
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                database_content = archive.read("pantry.db")
                for entry in archive.infolist():
                    if entry.filename.startswith("uploads/") and not entry.is_dir():
                        filename = Path(entry.filename).name
                        if filename and entry.file_size <= 10 * 1024 * 1024:
                            restored_photos.append((filename, archive.read(entry)))
        except (zipfile.BadZipFile, KeyError) as exc:
            raise HTTPException(400, "This is not a valid Shelf Life backup") from exc
    else:
        database_content = content
    candidate.write_bytes(database_content)
    try:
        with closing(sqlite3.connect(candidate)) as conn:
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise HTTPException(400, "The uploaded database is damaged")
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if not {"items", "locations", "item_stocks"}.issubset(tables):
                raise HTTPException(400, "This is not a Shelf Life backup")
        shutil.copy2(DB_PATH, safety_copy)
        candidate.replace(DB_PATH)
        for filename, photo_content in restored_photos:
            (UPLOAD_DIR / filename).write_bytes(photo_content)
        init_db()
    finally:
        candidate.unlink(missing_ok=True)
    return RedirectResponse("/manage?restored=1", status_code=303)


@app.get("/scan", response_class=HTMLResponse)
def scan_page(request: Request):
    return render(request, "scan.html")


def infer_category(tags: list[str]) -> str:
    text = " ".join(tags).lower()
    rules = {
        "dairy": ("dair", "milk", "cheese", "yogurt"),
        "meat": ("meat", "seafood", "fish", "poultry"),
        "frozen": ("frozen", "ice-cream"),
        "bakery": ("bread", "bakery", "pastr"),
        "drinks": ("beverage", "drink", "juice", "soda", "water"),
        "produce": ("fruit", "vegetable", "produce"),
    }
    return next((category for category, words in rules.items() if any(word in text for word in words)), "pantry")


@app.get("/api/barcode/{code}")
def barcode_lookup(code: str):
    digits = "".join(character for character in code if character.isdigit())
    if not 6 <= len(digits) <= 14:
        raise HTTPException(400, "Enter a valid barcode")
    with closing(db()) as conn:
        pantry_row = conn.execute(
            """SELECT items.*,
                      COALESCE(SUM(item_stocks.quantity), 0) AS total_quantity,
                      COALESCE(SUM(item_stocks.opened), 0) AS opened_quantity,
                      COUNT(CASE WHEN item_stocks.quantity > 0 THEN 1 END) AS active_locations,
                      MIN(CASE WHEN item_stocks.quantity > 0 THEN locations.name END) AS location_name
               FROM items
               LEFT JOIN item_stocks ON item_stocks.item_id = items.id
               LEFT JOIN locations ON locations.id = item_stocks.location_id
               WHERE items.barcode = ?
               GROUP BY items.id
               ORDER BY items.updated_at DESC LIMIT 1""",
            (digits,),
        ).fetchone()
    if pantry_row:
        pantry_item = view_item(pantry_row)
        return {
            "found": True,
            "inventory_match": True,
            "barcode": digits,
            "item_id": pantry_item["id"],
            "name": pantry_item["name"],
            "image_url": pantry_item["image_url"] or "",
            "unopened": pantry_item["unopened_quantity"],
            "opened": pantry_item["opened_quantity"],
            "unit": pantry_item["unit"],
        }
    fields = "code,product_name,brands,quantity,image_front_url,categories_tags,ingredients_text,ingredients_text_en"
    url = f"https://world.openfoodfacts.org/api/v3/product/{digits}?fields={urllib.parse.quote(fields)}"
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ShelfLife/1.0 (https://github.com/xyciasav/pantry_app)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            payload = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return JSONResponse({"found": False, "barcode": digits, "message": "Product lookup is temporarily unavailable"}, status_code=503)
    product = payload.get("product") or {}
    name = product.get("product_name") or product.get("product_name_en")
    if not name:
        return {"found": False, "barcode": digits, "message": "Barcode scanned. Add the product name to save it."}
    brand = product.get("brands", "").strip()
    display_name = f"{brand} {name}".strip() if brand and brand.lower() not in name.lower() else name
    quantity = product.get("quantity", "")
    return {
        "found": True,
        "barcode": digits,
        "name": display_name,
        "category": infer_category(product.get("categories_tags") or []),
        "unit": quantity or "item",
        "image_url": product.get("image_front_url") or "",
        "ingredients": product.get("ingredients_text") or product.get("ingredients_text_en") or "",
    }


@app.get("/api/inventory", dependencies=[Depends(require_api_key)])
def inventory_api():
    with closing(db()) as conn:
        rows = conn.execute(
            """SELECT items.*, product_groups.name AS group_name,
                      COALESCE(SUM(item_stocks.quantity), 0) AS total_quantity,
                      COALESCE(SUM(item_stocks.opened), 0) AS opened_quantity
               FROM items
               LEFT JOIN product_groups ON product_groups.id = items.group_id
               LEFT JOIN item_stocks ON item_stocks.item_id = items.id
               GROUP BY items.id ORDER BY items.name"""
        ).fetchall()
        stock_rows = conn.execute(
            """SELECT item_stocks.item_id, locations.name, locations.kind,
                      item_stocks.quantity, item_stocks.opened
               FROM item_stocks JOIN locations ON locations.id=item_stocks.location_id
               WHERE item_stocks.quantity > 0 ORDER BY locations.name"""
        ).fetchall()
        batch_rows = conn.execute(
            """SELECT stock_batches.item_id, stock_batches.id, locations.name AS location,
                      stock_batches.quantity, stock_batches.opened, stock_batches.bought_on, stock_batches.expires_on
               FROM stock_batches JOIN locations ON locations.id=stock_batches.location_id
               WHERE stock_batches.quantity > 0
               ORDER BY stock_batches.item_id, CASE WHEN stock_batches.expires_on IS NULL THEN 1 ELSE 0 END, stock_batches.expires_on"""
        ).fetchall()
    stocks: dict[int, list[dict]] = {}
    for row in stock_rows:
        stock = dict(row)
        stock["unopened"] = stock["quantity"] - stock["opened"]
        stocks.setdefault(stock.pop("item_id"), []).append(stock)
    batches: dict[int, list[dict]] = {}
    for row in batch_rows:
        batch = dict(row)
        batch["unopened"] = batch["quantity"] - batch["opened"]
        batches.setdefault(batch.pop("item_id"), []).append(batch)
    inventory = []
    for row in rows:
        item = view_item(row)
        inventory.append({
            "id": item["id"], "name": item["name"], "group": item.get("group_name"),
            "category": item["category_label"], "unopened": item["unopened_quantity"],
            "open": item["opened_quantity"], "total": item["quantity"], "unit": item["unit"],
            "bought_on": item["bought_on"], "expires_on": item["expires_on"], "state": item["state"],
            "essential": item["essential"], "opened_low": item["opened_low"], "critical": item["critical"],
            "barcode": item.get("barcode"), "notes": item["notes"], "ingredients": item.get("ingredients", ""), "locations": stocks.get(item["id"], []), "batches": batches.get(item["id"], []),
        })
    return {"version": APP_VERSION, "generated_at": datetime.now().isoformat(timespec="seconds"), "items": inventory}
