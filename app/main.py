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
APP_VERSION = os.getenv("APP_VERSION", "1.6.2")
AUTH_USERNAME = os.getenv("PANTRY_USERNAME", "")
AUTH_PASSWORD = os.getenv("PANTRY_PASSWORD", "")
AUTH_SECRET = os.getenv("PANTRY_SECRET_KEY", "")
API_KEY = os.getenv("PANTRY_API_KEY", "")
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
    public = path in {"/login", "/health", "/docs", "/openapi.json"} or path.startswith("/static/")
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
        for key, (label, icon) in DEFAULT_CATEGORIES.items():
            conn.execute("INSERT OR IGNORE INTO categories (key, label, icon, custom) VALUES (?, ?, ?, 0)", (key, label, icon))
        columns = {row[1] for row in conn.execute("PRAGMA table_info(items)")}
        for name, definition in {
            "location_id": "INTEGER REFERENCES locations(id)",
            "barcode": "TEXT",
            "image_url": "TEXT",
            "group_id": "INTEGER REFERENCES product_groups(id) ON DELETE SET NULL",
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
    if item["quantity"] <= 0:
        state = "out"
    elif item["unopened_quantity"] <= item["low_at"]:
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
    )
    item["image_url"] = item.get("image_url") or item_art_url(item["name"], item["category"])
    return item


def render(request: Request, name: str, **context) -> HTMLResponse:
    template = templates.get_template(name)
    return HTMLResponse(template.render(request=request, categories=CATEGORIES, locations=get_locations(), app_version=APP_VERSION, **context))


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
    items = sorted(visible_items, key=lambda item: (item["expires_on"] is None, item["expires_on"] or "", item["name"].lower()))
    counts = {
        "all": len(items),
        "attention": sum(i["state"] in {"out", "low", "expired", "expiring"} for i in items),
        "expiring": sum(i["state"] in {"expired", "expiring"} for i in items),
        "low": sum(i["state"] in {"out", "low"} for i in items),
    }
    return render(request, "index.html", items=items, counts=counts, filters={"location": location, "category": category, "q": q})


@app.get("/items/new", response_class=HTMLResponse)
def new_item(request: Request, name: str = "", barcode: str = "", image_url: str = "", category: str = "other", unit: str = "item"):
    item = {"name": name, "barcode": barcode, "image_url": image_url, "category": category, "unit": unit} if any((name, barcode, image_url)) else None
    return render(request, "form.html", item=item, is_new=True, today=date.today().isoformat())


@app.get("/items/{item_id}/edit", response_class=HTMLResponse)
def edit_item(request: Request, item_id: int):
    with closing(db()) as conn:
        row = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if not row:
        raise HTTPException(404)
    return render(request, "form.html", item=dict(row), is_new=False, today=date.today().isoformat())


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
    barcode: str = Form(""),
    image_url: str = Form(""),
    photo: UploadFile | None = File(None),
):
    starting_unopened = unopened if unopened is not None else quantity
    if not name.strip() or low_at < 0 or (starting_unopened is not None and starting_unopened < 0) or opened < 0:
        raise HTTPException(400, "Name is required and quantities cannot be negative")
    now = datetime.now().isoformat(timespec="seconds")
    saved_image_url = image_url.strip()
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
                "UPDATE items SET name=?, category=?, unit=?, low_at=?, bought_on=?, expires_on=?, notes=?, barcode=?, image_url=?, updated_at=? WHERE id=?",
                (name.strip(), category if category in CATEGORIES else "other", unit.strip() or "item", low_at, normalize_date(bought_on), normalize_date(expires_on), notes.strip(), barcode.strip(), saved_image_url, now, item_id),
            )
        else:
            if location_id is None or starting_unopened is None:
                raise HTTPException(400, "Choose a location and enter unopened and open quantities")
            total_quantity = starting_unopened + opened
            location_row = conn.execute("SELECT kind FROM locations WHERE id = ?", (location_id,)).fetchone()
            if not location_row:
                raise HTTPException(400, "Invalid storage location")
            cursor = conn.execute(
                "INSERT INTO items (name, category, location, location_id, quantity, unit, low_at, bought_on, expires_on, notes, barcode, image_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (name.strip(), category if category in CATEGORIES else "other", location_row["kind"], location_id, total_quantity, unit.strip() or "item", low_at, normalize_date(bought_on), normalize_date(expires_on), notes.strip(), barcode.strip(), saved_image_url, now, now),
            )
            conn.execute("INSERT INTO item_stocks (item_id, location_id, quantity, opened, updated_at) VALUES (?, ?, ?, ?, ?)", (cursor.lastrowid, location_id, total_quantity, opened, now))
        conn.commit()
    return RedirectResponse("/", status_code=303)


@app.post("/items/{item_id}/quantity")
def change_quantity(item_id: int, delta: float = Form(...)):
    with closing(db()) as conn:
        now = datetime.now().isoformat(timespec="seconds")
        stock = conn.execute(
            """SELECT * FROM item_stocks WHERE item_id = ?
               ORDER BY CASE WHEN quantity - opened > 0 THEN 0 ELSE 1 END, CASE WHEN opened > 0 THEN 0 ELSE 1 END, id LIMIT 1""",
            (item_id,),
        ).fetchone()
        if not stock:
            item = conn.execute("SELECT location_id FROM items WHERE id = ?", (item_id,)).fetchone()
            if not item or not item["location_id"]:
                raise HTTPException(404)
            conn.execute("INSERT INTO item_stocks (item_id, location_id, quantity, opened, updated_at) VALUES (?, ?, 0, 0, ?)", (item_id, item["location_id"], now))
            stock = conn.execute("SELECT * FROM item_stocks WHERE item_id = ? LIMIT 1", (item_id,)).fetchone()
        unopened = stock["quantity"] - stock["opened"]
        if delta < 0 and unopened <= 0 and stock["opened"] > 0:
            new_quantity = max(0, stock["quantity"] + delta)
            new_opened = max(0, stock["opened"] + delta)
        else:
            new_quantity = max(stock["opened"], stock["quantity"] + delta)
            new_opened = stock["opened"]
        new_opened = min(new_opened, new_quantity)
        cursor = conn.execute("UPDATE item_stocks SET quantity=?, opened=?, updated_at=? WHERE id=?", (new_quantity, new_opened, now, stock["id"]))
        total = conn.execute("SELECT COALESCE(SUM(quantity), 0) FROM item_stocks WHERE item_id = ?", (item_id,)).fetchone()[0]
        conn.execute("UPDATE items SET quantity=?, updated_at=? WHERE id=?", (total, now, item_id))
        conn.commit()
    if not cursor.rowcount:
        raise HTTPException(404)
    return RedirectResponse("/", status_code=303)


@app.get("/items/{item_id}/stock", response_class=HTMLResponse)
def item_stock_page(request: Request, item_id: int):
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
    return render(request, "stock.html", item=dict(item), stocks=stocks)


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
def inventory_list(request: Request, q: str = ""):
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
    items.sort(key=lambda item: (state_order[item["state"]], item["unopened_quantity"], item["expires_on"] is None, item["expires_on"] or "", item["name"].lower()))
    return render(request, "list.html", items=items, q=q)


@app.post("/items/{item_id}/stock")
async def update_item_stock(item_id: int, request: Request):
    form = await request.form()
    now = datetime.now().isoformat(timespec="seconds")
    with closing(db()) as conn:
        if not conn.execute("SELECT 1 FROM items WHERE id = ?", (item_id,)).fetchone():
            raise HTTPException(404)
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
        conn.commit()
    return RedirectResponse(f"/items/{item_id}/stock", status_code=303)


@app.post("/items/{item_id}/delete")
def delete_item(item_id: int):
    with closing(db()) as conn:
        conn.execute("DELETE FROM item_stocks WHERE item_id = ?", (item_id,))
        conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
        conn.commit()
    return RedirectResponse("/", status_code=303)


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
    return render(request, "manage.html", managed_categories=managed_categories, restored=restored, api_enabled=bool(API_KEY))


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
    fields = "code,product_name,brands,quantity,image_front_url,categories_tags"
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
    stocks: dict[int, list[dict]] = {}
    for row in stock_rows:
        stock = dict(row)
        stock["unopened"] = stock["quantity"] - stock["opened"]
        stocks.setdefault(stock.pop("item_id"), []).append(stock)
    inventory = []
    for row in rows:
        item = view_item(row)
        inventory.append({
            "id": item["id"], "name": item["name"], "group": item.get("group_name"),
            "category": item["category_label"], "unopened": item["unopened_quantity"],
            "open": item["opened_quantity"], "total": item["quantity"], "unit": item["unit"],
            "bought_on": item["bought_on"], "expires_on": item["expires_on"], "state": item["state"],
            "barcode": item.get("barcode"), "notes": item["notes"], "locations": stocks.get(item["id"], []),
        })
    return {"version": APP_VERSION, "generated_at": datetime.now().isoformat(timespec="seconds"), "items": inventory}
