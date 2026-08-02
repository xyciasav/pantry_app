from __future__ import annotations

import os
import sqlite3
import json
import re
import base64
import binascii
import hashlib
import hmac
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing
from datetime import date, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("PANTRY_DATA_DIR", BASE_DIR.parent / "data"))
DB_PATH = DATA_DIR / "pantry.db"
APP_VERSION = os.getenv("APP_VERSION", "1.4.2")
AUTH_USERNAME = os.getenv("PANTRY_USERNAME", "")
AUTH_PASSWORD = os.getenv("PANTRY_PASSWORD", "")
AUTH_SECRET = os.getenv("PANTRY_SECRET_KEY", "")
COOKIE_SECURE_MODE = os.getenv("PANTRY_COOKIE_SECURE", "auto").strip().lower()
SESSION_SECONDS = int(float(os.getenv("PANTRY_SESSION_HOURS", "12")) * 3600)
COOKIE_NAME = "pantry_session"
LEGACY_COOKIE_NAME = "__Host-pantry_session"
LOGIN_ATTEMPTS: dict[str, list[float]] = {}

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

app = FastAPI(title="Shelf Life")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
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


@app.middleware("http")
async def require_login(request: Request, call_next):
    path = request.url.path
    public = path in {"/login", "/health"} or path.startswith("/static/")
    session_token = request.cookies.get(COOKIE_NAME) or request.cookies.get(LEGACY_COOKIE_NAME)
    if not public and not valid_session_token(session_token):
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
        columns = {row[1] for row in conn.execute("PRAGMA table_info(items)")}
        for name, definition in {
            "location_id": "INTEGER REFERENCES locations(id)",
            "barcode": "TEXT",
            "image_url": "TEXT",
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
        clauses.append("items.name LIKE ?")
        params.append(f"%{q.strip()}%")
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
    breakdowns: dict[int, list[dict]] = {}
    for stock in stock_rows:
        stock_view = dict(stock)
        stock_view["unopened"] = max(0, stock_view["quantity"] - stock_view["opened"])
        breakdowns.setdefault(stock["item_id"], []).append(stock_view)
    items = [view_item(row) for row in rows]
    for item in items:
        item["stocks"] = breakdowns.get(item["id"], [])
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
def save_item(
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
):
    starting_unopened = unopened if unopened is not None else quantity
    if not name.strip() or low_at < 0 or (starting_unopened is not None and starting_unopened < 0) or opened < 0:
        raise HTTPException(400, "Name is required and quantities cannot be negative")
    now = datetime.now().isoformat(timespec="seconds")
    with closing(db()) as conn:
        if item_id:
            conn.execute(
                "UPDATE items SET name=?, category=?, unit=?, low_at=?, bought_on=?, expires_on=?, notes=?, barcode=?, image_url=?, updated_at=? WHERE id=?",
                (name.strip(), category if category in CATEGORIES else "other", unit.strip() or "item", low_at, normalize_date(bought_on), normalize_date(expires_on), notes.strip(), barcode.strip(), image_url.strip(), now, item_id),
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
                (name.strip(), category if category in CATEGORIES else "other", location_row["kind"], location_id, total_quantity, unit.strip() or "item", low_at, normalize_date(bought_on), normalize_date(expires_on), notes.strip(), barcode.strip(), image_url.strip(), now, now),
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


@app.get("/items/{item_id}/merge", response_class=HTMLResponse)
def merge_item_page(request: Request, item_id: int):
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
                   WHERE items.id != ?
                   GROUP BY items.id
                   ORDER BY CASE WHEN items.category = ? THEN 0 ELSE 1 END, items.name""",
                (item_id, item["category"]),
            )
        ]
    return render(request, "merge.html", item=dict(item), candidates=candidates)


@app.post("/items/{item_id}/merge")
def merge_item(item_id: int, source_id: int = Form(...)):
    if item_id == source_id:
        raise HTTPException(400, "An item cannot be combined with itself")
    now = datetime.now().isoformat(timespec="seconds")
    with closing(db()) as conn:
        target = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
        source = conn.execute("SELECT * FROM items WHERE id = ?", (source_id,)).fetchone()
        if not target or not source:
            raise HTTPException(404)
        source_stocks = conn.execute("SELECT * FROM item_stocks WHERE item_id = ?", (source_id,)).fetchall()
        for stock in source_stocks:
            conn.execute(
                """INSERT INTO item_stocks (item_id, location_id, quantity, opened, updated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(item_id, location_id) DO UPDATE SET
                     quantity = item_stocks.quantity + excluded.quantity,
                     opened = item_stocks.opened + excluded.opened,
                     updated_at = excluded.updated_at""",
                (item_id, stock["location_id"], stock["quantity"], stock["opened"], now),
            )
        details = f"Combined from {source['name']}"
        if source["barcode"]:
            details += f" [barcode {source['barcode']}]"
        if source["notes"]:
            details += f": {source['notes']}"
        merged_notes = "\n".join(part for part in (target["notes"].strip(), details) if part)
        expirations = [value for value in (target["expires_on"], source["expires_on"]) if value]
        purchase_dates = [value for value in (target["bought_on"], source["bought_on"]) if value]
        total = conn.execute("SELECT COALESCE(SUM(quantity), 0) FROM item_stocks WHERE item_id = ?", (item_id,)).fetchone()[0]
        conn.execute(
            """UPDATE items SET quantity=?, low_at=?, bought_on=?, expires_on=?, notes=?,
                     barcode=?, image_url=?, updated_at=? WHERE id=?""",
            (total, max(target["low_at"], source["low_at"]), min(purchase_dates) if purchase_dates else None, min(expirations) if expirations else None, merged_notes, target["barcode"] or source["barcode"], target["image_url"] or source["image_url"], now, item_id),
        )
        conn.execute("DELETE FROM item_stocks WHERE item_id = ?", (source_id,))
        conn.execute("DELETE FROM items WHERE id = ?", (source_id,))
        conn.commit()
    return RedirectResponse("/", status_code=303)


@app.post("/items/{item_id}/stock")
def update_item_stock(item_id: int, location_id: int = Form(...), unopened: float = Form(0), opened: float = Form(0)):
    if unopened < 0 or opened < 0:
        raise HTTPException(400, "Unopened and open quantities cannot be negative")
    quantity = unopened + opened
    now = datetime.now().isoformat(timespec="seconds")
    with closing(db()) as conn:
        if not conn.execute("SELECT 1 FROM items WHERE id = ?", (item_id,)).fetchone():
            raise HTTPException(404)
        if not conn.execute("SELECT 1 FROM locations WHERE id = ?", (location_id,)).fetchone():
            raise HTTPException(400, "Invalid storage location")
        conn.execute(
            """INSERT INTO item_stocks (item_id, location_id, quantity, opened, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(item_id, location_id) DO UPDATE SET quantity=excluded.quantity, opened=excluded.opened, updated_at=excluded.updated_at""",
            (item_id, location_id, quantity, opened, now),
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
