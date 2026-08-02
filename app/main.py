from __future__ import annotations

import os
import sqlite3
import json
import re
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
APP_VERSION = os.getenv("APP_VERSION", "1.0.1")

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

CATEGORY_ART = {
    "produce": "apple",
    "dairy": "milk",
    "meat": "chicken",
    "frozen": "frozen-food",
    "pantry": "canned-food",
    "bakery": "bread",
    "drinks": "milk",
}

app = FastAPI(title="Shelf Life")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Environment(
    loader=FileSystemLoader(BASE_DIR / "templates"),
    autoescape=select_autoescape(["html", "xml"]),
)


def db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
    fallback = CATEGORY_ART.get(category)
    return f"/static/items/{fallback}.webp" if fallback else None


def view_item(row: sqlite3.Row) -> dict:
    item = dict(row)
    today = date.today()
    expires = date.fromisoformat(item["expires_on"]) if item["expires_on"] else None
    days_left = (expires - today).days if expires else None
    if item["quantity"] <= 0:
        state = "out"
    elif item["quantity"] <= item["low_at"]:
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


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": APP_VERSION}


@app.get("/", response_class=HTMLResponse)
def home(request: Request, location: str = "all", category: str = "all", q: str = ""):
    clauses, params = [], []
    if location != "all":
        clauses.append("items.location_id = ?")
        params.append(int(location))
    if category != "all":
        clauses.append("category = ?")
        params.append(category)
    if q.strip():
        clauses.append("name LIKE ?")
        params.append(f"%{q.strip()}%")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with closing(db()) as conn:
        rows = conn.execute(
            f"""SELECT items.*, locations.name AS location_name, locations.kind AS location_kind
                FROM items LEFT JOIN locations ON locations.id = items.location_id
                {where} ORDER BY CASE WHEN expires_on IS NULL THEN 1 ELSE 0 END, expires_on, items.name""",
            params,
        ).fetchall()
    items = [view_item(row) for row in rows]
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
    location_id: int = Form(...),
    quantity: float = Form(1),
    unit: str = Form("item"),
    low_at: float = Form(1),
    bought_on: str | None = Form(None),
    expires_on: str | None = Form(None),
    notes: str = Form(""),
    barcode: str = Form(""),
    image_url: str = Form(""),
):
    if not name.strip() or quantity < 0 or low_at < 0:
        raise HTTPException(400, "Name is required and quantities cannot be negative")
    now = datetime.now().isoformat(timespec="seconds")
    with closing(db()) as conn:
        location_row = conn.execute("SELECT kind FROM locations WHERE id = ?", (location_id,)).fetchone()
        if not location_row:
            raise HTTPException(400, "Invalid storage location")
        values = (name.strip(), category if category in CATEGORIES else "other", location_row["kind"], location_id, quantity, unit.strip() or "item", low_at, normalize_date(bought_on), normalize_date(expires_on), notes.strip(), barcode.strip(), image_url.strip(), now)
        if item_id:
            conn.execute(
                "UPDATE items SET name=?, category=?, location=?, location_id=?, quantity=?, unit=?, low_at=?, bought_on=?, expires_on=?, notes=?, barcode=?, image_url=?, updated_at=? WHERE id=?",
                (*values, item_id),
            )
        else:
            conn.execute(
                "INSERT INTO items (name, category, location, location_id, quantity, unit, low_at, bought_on, expires_on, notes, barcode, image_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (*values[:-1], now, now),
            )
        conn.commit()
    return RedirectResponse("/", status_code=303)


@app.post("/items/{item_id}/quantity")
def change_quantity(item_id: int, delta: float = Form(...)):
    with closing(db()) as conn:
        cursor = conn.execute(
            "UPDATE items SET quantity = MAX(0, quantity + ?), updated_at = ? WHERE id = ?",
            (delta, datetime.now().isoformat(timespec="seconds"), item_id),
        )
        conn.commit()
    if not cursor.rowcount:
        raise HTTPException(404)
    return RedirectResponse("/", status_code=303)


@app.post("/items/{item_id}/delete")
def delete_item(item_id: int):
    with closing(db()) as conn:
        conn.execute("DELETE FROM items WHERE id = ?", (item_id,))
        conn.commit()
    return RedirectResponse("/", status_code=303)


@app.get("/locations", response_class=HTMLResponse)
def locations_page(request: Request):
    with closing(db()) as conn:
        locations = [
            dict(row)
            for row in conn.execute(
                """SELECT locations.*, COUNT(items.id) AS item_count
                   FROM locations LEFT JOIN items ON items.location_id = locations.id
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
        count = conn.execute("SELECT COUNT(*) FROM items WHERE location_id = ?", (location_id,)).fetchone()[0]
        if count:
            raise HTTPException(409, "Move the items in this location before deleting it")
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
