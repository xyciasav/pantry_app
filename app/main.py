from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from datetime import date, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("PANTRY_DATA_DIR", BASE_DIR.parent / "data"))
DB_PATH = DATA_DIR / "pantry.db"

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
        conn.commit()


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
    return item


def render(request: Request, name: str, **context) -> HTMLResponse:
    template = templates.get_template(name)
    return HTMLResponse(template.render(request=request, categories=CATEGORIES, **context))


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def home(request: Request, location: str = "all", category: str = "all", q: str = ""):
    clauses, params = [], []
    if location != "all":
        clauses.append("location = ?")
        params.append(location)
    if category != "all":
        clauses.append("category = ?")
        params.append(category)
    if q.strip():
        clauses.append("name LIKE ?")
        params.append(f"%{q.strip()}%")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with closing(db()) as conn:
        rows = conn.execute(
            f"SELECT * FROM items {where} ORDER BY CASE WHEN expires_on IS NULL THEN 1 ELSE 0 END, expires_on, name",
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
def new_item(request: Request):
    return render(request, "form.html", item=None, today=date.today().isoformat())


@app.get("/items/{item_id}/edit", response_class=HTMLResponse)
def edit_item(request: Request, item_id: int):
    with closing(db()) as conn:
        row = conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()
    if not row:
        raise HTTPException(404)
    return render(request, "form.html", item=dict(row), today=date.today().isoformat())


@app.post("/items/save")
def save_item(
    item_id: int | None = Form(None),
    name: str = Form(...),
    category: str = Form("other"),
    location: str = Form("pantry"),
    quantity: float = Form(1),
    unit: str = Form("item"),
    low_at: float = Form(1),
    bought_on: str | None = Form(None),
    expires_on: str | None = Form(None),
    notes: str = Form(""),
):
    if not name.strip() or quantity < 0 or low_at < 0:
        raise HTTPException(400, "Name is required and quantities cannot be negative")
    now = datetime.now().isoformat(timespec="seconds")
    values = (name.strip(), category if category in CATEGORIES else "other", location, quantity, unit.strip() or "item", low_at, normalize_date(bought_on), normalize_date(expires_on), notes.strip(), now)
    with closing(db()) as conn:
        if item_id:
            conn.execute(
                "UPDATE items SET name=?, category=?, location=?, quantity=?, unit=?, low_at=?, bought_on=?, expires_on=?, notes=?, updated_at=? WHERE id=?",
                (*values, item_id),
            )
        else:
            conn.execute(
                "INSERT INTO items (name, category, location, quantity, unit, low_at, bought_on, expires_on, notes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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

