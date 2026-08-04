# Shelf Life

A simple, touch-friendly pantry and fridge tracker. Add groceries, tap to adjust quantities, and see expiring or low-stock items at a glance.

## Run with Docker

```bash
docker compose up -d --build
```

Open `http://localhost:8000`. Inventory is stored in the `pantry-data` Docker volume.

To use a different host port, set `PANTRY_PORT` before starting the stack. For example:

```bash
PANTRY_PORT=8085 docker compose up -d --build
```

## Portainer stack

1. Add this Git repository as a Portainer stack.
2. Use `docker-compose.yml` as the compose path.
3. Add the required authentication environment variables listed below.
4. Optionally add `PANTRY_PORT` with the host port you want, such as `8085`. If omitted, it defaults to `8000`.
5. Deploy the stack and open that port on the Docker host.

The container continues to listen internally on port `8000`; only the host-facing port changes.

### Required login settings

The container will refuse to start without all three values:

- `PANTRY_USERNAME` — the login username
- `PANTRY_PASSWORD` — a strong, unique password
- `PANTRY_SECRET_KEY` — a random value at least 32 characters long used to sign sessions

Generate a signing key with `openssl rand -hex 32`, then save the output as `PANTRY_SECRET_KEY` in Portainer. Do not commit credentials to this repository.

Optional authentication settings:

- `PANTRY_SESSION_HOURS=12` controls session lifetime.
- `PANTRY_COOKIE_SECURE=auto` (the default) detects HTTPS directly or through a reverse proxy's `X-Forwarded-Proto` header. You can force `true` for HTTPS-only access or `false` for HTTP-only local access.

Changing the password or signing key immediately invalidates existing sessions. The login protects every inventory page and API route; only static assets and `/health` remain public for container health checks.

### Version and image name

The default Docker image is named `shelf-life:1.15.1`, and the same version appears in the website header, footer, and `/health` response.

Portainer stack variables can override these values:

- `PANTRY_VERSION=1.15.1` controls the Docker tag and displayed website version.
- `PANTRY_IMAGE_NAME=shelf-life` controls the image name.

For each release, change `PANTRY_VERSION` to the new version before rebuilding the stack. Portainer will then show images such as `shelf-life:1.1.0` instead of an ambiguous `latest` tag.

## Features

- Grocery-style inventory cards for pantry, fridge, and freezer
- Unlimited named storage locations for multiple fridges, freezers, and pantries
- Per-item stock split across multiple locations, with separate opened-package counts
- Separate dated purchase batches for the same product and location
- Manual “opened package getting low” status for partially used containers
- Starred essential items with red critical alerts and priority sorting
- Installable PWA with a favicon, app icon, and safe static-asset caching
- Login protection for the entire inventory and API
- Group similar products into one dashboard total while preserving each brand, barcode, location, and expiration
- Custom categories, item photo uploads, and downloadable/restorable database backups
- Read-only inventory API for local LLM integrations using `PANTRY_API_KEY`
- Renameable product groups and an attention-first, color-coded inventory list
- A private What's for Dinner assistant that uses current inventory, expiry dates, and a saved household taste profile
- A persistent, mobile-friendly Saved Recipes cookbook included in normal Shelf Life backups
- A weekly meal-planning board with drag-and-drop cards, mobile move controls, cooked history, and repeat avoidance
- A standalone recipe cookbook with manual add/edit and repeatable Outline JSON/ZIP imports, including recipe photos
- Inventory-aware recipes that show missing ingredients and suggest meals unlocked by buying one or two items
- Recipe meal-style and protein labels with a balanced weekly planner that preserves existing choices

## Recipe imports

Open **Recipes** and choose an Outline export ZIP or its `Recipes.json` file. The ZIP format is recommended because it also contains the uploaded recipe photos. Shelf Life recognizes ingredient and instruction sections, skips weekly meal-plan documents, and updates matching Outline recipes when the same export is imported again.

## Dinner Assistant

Shelf Life can call an OpenAI-compatible local LLM proxy directly. Add these stack environment variables in Portainer:

```text
PANTRY_LLM_URL=http://10.0.0.230:8084/v1
PANTRY_LLM_MODEL=lmstudio-proxy-ha
PANTRY_LLM_API_KEY=YOUR_PROXY_KEY
```

Leave `PANTRY_LLM_API_KEY` blank if the proxy does not require authentication. The API key stays in the container environment and is never shown or saved in the pantry database. The Dinner page sends in-stock item names, amounts, ingredient labels, and expiry dates to the configured proxy. Your proxy's existing assistant prompt supplies the household profile. Shelf Life first requests up to three meal names; it requests the full recipe only after you select one. It does not change inventory automatically.

Generated recipes can be pinned into Shelf Life's Saved Recipes cookbook. The saved record includes reserved source and Outline ID fields so a later Outline publishing integration can be added without changing the recipe format; version 1.10.0 does not contact or publish to Outline.

## Read-only dashboard and LLM API

Set a long random `PANTRY_API_KEY` in Portainer, then send it as a Bearer token:

```bash
curl -H "Authorization: Bearer YOUR_KEY" https://your-shelf-life.example/api/inventory
```

Available endpoints:

- `/api/dashboard` — combined summary, current weekly menu, alerts, shopping list, and recipe readiness
- `/api/inventory` — every item, group, unopened/open total, location, dated batch, barcode, note, and stock state
- `/api/alerts` — out, low, opened-low, critical, expiring, and expired items
- `/api/weekly-menu` — the current week, or use `?week=YYYY-MM-DD` for another week
- `/api/shopping-list` — tracked pantry purchases and recipe-only ingredients
- `/api/recipes` — saved recipes with meal type, protein, missing ingredients, and cookable status
- `/api/recipes?include_details=true` — also include ingredients, instructions, time, servings, and photos
- `/api/recipes/{id}` — one complete recipe with live inventory readiness

The API key grants read-only access and does not allow inventory or meal-plan changes.

OpenAPI discovery and interactive documentation are available without a webpage login at `/openapi.json` and `/docs`. All `/api/*` data endpoints require the Bearer API key.
- Phone camera barcode scanning with Open Food Facts product lookup
- One-tap quantity adjustment
- Purchase and expiration dates
- Low-stock thresholds and attention indicators
- Search, category filtering, and responsive mobile layout
- SQLite persistence and a Docker health check

## Barcode scanning

Open **Scan** from your phone, allow camera access, and point it at a UPC or EAN barcode. Shelf Life looks up the product through Open Food Facts and prefills the add-item form. Unknown products can still be entered manually.

Browsers require a secure HTTPS connection for camera access when the app is opened from another device. Put the Portainer service behind your usual HTTPS reverse proxy. Shelf Life uses native barcode detection when available and a bundled ZXing scanner on other modern browsers. Manual barcode entry works without camera access.
