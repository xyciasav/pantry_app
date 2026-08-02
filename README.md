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
- `PANTRY_COOKIE_SECURE=true` requires HTTPS and should remain enabled for an online deployment. Set it to `false` only for local HTTP testing.

Changing the password or signing key immediately invalidates existing sessions. The login protects every inventory page and API route; only static assets and `/health` remain public for container health checks.

### Version and image name

The default Docker image is named `shelf-life:1.3.0`, and the same version appears in the website header, footer, and `/health` response.

Portainer stack variables can override these values:

- `PANTRY_VERSION=1.3.0` controls the Docker tag and displayed website version.
- `PANTRY_IMAGE_NAME=shelf-life` controls the image name.

For each release, change `PANTRY_VERSION` to the new version before rebuilding the stack. Portainer will then show images such as `shelf-life:1.1.0` instead of an ambiguous `latest` tag.

## Features

- Grocery-style inventory cards for pantry, fridge, and freezer
- Unlimited named storage locations for multiple fridges, freezers, and pantries
- Per-item stock split across multiple locations, with separate opened-package counts
- Login protection for the entire inventory and API
- Phone camera barcode scanning with Open Food Facts product lookup
- One-tap quantity adjustment
- Purchase and expiration dates
- Low-stock thresholds and attention indicators
- Search, category filtering, and responsive mobile layout
- SQLite persistence and a Docker health check

## Barcode scanning

Open **Scan** from your phone, allow camera access, and point it at a UPC or EAN barcode. Shelf Life looks up the product through Open Food Facts and prefills the add-item form. Unknown products can still be entered manually.

Browsers require a secure HTTPS connection for camera access when the app is opened from another device. Put the Portainer service behind your usual HTTPS reverse proxy. Shelf Life uses native barcode detection when available and a bundled ZXing scanner on other modern browsers. Manual barcode entry works without camera access.
