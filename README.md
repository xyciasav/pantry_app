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
3. Optionally add a stack environment variable named `PANTRY_PORT` with the host port you want, such as `8085`. If omitted, it defaults to `8000`.
4. Deploy the stack and open that port on the Docker host.

The container continues to listen internally on port `8000`; only the host-facing port changes.

### Version and image name

The default Docker image is named `shelf-life:1.1.0`, and the same version appears in the website header, footer, and `/health` response.

Portainer stack variables can override these values:

- `PANTRY_VERSION=1.1.0` controls the Docker tag and displayed website version.
- `PANTRY_IMAGE_NAME=shelf-life` controls the image name.

For each release, change `PANTRY_VERSION` to the new version before rebuilding the stack. Portainer will then show images such as `shelf-life:1.1.0` instead of an ambiguous `latest` tag.

## Features

- Grocery-style inventory cards for pantry, fridge, and freezer
- Unlimited named storage locations for multiple fridges, freezers, and pantries
- Phone camera barcode scanning with Open Food Facts product lookup
- One-tap quantity adjustment
- Purchase and expiration dates
- Low-stock thresholds and attention indicators
- Search, category filtering, and responsive mobile layout
- SQLite persistence and a Docker health check

## Barcode scanning

Open **Scan** from your phone, allow camera access, and point it at a UPC or EAN barcode. Shelf Life looks up the product through Open Food Facts and prefills the add-item form. Unknown products can still be entered manually.

Browsers require a secure HTTPS connection for camera access when the app is opened from another device. Put the Portainer service behind your usual HTTPS reverse proxy. Shelf Life uses native barcode detection when available and a bundled ZXing scanner on other modern browsers. Manual barcode entry works without camera access.
