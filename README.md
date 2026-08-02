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

## Features

- Grocery-style inventory cards for pantry, fridge, and freezer
- One-tap quantity adjustment
- Purchase and expiration dates
- Low-stock thresholds and attention indicators
- Search, category filtering, and responsive mobile layout
- SQLite persistence and a Docker health check
