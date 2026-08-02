# Shelf Life

A simple, touch-friendly pantry and fridge tracker. Add groceries, tap to adjust quantities, and see expiring or low-stock items at a glance.

## Run with Docker

```bash
docker compose up -d --build
```

Open `http://localhost:8000`. Inventory is stored in the `pantry-data` Docker volume.

## Portainer stack

1. Add this Git repository as a Portainer stack.
2. Use `docker-compose.yml` as the compose path.
3. Deploy the stack and open port `8000` on the Docker host.

For a different public port, change the first number in `8000:8000`.

## Features

- Grocery-style inventory cards for pantry, fridge, and freezer
- One-tap quantity adjustment
- Purchase and expiration dates
- Low-stock thresholds and attention indicators
- Search, category filtering, and responsive mobile layout
- SQLite persistence and a Docker health check
