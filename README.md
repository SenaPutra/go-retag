# retag-api (minimal)

Simple POST API to retag & push Docker images via Docker CLI.

## Run (Docker Compose)
```bash
cp .env.example .env   # optional
docker compose up -d --build
docker compose logs -f retag-api
```

Set host port by env: `PORT=9000 docker compose up -d` (container listens on 8080).

Test:
```bash
curl -sS -H "Authorization: Bearer ${API_TOKEN:-secret}" -H "Content-Type: application/json"   -d '{"src":"reg/stg/app:stg","dest":"reg/prod/app:prod-20251112-Rev01","dry_run":true}'   http://localhost:${PORT:-8080}/retag | jq
```

## JSON Logs
- File: `./logs/access.log` (mounted)
- Two lines per request: `"Event":"request"` and `"Event":"response"`
- Server generates `RequestID` and returns it in header `X-Request-Id` and response body `request_id`.
