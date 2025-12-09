# retag-api (minimal)

Simple POST API to retag & push Docker images via Docker CLI.

Also includes a QRIS (EMV) validator that parses QR strings and reports the parsed tag tree plus CRC status.

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

### Validate QRIS (EMV QR)

```bash
curl -sS -H "Authorization: Bearer ${API_TOKEN:-secret}" -H "Content-Type: application/json"   -d '{"qr":"00020101021126660014ID.CO.QRIS.WWW01189360091410690860390210215UCOOBIDJA000031170212%2B62813360596680213R%2FNE01BD19220312C0712040103UMI51440014ID.OR.GPNQR.WWW02011300000303130303UMI52048912530336054045.005802ID5912Coba%20Bayar6008Jakarta610512340622605160676304608E"}'   http://localhost:${PORT:-8080}/qris/validate | jq
```

## JSON Logs
- File: `./logs/access.log` (mounted)
- Two lines per request: `"Event":"request"` and `"Event":"response"`
- Server generates `RequestID` and returns it in header `X-Request-Id` and response body `request_id`.
