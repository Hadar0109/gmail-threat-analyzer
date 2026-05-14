# Backend (FastAPI)

## Prerequisites

- Python 3.11+
- A virtual environment (recommended)

## Install

```bash
cd backend
python -m venv .venv
```

Activate `.venv` (Windows PowerShell: `.\.venv\Scripts\Activate.ps1`), then:

```bash
pip install -e ".[dev]"
```

## Run locally

```bash
cd backend
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Health check: `GET http://127.0.0.1:8000/health`

The Gmail add-on must call a **public HTTPS** URL in non-local demos; use a tunnel (for example Cloudflare Tunnel, ngrok) or deploy to Cloud Run / Fly.io / Render (see root README).

## Tests

```bash
cd backend
pytest
```

## Environment variables

See `.env.example` in this directory.

On import, `app.main` loads **`backend/.env`** into the process environment (via `python-dotenv`). Existing shell or platform variables are **not** overridden, so Render and `export …` still win. **Restart uvicorn** after changing `.env`.

Reputation keys are read only under these names (see `app/reputation/providers.py`):

| Variable | Purpose |
| --- | --- |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Safe Browsing v4 `threatMatches:find` |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 URL reports |

**Opt-in live checks:** from `backend/`, set `RUN_REPUTATION_LIVE=1` and run `pytest src/tests/test_reputation_live.py -v` (requires real keys and network). Confirms clean vs test phishing URL, VT response shape, and that `reputation_overlay` flows through `score_message`.

**Reputation observability:** each scoring request logs one INFO line from `app.reputation.providers` (`reputation_run url_candidates=… safe_browsing=… virustotal=…`) — no URLs or secrets. Use `uvicorn … --log-level info` (default) to see it.

```powershell
$body = '{"schema_version":"1.1","from_email":"a@b.com","urls":["https://www.google.com/"]}'
Invoke-RestMethod -Uri http://127.0.0.1:8000/v1/score -Method Post -ContentType 'application/json' -Body $body
```

Expect `reputation.providers.safe_browsing` (and/or `virustotal`) not `skipped_no_api_key`, and with a Google test phishing URL in `urls`, expect `safe_browsing: "threat"` and a non-zero `signals.reputation_overlay` when Safe Browsing is enabled.

### `POST /v1/score` (Phase 4)

- When **`HMAC_SECRET`** is set, clients must send header **`X-Body-Signature`**: lowercase **hex** digest of **HMAC-SHA256(secret, raw JSON body bytes)**. When unset, HMAC is not required (local dev only). Optional **`HMAC_SECRET_PREVIOUS`**: if set, a signature valid for either the current or previous secret is accepted (same **401** detail on failure). **`HMAC_SECRET_PREVIOUS` alone never enables HMAC**; production still requires **`HMAC_SECRET`** (see below).
- JSON body size is capped (see `MAX_SCORE_BODY_BYTES` in `app/limits.py`); larger payloads receive **413**.
- A simple per-IP sliding-window rate limit applies to this route (**429** when exceeded).

### Production HMAC (`ENVIRONMENT=production`)

On **Render** or any public host, set **`ENVIRONMENT=production`** (or `prod`). Then **`HMAC_SECRET` must be non-empty**: `POST /v1/score` returns **503** if it is missing, so the scoring API cannot accidentally run unsigned. Setting only **`HMAC_SECRET_PREVIOUS`** does **not** satisfy this check. **`GET /health`** is unchanged (suitable for load balancers).

**Secret rotation:** see the root [README.md](../README.md) section *HMAC secret rotation* for the step-by-step runbook (env vars, Script property, deploy both sides, then clear `HMAC_SECRET_PREVIOUS`).

For **local development**, omit `ENVIRONMENT` or set `ENVIRONMENT=development`; you may omit `HMAC_SECRET` and call `/v1/score` without signing.

#### Replay protection (`schema_version` **1.1**)

In **production**, each request body must include **`issued_at`** (Unix time in **milliseconds**) and **`request_id`** (UUID string). They are part of the JSON that is **HMAC-signed** with the rest of the body. The server rejects requests outside a clock-skew window (default ±120s, `SCORE_MAX_SKEW_SECONDS`) and duplicate `request_id` values within an in-process TTL (default 300s, `REPLAY_REQUEST_ID_TTL_SECONDS`). This cache is **per server process** only (no Redis)—use a **single worker** if you rely on it for demos.

In **non-production**, both fields may be omitted; if either is present, both must be present and valid.

#### Troubleshooting (401 / 503)

| HTTP | Typical cause |
| --- | --- |
| **401** `Missing HMAC signature` | Backend has `HMAC_SECRET` set but the client did not send `X-Body-Signature`. |
| **401** `Invalid HMAC signature` / `Invalid HMAC signature format` | Wrong secret vs add-on Script property, body bytes differ from what was signed (re-serialized JSON), or header is not 64-character lowercase hex. |
| **503** `HMAC_SECRET is required when ENVIRONMENT=production` | Production flag is set on the server but `HMAC_SECRET` is missing—set it in Render to match the add-on and redeploy. |
| **400** `issued_at and request_id are required in production` | Production requires replay fields in the JSON body (see add-on `Features.gs`). |
| **400** `issued_at is outside the allowed time window` | Client clock skew or stale replay; check `issued_at` is ms since epoch and within ±`SCORE_MAX_SKEW_SECONDS`. |
| **409** `Duplicate request_id within replay window` | Same `request_id` was reused within `REPLAY_REQUEST_ID_TTL_SECONDS` on this process. |

### Privacy (responses)

Validation errors (**422**) redact Pydantic `input` / `ctx` fields from JSON details so snippets or URLs are not echoed back in error bodies. The app does not add application-level logging of request bodies; avoid enabling verbose reverse-proxy body logging in production.

## Reputation providers (optional)

Orchestration: `app/reputation/providers.py`. Clients: `app/reputation/safebrowsing.py` (Google Safe Browsing v4), `app/reputation/virustotal.py` (VirusTotal v3 URL reports).

**Environment variable names** (must match exactly on Render and in `.env`):

| Variable | Purpose |
| --- | --- |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Safe Browsing API key |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key |

If either variable is unset or empty, that provider returns status **`skipped_no_api_key`** (treated as provider disabled / missing key; not a client error). The scoring engine **still** evaluates headers, sender, URLs, urgency, and attachments; reputation is an optional overlay.

**Timeouts:** shared `httpx` client uses a ~2.5s read timeout (see `run_reputation_checks`). Failures surface as `error_timeout` or `error_http`, not as crashed requests.

**VirusTotal 429:** returned as `error_http` with detail mentioning 429; remaining URLs may not be queried; Safe Browsing may still complete if configured.

**No storage:** the backend does not log or store email bodies, attachment bytes, or scan history; reputation calls send **IOC URLs only** within caps (`REPUTATION_MAX_URLS_TO_CHECK` in `app/limits.py`).