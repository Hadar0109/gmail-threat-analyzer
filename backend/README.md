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

### `POST /v1/score` (Phase 4)

- When **`HMAC_SECRET`** is set, clients must send header **`X-Body-Signature`**: lowercase **hex** digest of **HMAC-SHA256(secret, raw JSON body bytes)**. When unset, HMAC is not required (local dev only).
- JSON body size is capped (see `MAX_SCORE_BODY_BYTES` in `app/limits.py`); larger payloads receive **413**.
- A simple per-IP sliding-window rate limit applies to this route (**429** when exceeded).