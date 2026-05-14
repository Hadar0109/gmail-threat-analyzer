# Hardening checklist (MVP)

Use this as an ordered runbook for **local parity** and **production** hardening. It does not replace threat modeling for your own deployment.

## 1. Secrets and Git

- **Never commit** real API keys or `HMAC_SECRET`. The repo root [`.gitignore`](../.gitignore) ignores `.env` and `.env.*` while allowing **`.env.example`** (negation rule).
- **Local backend secrets file:** `backend/.env` (same directory as `backend/pyproject.toml`). Copy from [`backend/.env.example`](../backend/.env.example).
- **Production:** set the same variable **names** in your host’s environment (for example Render **Environment**). Process env wins over `backend/.env` when both exist (`load_dotenv(..., override=False)`).

## 2. HTTPS and add-on target

- The Gmail add-on must call a public **`https://`** origin (`BACKEND_BASE_URL` Script property).
- Use a tunnel or managed host with TLS for anything the add-on touches.

## 3. HMAC (production-style)

- Set **`ENVIRONMENT=production`** (or `prod`) on public backends so `POST /v1/score` cannot start without **`HMAC_SECRET`**.
- Match **`HMAC_SECRET`** between server and Apps Script **Script properties**; see [backend/README.md — Production HMAC](../backend/README.md#production-hmac-environmentproduction).

## 4. External reputation (Google Safe Browsing + VirusTotal) — **official step**

This step enables outbound URL checks; local heuristics always run regardless.

### 4.1 Variable names (must match exactly)

| Variable | Used for |
| --- | --- |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Safe Browsing v4 `threatMatches:find` |
| `VIRUSTOTAL_API_KEY` | VirusTotal v3 URL reports |

The backend reads them in **`app/reputation/providers.py`** via `os.getenv` inside `run_reputation_checks`.

### 4.2 Obtain keys

1. **Google Safe Browsing:** Google Cloud project → **APIs & Services** → **Library** → enable **Safe Browsing API** → **Credentials** → create an **API key**. For a server, avoid “HTTP referrer” restrictions unless you know the egress IPs.
2. **VirusTotal:** Account → **API key** (v3).

### 4.3 Configure locally

1. Create **`backend/.env`** from **`backend/.env.example`**.
2. Add (example — use your real values):

   ```env
   GOOGLE_SAFE_BROWSING_API_KEY=your-google-key-here
   VIRUSTOTAL_API_KEY=your-vt-key-here
   ```

3. Install deps and start the API from **`backend/`** (see root README §9). **`app/main.py`** calls `load_backend_dotenv()` on import so **`backend/.env`** is loaded before handling requests.
4. **Restart uvicorn** after any change to `.env`.

### 4.4 Configure production

1. In the host dashboard (for example Render **Web Service** → **Environment**), add **`GOOGLE_SAFE_BROWSING_API_KEY`** and **`VIRUSTOTAL_API_KEY`** with the same spelling as above.
2. **Redeploy or restart** the service so the process inherits new variables.

### 4.5 Preconditions for “active” providers

- Keys must be **non-empty** in the process environment after load.
- The score request must include at least one **sanitized public `http(s)`** URL in **`urls`** (subject/snippet/body extract in the add-on). If there are no candidates, providers report `skipped_no_urls` even when keys are set.

### 4.6 Verify integration

1. **Logs (server):** after `pip install` includes the app, each `POST /v1/score` that runs reputation emits one **INFO** line from `app.reputation.providers`, for example:  
   `reputation_run url_candidates=N safe_browsing=<status> virustotal=<status> overlay=... contributed=...`  
   Status values such as **`clean`**, **`threat`**, **`not_found`**, or **`skipped_no_api_key`** confirm whether each provider ran. **URLs and API keys are not logged.**

2. **JSON response:** inspect `reputation.providers.safe_browsing` and `reputation.providers.virustotal`. Anything other than **`skipped_no_api_key`** (when URLs exist) indicates that provider executed a remote call or a deterministic skip after a call (for example **`skipped_no_urls`** when the list is empty).

3. **Gmail score card:** under **Link reputation**, Safe Browsing and VirusTotal rows should show **“Checked — …”** labels when the backend returned a consulted status (not the “Disabled — set … API key” copy).

4. **`reputation_overlay` and final score:** the API exposes `signals.reputation_overlay` (raw overlay points before the engine’s fixed weight). The merged integer **`score`** includes that channel with weight **`0.10`** in `app/scoring/engine.py` (weights are not changed in this checklist).

5. **Automated opt-in tests:** from `backend/`, set **`RUN_REPUTATION_LIVE=1`** and run `pytest src/tests/test_reputation_live.py -v` (requires network and real keys). See [backend/README.md](../backend/README.md).

## 5. Rate limits and replay (production)

- Production requires **`issued_at`** and **`request_id`** in the JSON body (replay protection); see backend README.

## 6. Ongoing

- Rotate **`HMAC_SECRET`** using **`HMAC_SECRET_PREVIOUS`** when needed (root README §4).
- Monitor vendor quotas (especially VirusTotal **429**) via `error_http` / partial notices.
