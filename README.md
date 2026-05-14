# Gmail Malicious Email Scorer

Contextual **Gmail add-on** plus **FastAPI** backend that estimates phishing / maliciousness risk from **bounded message features** (headers, URLs, snippet windows, attachment metadata). This is **not** an antivirus and **does not** store raw email, bodies, or scan history (stateless MVP).

## 1. Project overview

- **Users**: security-conscious Gmail users who want an explainable, on-open risk readout.
- **Surfaces**: Card UI in Gmail (Apps Script) and `POST /v1/score` on the backend (Phases 1–5).
- **Non-goals**: attachment malware scanning, full MIME pipelines, databases, ML-first black-box scoring, automated Gmail actions.

### Implementation phases (status)

| Phase | Scope | Status |
| --- | --- | --- |
| 1 | Backend API skeleton (`POST /v1/score`, Pydantic, tests) | **Completed** |
| 2 | Local rule-based scoring (engine + signal modules, no external APIs) | **Completed** |
| 3 | Reputation providers (Safe Browsing, VirusTotal) + merge | **Completed** |
| 4 | HMAC auth, rate limits, payload hardening | **Completed** |
| 5 | Gmail add-on live reads + card rendering | **Completed** |
| 6 | Demo polish, docs, walkthrough scenarios | **Active** (current) |

## 2. Demo quickstart (stub until Phase 6 polish)

1. Deploy or tunnel the backend over **HTTPS** (add-on requires `https://` targets only).
2. Configure Apps Script **Script properties** from `addon/script-properties.template`.
3. Push the add-on with **clasp** (`addon/README.md`).
4. Install the add-on on a test Workspace / consumer Gmail and open a message.

Detailed steps will be finalized after Phases 3–5 (OAuth, GCP project, install flow).

## 3. Architecture

```mermaid
flowchart TB
  subgraph google [Google Workspace]
    GmailUI[Gmail UI]
    Addon[Apps Script add-on]
    GmailAPI[Gmail API]
  end
  subgraph backend [Your HTTPS host]
    API[FastAPI]
    Rules[Local rule engine]
    Rep[Reputation orchestrator]
  end
  subgraph vendors [MVP vendors]
    SB[Safe Browsing]
    VT[VirusTotal]
  end
  GmailUI --> Addon
  Addon --> GmailAPI
  Addon -->|"JSON + HMAC"| API
  API --> Rules
  API --> Rep
  Rep --> SB
  Rep --> VT
```

See also [docs/architecture.md](docs/architecture.md).

## 4. Security decisions (summary)

- **Least-privilege Gmail scopes** in `addon/src/appsscript.json` (aligned with Advanced Gmail usage in Phase 5).
- **HTTPS only** from the add-on to your API (`openLinkUrlPrefixes` allowlists `https://`).
- **HMAC** (or equivalent) between add-on and backend — implemented in Phase 4; secret in Script Properties + `HMAC_SECRET` env.
- **Strict validation**, payload caps, rate limits — Phases 1 and 4.
- **No raw email storage**; minimize fields sent to third-party reputation APIs (IOC-only).

### HMAC secret rotation (no extra infrastructure)

The backend signs nothing; the add-on sends **`X-Body-Signature`**: lowercase hex **HMAC-SHA256** over the **raw JSON body** bytes. During a key change, the API can accept either the current or the immediately previous server secret so old and new deploys can overlap.

1. On the backend host (for example Render), set **`HMAC_SECRET_PREVIOUS`** to the **old** secret and **`HMAC_SECRET`** to the **new** secret.
2. In the Gmail add-on Apps Script **Script properties**, set the scoring secret to the **new** value (must match **`HMAC_SECRET`** on the server).
3. **Deploy** the backend and **push** the add-on (`addon/README.md`) so both environments pick up the new values.
4. After every client uses the new secret, **remove** `HMAC_SECRET_PREVIOUS` from the backend environment and redeploy.

Invalid signatures use the same **401** response whether the mismatch would have been against the current or previous key (no distinction in errors or logs from this check).

### Hardening checklist

For a step-by-step production-style runbook (**secrets, HMAC, external reputation keys, verification**), see [docs/hardening-checklist.md](docs/hardening-checklist.md).

## 5. Privacy considerations

- **To your backend**: normalized, capped DTO (schema versioned; see `schema_version` in requests).
- **To vendors (Safe Browsing, VirusTotal)**: only the IOC strings their APIs require — **not** narrative body text.
- **Retention**: none by design (ephemeral requests).

## 6. Scoring logic (outline)

- **Verdict bands** (integer `score` 0–100 → `verdict` string): **Safe** 0–28 (`safe`), **Suspicious** 29–52 (`suspicious`), **Dangerous** 53–77 (`dangerous`), **Critical** 78–100 (`critical`). The engine may raise the score with combination rules (for example strong reputation hits) before mapping to these bands.
- **Confidence**: signal quality / coverage (not model softmax).
- **Local + reputation merge**: reputation augments within caps; local analysis always runs.
- **`reputation_notice`**: exact fallback string when no reputation contributed (see implementation plan §5.6).

## 7. Signals (outline)

1. Headers (SPF/DKIM/DMARC parsing, conservative unknowns).
2. Sender drift (Reply-To vs From, display-name heuristics).
3. URLs (shorteners, literals, TLD / IDN risk).
4. Urgency lexicon (bounded false-positive awareness).
5. Attachment metadata only (no byte scanning).
6. Reputation overlays (Safe Browsing + VirusTotal).

## 8. External integrations (MVP)

- **Google Safe Browsing** and **VirusTotal** — env vars in `backend/.env.example`; ~2–3 s per provider timeouts and a global reputation budget (Phase 3).
- Graceful degradation with structured `reputation` objects and correct `reputation_notice` semantics.

## 9. Local development

### Backend (uvicorn)

```bash
cd backend
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
# Copy .env.example → .env and set GOOGLE_SAFE_BROWSING_API_KEY / VIRUSTOTAL_API_KEY if you want live lookups.
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

On startup the app loads **`backend/.env`** into the process environment (without overriding variables already exported in your shell). Reputation keys must use the exact names **`GOOGLE_SAFE_BROWSING_API_KEY`** and **`VIRUSTOTAL_API_KEY`**. If both are missing or empty, providers stay in status `skipped_no_api_key` and the card shows “disabled” labels until keys are set and the server is restarted.

**Verify live providers (optional):** with keys in `backend/.env` or your environment:

```bash
cd backend
set RUN_REPUTATION_LIVE=1
pytest src/tests/test_reputation_live.py -v
```

(PowerShell: `$env:RUN_REPUTATION_LIVE='1'`. Unix: `export RUN_REPUTATION_LIVE=1`.)

- Health: `GET /health`
- More detail: [backend/README.md](backend/README.md)

### Gmail add-on (clasp)

```bash
cd addon
npm install
copy .clasp.json.example .clasp.json   # Windows: copy; Unix: cp
# Edit .clasp.json → real scriptId from script.google.com
npm run clasp:login
npm run clasp:push
```

See [addon/README.md](addon/README.md) for Script properties and GCP / OAuth checklist.

### Formatting / testing

```bash
cd backend
pytest
```

(Linters/formatters can be added in a later phase; keep installs minimal for now.)

## 10. Deployment (HTTPS)

Pick one managed host that gives you TLS and a stable URL, for example:

- **Google Cloud Run** (fits GCP + Gmail OAuth story)
- **Fly.io** or **Render**

The add-on’s `BACKEND_BASE_URL` Script property must be the public `https://` origin (no trailing slash). Local-only dev against Gmail UI requires an **HTTPS tunnel** to your machine.

### Render: reputation API keys (optional)

In the Render dashboard: your **Web Service** → **Environment** → **Add Environment Variable**. Names must match the code exactly (copy-paste):

| Name | Required | Notes |
| --- | --- | --- |
| `GOOGLE_SAFE_BROWSING_API_KEY` | No | Google Cloud project with **Safe Browsing API** enabled; API key restriction “HTTP referrer” is usually wrong for a server — prefer IP or none for testing. |
| `VIRUSTOTAL_API_KEY` | No | VirusTotal v3 personal API key. |
| `HMAC_SECRET` | **Yes** (with `ENVIRONMENT=production`) | Must match add-on Script property; see [backend README](backend/README.md#production-hmac-environmentproduction). |
| `ENVIRONMENT` | **Set to `production`** on Render | Omit on laptop; forces HMAC secret presence so `/v1/score` is never unsigned. |

Redeploy or restart the service after changing environment variables. Nothing is persisted: providers receive **URLs only** for lookups (see [Privacy considerations](#5-privacy-considerations)).

#### Reputation troubleshooting (status strings)

Provider status values appear in the API under `reputation.providers` and in the Gmail card (human-readable labels). Common cases:

| Status | Meaning |
| --- | --- |
| `skipped_no_api_key` | That provider’s API key is not set in the server process. Set **`GOOGLE_SAFE_BROWSING_API_KEY`** and/or **`VIRUSTOTAL_API_KEY`** in `backend/.env` (local) or Render **Environment** (exact spelling), then restart. Scoring continues with local heuristics (and the other provider if configured). |
| `skipped_no_urls` | No URLs were extracted for reputation checks (empty list). |
| `error_timeout` | Outbound HTTP to the provider exceeded the client timeout (~2.5s). Other provider may still succeed; `reputation_notice` may be **partial**. |
| `error_http` | Non-success HTTP from the provider (includes **VirusTotal 429** quota). Safe Browsing and VT are queried independently where possible. |
| `error_invalid_response` | Response body was not usable JSON/shape; treated as provider failure, not a client bug. |

Local scoring (`POST /v1/score`) **always** runs; reputation failures only reduce or omit the reputation overlay and adjust `reputation_notice` — they do **not** return 5xx solely because a vendor failed.

Details: [backend/README.md](backend/README.md#reputation-providers-optional).

## 11. Gmail add-on setup (checklist)

1. Create a **Google Cloud** project; enable the Apps Script API if using clasp.
2. Link the Apps Script project to that GCP project for OAuth branding.
3. Configure **OAuth consent** (test users while in testing).
4. `clasp create` / `clasp clone` / push from `addon/`.
5. Set **Script properties** using `addon/script-properties.template`.
6. Install the add-on on your mailbox and verify the contextual card opens.

## 12. Environment variables

| Variable | Where | Required | Purpose |
| --- | --- | --- | --- |
| `ENVIRONMENT` | backend `.env`, Render | **Set `production` on public deploys** | When `production` / `prod`, `HMAC_SECRET` is **required** for `POST /v1/score` (503 if missing). Omit locally. |
| `HMAC_SECRET` | backend `.env`, Script property | Required when secret enforced | Shared signing secret; optional locally if `ENVIRONMENT` is unset |
| `GOOGLE_SAFE_BROWSING_API_KEY` | backend `.env` | Optional MVP | URL threat checks |
| `VIRUSTOTAL_API_KEY` | backend `.env` | Optional MVP | URL/domain reputation |
| `BACKEND_BASE_URL` | Script property | Yes for real calls | HTTPS API origin |
| `LOG_LEVEL`, `DEBUG_LOGGING` | backend `.env` | Optional | Logging hygiene |

Full template: `backend/.env.example`.

#### HMAC / add-on errors (demo)

| Symptom | What to check |
| --- | --- |
| Add-on shows HTTP **401** from backend | `HMAC_SECRET` set on Render but missing or wrong in Apps Script **Script properties**, or signature computed on different raw JSON than sent. |
| HTTP **503** from `/v1/score` | Render has `ENVIRONMENT=production` but `HMAC_SECRET` not set—add secret and redeploy. |
| Scoring works locally but fails on Render | Set `ENVIRONMENT=production` and matching secrets on Render; confirm `BACKEND_BASE_URL` uses the Render `https://` host. |

Full table: [backend/README.md — Troubleshooting (401 / 503)](backend/README.md#troubleshooting-401--503).

## 13. Trade-offs and limitations

Heuristic scoring only; marketing and IT mail can resemble phishing; bounded extracts miss deep HTML tricks; no attachment content analysis; vendor quotas and latency affect enrichment.

## 14. Demo walkthrough

**Production-style demo (Render + Gmail)**

1. Render Web Service: set `ENVIRONMENT=production`, `HMAC_SECRET` (long random), optional reputation keys, redeploy.
2. Apps Script **Script properties**: `BACKEND_BASE_URL` = your Render `https://…` origin; `HMAC_SECRET` = **same** value as Render.
3. `clasp push` the add-on; open a message in Gmail and confirm the score card loads.
4. `GET /health` should return 200 without auth (for uptime checks).

**Local rule-only dev**

1. Do **not** set `ENVIRONMENT=production`. Omit `HMAC_SECRET` on the backend to allow unsigned `POST /v1/score` for quick curls.

Scenarios to spot-check: **healthy reputation**, **partial provider outage**, **full reputation outage** (expect the `reputation_notice` local-only string when no reputation contributed).

---

## Repository layout

```text
upwind/
  README.md                 ← this file
  .gitignore
  docs/
    architecture.md
  addon/
    package.json            ← clasp via npm scripts
    .clasp.json.example
    script-properties.template
    src/
      appsscript.json
      Main.gs
      GmailClient.gs
      Features.gs
      ScoreCard.gs
      BackendClient.gs
      Config.gs
  backend/
    pyproject.toml
    README.md
    .env.example
    src/
      app/
        main.py
        routes_score.py
        schemas.py
        security.py
        limits.py
        constants.py
        scoring/…
        reputation/…
      tests/
        …
```

## Request `schema_version`

Clients send `schema_version` (currently **`1.1`**) in the JSON body; the server constant lives in `backend/src/app/constants.py`. Bump together when the DTO changes.
