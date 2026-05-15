# Gmail add-on (Apps Script + clasp)

## Prerequisites

- Node.js 18+ (for `npm` / `npx`)
- A Google account and [clasp](https://github.com/google/clasp) (`npm install` in this folder installs `@google/clasp` locally)

## One-time setup

1. Create an Apps Script project at [script.google.com](https://script.google.com/) (standalone script), or run `npx clasp create --type standalone --title "Malicious Email Scorer"` from this directory.
2. Copy `.clasp.json.example` to `.clasp.json` and set `"scriptId"` to your project’s ID (Project Settings in the script editor).
3. Install dependencies:

```bash
cd addon
npm install
```

4. Authenticate clasp with your Google account:

```bash
npm run clasp:login
```

## Script properties (secrets + backend URL)

In the Apps Script editor: **Project Settings → Script properties**. Add keys from [script-properties.template](script-properties.template).

- `BACKEND_BASE_URL` must be a public **`https://`** origin (Gmail add-ons cannot call plain `http://` for production traffic). For local backend iteration, use an HTTPS reverse tunnel to `127.0.0.1:8000`.
- `HMAC_SECRET` must match the backend `HMAC_SECRET` once HMAC auth is enabled (Phase 4).

## Push / open

```bash
cd addon
npm run clasp:push
npm run clasp:open
```

`onGmailMessageOpen` reads the opened message (bounded), calls `POST /score` on `BACKEND_BASE_URL`, optional HMAC (`HMAC_SECRET`), and renders the backend verdict card. Advanced **Gmail API** (`Gmail` service) is enabled in `appsscript.json` for `Authentication-Results` headers only.

## GCP / OAuth (high level)

Link the script to a Google Cloud project, configure the **OAuth consent screen**, and add **test users** while the app is in testing. Exact clicks change in the Google Cloud console; keep least-privilege scopes aligned with `appsscript.json`.
