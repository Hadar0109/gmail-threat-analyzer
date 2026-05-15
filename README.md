# Gmail Phishing Risk Analyzer

## Project overview

gmail-threat-analyzer is a Gmail add-on and FastAPI backend that analyzes opened email messages and returns a phishing risk score with a clear verdict and explanations.

When a user opens an email in Gmail, the add-on extracts a limited and bounded set of metadata from the message and sends it to the backend over HTTPS. The backend runs a deterministic phishing detection pipeline, calculates a score from 0–100, and returns a verdict together with human-readable explanations.

The add-on is advisory only. It does not block, delete, or modify emails.

---

## Main goals of the project

The main goals during development were:

* Build a phishing scoring system that produces meaningful and explainable results
* Reduce false positives for legitimate workflow and security emails
* Treat backend and API security as a first-class concern
* Design the system as if it were publicly exposed on the internet
* Keep the architecture modular and maintainable
* Present technical findings in a way normal users can understand

---

## How the system works

```text
Gmail → Gmail Add-on → FastAPI Backend → Scoring Engine → Reputation Providers → Verdict
```

### High-level flow

1. The user opens an email in Gmail
2. The Gmail add-on extracts:

   * sender information
   * subject
   * snippet
   * links
   * attachment metadata
   * authentication headers
3. The add-on signs the request using HMAC and sends it to the backend over HTTPS
4. The backend validates the request and runs phishing detection logic
5. Optional reputation providers are queried for URL reputation
6. The backend returns:

   * score (0–100)
   * verdict
   * explanations
   * technical details
7. The Gmail side panel displays the result

---

# How to run the project

The project contains two main parts:

* `backend/` — FastAPI phishing scoring service
* `addon/` — Gmail add-on UI

For the live Gmail demo, the backend must be reachable through a public HTTPS URL.

---

## 1. Run the backend locally

```bash
cd backend
python -m venv .venv
```

Activate the virtual environment:

```bash
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

# macOS / Linux
source .venv/bin/activate
```

Install dependencies and start the API:

```bash
pip install -e .
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Verify:

```bash
curl http://127.0.0.1:8000/health
```

Scoring endpoint:

```text
POST /score
```

---

## 2. Run with Docker

```bash
cd backend
docker build -t gmail-threat-analyzer .
docker run --rm -p 8000:8000 gmail-threat-analyzer
```

Verify:

```bash
curl http://127.0.0.1:8000/health
```

---

## 3. Deploy on Render

Create a Render Web Service from the `backend/` directory.

Required environment variables:

```text
ENVIRONMENT=production
HMAC_SECRET=<shared-secret>
```

Optional reputation keys:

```text
GOOGLE_SAFE_BROWSING_API_KEY=<optional>
VIRUSTOTAL_API_KEY=<optional>
```

After deployment:

```text
https://<your-service>.onrender.com/health
```

Use the Render URL as the backend URL inside the Gmail add-on.

---

## 4. Configure the Gmail add-on

```bash
cd addon
npm install
npm run clasp:login
npm run clasp:push
npm run clasp:open
```

In Apps Script, configure these Script Properties:

```text
BACKEND_BASE_URL=https://<your-render-service>.onrender.com
HMAC_SECRET=<same-secret-as-backend>
```

Then open Gmail and launch the add-on.

> Gmail cannot call localhost directly, so the add-on must use a public HTTPS backend.

---

## Scoring system

The backend calculates a final phishing risk score from 0–100.

### Verdict ranges

| Score  | Verdict    |
| ------ | ---------- |
| 0–28   | Safe       |
| 29–52  | Suspicious |
| 53–77  | Dangerous  |
| 78–100 | Critical   |

The score is built from several signal families.

---

## What the system checks

### Sender and authentication

The backend analyzes:

* SPF
* DKIM
* DMARC
* sender/domain mismatches
* suspicious reply-to behavior
* lookalike domains
* homoglyph attacks
* fake company impersonation

Examples:

* `paypa1.com`
* `micros0ft-login.com`
* sender claims to be Microsoft but domain is unrelated

---

### Links and URLs

The backend analyzes:

* external login links
* suspicious login-style paths
* shortened URLs
* non-HTTPS links
* punycode domains
* suspicious TLDs
* raw IP links
* nested redirect URLs

Optional reputation checks:

* Google Safe Browsing
* VirusTotal

---

### Phishing wording and urgency

The system checks for:

* fake security alerts
* account suspension threats
* password reset pressure
* urgent language
* credential requests
* invoice/payment scams
* delivery scams
* social engineering language

Examples:

* “Your account will be suspended within 24 hours”
* “Verify your account immediately”
* “Failure to act may result in account lock”

---

### Attachments

The backend checks attachment metadata for:

* executable files
* suspicious MIME types
* double extensions
* archive files
* misleading filenames
* script-like attachments

The system does not execute or sandbox files.

---

## Combo rules

The scoring engine also uses combination rules.

A single suspicious signal usually does not make an email malicious by itself.

Additional risk is added when multiple phishing indicators appear together.

Examples:

* urgency + external login link
* fake security alert + sender mismatch
* credential request + suspicious domain
* invoice wording + dangerous attachment

This helps the system behave more like real phishing analysis instead of simple keyword matching.

---

## Reducing false positives

Reducing false positives was a major focus during development.

The system attempts to avoid aggressively flagging legitimate:

* password reset emails
* workflow notifications
* invoice emails
* shipping updates
* company security alerts

The backend includes:

* sender-brand alignment
* legitimacy scoring
* workflow/platform recognition
* contextual scoring
* urgency dampening when authentication passes

Example:

A real GitHub or LinkedIn notification should not be treated the same as a fake login email from an unrelated domain.

---

## Explainability

The add-on displays:

* a final verdict
* a risk score
* short explanations for normal users
* a “More details” section for technical users

The explanation system merges duplicate findings and avoids exposing raw internal debug output.

Example user-facing explanations:

* “The sender could not be fully verified.”
* “Some links in this email may redirect to unsafe websites.”
* “This message creates urgency and pressure to make you act quickly.”

---

## Security and threat model

Because the backend is publicly exposed through Render, security was treated as a first-class concern.

The system was designed assuming:

* requests may be forged
* endpoints may be abused
* attackers may replay captured requests
* external URLs may be malicious
* logs/errors may accidentally leak sensitive information

---

## Security protections implemented

### HTTPS-only communication

The Gmail add-on communicates with the backend using HTTPS only.

---

### HMAC request signing

Requests are signed using HMAC-SHA256.

This helps ensure:

* the request originated from the add-on
* the body was not modified in transit

---

### Replay protection

The backend validates:

* request timestamps
* unique request IDs

This prevents attackers from capturing and replaying old requests repeatedly.

---

### URL sanitization

Before URLs are sent to external reputation providers:

* sensitive query parameters are removed
* malformed URLs are rejected
* internal/private IPs are blocked

This reduces privacy and SSRF-related risks.

---

### Rate limiting and payload limits

The backend applies:

* request rate limiting
* body size limits
* URL count limits
* bounded payload validation

This helps reduce abuse and denial-of-service risks.

---

### Privacy-focused design

The system does not:

* store full email contents
* store scan history
* store API secrets in code
* expose raw provider responses to users

Logs and error handling were hardened to avoid leaking sensitive information.

---

## External security providers

The backend optionally integrates with:

### Google Safe Browsing

Used for detecting known malicious URLs.

### VirusTotal

Used for URL reputation and malicious detections.

These integrations are optional.

If providers fail or API keys are missing, scoring still completes using local phishing detection logic.

---

## Project structure

```text
upwind/
├── addon/                 # Gmail add-on (Apps Script)
├── backend/               # FastAPI backend
│   ├── src/app/
│   │   ├── api/           # API routes and security
│   │   ├── scoring/       # phishing scoring engine
│   │   ├── reputation/    # Safe Browsing / VirusTotal
│   │   ├── explain/       # explanation system
│   │   └── bootstrap/
│   ├── Dockerfile
│   └── pyproject.toml
└── README.md
```

---

## Architecture decisions

Several important design decisions were made during development:

### Deterministic scoring

The system uses deterministic phishing heuristics.

This makes the scoring:

* explainable
* reproducible
* easier to debug
* easier to validate

---

### Explainability-first design

The system was designed to explain why an email looks suspicious instead of returning a black-box result.

---

### Stateless backend

The backend does not require a database and does not persist email data.

This simplifies deployment and reduces privacy risks.

---

### Docker and deployment simplicity

The backend was containerized using Docker and deployed through Render for easy public HTTPS access.

---

## Testing

Backend tests:

```bash
cd backend
pytest
```

Add-on contract tests:

```bash
cd addon
npm run test:contract
```

---

## Final notes

This project was designed as a security-focused Gmail phishing analysis system with an emphasis on:

* explainability
* security-aware backend design
* realistic phishing detection
* false-positive reduction
* modular architecture
* clean deployment and maintainability

The goal was not only to detect suspicious emails, but also to build a system that explains its decisions clearly while remaining secure and practical to deploy.
