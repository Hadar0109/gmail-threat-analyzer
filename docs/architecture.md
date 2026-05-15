# Architecture

This document expands on the root [README](../README.md) with the same high-level design. Detailed threat modeling and API contracts live in the README and [hardening-checklist.md](hardening-checklist.md).

## Components

1. **Gmail Add-on** (`addon/`) — Google Apps Script using Card Service; reads bounded Gmail data, calls the backend over HTTPS, renders score and explanations.
2. **Backend** (`backend/`) — Python FastAPI; validates input, runs local rule-based scoring, orchestrates reputation providers (Safe Browsing, VirusTotal), returns structured JSON.

## Backend layout (`backend/src/app/`)

```text
app/
  main.py                 # FastAPI app, /health, includes score router
  constants.py            # SCHEMA_VERSION and shared constants
  schemas.py              # Pydantic request/response models
  limits.py               # Payload caps and rate limits
  bootstrap/
    env.py                # Loads backend/.env
  api/
    routes/score.py       # POST /score
    score_errors.py       # HTTP error shaping for score route
    score_logging.py      # Structured score-request logging
    security.py           # HMAC, replay protection, rate limit hooks
  scoring/
    engine.py             # score_message() public facade
    pipeline.py           # ScoringPipeline orchestration
    aggregate.py          # Weighted merge, caps, reputation floor
    legitimacy.py         # Trusted transactional dampening
    auth_band.py          # Authentication band (cycle isolation)
    weights.py            # Family weights and thresholds
    parsing/              # MessageFeatures and input normalization
    signals/              # Per-family evaluate_* detectors
      headers.py, sender.py, urls.py, attachments.py
      brand_impersonation.py
      content/            # Content/urgency tag detectors (patterns.py + categories)
    combos/               # Cross-signal combination rules
    data/                 # Brand/workflow JSON registries
  reputation/
    providers.py          # Orchestration (run_reputation_checks)
    safebrowsing.py, virustotal.py, guard.py, url_sanitizer.py
```

Fixture JSON: `backend/fixtures/scoring/{benign,phishing}/`, add-on contracts under `backend/fixtures/contract/addon/`.

Tests live in `backend/src/tests/` (for example `test_legitimacy.py`, `test_phishing_regressions.py`, `test_scoring_fixtures.py`).

## Request schema versioning

API requests include `schema_version` (currently `1.1`, see `backend/src/app/constants.py`). Breaking changes bump the version and are documented in the README.

## Diagram

See the Mermaid diagram in the README **Architecture** section.
