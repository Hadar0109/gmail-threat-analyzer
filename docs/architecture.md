# Architecture

This document expands on the root [README](../README.md) with the same high-level design. Detailed threat modeling and API contracts live in the README until Phase 6 polish. For an ordered production-style runbook (secrets, HMAC, external reputation), see [hardening-checklist.md](hardening-checklist.md).

## Components

1. **Gmail Add-on** (`addon/`) — Google Apps Script using Card Service; reads bounded Gmail data, calls the backend over HTTPS, renders score and explanations.
2. **Backend** (`backend/`) — Python FastAPI; validates input, runs local rule-based scoring, orchestrates reputation providers (Safe Browsing, VirusTotal), returns structured JSON.

## Request schema versioning

API requests include `schema_version` (currently `1.1`, see `backend/src/app/constants.py`). Breaking changes bump the version and are documented in the README.

## Diagram

See the Mermaid diagram in the README **Architecture** section.
