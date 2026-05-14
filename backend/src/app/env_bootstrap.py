"""Load `backend/.env` into the process environment (local dev / single-container deploys)."""

from __future__ import annotations

from pathlib import Path


def load_backend_dotenv() -> None:
    """
    Read key=value pairs from `.env` next to `pyproject.toml` (the `backend/` directory).
    Does not override variables already set in the environment (Render, systemd, shell export).
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    backend_dir = Path(__file__).resolve().parents[2]
    load_dotenv(backend_dir / ".env", override=False)
