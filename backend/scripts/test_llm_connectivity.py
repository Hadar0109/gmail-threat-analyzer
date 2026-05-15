#!/usr/bin/env python3
"""
Isolated Gemini LLM connectivity check (no Gmail add-on).

From the backend/ directory:

  python scripts/test_llm_connectivity.py

Loads backend/.env, calls run_llm_analysis once, prints status and signal points.
Set GEMINI_API_KEY in .env or the shell. Optional: LLM_MODEL, LLM_TIMEOUT_SECONDS.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_BACKEND / "src"))

from app.constants import SCHEMA_VERSION  # noqa: E402
from app.env_bootstrap import load_backend_dotenv  # noqa: E402
from app.llm.provider import (  # noqa: E402
    _env_bool_opt_out,
    _gemini_model,
    _llm_timeout,
    _resolve_api_key,
    run_llm_analysis,
)
from app.reputation.guard import llm_cooldown_active, reset_reputation_guard_for_testing  # noqa: E402
from app.schemas import ScoreRequest  # noqa: E402
from app.scoring.signals_llm import evaluate_llm_signal  # noqa: E402
from app.scoring.types import SignalChunk  # noqa: E402
from app.reputation.providers import ReputationRunResult  # noqa: E402


def main() -> int:
    load_backend_dotenv()
    reset_reputation_guard_for_testing()

    enabled = _env_bool_opt_out("LLM_ANALYSIS_ENABLED")
    key = _resolve_api_key()
    model = _gemini_model()
    timeout = _llm_timeout()

    print("=== LLM connectivity probe ===")
    print(f"LLM_ANALYSIS_ENABLED: {enabled}")
    print(f"API key configured: {bool(key)} (len={len(key) if key else 0})")
    print(f"LLM_MODEL: {model}")
    print(f"LLM_TIMEOUT_SECONDS (read): {timeout.read}")
    print(f"LLM cooldown active (cleared for probe): {llm_cooldown_active()}")

    if not enabled:
        print("\nFAIL: LLM_ANALYSIS_ENABLED is off. Unset it or set to true.")
        return 1
    if not key:
        print("\nFAIL: No usable GEMINI_API_KEY / LLM_API_KEY in environment.")
        return 1

    req = ScoreRequest.model_validate(
        {
            "schema_version": SCHEMA_VERSION,
            "from_email": "probe@example.com",
            "subject": "Security alert: verify your account immediately",
            "snippet": "Your mailbox will be suspended. Click the link to confirm credentials.",
            "urls": ["https://example.com/signin"],
        },
    )

    result = run_llm_analysis(req)
    print(f"\nProvider status: {result.status}")
    print(f"Latency ms: {result.latency_ms}")
    if result.analysis:
        print(f"risk_points: {result.analysis.risk_points}")
        print(f"confidence: {result.analysis.confidence}")
        print(f"categories: {result.analysis.categories}")

    empty_chunks = {
        "headers": SignalChunk(0.0, ()),
        "sender": SignalChunk(0.0, ()),
        "urls": SignalChunk(0.0, ()),
        "urgency": SignalChunk(0.0, ()),
        "attachments": SignalChunk(0.0, ()),
        "reputation_overlay": SignalChunk(0.0, ()),
    }
    rep = ReputationRunResult(
        overlay_points=0.0,
        reasons=(),
        contributed=False,
        providers={},
        notice_kind="local_only",
    )
    contrib = evaluate_llm_signal(result, empty_chunks, rep)
    print(f"Scoring chunk points: {contrib.chunk.points}")
    print(f"LLM addon (weighted): {contrib.llm_addon:.2f}")

    if result.status == "ok" and contrib.chunk.points > 0:
        print("\nOK: LLM returned analysis and contributes to score.")
        return 0

    print(
        "\nCheck server logs for: llm_skip, llm_provider_failure, "
        "llm_parse_failure, gemini_call_debug",
    )
    print(json.dumps({"status": result.status, "model": result.model}, indent=2))
    return 2 if result.status != "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
