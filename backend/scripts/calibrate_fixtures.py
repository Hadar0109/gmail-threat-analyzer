#!/usr/bin/env python3
"""Print per-fixture scoring breakdown for calibration."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running from repo root or backend/
_BACKEND = Path(__file__).resolve().parents[1]
_SRC = _BACKEND / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from app.scoring.auth_band import auth_band
from app.scoring.combos.context import build_scoring_context
from app.scoring.combos.evaluator import evaluate_combos
from app.scoring.engine import score_message
from app.scoring.signals.attachments import evaluate_attachments
from app.scoring.signals.brand_impersonation import evaluate_brand_impersonation
from app.scoring.signals.content import evaluate_urgency
from app.scoring.signals.headers import evaluate_headers
from app.scoring.signals.sender import evaluate_sender
from app.scoring.signals.urls import evaluate_urls
from app.scoring.types import SignalChunk
from tests.fixture_corpus import FIXTURES_ROOT, LabeledFixture, all_fixtures, iter_fixtures


def _chunks_for(req):  # noqa: ANN001
    brand_chunk, brand_findings = evaluate_brand_impersonation(req)
    chunks = {
        "headers": evaluate_headers(req),
        "sender": evaluate_sender(req),
        "brand": brand_chunk,
        "urls": evaluate_urls(req),
        "urgency": evaluate_urgency(req),
        "attachments": evaluate_attachments(req),
        "reputation_overlay": SignalChunk(0.0),
    }
    return chunks, brand_findings


def row_for(fixture: LabeledFixture) -> dict:
    req = fixture.request
    out = score_message(req)
    chunks, brand_findings = _chunks_for(req)
    ctx = build_scoring_context(req, chunks, brand_findings=brand_findings)
    combo = evaluate_combos(ctx)
    return {
        "id": fixture.id,
        "label": fixture.label,
        "score": out.score,
        "verdict": out.verdict.value,
        "expected_verdicts": sorted(v.value for v in fixture.expected_verdicts),
        "expected_score_min": fixture.expected_score_min,
        "expected_score_max": fixture.expected_score_max,
        "auth_band": auth_band(req),
        "signals": {
            "headers": out.signals.headers,
            "sender": out.signals.sender,
            "urls": out.signals.urls,
            "urgency": out.signals.urgency,
            "attachments": out.signals.attachments,
            "reputation_overlay": out.signals.reputation_overlay,
        },
        "tags": sorted(ctx.tags),
        "combo_boost": combo.boost,
        "combo_rules": list(combo.matched_rule_ids),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Fixture calibration report")
    parser.add_argument(
        "--write",
        type=Path,
        help="Write JSON snapshot (e.g. fixtures/scoring/baseline_scores.json)",
    )
    parser.add_argument(
        "--label",
        default="snapshot",
        help="Label stored in JSON output",
    )
    parser.add_argument("--category", choices=("phishing", "benign", "all"), default="all")
    args = parser.parse_args()

    if args.category == "all":
        fixtures = all_fixtures()
    else:
        fixtures = list(iter_fixtures(args.category))

    rows = [row_for(f) for f in fixtures]
    print(f"{'id':<32} {'score':>5} {'verdict':<12} {'expected':<8} note")
    for r in rows:
        exp = ",".join(r["expected_verdicts"])
        ok = r["verdict"] in r["expected_verdicts"]
        flag = "OK" if ok else "MISS"
        print(
            f"{r['id']:<32} {r['score']:>5} {r['verdict']:<12} "
            f"exp={exp:<24} {flag} combo={r['combo_boost']:.0f} tags={len(r['tags'])}",
        )

    if args.write:
        payload = {"label": args.label, "fixtures_root": str(FIXTURES_ROOT), "rows": rows}
        args.write.parent.mkdir(parents=True, exist_ok=True)
        args.write.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nWrote {args.write}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
