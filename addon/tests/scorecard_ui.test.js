/**
 * ScoreCard UI helper tests (Node — mirrors Apps Script helpers).
 * Run: node tests/scorecard_ui.test.js
 */

const assert = require('assert');

// Mirror verdictVisual_ mapping from ScoreCard.gs
function verdictVisual(verdict) {
  const v = String(verdict || '').toLowerCase();
  if (v === 'safe' || v === 'low_risk') {
    return { emoji: '\u2705', label: 'Safe' };
  }
  if (v === 'suspicious') {
    return { emoji: '\u26A0\uFE0F', label: 'Suspicious' };
  }
  if (v === 'dangerous') {
    return { emoji: '\uD83D\uDEA8', label: 'Dangerous' };
  }
  if (v === 'critical' || v === 'high_risk') {
    return { emoji: '\uD83D\uDD34', label: 'Critical' };
  }
  return { emoji: '\u2753', label: 'Unknown' };
}

const DETAIL_GROUP_UI = {
  authentication: { label: 'Authentication' },
  link_checks: { label: 'Link checks' },
  signal_scores: { label: 'Signal scores' }
};

assert.strictEqual(verdictVisual('safe').label, 'Safe');
assert.strictEqual(verdictVisual('suspicious').emoji, '\u26A0\uFE0F');
assert.strictEqual(verdictVisual('critical').label, 'Critical');
assert.ok(DETAIL_GROUP_UI.authentication.label === 'Authentication');
assert.ok(!DETAIL_GROUP_UI.link_checks.label.match(/[\u0590-\u05FF]/));

console.log('scorecard_ui tests passed');
