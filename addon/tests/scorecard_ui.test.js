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

function formatRiskScorePercent(score) {
  if (score == null || score === '') {
    return '\u2014';
  }
  return String(Math.round(Number(score))) + '%';
}

function formatSignalScoreLine(label, value) {
  const pts = Math.round(Number(value));
  return `${label}: ${pts}/max`;
}

function buildSignalScoreLines(signals) {
  if (!signals) {
    return [];
  }
  const rows = [
    { key: 'headers', label: 'Headers' },
    { key: 'sender', label: 'Sender' },
    { key: 'urls', label: 'Links' },
    { key: 'urgency', label: 'Message content' },
    { key: 'attachments', label: 'Attachments' },
    { key: 'reputation_overlay', label: 'Link reputation' }
  ];
  const lines = [];
  for (const row of rows) {
    const value = signals[row.key];
    if (value == null) {
      continue;
    }
    const pts = Number(value);
    if (!pts || pts <= 0) {
      continue;
    }
    lines.push(formatSignalScoreLine(row.label, pts));
  }
  return lines;
}

const DETAIL_GROUP_UI = {
  authentication: { label: 'Authentication' },
  links: { label: 'Links' },
  attachments: { label: 'Attachments' },
  reputation: { label: 'Reputation' },
  signal_scores: { label: 'Signal scores' }
};

assert.strictEqual(verdictVisual('safe').label, 'Safe');
assert.strictEqual(verdictVisual('suspicious').emoji, '\u26A0\uFE0F');
assert.strictEqual(verdictVisual('critical').label, 'Critical');
assert.ok(DETAIL_GROUP_UI.authentication.label === 'Authentication');
assert.ok(!DETAIL_GROUP_UI.links.label.match(/[\u0590-\u05FF]/));

assert.strictEqual(formatRiskScorePercent(44), '44%');
assert.strictEqual(formatRiskScorePercent(44.6), '45%');
assert.strictEqual(formatRiskScorePercent(null), '\u2014');

assert.strictEqual(formatSignalScoreLine('Headers', 6), 'Headers: 6/max');
assert.strictEqual(formatSignalScoreLine('Sender', 55), 'Sender: 55/max');

const signalLines = buildSignalScoreLines({
  headers: 6,
  sender: 55,
  urls: 24,
  urgency: 38,
  attachments: 0,
  reputation_overlay: 0
});
assert.deepStrictEqual(signalLines, [
  'Headers: 6/max',
  'Sender: 55/max',
  'Links: 24/max',
  'Message content: 38/max'
]);

console.log('scorecard_ui tests passed');
