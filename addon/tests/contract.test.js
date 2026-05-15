/**
 * Add-on contract shape checks (run with: node tests/contract.test.js)
 * Mirrors backend ScoreRequest validation expectations.
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const FIXTURES = path.join(__dirname, '..', '..', 'backend', 'fixtures', 'contract', 'addon');

function load(name) {
  const raw = fs.readFileSync(path.join(FIXTURES, name), 'utf8');
  return JSON.parse(raw).payload;
}

function assertReplyToBareEmail(replyTo) {
  assert.ok(!replyTo.includes('<'), 'reply_to must be bare email, not angle-addr');
  assert.ok(replyTo.includes('@'), 'reply_to must contain @');
}

function assertRequiredFields(p) {
  assert.strictEqual(p.schema_version, '1.2');
  assert.ok(p.from_email && p.from_email.includes('@'));
  assert.ok(typeof p.subject === 'string');
  assert.ok(typeof p.snippet === 'string');
  assert.ok(Array.isArray(p.urls));
  assert.ok(Array.isArray(p.attachments));
}

const full = load('addon_full_1_2.json');
assertRequiredFields(full);
assertReplyToBareEmail(full.reply_to);
assert.ok(full.body_text_for_scoring.length >= full.snippet.length);
assert.ok(full.links.length >= 1);
assert.ok(full.content_flags.length >= 1);

const angle = load('addon_reply_to_angle_1_2.json');
assertReplyToBareEmail(angle.reply_to);
assert.strictEqual(angle.reply_to, 'payee@other.net');

console.log('addon contract tests passed');
