/**
 * SPF/DKIM/DMARC parser checks (mirrors addon/src/Features.gs).
 * Run: node tests/auth_parse.test.js
 */

const assert = require('assert');

const CAP_AUTH_FIELD_ = 32;

function capString_(s, maxLen) {
  if (s === null || s === undefined) return '';
  const t = String(s);
  return t.length > maxLen ? t.substring(0, maxLen) : t;
}

function parseAuthenticationResults_(headerValue) {
  const out = { spf: null, dkim: null, dmarc: null };
  if (!headerValue) return out;
  const h = String(headerValue);

  function pickLast(tag) {
    const re = new RegExp('(?:^|[\\s;,])' + tag + '=([a-z]+)', 'gi');
    let mm;
    let last = null;
    while ((mm = re.exec(h)) !== null) {
      last = capString_(mm[1].toLowerCase(), CAP_AUTH_FIELD_);
    }
    return last;
  }

  out.spf = pickLast('spf') || pickLast('smtp\\.spf');
  out.dkim = pickLast('dkim');
  out.dmarc = pickLast('dmarc');

  if (!out.spf) {
    const rspf = h.match(/received-spf:\s*([a-z]+)/i);
    if (rspf) out.spf = capString_(rspf[1].toLowerCase(), CAP_AUTH_FIELD_);
  }

  return out;
}

const GMAIL_SAMPLE =
  'mx.google.com; dkim=pass header.i=@example.com header.s=20230601 header.b=abc; ' +
  'spf=pass (google.com: domain of user@example.com designates 209.85.128.52 as permitted sender) ' +
  'smtp.mailfrom=user@example.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com';

const parsed = parseAuthenticationResults_(GMAIL_SAMPLE);
assert.strictEqual(parsed.spf, 'pass');
assert.strictEqual(parsed.dkim, 'pass');
assert.strictEqual(parsed.dmarc, 'pass');

const arcSample =
  'i=1; mx.google.com; dkim=fail reason="signature verification failed"; ' +
  'spf=softfail (google.com: domain of x@evil.com does not designate ...) smtp.mailfrom=x@evil.com; ' +
  'dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=evil.com';
const arcParsed = parseAuthenticationResults_(arcSample);
assert.strictEqual(arcParsed.spf, 'softfail');
assert.strictEqual(arcParsed.dkim, 'fail');
assert.strictEqual(arcParsed.dmarc, 'fail');

const lastWins =
  'upstream.example.com; spf=pass; dkim=pass; dmarc=none\n' +
  'mx.google.com; spf=fail; dkim=pass; dmarc=pass';
const lastParsed = parseAuthenticationResults_(lastWins);
assert.strictEqual(lastParsed.spf, 'fail');
assert.strictEqual(lastParsed.dkim, 'pass');
assert.strictEqual(lastParsed.dmarc, 'pass');

const receivedOnly = 'Received-SPF: Pass (google.com: domain of a@b.com designates 1.2.3.4)';
const rspfParsed = parseAuthenticationResults_(receivedOnly);
assert.strictEqual(rspfParsed.spf, 'pass');
assert.strictEqual(rspfParsed.dkim, null);

console.log('auth_parse tests passed');
