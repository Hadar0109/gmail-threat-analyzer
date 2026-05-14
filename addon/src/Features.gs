/**
 * Normalization, deduplication, and strict caps for POST /v1/score payloads.
 */

function capString_(s, maxLen) {
  if (s === null || s === undefined) return '';
  var t = String(s);
  if (t.length > maxLen) return t.substring(0, maxLen);
  return t;
}

function extractPrimaryEmail_(fromHeader) {
  if (!fromHeader) return '';
  var m = String(fromHeader).match(/<([^>\s]+)>/);
  if (m && m[1]) return m[1].trim().toLowerCase();
  var m2 = String(fromHeader).match(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/);
  return m2 ? m2[0].trim().toLowerCase() : '';
}

function extractDisplayName_(fromHeader) {
  if (!fromHeader) return '';
  var s = String(fromHeader).trim();
  var lt = s.indexOf('<');
  if (lt <= 0) return '';
  return s.substring(0, lt).replace(/^["']|["']$/g, '').trim();
}

function extractUrlsFromText_(text) {
  var out = [];
  var seen = {};
  if (!text) return out;
  var t = String(text);
  if (t.length > CAP_BODY_TEXT_FOR_URLS_) t = t.substring(0, CAP_BODY_TEXT_FOR_URLS_);
  var re = /https?:\/\/[^\s<>"']+/gi;
  var m;
  while ((m = re.exec(t)) !== null) {
    var u = m[0].replace(/[),.;]+$/, '');
    if (!u || u.length > CAP_URL_LEN_) continue;
    if (seen[u]) continue;
    seen[u] = 1;
    out.push(u);
    if (out.length >= CAP_MAX_URLS_) break;
  }
  return out;
}

function parseAuthenticationResults_(headerValue) {
  var out = { spf: null, dkim: null, dmarc: null };
  if (!headerValue) return out;
  var h = String(headerValue).toLowerCase();
  function pick(tag) {
    var re = new RegExp(tag + '=([a-z]+)', 'i');
    var mm = h.match(re);
    return mm ? capString_(mm[1], CAP_AUTH_FIELD_) : null;
  }
  out.spf = pick('spf');
  out.dkim = pick('dkim');
  out.dmarc = pick('dmarc');
  return out;
}

/**
 * @param {Object} raw — output from GmailClient.readOpenMessageForScoring_
 * @return {Object} plain object ready for JSON.stringify → ScoreRequest
 */
function buildScoreRequestPayload_(raw) {
  var fromEmail = extractPrimaryEmail_(raw.fromHeader);
  if (!fromEmail) fromEmail = 'unknown@invalid.local';

  var replyTo = raw.replyToHeader ? capString_(String(raw.replyToHeader).trim(), CAP_EMAIL_) : null;
  if (replyTo === '') replyTo = null;

  var displayName = extractDisplayName_(raw.fromHeader);
  displayName = displayName ? capString_(displayName, CAP_DISPLAY_NAME_) : null;
  if (displayName === '') displayName = null;

  var subject = capString_(raw.subject || '', CAP_SUBJECT_);
  var snippet = capString_(raw.snippet || '', CAP_SNIPPET_);

  var urls = extractUrlsFromText_(subject + '\n' + snippet + '\n' + (raw.urlSourceText || ''));

  var attachments = [];
  for (var i = 0; i < (raw.attachments || []).length && i < CAP_MAX_ATTACHMENTS_; i++) {
    var a = raw.attachments[i];
    var fn = capString_(a.filename || 'unnamed', CAP_FILENAME_);
    var mt = capString_(a.mimeType || 'application/octet-stream', CAP_MIME_);
    var row = { filename: fn, mime_type: mt };
    if (a.sizeBytes != null && a.sizeBytes >= 0) row.size_bytes = a.sizeBytes;
    attachments.push(row);
  }

  var auth = raw.authentication;
  var authentication =
    auth && (auth.spf || auth.dkim || auth.dmarc)
      ? {
          spf: auth.spf || null,
          dkim: auth.dkim || null,
          dmarc: auth.dmarc || null
        }
      : null;

  var payload = {
    schema_version: SCHEMA_VERSION_,
    message_id: raw.messageId ? capString_(raw.messageId, CAP_MESSAGE_ID_) : null,
    thread_id: raw.threadId ? capString_(raw.threadId, CAP_THREAD_ID_) : null,
    from_email: capString_(fromEmail, CAP_EMAIL_),
    reply_to: replyTo,
    display_name: displayName,
    subject: subject,
    snippet: snippet,
    urls: urls,
    attachments: attachments
  };
  if (authentication) payload.authentication = authentication;
  return payload;
}
