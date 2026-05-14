/**
 * HTTPS POST /v1/score with optional HMAC-SHA256 (hex) on the raw JSON body.
 * HTTP errors never echo raw response bodies to the Gmail UI.
 */

/**
 * @param {number} code
 * @param {string} bodyText
 * @return {string}
 */
function userFacingScoreHttpError_(code, bodyText) {
  var byStatus = {
    400: 'This message could not be scored. Reopen the message or try again.',
    401:
      'The scoring service could not verify this add-on. Ask an administrator to check Script properties and server configuration.',
    409: 'That action was already submitted. Wait a moment or open a different message.',
    413: 'This message is too large for the scorer to process.',
    422: 'The request could not be accepted. Try reopening the message.',
    429: 'Too many scoring attempts. Please wait and try again.',
    500: 'Scoring is temporarily unavailable. Please try again.',
    503: 'Scoring is temporarily unavailable. Please try again.'
  };
  var fallback = byStatus[code] || 'Could not score this message. Please try again later.';
  try {
    var j = JSON.parse(bodyText || '{}');
    var d = j.detail;
    if (d && typeof d === 'object' && d.message) return String(d.message);
  } catch (e) {}
  return fallback;
}

function postScoreToBackend_(payload) {
  var base = getBackendBaseUrl_();
  if (!base || base.indexOf('https://') !== 0) {
    throw new Error('BACKEND_BASE_URL must be an https:// origin (Script properties).');
  }
  var url = base + '/v1/score';
  var raw = JSON.stringify(payload);
  var headers = { 'Content-Type': 'application/json; charset=utf-8' };
  var secret = getHmacSecret_();
  if (secret) {
    var sigBytes = Utilities.computeHmacSha256Signature(raw, secret);
    headers[HMAC_HEADER_NAME_] = Utilities.bytesToHex(sigBytes).toLowerCase();
  }
  var resp = UrlFetchApp.fetch(url, {
    method: 'post',
    contentType: 'application/json; charset=utf-8',
    muteHttpExceptions: true,
    payload: raw,
    headers: headers,
    followRedirects: true,
    validateHttpsCertificates: true
  });
  var code = resp.getResponseCode();
  var text = resp.getContentText() || '';
  if (code !== 200) {
    throw new Error(userFacingScoreHttpError_(code, text));
  }
  try {
    return JSON.parse(text);
  } catch (pe) {
    throw new Error('Scoring returned an unexpected response. Please try again.');
  }
}
