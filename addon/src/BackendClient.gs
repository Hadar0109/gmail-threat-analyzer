/**
 * HTTPS POST /v1/score with optional HMAC-SHA256 (hex) on the raw JSON body.
 */

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
    throw new Error('Backend returned HTTP ' + code + ': ' + text.substring(0, 800));
  }
  try {
    return JSON.parse(text);
  } catch (pe) {
    throw new Error('Backend returned non-JSON response.');
  }
}
