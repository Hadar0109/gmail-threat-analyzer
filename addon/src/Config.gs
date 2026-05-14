/**
 * Script properties + request caps (must stay aligned with backend/src/app/limits.py).
 * @see ../script-properties.template
 */

var SCHEMA_VERSION_ = '1.0';
var HMAC_HEADER_NAME_ = 'X-Body-Signature';

var CAP_MESSAGE_ID_ = 256;
var CAP_THREAD_ID_ = 256;
var CAP_EMAIL_ = 320;
var CAP_DISPLAY_NAME_ = 256;
var CAP_SUBJECT_ = 998;
var CAP_SNIPPET_ = 4096;
var CAP_MAX_URLS_ = 64;
var CAP_URL_LEN_ = 2048;
var CAP_MAX_ATTACHMENTS_ = 32;
var CAP_FILENAME_ = 255;
var CAP_MIME_ = 128;
var CAP_AUTH_FIELD_ = 32;
/** Plain / HTML text window used only for URL discovery (not sent as body). */
var CAP_BODY_TEXT_FOR_URLS_ = 12000;

function getBackendBaseUrl_() {
  var v = PropertiesService.getScriptProperties().getProperty('BACKEND_BASE_URL');
  return v ? String(v).trim().replace(/\/+$/, '') : '';
}

function getHmacSecret_() {
  var v = PropertiesService.getScriptProperties().getProperty('HMAC_SECRET');
  return v ? String(v).trim() : '';
}
