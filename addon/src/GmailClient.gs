/**
 * Bounded Gmail reads: GmailApp for message surface + Gmail API (Advanced) for auth headers.
 */

function stripHtmlToText_(html) {
  if (!html) return '';
  var t = String(html);
  t = t.replace(/<script[\s\S]*?<\/script>/gi, ' ');
  t = t.replace(/<style[\s\S]*?<\/style>/gi, ' ');
  t = t.replace(/<br\s*\/?>/gi, '\n');
  t = t.replace(/<\/p>/gi, '\n');
  t = t.replace(/<[^>]+>/g, ' ');
  t = t.replace(/&nbsp;/gi, ' ');
  t = t.replace(/&amp;/gi, '&');
  t = t.replace(/&lt;/gi, '<');
  t = t.replace(/&gt;/gi, '>');
  t = t.replace(/\s+/g, ' ');
  return t.trim();
}

/** @return {string[]} non-empty Authentication-Results / ARC lines from a metadata payload */
function _authHeaderLinesFromPayload_(payload) {
  var out = [];
  var headers = (payload && payload.headers) || [];
  for (var i = 0; i < headers.length; i++) {
    var h = headers[i];
    if (!h || !h.name) continue;
    var n = String(h.name).toLowerCase();
    if (n === 'authentication-results' || n === 'arc-authentication-results') {
      var v = String(h.value || '').trim();
      if (v) out.push(v);
    }
  }
  return out;
}

/**
 * @param {GoogleAppsScript.Gmail.GmailMessage} msg
 * @param {string} headerName
 * @return {string}
 */
function _safeGetHeader_(msg, headerName) {
  try {
    var v = msg.getHeader(headerName);
    return v ? String(v).trim() : '';
  } catch (e) {
    return '';
  }
}

function _gmailAdvancedServiceAvailable_() {
  try {
    return !!(typeof Gmail !== 'undefined' && Gmail.Users && Gmail.Users.Messages && Gmail.Users.Messages.get);
  } catch (e) {
    return false;
  }
}

/**
 * Collect Authentication-Results text for SPF/DKIM/DMARC parsing.
 * Merges GmailApp.getHeader values with Gmail API metadata (all headers, no metadataHeaders filter).
 *
 * @param {GoogleAppsScript.Gmail.GmailMessage} msg
 * @param {string} messageId
 * @return {string}
 */
function collectAuthenticationHeaderText_(msg, messageId) {
  var parts = [];
  var seen = {};

  function addUnique(text) {
    if (!text) return;
    var t = String(text).trim();
    if (!t || seen[t]) return;
    seen[t] = 1;
    parts.push(t);
  }

  addUnique(_safeGetHeader_(msg, 'Authentication-Results'));
  addUnique(_safeGetHeader_(msg, 'ARC-Authentication-Results'));

  var receivedSpf = _safeGetHeader_(msg, 'Received-SPF');
  if (receivedSpf) addUnique('Received-SPF: ' + receivedSpf);

  if (_gmailAdvancedServiceAvailable_()) {
    try {
      var meta = Gmail.Users.Messages.get('me', messageId, { format: 'metadata' });
      var fromApi = _authHeaderLinesFromPayload_(meta.payload);
      for (var j = 0; j < fromApi.length; j++) addUnique(fromApi[j]);
    } catch (e3) {
      // Advanced Gmail service disabled or API error
    }
  }

  return parts.join('\n');
}

/**
 * @param {Object} event Gmail contextual trigger event
 * @return {Object} raw feature bundle for Features.buildScoreRequestPayload_
 */
function readOpenMessageForScoring_(event) {
  var g = event.gmail;
  if (!g || !g.messageId) {
    throw new Error('Missing gmail.messageId on event object.');
  }
  var messageId = String(g.messageId);
  var threadId = g.threadId ? String(g.threadId) : null;

  var msg = GmailApp.getMessageById(messageId);
  var fromHeader = msg.getFrom();
  var replyToHeader = msg.getReplyTo() || '';
  var subject = msg.getSubject() || '';
  var snippet = '';
  try {
    snippet = msg.getPlainBody() || '';
  } catch (e) {
    snippet = subject || '';
  }

  if (!snippet || String(snippet).trim().length < 40) {
    try {
      var htmlBody = msg.getBody() || '';
      var fromHtml = stripHtmlToText_(htmlBody);
      if (fromHtml.length > snippet.length) snippet = fromHtml;
    } catch (eHtml) {
      // keep plain snippet fallback
    }
  }

  snippet = String(snippet);
  if (snippet.length > CAP_SCORING_SNIPPET_) {
    snippet = snippet.substring(0, CAP_SCORING_SNIPPET_);
  }

  /** Small plain slice for URL extraction (avoid full MIME). */
  var plain = '';
  try {
    plain = msg.getPlainBody() || '';
  } catch (e2) {
    plain = '';
  }
  if (!plain || plain.length < 40) {
    try {
      var htmlForUrls = msg.getBody() || '';
      var plainFromHtml = stripHtmlToText_(htmlForUrls);
      if (plainFromHtml.length > plain.length) plain = plainFromHtml;
    } catch (e3) {
      // ignore
    }
  }
  if (plain.length > CAP_BODY_TEXT_FOR_URLS_) plain = plain.substring(0, CAP_BODY_TEXT_FOR_URLS_);

  var attachments = [];
  var atts = msg.getAttachments({
    includeInlineImages: false,
    includeAttachments: true,
    maxSize: 25 * 1024 * 1024
  });
  for (var j = 0; j < atts.length && j < CAP_MAX_ATTACHMENTS_; j++) {
    var att = atts[j];
    attachments.push({
      filename: att.getName() || 'attachment',
      mimeType: att.getContentType() || 'application/octet-stream',
      sizeBytes: typeof att.getSize === 'function' ? att.getSize() : null
    });
  }

  var authHeader = collectAuthenticationHeaderText_(msg, messageId);
  var authentication = parseAuthenticationResults_(authHeader);

  return {
    messageId: messageId,
    threadId: threadId,
    fromHeader: fromHeader,
    replyToHeader: replyToHeader,
    subject: subject,
    snippet: snippet,
    urlSourceText: plain,
    attachments: attachments,
    authentication: authentication
  };
}
