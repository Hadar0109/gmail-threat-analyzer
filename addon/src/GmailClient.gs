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

function _headerMapFromPayload_(payload) {
  var map = {};
  var headers = (payload && payload.headers) || [];
  for (var i = 0; i < headers.length; i++) {
    var h = headers[i];
    if (h && h.name) map[String(h.name).toLowerCase()] = String(h.value || '');
  }
  return map;
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

  var authHeader = '';
  try {
    var meta = Gmail.Users.Messages.get('me', messageId, {
      format: 'metadata',
      metadataHeaders: ['Authentication-Results', 'ARC-Authentication-Results']
    });
    var headersMap = _headerMapFromPayload_(meta.payload);
    authHeader = headersMap['authentication-results'] || headersMap['arc-authentication-results'] || '';
  } catch (e4) {
    authHeader = '';
  }

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
