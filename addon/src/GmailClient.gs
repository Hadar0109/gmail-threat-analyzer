/**
 * Bounded Gmail reads: GmailApp for message surface + Gmail API (Advanced) for auth headers.
 */

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

  snippet = String(snippet);
  if (snippet.length > 300) {
    snippet = snippet.substring(0, 300);
  }

  /** Small plain slice for URL extraction (avoid full MIME). */
  var plain = '';
  try {
    plain = msg.getPlainBody() || '';
  } catch (e) {
    plain = '';
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
  } catch (e2) {
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
