/**
 * Card Service UI for score results (backend is source of truth).
 */

function verdictLabel_(verdict) {
  var v = String(verdict || '').toLowerCase();
  if (v === 'high_risk') return 'High risk';
  if (v === 'suspicious') return 'Suspicious';
  if (v === 'low_risk') return 'Low risk';
  return verdict || 'Unknown';
}

/**
 * Map backend reputation provider status codes to short user-facing labels.
 * Raw codes remain available in API responses for operators.
 * @param {string} status
 * @return {string}
 */
function reputationProviderLabel_(status) {
  var s = String(status || '').toLowerCase();
  var map = {
    skipped_no_api_key: 'Skipped — no API key on server',
    skipped_no_urls: 'Skipped — no URLs to check',
    clean: 'Checked — no known threat match',
    threat: 'Checked — known threat match',
    malicious: 'Checked — strong malicious signals',
    suspicious: 'Checked — suspicious signals',
    not_found: 'Checked — no prior VT report',
    error_timeout: 'Provider timed out',
    error_http: 'Provider HTTP error or rate limit',
    error_invalid_response: 'Provider returned unusable data'
  };
  return map[s] || (status ? String(status) : '—');
}

/**
 * @param {Object} score — parsed JSON from POST /v1/score
 * @return {CardService.Card}
 */
function buildScoreResultCard_(score) {
  var header = CardService.newCardHeader().setTitle('Malicious Email Scorer');
  var verdict = score.verdict || '';
  header.setSubtitle(verdictLabel_(verdict));

  var top = CardService.newCardSection();
  top.addWidget(
    CardService.newKeyValue()
      .setTopLabel('Score')
      .setContent(String(score.score != null ? score.score : '—'))
      .setBottomLabel('0–100 (combined local + optional reputation)')
  );
  top.addWidget(
    CardService.newKeyValue().setTopLabel('Verdict').setContent(verdictLabel_(verdict))
  );
  top.addWidget(
    CardService.newKeyValue()
      .setTopLabel('Confidence')
      .setContent(score.confidence != null ? String(score.confidence) : '—')
  );

  var rep = CardService.newCardSection().setHeader('Link reputation (optional)');
  rep.addWidget(
    CardService.newTextParagraph().setText(
      score.reputation_notice ||
        'No reputation summary was returned. Local signals still determine the score above.'
    )
  );
  if (score.reputation && score.reputation.providers) {
    var prov = score.reputation.providers;
    rep.addWidget(
      CardService.newKeyValue()
        .setTopLabel('Google Safe Browsing')
        .setContent(reputationProviderLabel_(prov.safe_browsing))
    );
    rep.addWidget(
      CardService.newKeyValue()
        .setTopLabel('VirusTotal')
        .setContent(reputationProviderLabel_(prov.virustotal))
    );
  }

  var reasonsSec = CardService.newCardSection().setHeader('Reasons');
  var reasons = score.reasons || [];
  var maxR = Math.min(reasons.length, 12);
  for (var i = 0; i < maxR; i++) {
    reasonsSec.addWidget(
      CardService.newTextParagraph().setText('• ' + String(reasons[i]))
    );
  }
  if (!reasons.length) {
    reasonsSec.addWidget(CardService.newTextParagraph().setText('No reasons returned.'));
  }

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(top)
    .addSection(rep)
    .addSection(reasonsSec)
    .build();
}

function buildErrorCard_(title, message) {
  var header = CardService.newCardHeader().setTitle(title || 'Error');
  var section = CardService.newCardSection();
  section.addWidget(CardService.newTextParagraph().setText(String(message || 'Unknown error.')));
  return CardService.newCardBuilder().setHeader(header).addSection(section).build();
}
