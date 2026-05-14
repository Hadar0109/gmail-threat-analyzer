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
      .setBottomLabel('0–100 (backend)')
  );
  top.addWidget(
    CardService.newKeyValue().setTopLabel('Verdict').setContent(verdictLabel_(verdict))
  );
  top.addWidget(
    CardService.newKeyValue()
      .setTopLabel('Confidence')
      .setContent(score.confidence != null ? String(score.confidence) : '—')
  );

  var rep = CardService.newCardSection().setHeader('Reputation');
  rep.addWidget(
    CardService.newTextParagraph().setText(
      score.reputation_notice || 'No reputation notice was returned.'
    )
  );
  if (score.reputation && score.reputation.providers) {
    var prov = score.reputation.providers;
    var line =
      'Providers — Safe Browsing: ' +
      (prov.safe_browsing || '—') +
      ', VirusTotal: ' +
      (prov.virustotal || '—');
    rep.addWidget(CardService.newTextParagraph().setText(line));
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
