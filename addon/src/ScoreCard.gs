/**
 * Card Service UI for score results (backend is source of truth).
 */

function verdictLabel_(verdict) {
  var v = String(verdict || '').toLowerCase();
  if (v === 'safe') return 'Safe';
  if (v === 'suspicious') return 'Suspicious';
  if (v === 'dangerous') return 'Dangerous';
  if (v === 'critical') return 'Critical';
  // Legacy API values (older deployments)
  if (v === 'low_risk') return 'Safe';
  if (v === 'high_risk') return 'Critical';
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
    skipped_no_api_key: 'Provider disabled — missing server API key',
    skipped_no_urls: 'Skipped — no URLs to check',
    clean: 'Checked — no known threat match',
    threat: 'Checked — known threat match',
    malicious: 'Checked — strong malicious signals',
    suspicious: 'Checked — suspicious signals',
    not_found: 'Checked — no prior VT report',
    error_timeout: 'Provider timed out',
    error_http: 'Provider HTTP error or rate limit',
    error_rate_limited: 'Provider rate limit — try again later',
    error_invalid_response: 'Provider returned unusable data',
    skipped_budget: 'Reputation checks paused — service quota',
    skipped_cooldown: 'Reputation checks paused — cooling down after rate limit'
  };
  if (map[s]) return map[s];
  if (!status) return '—';
  return 'Provider status unavailable';
}

/**
 * @param {string} status
 * @return {string}
 */
function reputationSafeBrowsingLabel_(status) {
  if (String(status || '').toLowerCase() === 'skipped_no_api_key') {
    return 'Disabled — set GOOGLE_SAFE_BROWSING_API_KEY on the server';
  }
  return reputationProviderLabel_(status);
}

/**
 * @param {string} status
 * @return {string}
 */
function reputationVirusTotalLabel_(status) {
  if (String(status || '').toLowerCase() === 'skipped_no_api_key') {
    return 'Disabled — set VIRUSTOTAL_API_KEY on the server';
  }
  return reputationProviderLabel_(status);
}

/** User-safe note when LLM did not run but the score is still valid. */
var LLM_SKIPPED_SCORE_NOTE_ =
  ' LLM analysis was skipped, and the score is based on local heuristics and external reputation only.';

/**
 * Map backend LLM provider status codes to short user-facing labels.
 * Technical codes stay in the API; Gmail users see plain language only.
 * @param {string} status
 * @return {string}
 */
function llmAnalysisLabel_(status) {
  var s = String(status || '').toLowerCase();
  var map = {
    ok: 'Analyzed — contributed to score',
    skipped_disabled: 'LLM analysis is turned off on the server.' + LLM_SKIPPED_SCORE_NOTE_,
    skipped_no_api_key: 'LLM analysis is not configured on the server.' + LLM_SKIPPED_SCORE_NOTE_,
    skipped_cooldown:
      'Gemini LLM is temporarily paused after a quota limit.' + LLM_SKIPPED_SCORE_NOTE_,
    skipped_budget:
      'Gemini LLM usage limit for this period was reached.' + LLM_SKIPPED_SCORE_NOTE_,
    skipped_unsupported_backend:
      'LLM analysis is not available with the current server setup.' + LLM_SKIPPED_SCORE_NOTE_,
    error_timeout: 'Gemini LLM did not respond in time.' + LLM_SKIPPED_SCORE_NOTE_,
    error_http: 'Gemini LLM could not complete analysis.' + LLM_SKIPPED_SCORE_NOTE_,
    error_auth: 'Gemini LLM is not available (server configuration).' + LLM_SKIPPED_SCORE_NOTE_,
    error_rate_limited:
      'Gemini LLM quota was reached.' + LLM_SKIPPED_SCORE_NOTE_,
    error_invalid_response: 'Gemini LLM returned an unusable response.' + LLM_SKIPPED_SCORE_NOTE_,
    error_invalid_json: 'Gemini LLM returned an unusable response.' + LLM_SKIPPED_SCORE_NOTE_
  };
  if (map[s]) return map[s];
  if (!status) return '—';
  return 'LLM analysis was not used for this score.' + LLM_SKIPPED_SCORE_NOTE_;
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
      .setBottomLabel('0–100 (local + optional reputation + LLM)')
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
        .setContent(reputationSafeBrowsingLabel_(prov.safe_browsing))
    );
    rep.addWidget(
      CardService.newKeyValue()
        .setTopLabel('VirusTotal')
        .setContent(reputationVirusTotalLabel_(prov.virustotal))
    );
  }

  var llmSec = CardService.newCardSection().setHeader('LLM analysis (optional)');
  var llmMeta = score.llm_analysis;
  var llmStatus = llmMeta && llmMeta.status ? String(llmMeta.status) : '';
  var llmPoints =
    score.signals && score.signals.llm_analysis != null
      ? String(score.signals.llm_analysis)
      : '0';
  llmSec.addWidget(
    CardService.newKeyValue()
      .setTopLabel('Status')
      .setContent(llmAnalysisLabel_(llmStatus))
  );
  llmSec.addWidget(
    CardService.newKeyValue()
      .setTopLabel('LLM risk signal (0–100)')
      .setContent(llmPoints)
      .setBottomLabel('Raw model severity before engine weighting')
  );
  if (llmMeta && llmMeta.model) {
    llmSec.addWidget(
      CardService.newKeyValue().setTopLabel('Model').setContent(String(llmMeta.model))
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
    .addSection(llmSec)
    .addSection(reasonsSec)
    .build();
}

function buildErrorCard_(title, message) {
  var header = CardService.newCardHeader().setTitle(title || 'Error');
  var section = CardService.newCardSection();
  section.addWidget(CardService.newTextParagraph().setText(String(message || 'Unknown error.')));
  return CardService.newCardBuilder().setHeader(header).addSection(section).build();
}
