/**
 * Card Service UI for score results (backend is source of truth).
 */

function verdictLabel_(verdict) {
  var v = String(verdict || '').toLowerCase();
  if (v === 'safe') return 'Safe';
  if (v === 'suspicious') return 'Suspicious';
  if (v === 'dangerous') return 'Dangerous';
  if (v === 'critical') return 'Critical';
  if (v === 'low_risk') return 'Safe';
  if (v === 'high_risk') return 'Critical';
  return verdict || 'Unknown';
}

function severityLabel_(severity) {
  var s = String(severity || '').toLowerCase();
  if (s === 'low') return 'Low concern';
  if (s === 'medium') return 'Medium concern';
  if (s === 'high') return 'High concern';
  if (s === 'critical') return 'Critical concern';
  return '';
}

function reputationProviderLabel_(status) {
  var s = String(status || '').toLowerCase();
  var map = {
    skipped_no_api_key: 'Link checks not enabled on the server',
    skipped_no_urls: 'No links to check in this message',
    clean: 'Checked — no known unsafe links found',
    threat: 'Checked — unsafe link reported',
    malicious: 'Checked — strong malicious signals',
    suspicious: 'Checked — suspicious signals',
    not_found: 'Checked — no prior report for this link',
    error_timeout: 'Link check timed out',
    error_http: 'Link check unavailable (server error)',
    error_rate_limited: 'Link check paused — try again later',
    error_invalid_response: 'Link check returned unusable data',
    skipped_budget: 'Link checks paused — service quota',
    skipped_cooldown: 'Link checks paused — cooling down after rate limit'
  };
  if (map[s]) return map[s];
  if (!status) return '—';
  return 'Status unavailable';
}

function reputationSafeBrowsingLabel_(status) {
  if (String(status || '').toLowerCase() === 'skipped_no_api_key') {
    return 'Not enabled — ask your administrator to configure link safety checks';
  }
  return reputationProviderLabel_(status);
}

function reputationVirusTotalLabel_(status) {
  if (String(status || '').toLowerCase() === 'skipped_no_api_key') {
    return 'Not enabled — ask your administrator to configure link safety checks';
  }
  return reputationProviderLabel_(status);
}

function formatExplanationItem_(item) {
  if (!item) return '';
  var lines = [];
  var sev = severityLabel_(item.severity);
  if (sev) {
    lines.push('[' + sev + '] ' + String(item.message || ''));
  } else {
    lines.push(String(item.message || ''));
  }
  if (item.guidance) {
    lines.push('→ ' + String(item.guidance));
  }
  return lines.join('\n');
}

function buildScoreResultCard_(score) {
  var header = CardService.newCardHeader().setTitle('Email Safety Check');
  var verdict = score.verdict || '';
  header.setSubtitle(verdictLabel_(verdict));

  var top = CardService.newCardSection();
  top.addWidget(
    CardService.newKeyValue()
      .setTopLabel('Risk score')
      .setContent(String(score.score != null ? score.score : '—'))
      .setBottomLabel('0 = lower concern, 100 = higher concern')
  );
  top.addWidget(
    CardService.newKeyValue().setTopLabel('Result').setContent(verdictLabel_(verdict))
  );

  var explanation = score.explanation || {};
  var guidance = explanation.verdict_guidance || {};
  if (guidance.summary) {
    top.addWidget(CardService.newTextParagraph().setText(String(guidance.summary)));
  }
  if (guidance.recommended_action) {
    top.addWidget(
      CardService.newTextParagraph().setText('What to do: ' + String(guidance.recommended_action))
    );
  }

  var builder = CardService.newCardBuilder().setHeader(header).addSection(top);

  var groups = explanation.groups || [];
  var maxGroups = Math.min(groups.length, 6);
  for (var g = 0; g < maxGroups; g++) {
    var group = groups[g];
    var groupSec = CardService.newCardSection().setHeader(String(group.label || 'Details'));
    var items = group.items || [];
    var maxItems = Math.min(items.length, 5);
    for (var i = 0; i < maxItems; i++) {
      groupSec.addWidget(CardService.newTextParagraph().setText(formatExplanationItem_(items[i])));
    }
    builder.addSection(groupSec);
  }

  if (!groups.length) {
    var reasonsSec = CardService.newCardSection().setHeader('Why this was flagged');
    var reasons = (explanation.reasons && explanation.reasons.length)
      ? explanation.reasons
      : score.reasons || [];
    var maxR = Math.min(reasons.length, 12);
    for (var r = 0; r < maxR; r++) {
      reasonsSec.addWidget(
        CardService.newTextParagraph().setText('• ' + String(reasons[r]))
      );
    }
    if (!reasons.length) {
      reasonsSec.addWidget(
        CardService.newTextParagraph().setText('No specific reasons were returned.')
      );
    }
    builder.addSection(reasonsSec);
  }

  var rep = CardService.newCardSection().setHeader('Link safety checks (optional)');
  rep.addWidget(
    CardService.newTextParagraph().setText(
      score.reputation_notice ||
        'Link safety databases were not summarized. The score above still reflects patterns in the email.'
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

  return builder.addSection(rep).build();
}

function buildErrorCard_(title, message) {
  var header = CardService.newCardHeader().setTitle(title || 'Error');
  var section = CardService.newCardSection();
  section.addWidget(CardService.newTextParagraph().setText(String(message || 'Unknown error.')));
  return CardService.newCardBuilder().setHeader(header).addSection(section).build();
}
