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

function formatKeyFinding_(finding) {
  if (!finding) return '';
  var lines = [String(finding.message || '')];
  if (finding.guidance) {
    lines.push(String(finding.guidance));
  }
  return lines.join('\n');
}

function buildScoreResultCard_(score) {
  var header = CardService.newCardHeader().setTitle('Email Safety Check');
  var verdict = score.verdict || '';
  header.setSubtitle(verdictLabel_(verdict));

  var main = CardService.newCardSection();
  main.addWidget(
    CardService.newKeyValue()
      .setTopLabel('Risk score')
      .setContent(String(score.score != null ? score.score : '—'))
      .setBottomLabel('0 = lower concern, 100 = higher concern')
  );
  main.addWidget(
    CardService.newKeyValue().setTopLabel('Result').setContent(verdictLabel_(verdict))
  );

  var explanation = score.explanation || {};
  var guidance = explanation.verdict_guidance || {};
  if (guidance.summary) {
    main.addWidget(CardService.newTextParagraph().setText(String(guidance.summary)));
  }

  var keyFindings = explanation.key_findings || [];
  if (keyFindings.length) {
    main.addWidget(CardService.newTextParagraph().setText('What stood out:'));
    var maxFindings = Math.min(keyFindings.length, 5);
    for (var f = 0; f < maxFindings; f++) {
      main.addWidget(
        CardService.newTextParagraph().setText('• ' + formatKeyFinding_(keyFindings[f]))
      );
    }
  } else if (explanation.reasons && explanation.reasons.length) {
    main.addWidget(CardService.newTextParagraph().setText('What stood out:'));
    var maxR = Math.min(explanation.reasons.length, 5);
    for (var r = 0; r < maxR; r++) {
      main.addWidget(
        CardService.newTextParagraph().setText('• ' + String(explanation.reasons[r]))
      );
    }
  }

  if (guidance.recommended_action) {
    main.addWidget(
      CardService.newTextParagraph().setText('Recommended: ' + String(guidance.recommended_action))
    );
  }

  var builder = CardService.newCardBuilder().setHeader(header).addSection(main);

  var detailSections = explanation.detail_sections || [];
  for (var s = 0; s < detailSections.length; s++) {
    var block = detailSections[s];
    if (!block || !block.items || !block.items.length) continue;
    var sec = CardService.newCardSection()
      .setHeader(String(block.label || 'More details'))
      .setCollapsible(true);
    var maxItems = Math.min(block.items.length, 10);
    for (var i = 0; i < maxItems; i++) {
      var item = block.items[i];
      var line = String(item.message || '');
      if (item.guidance) {
        line = line + '\n' + String(item.guidance);
      }
      sec.addWidget(CardService.newTextParagraph().setText(line));
    }
    builder.addSection(sec);
  }

  if (!detailSections.length && score.reputation_notice) {
    var repFallback = CardService.newCardSection()
      .setHeader('Link safety checks')
      .setCollapsible(true);
    repFallback.addWidget(
      CardService.newTextParagraph().setText(String(score.reputation_notice))
    );
    builder.addSection(repFallback);
  }

  return builder.build();
}

function buildErrorCard_(title, message) {
  var header = CardService.newCardHeader().setTitle(title || 'Error');
  var section = CardService.newCardSection();
  section.addWidget(CardService.newTextParagraph().setText(String(message || 'Unknown error.')));
  return CardService.newCardBuilder().setHeader(header).addSection(section).build();
}
