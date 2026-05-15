/**
 * Minimal Gmail card: verdict (once) → score → brief sentences → grouped More details.
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

function buildScoreResultCard_(score) {
  var explanation = score.explanation || {};
  var verdict = score.verdict || '';
  var header = CardService.newCardHeader().setTitle('Email Safety Check');

  var main = CardService.newCardSection();

  // Final result — shown only once on the main card
  main.addWidget(
    CardService.newDecoratedText().setText(verdictLabel_(verdict))
  );

  main.addWidget(
    CardService.newKeyValue()
      .setTopLabel('Risk score')
      .setContent(String(score.score != null ? score.score : '—'))
  );

  var brief = explanation.brief_sentences || explanation.reasons || [];
  for (var b = 0; b < brief.length && b < 3; b++) {
    main.addWidget(CardService.newTextParagraph().setText(String(brief[b])));
  }

  var builder = CardService.newCardBuilder().setHeader(header).addSection(main);

  var groups = explanation.detail_groups || [];
  if (groups.length) {
    var details = CardService.newCardSection()
      .setHeader('More details')
      .setCollapsible(true);
    for (var g = 0; g < groups.length; g++) {
      var group = groups[g];
      if (!group || !group.items || !group.items.length) continue;
      details.addWidget(
        CardService.newTextParagraph().setText(String(group.label || ''))
      );
      var maxItems = Math.min(group.items.length, 8);
      for (var i = 0; i < maxItems; i++) {
        details.addWidget(
          CardService.newTextParagraph().setText('• ' + String(group.items[i]))
        );
      }
    }
    builder.addSection(details);
  }

  return builder.build();
}

function buildErrorCard_(title, message) {
  var header = CardService.newCardHeader().setTitle(title || 'Error');
  var section = CardService.newCardSection();
  section.addWidget(CardService.newTextParagraph().setText(String(message || 'Unknown error.')));
  return CardService.newCardBuilder().setHeader(header).addSection(section).build();
}
