/**
 * Minimal Gmail card: checked → verdict → score → brief library sentences → More details.
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
  var header = CardService.newCardHeader()
    .setTitle('Email Safety Check')
    .setSubtitle(verdictLabel_(verdict));

  var main = CardService.newCardSection();

  // 1. Email checked
  main.addWidget(
    CardService.newTextParagraph().setText(
      String(explanation.checked_notice || 'This email was checked.')
    )
  );

  // 2. Main result — prominent verdict only
  main.addWidget(
    CardService.newDecoratedText()
      .setText(verdictLabel_(verdict))
      .setBottomLabel('Result')
  );

  // 3. Risk score — number only
  main.addWidget(
    CardService.newKeyValue()
      .setTopLabel('Risk score')
      .setContent(String(score.score != null ? score.score : '—'))
  );

  // 4. Short library sentences (why)
  var brief = explanation.brief_sentences || explanation.reasons || [];
  for (var b = 0; b < brief.length; b++) {
    main.addWidget(CardService.newTextParagraph().setText(String(brief[b])));
  }

  var builder = CardService.newCardBuilder().setHeader(header).addSection(main);

  // 5. More details — single collapsible section, technical only
  var sections = explanation.detail_sections || [];
  var moreSec = null;
  for (var s = 0; s < sections.length; s++) {
    if (sections[s] && sections[s].section_id === 'more_details') {
      moreSec = sections[s];
      break;
    }
  }
  if (!moreSec && sections.length === 1) {
    moreSec = sections[0];
  }

  if (moreSec && moreSec.items && moreSec.items.length) {
    var details = CardService.newCardSection()
      .setHeader(String(moreSec.label || 'More details'))
      .setCollapsible(true);
    var maxItems = Math.min(moreSec.items.length, 20);
    for (var i = 0; i < maxItems; i++) {
      details.addWidget(
        CardService.newTextParagraph().setText(String(moreSec.items[i].message || ''))
      );
    }
    builder.addSection(details);
  } else if (score.reputation_notice) {
    var repOnly = CardService.newCardSection()
      .setHeader('More details')
      .setCollapsible(true);
    repOnly.addWidget(CardService.newTextParagraph().setText(String(score.reputation_notice)));
    builder.addSection(repOnly);
  }

  return builder.build();
}

function buildErrorCard_(title, message) {
  var header = CardService.newCardHeader().setTitle(title || 'Error');
  var section = CardService.newCardSection();
  section.addWidget(CardService.newTextParagraph().setText(String(message || 'Unknown error.')));
  return CardService.newCardBuilder().setHeader(header).addSection(section).build();
}
