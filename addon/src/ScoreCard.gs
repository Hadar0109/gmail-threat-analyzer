/**
 * Gmail add-on card UI — modern, compact, English-only presentation layer.
 * Scoring and explanation copy come from the backend API.
 */

/** Left-to-right mark — keeps layout consistent in RTL Gmail locales. */
var LTR_ = '\u200E';

var UI_TITLE = 'Email Safety Check';
var UI_MORE_DETAILS = 'More details';
var UI_RISK_SCORE = 'Risk score';
var UI_RESULT = 'Result';
var UI_WHY = 'Why we flagged this';

/** English detail group labels (never mixed-language). */
var DETAIL_GROUP_UI_ = {
  authentication: { emoji: '\uD83D\uDD12', label: 'Authentication' },
  link_checks: { emoji: '\uD83D\uDD17', label: 'Link checks' },
  signal_scores: { emoji: '\uD83D\uDCCA', label: 'Signal scores' }
};

/**
 * @param {string} text
 * @return {string}
 */
function ltrText_(text) {
  return LTR_ + String(text || '');
}

/**
 * @param {CardService.Icon} iconEnum
 * @return {GoogleAppsScript.Card_Service.IconImage}
 */
function cardIcon_(iconEnum) {
  return CardService.newIconImage().setIcon(iconEnum);
}

/**
 * @param {string} verdict
 * @return {{emoji: string, label: string, hint: string, icon: (*|CardService.Icon)}}
 */
function verdictVisual_(verdict) {
  var v = String(verdict || '').toLowerCase();
  if (v === 'safe' || v === 'low_risk') {
    return {
      emoji: '\u2705',
      label: 'Safe',
      hint: 'Low concern — looks okay based on our checks',
      icon: CardService.Icon.STAR
    };
  }
  if (v === 'suspicious') {
    return {
      emoji: '\u26A0\uFE0F',
      label: 'Suspicious',
      hint: 'Moderate concern — review before you click or reply',
      icon: CardService.Icon.DESCRIPTION
    };
  }
  if (v === 'dangerous') {
    return {
      emoji: '\uD83D\uDEA8',
      label: 'Dangerous',
      hint: 'High concern — be careful with links and attachments',
      icon: CardService.Icon.DESCRIPTION
    };
  }
  if (v === 'critical' || v === 'high_risk') {
    return {
      emoji: '\uD83D\uDD34',
      label: 'Critical',
      hint: 'Severe concern — avoid interacting with this message',
      icon: CardService.Icon.DESCRIPTION
    };
  }
  return {
    emoji: '\u2753',
    label: 'Unknown',
    hint: '',
    icon: CardService.Icon.NONE
  };
}

/**
 * @param {CardService.CardSection} section
 */
function addSpacer_(section) {
  section.addWidget(CardService.newTextParagraph().setText(ltrText_(' ')));
}

/**
 * @param {string} groupId
 * @param {string} fallbackLabel
 * @return {{emoji: string, label: string}}
 */
function detailGroupUi_(groupId, fallbackLabel) {
  var id = String(groupId || '').toLowerCase();
  if (DETAIL_GROUP_UI_[id]) {
    return DETAIL_GROUP_UI_[id];
  }
  return { emoji: '\u2022', label: String(fallbackLabel || 'Details') };
}

/**
 * @param {Object} score — parsed JSON from POST /score
 * @return {CardService.Card}
 */
function buildScoreResultCard_(score) {
  var explanation = score.explanation || {};
  var verdict = score.verdict || '';
  var visual = verdictVisual_(verdict);

  var header = CardService.newCardHeader()
    .setTitle(ltrText_(UI_TITLE))
    .setSubtitle(ltrText_('Analysis complete'));

  var main = CardService.newCardSection();

  // 1. Final result — large, color-coded via emoji + icon
  var resultWidget = CardService.newDecoratedText()
    .setTopLabel(ltrText_(UI_RESULT))
    .setText(ltrText_(visual.emoji + '  ' + visual.label))
    .setWrapText(true);
  if (visual.icon && visual.icon !== CardService.Icon.NONE) {
    resultWidget.setStartIcon(cardIcon_(visual.icon));
  }
  if (visual.hint) {
    resultWidget.setBottomLabel(ltrText_(visual.hint));
  }
  main.addWidget(resultWidget);

  addSpacer_(main);

  // 2. Risk score — compact, no extra lines
  main.addWidget(
    CardService.newKeyValue()
      .setTopLabel(ltrText_(UI_RISK_SCORE))
      .setContent(ltrText_(String(score.score != null ? score.score : '—')))
      .setBottomLabel(ltrText_('0 = lower concern, 100 = higher'))
  );

  // 3. Short explanation sentences
  var brief = explanation.brief_sentences || explanation.reasons || [];
  if (brief.length) {
    addSpacer_(main);
    main.addWidget(
      CardService.newDecoratedText()
        .setTopLabel(ltrText_(UI_WHY))
        .setText(ltrText_(' '))
    );
    var maxBrief = Math.min(brief.length, 3);
    for (var b = 0; b < maxBrief; b++) {
      main.addWidget(
        CardService.newDecoratedText()
          .setText(ltrText_('\u2022  ' + String(brief[b])))
          .setWrapText(true)
      );
    }
  }

  var builder = CardService.newCardBuilder().setHeader(header).addSection(main);

  // 4. More details — single collapsible, grouped subsections
  var groups = explanation.detail_groups || [];
  if (groups.length) {
    var details = CardService.newCardSection()
      .setHeader(ltrText_(UI_MORE_DETAILS))
      .setCollapsible(true);

    for (var g = 0; g < groups.length; g++) {
      var group = groups[g];
      if (!group || !group.items || !group.items.length) continue;

      var groupUi = detailGroupUi_(group.group_id, group.label);
      if (g > 0) {
        addSpacer_(details);
      }

      details.addWidget(
        CardService.newDecoratedText()
          .setText(ltrText_(groupUi.emoji + '  ' + groupUi.label))
          .setWrapText(true)
      );

      var maxItems = Math.min(group.items.length, 8);
      for (var i = 0; i < maxItems; i++) {
        details.addWidget(
          CardService.newDecoratedText()
            .setText(ltrText_('   \u2022  ' + String(group.items[i])))
            .setWrapText(true)
        );
      }
    }

    builder.addSection(details);
  }

  return builder.build();
}

/**
 * @param {string} title
 * @param {string} message
 * @return {CardService.Card}
 */
function buildErrorCard_(title, message) {
  var header = CardService.newCardHeader()
    .setTitle(ltrText_(title || 'Error'))
    .setSubtitle(ltrText_('Something went wrong'));

  var section = CardService.newCardSection();
  section.addWidget(
    CardService.newDecoratedText()
      .setStartIcon(cardIcon_(CardService.Icon.DESCRIPTION))
      .setText(ltrText_(String(message || 'Unknown error.')))
      .setWrapText(true)
  );

  return CardService.newCardBuilder().setHeader(header).addSection(section).build();
}

/** @deprecated Use verdictVisual_().label — kept for any legacy callers. */
function verdictLabel_(verdict) {
  return verdictVisual_(verdict).label;
}
