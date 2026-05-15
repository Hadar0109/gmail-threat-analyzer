/**
 * Gmail add-on card UI — modern, compact, English-only presentation layer.
 * Scoring and explanation copy come from the backend API.
 */

/** Left-to-right mark — keeps layout consistent in RTL Gmail locales. */
var LTR_ = '\u200E';
var LRI_ = '\u2066';
var PDI_ = '\u2069';

var UI_TITLE = 'Email Safety Check';
var UI_MORE_DETAILS = 'More details';
var UI_RISK_SCORE = 'Risk score';

/** Signal breakdown labels and API field keys (presentation only). */
var SIGNAL_DISPLAY_ROWS_ = [
  { key: 'headers', label: 'Headers' },
  { key: 'sender', label: 'Sender' },
  { key: 'urls', label: 'Links' },
  { key: 'urgency', label: 'Message content' },
  { key: 'attachments', label: 'Attachments' },
  { key: 'reputation_overlay', label: 'Link reputation' }
];

/** English detail group labels (never mixed-language). */
var DETAIL_GROUP_UI_ = {
  authentication: { emoji: '\uD83D\uDD12', label: 'Authentication' },
  sender_identity: { emoji: '\uD83D\uDC64', label: 'Sender identity' },
  links: { emoji: '\uD83D\uDD17', label: 'Links' },
  link_checks: { emoji: '\uD83D\uDD17', label: 'Links' },
  attachments: { emoji: '\uD83D\uDCCE', label: 'Attachments' },
  reputation: { emoji: '\uD83D\uDEE1\uFE0F', label: 'Reputation' },
  signal_scores: { emoji: '\uD83D\uDCCA', label: 'Signal scores' }
};

/**
 * @param {string} text
 * @return {string}
 */
function ltrText_(text) {
  return LRI_ + LTR_ + String(text || '') + PDI_;
}

/**
 * @param {number|null|undefined} score
 * @return {string}
 */
function formatRiskScorePercent_(score) {
  if (score == null || score === '') {
    return '\u2014';
  }
  return String(Math.round(Number(score))) + '%';
}

/**
 * @param {string} label
 * @param {number} value
 * @return {string}
 */
function formatSignalScoreLine_(label, value) {
  var pts = Math.round(Number(value));
  return String(label) + ': ' + pts + '/max';
}

/**
 * @param {Object|null|undefined} signals
 * @return {string[]}
 */
function buildSignalScoreLines_(signals) {
  if (!signals) {
    return [];
  }
  var lines = [];
  for (var i = 0; i < SIGNAL_DISPLAY_ROWS_.length; i++) {
    var row = SIGNAL_DISPLAY_ROWS_[i];
    var value = signals[row.key];
    if (value == null) {
      continue;
    }
    var pts = Number(value);
    if (!pts || pts <= 0) {
      continue;
    }
    lines.push(formatSignalScoreLine_(row.label, pts));
  }
  return lines;
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
 * @param {Object} group
 * @param {Object} score
 * @return {string[]}
 */
function detailGroupItems_(group, score) {
  if (!group) {
    return [];
  }
  if (String(group.group_id || '').toLowerCase() === 'signal_scores') {
    return buildSignalScoreLines_(score.signals);
  }
  return group.items || [];
}

/**
 * @param {Object} score — parsed JSON from POST /score
 * @return {CardService.Card}
 */
function buildScoreResultCard_(score) {
  var explanation = score.explanation || {};
  var verdict = score.verdict || '';
  var visual = verdictVisual_(verdict);

  var header = CardService.newCardHeader().setTitle(ltrText_(UI_TITLE));

  var main = CardService.newCardSection();

  var resultWidget = CardService.newDecoratedText()
    .setText(ltrText_(visual.emoji + '  ' + visual.label))
    .setWrapText(true);
  if (visual.icon && visual.icon !== CardService.Icon.NONE) {
    resultWidget.setStartIcon(cardIcon_(visual.icon));
  }
  main.addWidget(resultWidget);

  addSpacer_(main);

  main.addWidget(
    CardService.newKeyValue()
      .setTopLabel(ltrText_(UI_RISK_SCORE))
      .setContent(ltrText_(formatRiskScorePercent_(score.score)))
  );

  var brief = explanation.brief_sentences || explanation.reasons || [];
  if (brief.length) {
    addSpacer_(main);
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

  var groups = explanation.detail_groups || [];
  var detailGroups = [];
  for (var gi = 0; gi < groups.length; gi++) {
    var items = detailGroupItems_(groups[gi], score);
    if (items.length) {
      detailGroups.push({ group: groups[gi], items: items });
    }
  }

  if (detailGroups.length) {
    var details = CardService.newCardSection();
    details.addWidget(
      CardService.newCollapseControl().setText(ltrText_(UI_MORE_DETAILS))
    );

    for (var g = 0; g < detailGroups.length; g++) {
      var entry = detailGroups[g];
      var group = entry.group;
      var groupItems = entry.items;

      var groupUi = detailGroupUi_(group.group_id, group.label);
      if (g > 0) {
        addSpacer_(details);
      }

      details.addWidget(
        CardService.newDecoratedText()
          .setText(ltrText_(groupUi.emoji + '  ' + groupUi.label))
          .setWrapText(true)
      );

      var maxItems = Math.min(groupItems.length, 8);
      for (var i = 0; i < maxItems; i++) {
        details.addWidget(
          CardService.newDecoratedText()
            .setText(ltrText_('   \u2022  ' + String(groupItems[i])))
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
  var header = CardService.newCardHeader().setTitle(ltrText_(title || 'Error'));

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
