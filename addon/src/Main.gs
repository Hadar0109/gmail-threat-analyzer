/**
 * Gmail contextual trigger (appsscript.json → onTriggerFunction).
 *
 * @param {Object} event Open-message event from Gmail.
 * @return {CardService.Card[]}
 */
function onGmailMessageOpen(event) {
  try {
    if (!getBackendBaseUrl_()) {
      return [
        buildErrorCard_(
          'Configure backend',
          'Set Script property BACKEND_BASE_URL to your public https:// API origin (no trailing slash).'
        )
      ];
    }

    var raw;
    var payload;
    try {
      raw = readOpenMessageForScoring_(event);
      payload = buildScoreRequestPayload_(raw);
    } catch (readErr) {
      return [
        buildErrorCard_(
          'Could not score message',
          'This message could not be read for scoring. Try reopening it or pick another message.'
        )
      ];
    }

    var score;
    try {
      score = postScoreToBackend_(payload);
    } catch (httpErr) {
      var hm = httpErr && httpErr.message ? String(httpErr.message) : '';
      if (hm.indexOf('BACKEND_BASE_URL must') === 0) {
        return [
          buildErrorCard_(
            'Configure backend',
            'BACKEND_BASE_URL must be an https:// origin (Script properties).'
          )
        ];
      }
      return [buildErrorCard_('Could not score message', hm || 'Please try again later.')];
    }
    return [buildScoreResultCard_(score)];
  } catch (err) {
    return [
      buildErrorCard_(
        'Could not score message',
        'Something went wrong while scoring. Please try again.'
      )
    ];
  }
}
