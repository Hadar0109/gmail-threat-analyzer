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

    var raw = readOpenMessageForScoring_(event);
    var payload = buildScoreRequestPayload_(raw);
    var score = postScoreToBackend_(payload);
    return [buildScoreResultCard_(score)];
  } catch (err) {
    var msg = err && err.message ? err.message : String(err);
    return [buildErrorCard_('Could not score message', msg)];
  }
}
