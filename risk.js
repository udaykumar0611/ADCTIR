// ADCTIR mock risk engine (client-side stub for Sprint 1/2 demo).
// Mirrors the shape the real backend's POST /api/threats response is
// expected to return, so swapping in the live API later is a drop-in
// replacement - see api.js.

function scoreIndicators(indicators) {
  let score = 0;
  const reasons = [];

  if (!indicators.https_used) {
    score += 25;
    reasons.push("Connection is not using HTTPS");
  }
  if (indicators.has_login_form && !indicators.https_used) {
    score += 25;
    reasons.push("Login form present on a non-HTTPS page");
  }
  if (indicators.redirect_count >= 3) {
    score += 15;
    reasons.push(`Page was reached after ${indicators.redirect_count} redirects`);
  }
  if (indicators.suspicious_pattern) {
    const patternHits = indicators.suspicious_pattern
      .split(";")
      .map((pattern) => pattern.trim())
      .filter((pattern) => pattern && pattern !== "Page is not served over HTTPS");
    score += Math.min(patternHits.length * 12, 40);
    patternHits.forEach((p) => reasons.push(p.trim()));
  }

  score = Math.min(score, 100);

  let level = "Safe";
  if (score >= 60) level = "High-Risk";
  else if (score >= 25) level = "Suspicious";

  if (reasons.length === 0) {
    reasons.push("No suspicious indicators detected on this page");
  }

  return {
    risk_score: score,
    risk_level: level,
    reasons
  };
}

// Exposed for popup.js
window.ADCTIR_RISK = { scoreIndicators };
