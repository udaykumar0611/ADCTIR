// ADCTIR API client.
// When ADCTIR_CONFIG.USE_MOCK_DATA is true, every call resolves locally
// with realistic mock data instead of hitting the network. Flip that flag
// once Member 3's ASP.NET Core API is deployed - the call sites in
// popup.js do not need to change.

function mockDelay(ms = 500) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function apiFetch(path, options = {}) {
  const { timeoutMs = ADCTIR_CONFIG.REQUEST_TIMEOUT_MS, ...fetchOptions } = options;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(ADCTIR_CONFIG.API_BASE_URL + path, {
      ...fetchOptions,
      headers: { "Content-Type": "application/json", ...(fetchOptions.headers || {}) },
      signal: controller.signal
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Server returned ${response.status}`);
    return body;
  } catch (error) {
    if (error.name === "AbortError") throw new Error("The ADCTIR server did not respond in time");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function analyzePage(indicators) {
  if (ADCTIR_CONFIG.USE_MOCK_DATA) {
    await mockDelay(250);
    return window.ADCTIR_RISK.scoreIndicators(indicators);
  }
  return apiFetch(ADCTIR_CONFIG.ENDPOINTS.ANALYZE_THREAT, {
    method: "POST",
    body: JSON.stringify({ indicators })
  });
}

// Retrieval-augmented explanation of an existing verdict. The knowledge corpus
// and any model call live on the server, so offline mock mode returns a plain
// restatement of the local score rather than pretending to have retrieved
// anything.
async function explainThreat(indicators) {
  if (ADCTIR_CONFIG.USE_MOCK_DATA) {
    await mockDelay(300);
    const local = window.ADCTIR_RISK.scoreIndicators(indicators);
    return {
      summary: `Offline mode: ${indicators.domain} scored ${local.risk_score} of 100 (${local.risk_level}) from the local rule stub. Start the ADCTIR API for a retrieval-grounded explanation.`,
      key_points: local.reasons.map((reason) => ({ point: reason, citation: null })),
      recommended_actions: [],
      confidence: "low",
      generator: "mock",
      model: null,
      passages: [],
      degraded_reason: "Offline demonstration mode - no knowledge corpus available"
    };
  }

  const body = await apiFetch(ADCTIR_CONFIG.ENDPOINTS.EXPLAIN_THREAT, {
    method: "POST",
    body: JSON.stringify({ indicators }),
    timeoutMs: ADCTIR_CONFIG.EXPLAIN_TIMEOUT_MS
  });
  return body.explanation;
}

async function submitThreatReport(indicators, riskResult) {
  if (ADCTIR_CONFIG.USE_MOCK_DATA) {
    await mockDelay();
    return {
      ok: true,
      threat_id: Math.floor(1000 + Math.random() * 9000),
      status: "received",
      message: "Mock submission accepted - no backend connected yet."
    };
  }

  return apiFetch(ADCTIR_CONFIG.ENDPOINTS.SUBMIT_THREAT, {
    method: "POST",
    body: JSON.stringify({ indicators, client_analysis: riskResult })
  });
}

window.ADCTIR_API = { analyzePage, explainThreat, submitThreatReport };
