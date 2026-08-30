// ADCTIR extension configuration
// Sprint 1/2: no backend yet, so USE_MOCK_DATA stays true and analysis
// runs with a local rule-based stub that mirrors the real risk engine's
// expected inputs/outputs. When Member 3's API is ready, set
// USE_MOCK_DATA to false and point API_BASE_URL at the ASP.NET Core API.

const ADCTIR_CONFIG = {
  USE_MOCK_DATA: false,
  API_BASE_URL: "http://127.0.0.1:5001",
  REQUEST_TIMEOUT_MS: 8000,
  // Explanation runs retrieval plus synthesis, and synthesis may be a live
  // model call, so it gets a longer budget than a plain rules analysis.
  EXPLAIN_TIMEOUT_MS: 25000,
  ENDPOINTS: {
    SUBMIT_THREAT: "/api/threats",
    ANALYZE_THREAT: "/api/threats/analyze",
    EXPLAIN_THREAT: "/api/threats/explain"
  },
  async load() {
    const saved = await chrome.storage.sync.get({
      useMockData: this.USE_MOCK_DATA,
      apiBaseUrl: this.API_BASE_URL
    });
    this.USE_MOCK_DATA = saved.useMockData;
    this.API_BASE_URL = String(saved.apiBaseUrl || this.API_BASE_URL).replace(/\/$/, "");
    return this;
  }
};
