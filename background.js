// ADCTIR background service worker.
// Currently minimal - reserved for future work (badge updates, alarms,
// cross-tab caching of last risk result) once Sprint 2 backend is live.

chrome.runtime.onInstalled.addListener(() => {
  console.log("[ADCTIR] extension installed");
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== "ADCTIR_SET_BADGE") return;
  const level = message.level;
  const text = level === "High-Risk" ? "!!" : level === "Suspicious" ? "?" : "✓";
  const color = level === "High-Risk" ? "#dc2626" : level === "Suspicious" ? "#d97706" : "#15803d";
  chrome.action.setBadgeBackgroundColor({ color, tabId: message.tabId });
  chrome.action.setBadgeText({ text, tabId: message.tabId });
  sendResponse({ ok: true });
});
