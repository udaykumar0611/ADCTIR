// ADCTIR content script
// Collects ONLY permitted, non-sensitive indicators about the current page.
// Never reads input values, passwords, or form contents.

function getRedirectCount() {
  try {
    const nav = performance.getEntriesByType("navigation")[0];
    if (nav && typeof nav.redirectCount === "number") return nav.redirectCount;
  } catch (e) {
    // performance API not available - fall back to 0
  }
  return 0;
}

function hasLoginForm() {
  // Presence-only check: is there a password field on the page?
  // We never read its value.
  return document.querySelectorAll('input[type="password"]').length > 0;
}

function detectSuspiciousPatterns(url) {
  const reasons = [];
  try {
    const u = new URL(url);
    const host = u.hostname;

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      reasons.push("Host is a raw IP address instead of a domain name");
    }
    if (host.startsWith("xn--") || host.includes(".xn--")) {
      reasons.push("Punycode / internationalized domain (possible lookalike)");
    }
    if ((host.match(/-/g) || []).length >= 3) {
      reasons.push("Domain contains an unusually high number of hyphens");
    }
    if (u.username || u.password || url.includes("@") && url.indexOf("@") < url.indexOf(host)) {
      reasons.push("URL contains embedded credentials before the host");
    }
    const subdomainCount = host.split(".").length - 2;
    if (subdomainCount >= 3) {
      reasons.push("Excessive number of subdomains");
    }
    if (u.protocol !== "https:") {
      reasons.push("Page is not served over HTTPS");
    }
    const sensitiveWords = ["login", "verify", "secure", "account", "update", "signin"];
    const wordHits = sensitiveWords.filter((w) => host.toLowerCase().includes(w));
    if (wordHits.length > 0) {
      reasons.push("Domain name contains sensitive-sounding keywords (" + wordHits.join(", ") + ")");
    }
  } catch (e) {
    reasons.push("Could not fully parse URL");
  }
  return reasons;
}

function collectIndicators() {
  const url = window.location.href;
  const u = new URL(url);

  return {
    url,
    domain: u.hostname,
    https_used: u.protocol === "https:",
    redirect_count: getRedirectCount(),
    has_login_form: hasLoginForm(),
    suspicious_pattern: detectSuspiciousPatterns(url).join("; ") || null,
    domain_age_days: null, // requires backend/whois lookup - not available client-side
    indicator_description: "Collected via ADCTIR browser extension (client-side, non-sensitive signals only)"
  };
}

if (!globalThis.__ADCTIR_CONTENT_READY__) {
  globalThis.__ADCTIR_CONTENT_READY__ = true;
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === "ADCTIR_COLLECT_INDICATORS") {
      sendResponse({ ok: true, indicators: collectIndicators() });
    }
  });
}
