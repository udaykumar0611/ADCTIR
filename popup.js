const els = {
  shieldMark: document.getElementById("shieldMark"),
  modeBadge: document.getElementById("modeBadge"),
  pageDomain: document.getElementById("pageDomain"),
  idleState: document.getElementById("idleState"),
  loadingState: document.getElementById("loadingState"),
  resultState: document.getElementById("resultState"),
  analyzeBtn: document.getElementById("analyzeBtn"),
  rescanBtn: document.getElementById("rescanBtn"),
  reportBtn: document.getElementById("reportBtn"),
  riskBadge: document.getElementById("riskBadge"),
  riskLevel: document.getElementById("riskLevel"),
  riskScore: document.getElementById("riskScore"),
  meterFill: document.getElementById("meterFill"),
  reasonsList: document.getElementById("reasonsList"),
  explainBtn: document.getElementById("explainBtn"),
  explainPanel: document.getElementById("explainPanel"),
  explainSummary: document.getElementById("explainSummary"),
  explainPoints: document.getElementById("explainPoints"),
  explainActionsBlock: document.getElementById("explainActionsBlock"),
  explainActions: document.getElementById("explainActions"),
  explainMeta: document.getElementById("explainMeta"),
  reportStatus: document.getElementById("reportStatus"),
  footerNote: document.getElementById("footerNote"),
  settingsBtn: document.getElementById("settingsBtn")
};

let currentIndicators = null;
let currentRiskResult = null;
let currentExplanation = null;

function setView(view) {
  els.idleState.hidden = view !== "idle";
  els.loadingState.hidden = view !== "loading";
  els.resultState.hidden = view !== "result";
  els.shieldMark.classList.toggle("scanning", view === "loading");
}

function levelToClass(level) {
  if (level === "Safe") return "level-safe";
  if (level === "Suspicious") return "level-suspicious";
  return "level-high-risk";
}

function levelToMeterColor(level) {
  if (level === "Safe") return "var(--safe)";
  if (level === "Suspicious") return "var(--suspicious)";
  return "var(--high-risk)";
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function collectIndicatorsFromTab(tabId) {
  const sendCollectionMessage = () => new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, { type: "ADCTIR_COLLECT_INDICATORS" }, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      if (!response || !response.ok) {
        reject(new Error("No response from content script"));
        return;
      }
      resolve(response.indicators);
    });
  });

  try {
    return await sendCollectionMessage();
  } catch {
    await chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] });
    return sendCollectionMessage();
  }
}

function describeGenerator(explanation) {
  if (explanation.generator === "mock") return "Offline demonstration mode.";

  const count = (explanation.passages || []).length;
  const retrieved = count ? `Retrieved ${count} reference passage${count === 1 ? "" : "s"}; ` : "";
  const writer = explanation.generator === "model"
    ? `written by ${explanation.model}.`
    : "written by the local rules explainer.";
  return retrieved + writer;
}

function renderExplanation(explanation) {
  currentExplanation = explanation;

  els.explainSummary.textContent = explanation.summary || "";

  els.explainPoints.innerHTML = "";
  (explanation.key_points || []).forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item.point;
    if (item.citation) {
      const cite = document.createElement("span");
      cite.className = "explain__cite";
      cite.textContent = item.citation;
      li.appendChild(cite);
    }
    els.explainPoints.appendChild(li);
  });

  const actions = explanation.recommended_actions || [];
  els.explainActions.innerHTML = "";
  actions.forEach((action) => {
    const li = document.createElement("li");
    li.textContent = action;
    els.explainActions.appendChild(li);
  });
  els.explainActionsBlock.hidden = actions.length === 0;

  els.explainMeta.classList.toggle("is-error", Boolean(explanation.degraded_reason));
  els.explainMeta.textContent = explanation.degraded_reason
    ? `${describeGenerator(explanation)} AI synthesis unavailable: ${explanation.degraded_reason}`
    : describeGenerator(explanation);

  els.explainPanel.hidden = false;
  els.explainBtn.hidden = true;
}

function resetExplanation() {
  currentExplanation = null;
  els.explainPanel.hidden = true;
  els.explainBtn.hidden = false;
  els.explainBtn.disabled = false;
  els.explainBtn.textContent = "Explain this result";
  els.explainMeta.classList.remove("is-error");
}

function renderResult(indicators, riskResult, explanation = null) {
  currentIndicators = indicators;
  currentRiskResult = riskResult;

  els.riskBadge.className = "risk-badge " + levelToClass(riskResult.risk_level);
  els.riskLevel.textContent = riskResult.risk_level;
  els.riskScore.textContent = riskResult.risk_score;

  els.meterFill.style.width = riskResult.risk_score + "%";
  els.meterFill.style.background = levelToMeterColor(riskResult.risk_level);

  els.reasonsList.innerHTML = "";
  riskResult.reasons.forEach((reason) => {
    const li = document.createElement("li");
    li.textContent = reason;
    els.reasonsList.appendChild(li);
  });

  els.reportStatus.hidden = true;
  els.reportStatus.textContent = "";
  els.reportBtn.disabled = false;
  els.reportBtn.textContent = "Report to ADCTIR";

  resetExplanation();
  if (explanation) renderExplanation(explanation);

  setView("result");
}

async function requestExplanation() {
  if (!currentIndicators) return;
  els.explainBtn.disabled = true;
  els.explainBtn.textContent = "Retrieving…";

  try {
    const explanation = await window.ADCTIR_API.explainThreat(currentIndicators);
    renderExplanation(explanation);
    const tab = await getActiveTab();
    if (tab) {
      await chrome.storage.session.set({
        [`tabResult:${tab.id}`]: { indicators: currentIndicators, riskResult: currentRiskResult, explanation }
      });
    }
  } catch (err) {
    els.explainBtn.disabled = false;
    els.explainBtn.textContent = "Retry explanation";
    els.explainPanel.hidden = false;
    els.explainSummary.textContent = "";
    els.explainPoints.innerHTML = "";
    els.explainActionsBlock.hidden = true;
    els.explainMeta.classList.add("is-error");
    els.explainMeta.textContent = "Couldn't explain this result: " + err.message;
  }
}

async function runAnalysis() {
  setView("loading");
  try {
    const tab = await getActiveTab();
    if (!tab || !tab.url || !/^https?:/.test(tab.url)) {
      throw new Error("This page cannot be analyzed (unsupported URL scheme)");
    }
    const indicators = await collectIndicatorsFromTab(tab.id);
    const riskResult = await window.ADCTIR_API.analyzePage(indicators);
    const enrichedIndicators = riskResult.indicators || indicators;
    renderResult(enrichedIndicators, riskResult);
    await chrome.storage.session.set({ [`tabResult:${tab.id}`]: { indicators: enrichedIndicators, riskResult } });
    chrome.runtime.sendMessage({ type: "ADCTIR_SET_BADGE", tabId: tab.id, level: riskResult.risk_level });
    els.footerNote.textContent = riskResult.engine_version
      ? `Analyzed by ${riskResult.engine_version}. No passwords or form contents were read.`
      : "Analyzed locally. No passwords or form contents were read.";
  } catch (err) {
    setView("idle");
    els.footerNote.textContent = "Couldn't analyze this page: " + err.message;
  }
}

async function submitReport() {
  if (!currentIndicators || !currentRiskResult) return;
  els.reportBtn.disabled = true;
  els.reportBtn.textContent = "Sending…";
  els.reportStatus.hidden = true;

  try {
    const result = await window.ADCTIR_API.submitThreatReport(currentIndicators, currentRiskResult);
    els.reportStatus.hidden = false;
    els.reportStatus.classList.remove("is-error");
    els.reportStatus.textContent =
      "Reported — threat #" + result.threat_id + (result.message ? " (" + result.message + ")" : "");
    els.reportBtn.textContent = "Reported ✓";
  } catch (err) {
    els.reportStatus.hidden = false;
    els.reportStatus.classList.add("is-error");
    els.reportStatus.textContent = "Report failed: " + err.message;
    els.reportBtn.disabled = false;
    els.reportBtn.textContent = "Retry report";
  }
}

async function init() {
  await ADCTIR_CONFIG.load();
  if (ADCTIR_CONFIG.USE_MOCK_DATA) {
    els.modeBadge.textContent = "mock mode";
    els.modeBadge.hidden = false;
  } else {
    els.modeBadge.hidden = true;
  }

  try {
    const tab = await getActiveTab();
    els.pageDomain.textContent = tab && tab.url ? new URL(tab.url).hostname : "unavailable";
    if (tab) {
      const saved = await chrome.storage.session.get(`tabResult:${tab.id}`);
      const previous = saved[`tabResult:${tab.id}`];
      if (previous) renderResult(previous.indicators, previous.riskResult, previous.explanation || null);
    }
  } catch (e) {
    els.pageDomain.textContent = "unavailable";
  }

  els.analyzeBtn.addEventListener("click", runAnalysis);
  els.rescanBtn.addEventListener("click", runAnalysis);
  els.explainBtn.addEventListener("click", requestExplanation);
  els.reportBtn.addEventListener("click", submitReport);
  els.settingsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());
}

document.addEventListener("DOMContentLoaded", init);
