const mockMode = document.getElementById("mockMode");
const apiBaseUrl = document.getElementById("apiBaseUrl");
const saveBtn = document.getElementById("saveBtn");
const clearBtn = document.getElementById("clearBtn");
const status = document.getElementById("status");

async function init() {
  const saved = await chrome.storage.sync.get({
    useMockData: ADCTIR_CONFIG.USE_MOCK_DATA,
    apiBaseUrl: ADCTIR_CONFIG.API_BASE_URL
  });
  mockMode.checked = saved.useMockData;
  apiBaseUrl.value = saved.apiBaseUrl;
}

saveBtn.addEventListener("click", async () => {
  try {
    const parsed = new URL(apiBaseUrl.value);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Use an HTTP or HTTPS server address");
    if (!mockMode.checked && parsed.protocol === "https:" && !["localhost", "127.0.0.1"].includes(parsed.hostname)) {
      const granted = await chrome.permissions.request({ origins: [`${parsed.origin}/*`] });
      if (!granted) throw new Error("Permission to contact that server was not granted");
    }
    await chrome.storage.sync.set({
      useMockData: mockMode.checked,
      apiBaseUrl: parsed.origin
    });
    status.textContent = "Settings saved.";
  } catch (error) {
    status.textContent = error.message;
  }
});

clearBtn.addEventListener("click", async () => {
  await chrome.storage.session.clear();
  status.textContent = "Saved scan results cleared.";
});

init();
