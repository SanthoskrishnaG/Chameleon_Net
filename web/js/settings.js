import { API, showToast } from "./api.js";
import { setupNavigation } from "./nav.js";
import { getApiBaseUrl, setApiBaseUrl, getApiKey, setApiKey, resetConfig } from "./config.js";

document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation("settings");

  loadSettings();
  initBackendConnection();

  // Attach slider input listeners
  const sliders = ["wSize", "wTiming", "wVolume", "wBurst", "wTransport", "tHigh", "tModerate"];
  sliders.forEach(id => {
    document.getElementById(id)?.addEventListener("input", updateTotalWeights);
  });

  // Buttons
  document.getElementById("btnSaveSettings")?.addEventListener("click", handleSaveSettings);
  document.getElementById("btnResetSettings")?.addEventListener("click", handleResetSettings);

  // Backend Connection Buttons
  document.getElementById("btnTestConnection")?.addEventListener("click", testBackendConnection);
  document.getElementById("btnSaveConnection")?.addEventListener("click", saveBackendConnection);
  document.getElementById("btnResetConnection")?.addEventListener("click", resetBackendConnection);
});

async function loadSettings() {
  try {
    const config = await API.get("/api/settings");
    const w = config.weights || {};
    const t = config.thresholds || {};

    setSlider("wSize", Math.round((w.packet_size || 0.25) * 100));
    setSlider("wTiming", Math.round((w.timing || 0.25) * 100));
    setSlider("wVolume", Math.round((w.volume || 0.15) * 100));
    setSlider("wBurst", Math.round((w.burst_jitter || 0.20) * 100));
    setSlider("wTransport", Math.round((w.transport || 0.15) * 100));

    setSlider("tHigh", Math.round(t.high_confidence || 80));
    setSlider("tModerate", Math.round(t.moderate_confidence || 50));

    updateTotalWeights();
  } catch (err) {
    showToast(`Failed to load classifier settings: ${err.message}`, "error");
  }
}

function setSlider(id, val) {
  const input = document.getElementById(id);
  const display = document.getElementById(`${id}Val`);
  if (input) input.value = val;
  if (display) display.innerText = `${val}%`;
}

function updateTotalWeights() {
  const getVal = (id) => {
    const el = document.getElementById(id);
    const disp = document.getElementById(`${id}Val`);
    const val = parseInt(el ? el.value : 0) || 0;
    if (disp) disp.innerText = `${val}%`;
    return val;
  };

  const wS = getVal("wSize");
  const wT = getVal("wTiming");
  const wV = getVal("wVolume");
  const wB = getVal("wBurst");
  const wTr = getVal("wTransport");

  getVal("tHigh");
  getVal("tModerate");

  const total = wS + wT + wV + wB + wTr;
  const totalEl = document.getElementById("totalWeightBadge");
  if (totalEl) {
    totalEl.innerText = `Total: ${total}%`;
    totalEl.className = total === 100 ? "badge badge-green" : "badge badge-amber";
  }
}

async function handleSaveSettings() {
  const getVal = (id) => parseInt(document.getElementById(id).value) || 0;

  const wS = getVal("wSize") / 100;
  const wT = getVal("wTiming") / 100;
  const wV = getVal("wVolume") / 100;
  const wB = getVal("wBurst") / 100;
  const wTr = getVal("wTransport") / 100;

  const tHigh = getVal("tHigh");
  const tMod = getVal("tModerate");

  if (Math.round((wS + wT + wV + wB + wTr) * 100) !== 100) {
    showToast("Total rule weight must equal exactly 100%.", "warning");
    return;
  }

  const payload = {
    weights: {
      packet_size: wS,
      timing: wT,
      volume: wV,
      burst_jitter: wB,
      transport: wTr
    },
    thresholds: {
      high_confidence: tHigh,
      moderate_confidence: tMod
    }
  };

  try {
    await API.put("/api/settings", payload);
    showToast("Classifier parameters updated successfully.", "success");
  } catch (err) {
    showToast(`Failed to update settings: ${err.message}`, "error");
  }
}

async function handleResetSettings() {
  if (!confirm("Reset all classifier weights and thresholds to laboratory factory defaults?")) {
    return;
  }

  try {
    const res = await API.put("/api/settings", { reset: true });
    loadSettings();
    showToast("Configuration reset to factory defaults.", "info");
  } catch (err) {
    showToast(`Reset failed: ${err.message}`, "error");
  }
}

// -----------------------------------------------------------------------------
// Backend Connection Management
// -----------------------------------------------------------------------------
function initBackendConnection() {
  const urlInput = document.getElementById("backendUrlInput");
  const keyInput = document.getElementById("apiKeyInput");
  if (urlInput) urlInput.value = getApiBaseUrl();
  if (keyInput) keyInput.value = getApiKey();
  checkCurrentBackend();
}

async function checkCurrentBackend() {
  const badge = document.getElementById("backendStatusBadge");
  try {
    const res = await API.get("/api/health");
    if (res && res.status === "online") {
      if (badge) {
        badge.innerText = "Connected (Online)";
        badge.className = "badge badge-green";
      }
    }
  } catch (err) {
    if (badge) {
      badge.innerText = "Offline / Unreachable";
      badge.className = "badge badge-amber";
    }
  }
}

async function testBackendConnection() {
  const urlInput = document.getElementById("backendUrlInput");
  const keyInput = document.getElementById("apiKeyInput");
  const testUrl = (urlInput ? urlInput.value.trim() : "").replace(/\/+$/, "");
  const testKey = keyInput ? keyInput.value.trim() : "";

  const box = document.getElementById("connectionDiagnosticBox");
  const textEl = document.getElementById("diagnosticText");
  const latencyEl = document.getElementById("latencyBadge");
  const badge = document.getElementById("backendStatusBadge");

  if (box) box.style.display = "block";
  if (textEl) textEl.innerText = "Pinging health endpoint at " + (testUrl || window.location.origin) + "...";
  if (latencyEl) latencyEl.innerText = "";

  const endpoint = testUrl ? `${testUrl}/api/health` : "/api/health";
  const t0 = performance.now();

  try {
    const headers = {};
    if (testKey) headers["X-API-Key"] = testKey;
    const res = await fetch(endpoint, { method: "GET", headers });
    const elapsed = Math.round(performance.now() - t0);

    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    const data = await res.json();
    if (textEl) {
      textEl.innerHTML = `<span style="color:var(--success);">✓ Connected</span> — ${data.engine || "Protocol Mimicry Engine"} (v${data.version || "1.0"}) | Loopback Guard: ${data.loopback_only ? "Active" : "Disabled"}`;
    }
    if (latencyEl) latencyEl.innerText = `Latency: ${elapsed}ms`;
    if (badge) {
      badge.innerText = "Connected (Online)";
      badge.className = "badge badge-green";
    }
    showToast(`Successfully connected to backend in ${elapsed}ms!`, "success");
  } catch (e) {
    if (textEl) {
      textEl.innerHTML = `<span style="color:#DC2626;">✕ Failed to connect:</span> ${e.message}`;
    }
    if (latencyEl) latencyEl.innerText = "";
    if (badge) {
      badge.innerText = "Offline / Error";
      badge.className = "badge badge-amber";
    }
    showToast(`Backend connection failed: ${e.message}`, "error");
  }
}

function saveBackendConnection() {
  const urlInput = document.getElementById("backendUrlInput");
  const keyInput = document.getElementById("apiKeyInput");
  const url = urlInput ? urlInput.value.trim() : "";
  const key = keyInput ? keyInput.value.trim() : "";

  setApiBaseUrl(url);
  setApiKey(key);
  showToast("Backend connection settings saved to browser storage.", "success");
  testBackendConnection();
}

function resetBackendConnection() {
  resetConfig();
  const urlInput = document.getElementById("backendUrlInput");
  const keyInput = document.getElementById("apiKeyInput");
  if (urlInput) urlInput.value = "";
  if (keyInput) keyInput.value = "";
  showToast("Backend connection reset to localhost defaults.", "info");
  testBackendConnection();
}
