import { API, showToast } from "./api.js";
import { setupNavigation } from "./nav.js";

document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation("settings");

  loadSettings();

  // Attach slider input listeners
  const sliders = ["wSize", "wTiming", "wVolume", "wBurst", "wTransport", "tHigh", "tModerate"];
  sliders.forEach(id => {
    document.getElementById(id)?.addEventListener("input", updateTotalWeights);
  });

  // Buttons
  document.getElementById("btnSaveSettings")?.addEventListener("click", handleSaveSettings);
  document.getElementById("btnResetSettings")?.addEventListener("click", handleResetSettings);
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
    showToast(`Failed to load settings: ${err.message}`, "error");
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

  const tH = getVal("tHigh");
  const tM = getVal("tModerate");

  const payload = {
    weights: {
      packet_size: wS,
      timing: wT,
      volume: wV,
      burst_jitter: wB,
      transport: wTr
    },
    thresholds: {
      high_confidence: tH,
      moderate_confidence: tM
    },
    tolerances: {
      size_decay_bytes: 350.0,
      timing_decay_ms: 60.0,
      volume_decay_count: 80.0,
      jitter_decay_ms: 25.0,
      burst_decay_len: 4.0
    },
    burst_ipt_threshold_ms: 20.0
  };

  try {
    await API.put("/api/settings", payload);
    showToast("Classifier weights and thresholds updated successfully!", "success");
  } catch (err) {
    showToast(`Failed to save settings: ${err.message}`, "error");
  }
}

async function handleResetSettings() {
  if (confirm("Reset classifier weights and thresholds to default values?")) {
    try {
      await API.put("/api/settings", { reset: true });
      showToast("Reset to factory defaults.", "info");
      loadSettings();
    } catch (err) {
      showToast(`Reset failed: ${err.message}`, "error");
    }
  }
}
