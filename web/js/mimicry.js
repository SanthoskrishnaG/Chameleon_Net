import { API, showToast } from "./api.js";
import { setupNavigation } from "./nav.js";

let currentExpId = null;
let selectedProfileId = "voip_call";
let profilesMap = {};
let originalExperiment = null;

document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation("mimicry");

  const urlParams = new URLSearchParams(window.location.search);
  currentExpId = urlParams.get("id");

  if (!currentExpId) {
    try {
      const expRes = await API.get("/api/experiments");
      if (expRes.experiments && expRes.experiments.length > 0) {
        currentExpId = expRes.experiments[0].id;
      }
    } catch (e) {
      console.error(e);
    }
  }

  // Load profiles
  try {
    const profRes = await API.get("/api/profiles");
    profilesMap = profRes.map || {};
    renderProfileCards(profRes.profiles || []);
  } catch (e) {
    console.error("Profiles load error:", e);
  }

  // Load original experiment
  if (currentExpId) {
    loadExperiment(currentExpId);
  } else {
    showEmptyState();
  }

  // Slider events
  document.getElementById("jitterSlider")?.addEventListener("input", (e) => {
    document.getElementById("jitterValDisplay").innerText = `${e.target.value} ms`;
    updatePreview();
  });

  document.getElementById("burstSlider")?.addEventListener("input", (e) => {
    document.getElementById("burstValDisplay").innerText = `${e.target.value} pkts`;
    updatePreview();
  });

  // Toggle events
  document.getElementById("paddingToggle")?.addEventListener("change", updatePreview);
  document.getElementById("timingToggle")?.addEventListener("change", updatePreview);
  document.getElementById("burstToggle")?.addEventListener("change", updatePreview);
  document.getElementById("transportSelect")?.addEventListener("change", updatePreview);

  // Apply button
  document.getElementById("btnApplyMimicry")?.addEventListener("click", handleApplyMimicry);
});

async function loadExperiment(expId) {
  try {
    document.getElementById("expIdBadge").innerText = expId;
    const exp = await API.get(`/api/experiments/${expId}`);
    originalExperiment = exp;

    // Show baseline info
    const bFeat = exp.features_before || {};
    const bClass = exp.classification_before || {};
    document.getElementById("baselineSummary").innerHTML = `
      <strong>Baseline Flow:</strong> ${bClass.category_name || "Unknown"} (${bClass.confidence || 0}%) | 
      Mean Size: ${bFeat.mean_size || 0} B | Mean Cadence: ${bFeat.mean_ipt_ms || 0} ms | Protocol: ${bFeat.protocol || "TCP"}
    `;

    updatePreview();
  } catch (e) {
    // If not in experiment store, load features
    try {
      const featRes = await API.get(`/api/features/${expId}`);
      originalExperiment = { id: expId, features_before: featRes.features_before };
      updatePreview();
    } catch (err) {
      showEmptyState();
    }
  }
}

function renderProfileCards(profiles) {
  const container = document.getElementById("profileCardsGrid");
  if (!container) return;

  container.innerHTML = profiles.map(p => `
    <div class="card profile-select-card ${p.id === selectedProfileId ? 'selected' : ''}" 
         data-id="${p.id}" 
         style="cursor:pointer; border:2px solid ${p.id === selectedProfileId ? 'var(--primary)' : 'var(--border)'}; padding:16px;">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
        <strong style="color:var(--text); font-size:14px;">${p.name}</strong>
        <span class="badge ${p.transport === 'TCP' ? 'badge-blue' : 'badge-amber'}">${p.transport}</span>
      </div>
      <p style="font-size:12px; color:var(--text-muted); margin-bottom:10px; line-height:1.4;">${p.description}</p>
      <div style="font-size:11px; color:var(--text-muted); background:var(--surface-alt); padding:8px; border-radius:6px;">
        Target Size: <strong>${p.target_size} B</strong> | IPT: <strong>${p.target_ipt_ms} ms</strong> | Jitter: <strong>${p.target_jitter_ms} ms</strong>
      </div>
    </div>
  `).join("");

  document.querySelectorAll(".profile-select-card").forEach(el => {
    el.addEventListener("click", () => {
      document.querySelectorAll(".profile-select-card").forEach(c => {
        c.classList.remove("selected");
        c.style.borderColor = "var(--border)";
      });
      el.classList.add("selected");
      el.style.borderColor = "var(--primary)";
      selectedProfileId = el.getAttribute("data-id");
      updatePreview();
    });
  });
}

function updatePreview() {
  const target = profilesMap[selectedProfileId];
  if (!target || !originalExperiment) return;

  const bFeat = originalExperiment.features_before || {};
  const usePadding = document.getElementById("paddingToggle")?.checked;
  const useTiming = document.getElementById("timingToggle")?.checked;
  const useBurst = document.getElementById("burstToggle")?.checked;

  const predSize = usePadding ? target.target_size : bFeat.mean_size;
  const predIPT = useTiming ? target.target_ipt_ms : bFeat.mean_ipt_ms;

  document.getElementById("previewOriginalSize").innerText = `${bFeat.mean_size || "-"} B`;
  document.getElementById("previewTargetSize").innerText = `${predSize} B`;

  document.getElementById("previewOriginalIPT").innerText = `${bFeat.mean_ipt_ms || "-"} ms`;
  document.getElementById("previewTargetIPT").innerText = `${predIPT} ms`;

  // Limitation preview
  const transportMode = document.getElementById("transportSelect")?.value || "keep_original";
  const limitationBox = document.getElementById("transportLimitationNotice");
  if (limitationBox) {
    if (transportMode === "keep_original" && bFeat.protocol && bFeat.protocol !== target.transport) {
      limitationBox.classList.remove("hidden");
      limitationBox.innerHTML = `
        <strong>Honest Protocol Limitation:</strong> Baseline traffic uses ${bFeat.protocol}, but target '${target.name}' 
        is defined on ${target.transport}. Without transport conversion, DPI rule 5 will detect the transport mismatch.
      `;
    } else {
      limitationBox.classList.add("hidden");
    }
  }
}

async function handleApplyMimicry() {
  const btn = document.getElementById("btnApplyMimicry");
  if (btn) btn.disabled = true;

  const usePadding = document.getElementById("paddingToggle").checked;
  const useTiming = document.getElementById("timingToggle").checked;
  const useBurst = document.getElementById("burstToggle").checked;
  const customJitter = parseFloat(document.getElementById("jitterSlider").value);
  const customBurst = parseFloat(document.getElementById("burstSlider").value);
  const transportMode = document.getElementById("transportSelect").value;

  showToast("Re-transmitting reshaped traffic over 127.0.0.1 sockets...", "info");

  try {
    const res = await API.post("/api/mimicry/apply", {
      id: currentExpId,
      target_profile: selectedProfileId,
      toggles: {
        padding: usePadding,
        timing: useTiming,
        burst: useBurst
      },
      custom_jitter_ms: customJitter,
      custom_burst_len: customBurst,
      transport_mode: transportMode,
      original_text: originalExperiment?.text_info?.preview || originalExperiment?.config?.custom_text
    });

    showToast("Mimicry transformation and loopback re-transmission complete!", "success");
    renderMimicryResults(res);

  } catch (err) {
    showToast(`Mimicry failed: ${err.message}`, "error");
  } finally {
    if (btn) btn.disabled = false;
  }
}

function renderMimicryResults(res) {
  const container = document.getElementById("resultsContainer");
  if (!container) return;
  container.classList.remove("hidden");

  const ovh = res.mimicry_result.overhead || {};
  document.getElementById("extraBytesMeter").innerText = `+${ovh.extra_bytes_percent}%`;
  document.getElementById("addedDelayMeter").innerText = `+${ovh.added_delay_percent}%`;
  document.getElementById("throughputMeter").innerText = `${ovh.throughput_change_percent}%`;

  // Deception Verdict
  const comp = res.comparison || {};
  const verdictEl = document.getElementById("mimicryVerdictBanner");
  if (verdictEl) {
    verdictEl.className = `verdict-banner ${comp.banner_type || 'warning'}`;
    verdictEl.innerHTML = `
      <span style="font-size:20px;">${comp.fooled_target ? '🎯' : '⚠️'}</span>
      <div>
        <div style="font-size:15px; font-weight:800;">${comp.status_banner}</div>
        <div style="font-size:13px; font-weight:500;">${comp.verdict}</div>
      </div>
    `;
  }

  // Text preservation proof box
  const textProofBox = document.getElementById("textProofBox");
  if (res.mimicry_result.reassembled_text && textProofBox) {
    textProofBox.classList.remove("hidden");
    document.getElementById("proofReassembledText").innerText = res.mimicry_result.reassembled_text;
    const badge = document.getElementById("proofBadge");
    if (badge) {
      badge.className = res.mimicry_result.text_preserved ? "badge badge-green" : "badge badge-red";
      badge.innerText = res.mimicry_result.text_preserved ? "✓ Original Text 100% Preserved" : "Discrepancy";
    }
  }

  // Update navigation links
  document.getElementById("btnProceedComparison").href = `comparison.html?id=${currentExpId}`;
  document.getElementById("btnProceedClassifierAfter").href = `classifier.html?id=${currentExpId}&stage=after`;
}

function showEmptyState() {
  const c = document.getElementById("mimicryMainContent");
  if (c) {
    c.innerHTML = `
      <div class="card" style="text-align:center; padding:48px;">
        <h3>No Baseline Traffic Found</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Generate baseline traffic to apply protocol mimicry.</p>
        <a href="generator.html" class="btn btn-primary">Go to Traffic Generator</a>
      </div>
    `;
  }
}
