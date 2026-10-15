import { API, showToast } from "./api.js";
import { setupNavigation, updatePipelineStepperState } from "./nav.js";

let currentExpId = null;
let overlayChart = null;
let cachedTemplateHtml = null;

document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation("comparison");

  // Cache template HTML before any empty state can overwrite it
  const container = document.getElementById("comparisonContent");
  if (container) {
    cachedTemplateHtml = container.innerHTML;
  }

  const urlParams = new URLSearchParams(window.location.search);
  currentExpId = urlParams.get("id");

  // Initialize experiment selector and discover experiments
  await initExperimentSelector(currentExpId);

  // If no expId was in URL, use the selector's value
  if (!currentExpId) {
    const sel = document.getElementById("comparisonExpSelector");
    if (sel && sel.value) {
      currentExpId = sel.value;
      const newUrl = new URL(window.location.href);
      newUrl.searchParams.set("id", currentExpId);
      window.history.replaceState({}, "", newUrl.toString());
    }
  }

  if (currentExpId) {
    loadComparison(currentExpId);
  } else {
    showEmptyState("No experimental runs recorded yet. Generate baseline traffic first.", null);
  }
});

async function initExperimentSelector(selectedExpId) {
  const sel = document.getElementById("comparisonExpSelector");
  if (!sel) return;

  try {
    const res = await API.get("/api/experiments");
    const experiments = res.experiments || [];

    if (experiments.length === 0) {
      sel.innerHTML = `<option value="">No experiments found</option>`;
      return;
    }

    sel.innerHTML = experiments.map(exp => {
      const isSelected = exp.id === selectedExpId ? "selected" : "";
      const hasMimic = Boolean(exp.category_after && exp.category_after !== "-");
      const statusIcon = hasMimic ? "🎯" : "⏳";
      const label = `${statusIcon} ${exp.id} (${exp.protocol || "TCP"}, ${exp.payload_mode || "traffic"})`;
      return `<option value="${exp.id}" ${isSelected}>${label}</option>`;
    }).join("");

    sel.addEventListener("change", (e) => {
      const newId = e.target.value;
      if (newId) {
        currentExpId = newId;
        const newUrl = new URL(window.location.href);
        newUrl.searchParams.set("id", newId);
        window.history.replaceState({}, "", newUrl.toString());
        loadComparison(newId);
      }
    });

  } catch (err) {
    console.warn("Could not load experiments list for selector:", err);
  }
}

async function loadComparison(expId) {
  try {
    // Restore layout template if it was replaced by an empty/error state
    const container = document.getElementById("comparisonContent");
    if (container && cachedTemplateHtml && !document.getElementById("deltasTableBody")) {
      container.innerHTML = cachedTemplateHtml;
    }

    const badge = document.getElementById("expIdBadge");
    if (badge) badge.innerText = expId;

    const sel = document.getElementById("comparisonExpSelector");
    if (sel && sel.value !== expId) {
      sel.value = expId;
    }

    // Call comparison endpoint with stable identifier
    const comp = await API.get(`/api/compare/${encodeURIComponent(expId)}`);

    // Update workflow stepper to reflect verified completion
    updatePipelineStepperState({
      id: expId,
      features_before: comp.classification?.before,
      features_after: comp.classification?.after,
      classification_before: comp.classification?.before,
      classification_after: comp.classification?.after,
      comparison: comp
    }, "comparison");

    renderComparisonView(comp);

  } catch (err) {
    showToast(`Comparison error: ${err.message}`, "error");

    // Check underlying experiment status to update stepper accurately
    try {
      const expRes = await API.get(`/api/experiments/${encodeURIComponent(expId)}`);
      updatePipelineStepperState(expRes, "comparison");
    } catch (e) {
      updatePipelineStepperState({ id: expId }, "comparison");
    }

    showEmptyState(err.message, expId, err);
  }
}

function renderComparisonView(c) {
  const container = document.getElementById("comparisonContent");
  if (!container) return;

  const expId = c.experiment_id || c.baseline_id || currentExpId;
  const badge = document.getElementById("expIdBadge");
  if (badge) badge.innerText = expId;

  // Verdict Banner
  const banner = document.getElementById("verdictBanner");
  if (banner) {
    banner.className = `verdict-banner ${c.banner_type || 'warning'}`;
    banner.innerHTML = `
      <span style="font-size:26px;">${c.fooled_target ? '🎯' : c.category_diverted ? '⚠️' : '🛡️'}</span>
      <div>
        <div style="font-size:16px; font-weight:800; letter-spacing:0.02em;">${c.status_banner}</div>
        <div style="font-size:13px; font-weight:500; margin-top:2px;">${c.verdict}</div>
      </div>
    `;
  }

  // Side-by-Side Classification Cards
  const before = c.classification?.before || {};
  const after = c.classification?.after || {};

  const beforeCatEl = document.getElementById("beforeCategory");
  if (beforeCatEl) beforeCatEl.innerText = before.name || before.category || "Unknown";

  const beforeConfEl = document.getElementById("beforeConfidence");
  if (beforeConfEl) beforeConfEl.innerText = `${before.confidence ?? 0}% (${before.label || 'Unclassified'})`;

  const afterCatEl = document.getElementById("afterCategory");
  if (afterCatEl) afterCatEl.innerText = after.name || after.category || "Unknown";

  const afterConfEl = document.getElementById("afterConfidence");
  if (afterConfEl) afterConfEl.innerText = `${after.confidence ?? 0}% (${after.label || 'Unclassified'})`;

  const targetProfEl = document.getElementById("targetProfileName");
  if (targetProfEl) targetProfEl.innerText = c.target_profile?.name || "Target Profile";

  const simEl = document.getElementById("similarityScore");
  if (simEl) simEl.innerText = `${c.similarity_to_target ?? 0}%`;

  // Delta Table
  renderDeltaTable(c.deltas || {});

  // Overhead Cards
  const ovh = c.overhead || {};
  const ovhBytes = document.getElementById("ovhExtraBytes");
  if (ovhBytes) ovhBytes.innerText = `+${ovh.extra_bytes_percent ?? 0}%`;

  const ovhDelay = document.getElementById("ovhAddedDelay");
  if (ovhDelay) ovhDelay.innerText = `+${ovh.added_delay_percent ?? 0}%`;

  const ovhThroughput = document.getElementById("ovhThroughput");
  if (ovhThroughput) ovhThroughput.innerText = `${ovh.throughput_change_percent ?? 0}%`;

  // Render Overlay Bar Chart
  renderOverlayBarChart(c.deltas || {});

  // Export Links
  const btnReport = document.getElementById("btnExportReport");
  if (btnReport) btnReport.href = API.url(`/api/export/${encodeURIComponent(expId)}?format=html`);
  const btnCSV = document.getElementById("btnExportCSV");
  if (btnCSV) btnCSV.href = API.url(`/api/export/${encodeURIComponent(expId)}?format=csv`);
}

function renderDeltaTable(deltas) {
  const tbody = document.getElementById("deltasTableBody");
  if (!tbody) return;

  const entries = Object.entries(deltas);
  if (entries.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:20px; color:var(--text-muted);">No delta metrics available</td></tr>`;
    return;
  }

  tbody.innerHTML = entries.map(([key, d]) => {
    const isPositive = d.delta > 0;
    const arrow = isPositive ? "↑" : d.delta < 0 ? "↓" : "→";
    const arrowColor = key.includes("size") || key.includes("ipt") ? "var(--primary)" : isPositive ? "var(--warning)" : "var(--success)";

    return `
      <tr>
        <td><strong>${d.label || key}</strong></td>
        <td class="mono" style="text-align:right;">${d.before ?? 0}</td>
        <td class="mono" style="text-align:right; font-weight:700; color:var(--primary);">${d.after ?? 0}</td>
        <td class="mono" style="text-align:right; color:${arrowColor}; font-weight:700;">
          ${arrow} ${d.delta > 0 ? '+' : ''}${d.delta ?? 0}
        </td>
        <td class="mono" style="text-align:right; font-weight:600;">
          ${d.percent_change > 0 ? '+' : ''}${d.percent_change ?? 0}%
        </td>
      </tr>
    `;
  }).join("");
}

function renderOverlayBarChart(deltas) {
  const canvas = document.getElementById("overlayChartCanvas");
  if (!canvas || !window.Chart) return;

  if (overlayChart) overlayChart.destroy();

  const metrics = [
    { key: "mean_size", label: "Packet Size (B)" },
    { key: "mean_ipt_ms", label: "Timing Cadence (ms)" },
    { key: "jitter_ms", label: "Jitter (ms)" },
    { key: "burst_count", label: "Burst Clusters" }
  ];

  const labels = metrics.map(m => m.label);
  const beforeData = metrics.map(m => deltas[m.key]?.before ?? 0);
  const afterData = metrics.map(m => deltas[m.key]?.after ?? 0);

  overlayChart = new window.Chart(canvas, {
    type: "bar",
    data: {
      labels: labels,
      datasets: [
        {
          label: "Baseline (Original)",
          data: beforeData,
          backgroundColor: "#CBD5E1",
          borderRadius: 6
        },
        {
          label: "Transformed (Mimicked)",
          data: afterData,
          backgroundColor: "#2563EB",
          borderRadius: 6
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: "#F1F5F9" }
        },
        x: {
          grid: { display: false }
        }
      }
    }
  });
}

function showEmptyState(message = null, expId = null, err = null) {
  const c = document.getElementById("comparisonContent");
  if (!c) return;

  const isMimicryMissing = message && (
    message.toLowerCase().includes("mimicry") ||
    message.toLowerCase().includes("after") ||
    message.toLowerCase().includes("both baseline and mimicry")
  );

  const isBaselineMissing = message && message.toLowerCase().includes("baseline") && !isMimicryMissing;

  let actionButtons = "";
  if (expId) {
    if (isMimicryMissing) {
      actionButtons = `
        <div style="display:flex; justify-content:center; gap:12px; margin-top:20px; flex-wrap:wrap;">
          <a href="mimicry.html?id=${encodeURIComponent(expId)}" class="btn btn-primary">
            Apply Mimicry to ${expId} (Stage 04) →
          </a>
          <button onclick="window.location.reload()" class="btn btn-secondary">
            Retry Comparison
          </button>
        </div>
      `;
    } else if (isBaselineMissing) {
      actionButtons = `
        <div style="display:flex; justify-content:center; gap:12px; margin-top:20px; flex-wrap:wrap;">
          <a href="features.html?id=${encodeURIComponent(expId)}" class="btn btn-primary">
            Extract Baseline Features (Stage 02) →
          </a>
          <a href="generator.html" class="btn btn-secondary">
            Generate New Baseline (Stage 01)
          </a>
        </div>
      `;
    } else {
      actionButtons = `
        <div style="display:flex; justify-content:center; gap:12px; margin-top:20px; flex-wrap:wrap;">
          <a href="mimicry.html?id=${encodeURIComponent(expId)}" class="btn btn-primary">
            Go to Mimicry Lab
          </a>
          <button onclick="window.location.reload()" class="btn btn-secondary">
            Reload
          </button>
        </div>
      `;
    }
  } else {
    actionButtons = `
      <div style="display:flex; justify-content:center; gap:12px; margin-top:20px;">
        <a href="generator.html" class="btn btn-primary">Start New Experiment (Stage 01)</a>
      </div>
    `;
  }

  c.innerHTML = `
    <div class="card" style="text-align:center; padding:48px 24px; max-width:680px; margin:40px auto;">
      <div style="font-size:42px; margin-bottom:12px;">📊</div>
      <h3 style="font-size:20px; font-weight:800; margin-bottom:8px;">No Comparison Data Available</h3>
      <p style="color:var(--text-muted); margin-bottom:16px; font-size:14px; line-height:1.6;">
        ${message || "Both baseline traffic and post-mimicry transformed traffic must be generated and analyzed before direct comparative evaluation can occur."}
      </p>
      ${expId ? `<p style="font-size:12px; color:var(--text-muted); margin-bottom:8px;">Active Target Run: <strong class="mono" style="color:var(--primary);">${expId}</strong></p>` : ""}
      ${actionButtons}
    </div>
  `;
}
