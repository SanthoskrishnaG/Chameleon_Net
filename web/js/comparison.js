import { API, showToast } from "./api.js";
import { setupNavigation } from "./nav.js";

let currentExpId = null;
let overlayChart = null;

document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation("comparison");

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

  if (currentExpId) {
    loadComparison(currentExpId);
  } else {
    showEmptyState();
  }
});

async function loadComparison(expId) {
  try {
    document.getElementById("expIdBadge").innerText = expId;
    const comp = await API.get(`/api/compare/${expId}`);
    renderComparisonView(comp);
  } catch (err) {
    showToast(`Comparison error: ${err.message}`, "error");
    showEmptyState();
  }
}

function renderComparisonView(c) {
  const container = document.getElementById("comparisonContent");
  if (!container) return;

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

  // Side-by-Side Cards
  const before = c.classification.before;
  const after = c.classification.after;

  document.getElementById("beforeCategory").innerText = before.name;
  document.getElementById("beforeConfidence").innerText = `${before.confidence}% (${before.label})`;

  document.getElementById("afterCategory").innerText = after.name;
  document.getElementById("afterConfidence").innerText = `${after.confidence}% (${after.label})`;
  document.getElementById("targetProfileName").innerText = c.target_profile.name;
  document.getElementById("similarityScore").innerText = `${c.similarity_to_target}%`;

  // Delta Table
  renderDeltaTable(c.deltas || {});

  // Overhead Cards
  const ovh = c.overhead || {};
  document.getElementById("ovhExtraBytes").innerText = `+${ovh.extra_bytes_percent || 0}%`;
  document.getElementById("ovhAddedDelay").innerText = `+${ovh.added_delay_percent || 0}%`;
  document.getElementById("ovhThroughput").innerText = `${ovh.throughput_change_percent || 0}%`;

  // Render Overlay Bar Chart
  renderOverlayBarChart(c.deltas || {});

  // Export Links
  const btnReport = document.getElementById("btnExportReport");
  if (btnReport) btnReport.href = API.url(`/api/export/${currentExpId}?format=html`);
  const btnCSV = document.getElementById("btnExportCSV");
  if (btnCSV) btnCSV.href = API.url(`/api/export/${currentExpId}?format=csv`);
}

function renderDeltaTable(deltas) {
  const tbody = document.getElementById("deltasTableBody");
  if (!tbody) return;

  tbody.innerHTML = Object.entries(deltas).map(([key, d]) => {
    const isPositive = d.delta > 0;
    const arrow = isPositive ? "↑" : d.delta < 0 ? "↓" : "→";
    const arrowColor = key.includes("size") || key.includes("ipt") ? "var(--primary)" : isPositive ? "var(--warning)" : "var(--success)";

    return `
      <tr>
        <td><strong>${d.label || key}</strong></td>
        <td class="mono" style="text-align:right;">${d.before}</td>
        <td class="mono" style="text-align:right; font-weight:700; color:var(--primary);">${d.after}</td>
        <td class="mono" style="text-align:right; color:${arrowColor}; font-weight:700;">
          ${arrow} ${d.delta > 0 ? '+' : ''}${d.delta}
        </td>
        <td class="mono" style="text-align:right; font-weight:600;">
          ${d.percent_change > 0 ? '+' : ''}${d.percent_change}%
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
  const beforeData = metrics.map(m => deltas[m.key]?.before || 0);
  const afterData = metrics.map(m => deltas[m.key]?.after || 0);

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

function showEmptyState() {
  const c = document.getElementById("comparisonContent");
  if (c) {
    c.innerHTML = `
      <div class="card" style="text-align:center; padding:48px;">
        <h3>No Comparison Data Available</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">
          Both baseline generation and mimicry transformation are required to evaluate comparative deltas.
        </p>
        <a href="mimicry.html" class="btn btn-primary">Go to Mimicry Lab</a>
      </div>
    `;
  }
}
