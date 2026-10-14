import { API, showToast } from "./api.js";
import { setupNavigation } from "./nav.js";
import { drawConfidenceGauge } from "./charts.js";

let currentExpId = null;
let currentStage = "before";

document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation("classifier");

  const urlParams = new URLSearchParams(window.location.search);
  currentExpId = urlParams.get("id");
  currentStage = urlParams.get("stage") || "before";

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

  // Stage Tabs
  document.getElementById("tabBefore")?.addEventListener("click", () => switchStage("before"));
  document.getElementById("tabAfter")?.addEventListener("click", () => switchStage("after"));

  if (currentExpId) {
    loadClassification(currentExpId, currentStage);
  } else {
    showEmptyState();
  }
});

function switchStage(stage) {
  currentStage = stage;
  document.getElementById("tabBefore").classList.toggle("btn-primary", stage === "before");
  document.getElementById("tabBefore").classList.toggle("btn-secondary", stage !== "before");
  document.getElementById("tabAfter").classList.toggle("btn-primary", stage === "after");
  document.getElementById("tabAfter").classList.toggle("btn-secondary", stage !== "after");

  if (currentExpId) {
    loadClassification(currentExpId, currentStage);
  }
}

async function loadClassification(expId, stage) {
  try {
    document.getElementById("expIdBadge").innerText = expId;
    const res = await API.post(`/api/classify/${expId}?stage=${stage}`, {});
    const c = res.classification;
    if (!c) {
      showEmptyState();
      return;
    }

    // Top Category & Confidence
    document.getElementById("detectedCategoryName").innerText = c.category_name;
    document.getElementById("confidenceLabelBadge").innerText = `${c.label} Confidence`;
    
    let labelBadgeClass = "badge-blue";
    if (c.label === "High") labelBadgeClass = "badge-green";
    else if (c.label === "Low") labelBadgeClass = "badge-red";
    document.getElementById("confidenceLabelBadge").className = `badge ${labelBadgeClass}`;

    // Animated Gauge
    drawConfidenceGauge("gaugeCanvas", c.confidence);
    document.getElementById("gaugeCenterVal").innerText = `${c.confidence}%`;

    // Plain English narrative
    document.getElementById("explanationText").innerText = c.explanation;

    // Contribution bars
    renderContributionBars(c.rule_contributions || {});

    // Rules Catalog Matrix
    renderRulesCatalog(c.profile_details || {}, c.detected_category);

    // Update Action Buttons
    const btnMimic = document.getElementById("btnGoMimicry");
    if (btnMimic) {
      btnMimic.href = `mimicry.html?id=${expId}`;
    }
    const btnCompare = document.getElementById("btnGoCompare");
    if (btnCompare) {
      btnCompare.href = `comparison.html?id=${expId}`;
    }

  } catch (err) {
    if (stage === "after") {
      showToast("Mimicked features not yet generated for this experiment. Apply mimicry first.", "info");
      switchStage("before");
    } else {
      showToast(`Classifier error: ${err.message}`, "error");
      showEmptyState();
    }
  }
}

function renderContributionBars(contribs) {
  const container = document.getElementById("contributionBarsContainer");
  if (!container) return;

  container.innerHTML = Object.entries(contribs).map(([ruleName, score]) => `
    <div style="margin-bottom:12px;">
      <div style="display:flex; justify-content:space-between; font-size:12px; font-weight:600; margin-bottom:4px;">
        <span>${ruleName}</span>
        <span style="color:var(--primary); font-family:var(--font-mono);">${score}%</span>
      </div>
      <div style="height:8px; background:var(--surface-alt); border-radius:var(--radius-full); overflow:hidden;">
        <div style="height:100%; width:${score}%; background:var(--primary); border-radius:var(--radius-full); transition:width 0.6s ease;"></div>
      </div>
    </div>
  `).join("");
}

function renderRulesCatalog(details, detectedId) {
  const tbody = document.getElementById("rulesCatalogBody");
  if (!tbody) return;

  tbody.innerHTML = Object.entries(details).map(([pid, p]) => {
    const isSelected = pid === detectedId;
    const rowBg = isSelected ? "background:#F0FDF4;" : "";
    const rules = p.rules;

    const renderPassFail = (r) => {
      if (!r) return `<span class="badge badge-gray">-</span>`;
      return r.pass 
        ? `<span class="badge badge-green">✓ Pass (${Math.round(r.score * 100)}%)</span>`
        : `<span class="badge badge-red">✗ Fail (${Math.round(r.score * 100)}%)</span>`;
    };

    return `
      <tr style="${rowBg}">
        <td>
          <strong>${p.name}</strong>
          ${isSelected ? `<span class="badge badge-green" style="margin-left:6px;">MATCH</span>` : ""}
        </td>
        <td class="mono" style="font-weight:700; color:${isSelected ? 'var(--success)' : 'var(--text)'};">${p.score}%</td>
        <td>${renderPassFail(rules.packet_size)}</td>
        <td>${renderPassFail(rules.timing)}</td>
        <td>${renderPassFail(rules.volume)}</td>
        <td>${renderPassFail(rules.burst_jitter)}</td>
        <td>${renderPassFail(rules.transport)}</td>
      </tr>
    `;
  }).join("");
}

function showEmptyState() {
  const c = document.getElementById("classifierMainContent");
  if (c) {
    c.innerHTML = `
      <div class="card" style="text-align:center; padding:48px;">
        <h3>No Experiment Selected</h3>
        <p style="color:var(--text-muted); margin-bottom:16px;">Generate baseline traffic to classify observable network features.</p>
        <a href="generator.html" class="btn btn-primary">Go to Traffic Generator</a>
      </div>
    `;
  }
}
