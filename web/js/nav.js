/**
 * Navigation, Layout Component Injection, and Health Monitoring
 * Protocol Mimicry Engine Laboratory
 */

import { API } from "./api.js";

const NAV_ITEMS = [
  { section: "LABORATORY" },
  { id: "dashboard", label: "Dashboard", href: "dashboard.html", icon: "grid", stage: 0 },
  { id: "generator", label: "Traffic Generator", href: "generator.html", icon: "activity", stage: 1 },
  { id: "features", label: "Feature Analysis", href: "features.html", icon: "bar-chart-2", stage: 2 },
  { id: "classifier", label: "DPI Classifier", href: "classifier.html", icon: "shield", stage: 3 },
  { id: "mimicry", label: "Mimicry Lab", href: "mimicry.html", icon: "shuffle", stage: 4 },
  { id: "comparison", label: "Comparison", href: "comparison.html", icon: "git-commit", stage: 5 },
  { id: "results", label: "Results History", href: "results.html", icon: "archive", stage: 6 },
  { id: "demo", label: "Live Demo", href: "demo.html", icon: "play", stage: null },
  { section: "REFERENCE" },
  { id: "settings", label: "Settings & Weights", href: "settings.html", icon: "sliders", stage: null }
];

const ICONS = {
  grid: `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>`,
  activity: `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>`,
  "bar-chart-2": `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg>`,
  shield: `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/></svg>`,
  shuffle: `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4h4l3 5m4 6l3 5h4M4 20h4l3-5m4-6l3-5h4"/></svg>`,
  "git-commit": `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4" stroke-width="2"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 2v6m0 8v6M2 12h6m8 0h6"/></svg>`,
  archive: `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"/></svg>`,
  play: `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>`,
  sliders: `<svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"/></svg>`
};

export function setupNavigation(activePageId) {
  // Inject Sidebar
  const sidebarEl = document.getElementById("appSidebar");
  if (sidebarEl) {
    let navHtml = `
      <div class="sidebar-header">
        <a href="dashboard.html" class="brand">
          <div class="brand-icon">
            <svg width="22" height="22" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/></svg>
          </div>
          <div class="brand-text">
            <h1>Protocol Mimicry</h1>
            <span>Controlled Lab</span>
          </div>
        </a>
      </div>
      <nav class="sidebar-nav">
    `;

    NAV_ITEMS.forEach(item => {
      if (item.section) {
        navHtml += `<div class="nav-section-title">${item.section}</div>`;
      } else {
        const isActive = item.id === activePageId ? "active" : "";
        navHtml += `
          <a href="${item.href}" class="nav-item ${isActive}">
            ${ICONS[item.icon] || ""}
            <span>${item.label}</span>
          </a>
        `;
      }
    });

    navHtml += `
      </nav>
      <div class="sidebar-footer">
        <div class="guard-pill">
          <span style="font-size:14px;">🔒</span> 127.0.0.1 Guard Active
        </div>
      </div>
    `;
    sidebarEl.innerHTML = navHtml;
  }

  // Inject Topbar
  const topbarEl = document.getElementById("appTopbar");
  if (topbarEl) {
    const currentItem = NAV_ITEMS.find(i => i.id === activePageId) || { label: "Laboratory" };
    const stageText = currentItem.stage !== null && currentItem.stage !== undefined && currentItem.stage > 0 
      ? `Stage 0${currentItem.stage}` 
      : "Controlled Environment";

    topbarEl.innerHTML = `
      <div class="topbar-left">
        <button id="mobileMenuToggle" class="mobile-menu-btn" aria-label="Toggle Menu">
          <svg width="24" height="24" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>
        </button>
        <div class="page-title-block">
          <h2>${currentItem.label}</h2>
          <div class="breadcrumb">
            <span>Lab</span> <span>/</span> <span class="stage-badge">${stageText}</span>
          </div>
        </div>
      </div>
      <div class="topbar-right">
        <span class="status-chip">Localhost Only</span>
        <span id="healthChip" class="status-chip online">
          <span class="pulse-dot"></span> Engine Online
        </span>
      </div>
    `;

    const toggleBtn = document.getElementById("mobileMenuToggle");
    if (toggleBtn) {
      toggleBtn.onclick = () => {
        const sb = document.getElementById("appSidebar");
        if (sb) sb.classList.toggle("open");
      };
    }
  }

  // Inject Stepper Strip if element exists
  const stepperEl = document.getElementById("appStepper");
  if (stepperEl) {
    renderPipelineStepper(stepperEl, activePageId);
  }

  // Inject Footer Safety Notice if element exists
  const footerEl = document.getElementById("appFooter");
  if (footerEl) {
    footerEl.innerHTML = `
      <div class="safety-notice">
        <span>🛡️</span>
        <span>Educational computer-networks laboratory. Bound strictly to 127.0.0.1 loopback. Rule-based heuristic classifier. No packet injection or raw sockets.</span>
      </div>
      <div>Python 3.10+ | Flask REST Engine</div>
    `;
  }

  // Start Health Heartbeat
  checkHealth();
  setInterval(checkHealth, 10000);
}

function renderPipelineStepper(container, activePageId) {
  const steps = [
    { id: "generator", num: 1, label: "Generate Baseline", href: "generator.html" },
    { id: "features", num: 2, label: "Extract Features", href: "features.html" },
    { id: "classifier", num: 3, label: "Classify Baseline", href: "classifier.html" },
    { id: "mimicry", num: 4, label: "Apply Mimicry", href: "mimicry.html" },
    { id: "comparison", num: 5, label: "Compare & Evaluate", href: "comparison.html" }
  ];

  const currentIdx = steps.findIndex(s => s.id === activePageId);

  let html = `<div class="stepper">`;
  steps.forEach((s, idx) => {
    let state = "";
    if (idx < currentIdx) state = "completed";
    else if (idx === currentIdx) state = "active";

    html += `
      <a href="${s.href}" class="step-item ${state}">
        <span class="step-num">${state === "completed" ? "✓" : s.num}</span>
        <span>${s.label}</span>
      </a>
    `;
    if (idx < steps.length - 1) {
      html += `<span class="step-arrow">→</span>`;
    }
  });
  html += `</div>`;
  container.innerHTML = html;
}

async function checkHealth() {
  const chip = document.getElementById("healthChip");
  if (!chip) return;
  try {
    const res = await API.get("/api/health");
    if (res.status === "online") {
      chip.className = "status-chip online";
      chip.innerHTML = `<span class="pulse-dot"></span> Engine Online`;
    }
  } catch (e) {
    chip.className = "status-chip";
    chip.innerHTML = `<span style="color:#DC2626;">●</span> Engine Offline`;
  }
}
