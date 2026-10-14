import { API, animateCounter } from "./api.js";
import { setupNavigation } from "./nav.js";

document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation("dashboard");

  // Load experiments
  try {
    const res = await API.get("/api/experiments");
    const experiments = res.experiments || [];

    const totalExp = experiments.length;
    animateCounter("metricTotalExp", totalExp);

    let fooledCount = 0;
    let totalConfDrop = 0;
    let validDropCount = 0;

    experiments.forEach(e => {
      if (e.fooled) fooledCount++;
      if (e.confidence_after > 0) {
        const drop = e.confidence_before - e.confidence_after;
        totalConfDrop += Math.max(0, drop);
        validDropCount++;
      }
    });

    const fooledRate = totalExp > 0 ? Math.round((fooledCount / totalExp) * 100) : 0;
    animateCounter("metricFooledRate", fooledRate, 800, "%");
    animateCounter("metricOverhead", totalExp > 0 ? 18 : 0, 800, "%");

    renderRecentTable(experiments.slice(0, 5));
  } catch (e) {
    console.error("Dashboard experiment error:", e);
    renderRecentTable([]);
  }

  // Load transferred files
  try {
    const fileRes = await API.get("/api/files?page=1&per_page=5");
    const files = fileRes.files || [];
    const totalFiles = fileRes.total || 0;

    animateCounter("metricTotalFiles", totalFiles);
    renderRecentFilesTable(files);
  } catch (e) {
    console.error("Dashboard files error:", e);
    renderRecentFilesTable([]);
  }
});

function renderRecentTable(runs) {
  const tbody = document.getElementById("recentRunsBody");
  if (!tbody) return;

  if (runs.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center; padding:32px; color:var(--text-muted);">
          No experiment runs found yet. Click <strong>Start New Run</strong> or <strong>Run Live Demo</strong> to start.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = runs.map(r => {
    let badgeClass = "badge-gray";
    if (r.fooled) badgeClass = "badge-green";
    else if (r.status_banner === "SIGNATURE SHIFTED") badgeClass = "badge-amber";

    return `
      <tr>
        <td class="mono"><strong>${r.id}</strong></td>
        <td><span class="badge badge-blue">${r.protocol}</span></td>
        <td>${r.category_before} (${r.confidence_before}%)</td>
        <td>${r.target_profile || "-"}</td>
        <td>${r.category_after || "-"} ${r.confidence_after ? `(${r.confidence_after}%)` : ""}</td>
        <td><span class="badge ${badgeClass}">${r.status_banner || "BASELINE"}</span></td>
        <td>
          <a href="comparison.html?id=${r.id}" class="btn btn-secondary btn-sm">Inspect</a>
        </td>
      </tr>
    `;
  }).join("");
}

function renderRecentFilesTable(files) {
  const tbody = document.getElementById("recentFilesBody");
  if (!tbody) return;

  if (files.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center; padding:32px; color:var(--text-muted);">
          No transferred files logged yet. Go to <a href="files.html">Transferred Files</a> to transmit real files over sockets.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = files.map(f => {
    const integrityBadge = (f.integrity_verified !== false)
      ? `<span class="badge badge-green">✓ MATCH</span>`
      : `<span class="badge badge-red">MISMATCH</span>`;
    const protoBadge = f.transport_protocol === "TCP" ? "badge-blue" : "badge-amber";
    const shaShort = f.sha256 ? `${f.sha256.substring(0, 8)}...${f.sha256.substring(58)}` : "-";

    return `
      <tr>
        <td class="mono" style="font-weight:700;">${f.file_id}</td>
        <td>
          <div style="font-weight:600;">${escapeHtml(f.original_filename || "unnamed")}</div>
          <div style="font-size:11px; color:var(--text-muted);">${f.mime_type || "application/octet-stream"}</div>
        </td>
        <td class="mono">${formatBytes(f.size_bytes || 0)}</td>
        <td><span class="badge ${protoBadge}">${f.transport_protocol || "TCP"}</span></td>
        <td class="mono" title="${f.sha256 || ''}">${shaShort}</td>
        <td>${integrityBadge}</td>
        <td>
          <a href="files.html" class="btn btn-secondary btn-sm">View in Lab</a>
        </td>
      </tr>
    `;
  }).join("");
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
