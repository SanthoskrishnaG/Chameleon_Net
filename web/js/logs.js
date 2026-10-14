/**
 * Transfer Logs & Audit Trail Controller
 * Protocol Mimicry Engine Laboratory
 * Pure Vanilla JavaScript & REST API Integration
 */

import { API, showToast, animateCounter } from "./api.js";
import { setupNavigation } from "./nav.js";

let currentPage = 1;
const perPage = 20;
let currentSearch = "";
let currentEventType = "";
let currentStatus = "";

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation("logs");

  initEventListeners();
  loadLogs();
});

function initEventListeners() {
  let searchTimeout;
  document.getElementById("searchLogInput")?.addEventListener("input", (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      currentSearch = e.target.value.trim();
      currentPage = 1;
      loadLogs();
    }, 250);
  });

  document.getElementById("filterEventType")?.addEventListener("change", (e) => {
    currentEventType = e.target.value;
    currentPage = 1;
    loadLogs();
  });

  document.getElementById("filterLogStatus")?.addEventListener("change", (e) => {
    currentStatus = e.target.value;
    currentPage = 1;
    loadLogs();
  });

  document.getElementById("btnRefreshLogs")?.addEventListener("click", () => {
    loadLogs();
    showToast("Audit logs refreshed.", "info");
  });

  document.getElementById("btnPrevLogPage")?.addEventListener("click", () => {
    if (currentPage > 1) {
      currentPage--;
      loadLogs();
    }
  });

  document.getElementById("btnNextLogPage")?.addEventListener("click", () => {
    currentPage++;
    loadLogs();
  });
}

async function loadLogs() {
  const tbody = document.getElementById("logsTableBody");
  if (!tbody) return;

  try {
    let url = `/api/logs?page=${currentPage}&per_page=${perPage}`;
    if (currentSearch) url += `&search=${encodeURIComponent(currentSearch)}`;
    if (currentEventType) url += `&event_type=${encodeURIComponent(currentEventType)}`;
    if (currentStatus) url += `&status=${encodeURIComponent(currentStatus)}`;

    const data = await API.get(url);
    const logs = data.logs || [];
    const total = data.total || 0;
    const pages = data.pages || 1;

    updateKPIs(logs, total);
    renderLogsTable(logs);
    updatePagination(total, pages);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:24px; color:var(--danger);">Failed to load logs: ${err.message}</td></tr>`;
  }
}

function updateKPIs(batch, totalCount) {
  animateCounter("statTotalLogs", totalCount);

  let successCount = 0;
  let failedCount = 0;

  batch.forEach(l => {
    const s = (l.status || "").toLowerCase();
    if (s === "success" || s === "completed") {
      successCount++;
    } else if (s === "failed" || s === "error") {
      failedCount++;
    }
  });

  animateCounter("statSuccessLogs", successCount);
  animateCounter("statFailedLogs", failedCount);
}

function renderLogsTable(logs) {
  const tbody = document.getElementById("logsTableBody");
  if (!tbody) return;

  if (logs.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center; padding:36px; color:var(--text-muted);">
          No audit logs recorded matching the criteria.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = logs.map(l => {
    const dateStr = l.timestamp ? new Date(l.timestamp).toLocaleString() : "-";
    const statusLower = (l.status || "").toLowerCase();
    let statusBadge = "badge-gray";
    if (statusLower === "success" || statusLower === "completed") statusBadge = "badge-green";
    else if (statusLower === "failed" || statusLower === "error") statusBadge = "badge-red";
    else if (statusLower === "warning") statusBadge = "badge-amber";

    const fileRef = l.file_id 
      ? `<a href="files.html" class="mono" style="font-size:12px; font-weight:700; color:var(--primary);">${l.file_id}</a>` 
      : `<span style="color:var(--text-muted);">-</span>`;

    const expRef = l.experiment_id 
      ? `<a href="comparison.html?id=${l.experiment_id}" class="mono" style="font-size:12px; font-weight:700; color:var(--accent);">${l.experiment_id}</a>` 
      : `<span style="color:var(--text-muted);">-</span>`;

    const errDetail = l.error 
      ? `<span style="color:var(--danger); font-size:12px; font-weight:600;">${escapeHtml(l.error)}</span>` 
      : `<span style="color:var(--text-muted); font-size:11px;">OK</span>`;

    return `
      <tr>
        <td style="font-size:12px; color:var(--text-muted); white-space:nowrap;">${dateStr}</td>
        <td><span class="badge badge-purple">${escapeHtml(l.event_type || "event")}</span></td>
        <td><span class="badge ${statusBadge}">${escapeHtml(l.status || "unknown")}</span></td>
        <td>
          <div style="font-size:13px; font-weight:500;">${escapeHtml(l.message || "-")}</div>
        </td>
        <td>${fileRef}</td>
        <td>${expRef}</td>
        <td>${errDetail}</td>
      </tr>
    `;
  }).join("");
}

function updatePagination(total, pages) {
  const pageInfo = document.getElementById("logsPageInfo");
  const btnPrev = document.getElementById("btnPrevLogPage");
  const btnNext = document.getElementById("btnNextLogPage");

  if (pageInfo) {
    const start = total === 0 ? 0 : (currentPage - 1) * perPage + 1;
    const end = Math.min(currentPage * perPage, total);
    pageInfo.innerText = `Showing ${start} - ${end} of ${total} events (Page ${currentPage} of ${pages})`;
  }

  if (btnPrev) btnPrev.disabled = (currentPage <= 1);
  if (btnNext) btnNext.disabled = (currentPage >= pages);
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
