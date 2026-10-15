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
let isFetching = false;
let pollTimer = null;

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation("logs");

  initEventListeners();
  loadLogs();

  // Periodic polling when tab is active
  startPolling();
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

  // Listen to transfer and delete events emitted by other pages or tabs
  window.addEventListener("chameleon:file_transferred", () => {
    loadLogs(true);
  });

  window.addEventListener("chameleon:file_deleted", () => {
    loadLogs(true);
  });

  window.addEventListener("storage", (e) => {
    if (e.key === "chameleon_last_transfer_ts") {
      loadLogs(true);
    }
  });

  // Auto-refresh when tab gains focus
  window.addEventListener("focus", () => {
    loadLogs(true);
  });
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => {
    if (document.visibilityState === "visible" && !isFetching) {
      loadLogs(true);
    }
  }, 8000);
}

async function loadLogs(silent = false) {
  const tbody = document.getElementById("logsTableBody");
  if (!tbody) return;

  if (isFetching) return;
  isFetching = true;

  if (!silent) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center; padding:32px; color:var(--text-muted);">
          <div style="display:inline-flex; align-items:center; gap:8px;">
            <span class="spinner" style="display:inline-block; width:16px; height:16px; border:2px solid var(--primary); border-top-color:transparent; border-radius:50%; animation:spin 0.6s linear infinite;"></span>
            <span>Loading transfer logs from storage...</span>
          </div>
        </td>
      </tr>
    `;
  }

  try {
    let url = `/api/logs?page=${currentPage}&per_page=${perPage}`;
    if (currentSearch) url += `&search=${encodeURIComponent(currentSearch)}`;
    if (currentEventType) url += `&event_type=${encodeURIComponent(currentEventType)}`;
    if (currentStatus) url += `&status=${encodeURIComponent(currentStatus)}`;

    const data = await API.get(url);
    const logs = data.logs || data.items || [];
    const total = data.total ?? (Array.isArray(logs) ? logs.length : 0);
    const pages = data.pages || Math.max(1, Math.ceil(total / perPage));

    // Ensure sorted strictly descending by timestamp
    logs.sort((a, b) => {
      const ta = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const tb = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      return tb - ta;
    });

    updateKPIs(data.stats, logs, total);
    renderLogsTable(logs);
    updatePagination(total, pages);
  } catch (err) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center; padding:32px; color:var(--danger);">
          <div style="font-size:22px; margin-bottom:6px;">⚠️</div>
          <div style="font-weight:700; margin-bottom:4px;">Failed to load transfer logs</div>
          <div style="font-size:12px; color:var(--text-muted); margin-bottom:12px;">${escapeHtml(err.message)}</div>
          <button id="btnRetryLogs" class="btn btn-secondary btn-sm">Retry Connection</button>
        </td>
      </tr>
    `;
    document.getElementById("btnRetryLogs")?.addEventListener("click", () => loadLogs());
  } finally {
    isFetching = false;
  }
}

function updateKPIs(stats, fallbackBatch, totalCount) {
  if (stats) {
    animateCounter("statTotalLogs", stats.total ?? totalCount);
    animateCounter("statSuccessLogs", stats.success ?? 0);
    animateCounter("statFailedLogs", stats.failed ?? 0);
    return;
  }

  // Fallback if backend does not supply stats object
  animateCounter("statTotalLogs", totalCount);

  let successCount = 0;
  let failedCount = 0;

  fallbackBatch.forEach(l => {
    const s = (l.status || "").toLowerCase();
    if (s === "success" || s === "completed") {
      successCount++;
    } else if (s === "failed" || s === "error" || s === "incomplete") {
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
        <td colspan="7" style="text-align:center; padding:40px; color:var(--text-muted);">
          <div style="font-size:24px; margin-bottom:6px;">📋</div>
          <div style="font-weight:600; font-size:14px; margin-bottom:4px;">No Transfer Logs Found</div>
          <div style="font-size:12px;">No audit records matched your search or filter criteria.</div>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = logs.map(l => {
    const dateStr = l.timestamp ? new Date(l.timestamp).toLocaleString() : "-";
    const statusLower = (l.status || "").toLowerCase();

    let statusBadge = "badge-gray";
    let statusLabel = l.status || "unknown";

    if (statusLower === "success" || statusLower === "completed") {
      statusBadge = "badge-green";
      statusLabel = statusLower === "completed" ? "completed" : "success";
    } else if (statusLower === "started") {
      statusBadge = "badge-blue";
      statusLabel = "started";
    } else if (statusLower === "failed" || statusLower === "error") {
      statusBadge = "badge-red";
      statusLabel = "failed";
    } else if (statusLower === "incomplete") {
      statusBadge = "badge-amber";
      statusLabel = "incomplete";
    } else if (statusLower === "warning") {
      statusBadge = "badge-amber";
    }

    // Event type badge styling
    let eventBadgeClass = "badge-purple";
    const evtType = (l.event_type || "event").toLowerCase();
    if (evtType === "file_transfer") eventBadgeClass = "badge-blue";
    else if (evtType === "file_delete") eventBadgeClass = "badge-amber";
    else if (evtType === "experiment_delete") eventBadgeClass = "badge-red";

    // Associated file display
    const filename = l.original_filename || l.filename || (l.details && (l.details.original_filename || l.details.filename));
    let fileRef = `<span style="color:var(--text-muted);">-</span>`;
    if (l.file_id) {
      fileRef = `
        <div>
          <a href="files.html" class="mono" style="font-size:12px; font-weight:700; color:var(--primary); text-decoration:none;">
            ${escapeHtml(l.file_id)}
          </a>
          ${filename ? `<div style="font-size:11px; color:var(--text-muted); max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${escapeHtml(filename)}">${escapeHtml(filename)}</div>` : ""}
        </div>
      `;
    }

    // Associated experiment display
    const expRef = l.experiment_id 
      ? `<a href="comparison.html?id=${encodeURIComponent(l.experiment_id)}" class="mono" style="font-size:12px; font-weight:700; color:var(--accent); text-decoration:none;">${escapeHtml(l.experiment_id)}</a>` 
      : `<span style="color:var(--text-muted);">-</span>`;

    // Protocol & File Details snippet
    const proto = l.protocol || (l.details && l.details.protocol);
    const size = l.size_bytes ?? (l.details && l.details.size_bytes);
    let detailsSnippet = "";
    if (proto || size !== undefined) {
      const parts = [];
      if (proto) parts.push(`<span class="badge ${proto === 'TCP' ? 'badge-blue' : 'badge-amber'}" style="font-size:10px; padding:2px 5px;">${escapeHtml(proto)}</span>`);
      if (size !== undefined && size !== null) parts.push(`<span class="mono" style="font-size:11px; color:var(--text-muted);">${formatBytes(size)}</span>`);
      detailsSnippet = `<div style="margin-top:4px; display:flex; align-items:center; gap:6px;">${parts.join(" ")}</div>`;
    }

    // Error / Integrity Detail display
    const integrityVerified = l.integrity_verified ?? (l.details && l.details.integrity_verified);
    let errDetail;
    if (l.error) {
      errDetail = `<span style="color:var(--danger); font-size:12px; font-weight:600;">⚠ ${escapeHtml(l.error)}</span>`;
    } else if (statusLower === "started") {
      errDetail = `<span style="color:var(--primary); font-size:11px; font-weight:500;">Transmitting...</span>`;
    } else if (integrityVerified === true) {
      errDetail = `<span style="color:var(--success); font-size:11px; font-weight:600;">✓ SHA-256 Verified</span>`;
    } else if (integrityVerified === false) {
      errDetail = `<span style="color:var(--danger); font-size:11px; font-weight:600;">✕ Checksum Mismatch</span>`;
    } else {
      errDetail = `<span style="color:var(--text-muted); font-size:11px;">OK</span>`;
    }

    return `
      <tr>
        <td style="font-size:12px; color:var(--text-muted); white-space:nowrap;">${dateStr}</td>
        <td><span class="badge ${eventBadgeClass}">${escapeHtml(l.event_type || "event")}</span></td>
        <td><span class="badge ${statusBadge}">${escapeHtml(statusLabel)}</span></td>
        <td>
          <div style="font-size:13px; font-weight:500;">${escapeHtml(l.message || "-")}</div>
          ${detailsSnippet}
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

function formatBytes(bytes) {
  if (bytes === undefined || bytes === null || isNaN(bytes)) return "-";
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
