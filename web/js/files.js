/**
 * Transferred Files & Socket Storage Controller
 * Protocol Mimicry Engine Laboratory
 * Pure Vanilla JavaScript & REST API Integration
 */

import { API, showToast, animateCounter } from "./api.js";
import { setupNavigation } from "./nav.js";

let currentPage = 1;
const perPage = 10;
let currentSearch = "";
let currentProtocol = "";
let currentStatus = "";

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation("files");

  initEventListeners();
  loadTransferredFiles();
});

function initEventListeners() {
  // Search input with debounce
  let searchTimeout;
  document.getElementById("searchInput")?.addEventListener("input", (e) => {
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(() => {
      currentSearch = e.target.value.trim();
      currentPage = 1;
      loadTransferredFiles();
    }, 250);
  });

  // Filter dropdowns
  document.getElementById("filterProtocol")?.addEventListener("change", (e) => {
    currentProtocol = e.target.value;
    currentPage = 1;
    loadTransferredFiles();
  });

  document.getElementById("filterStatus")?.addEventListener("change", (e) => {
    currentStatus = e.target.value;
    currentPage = 1;
    loadTransferredFiles();
  });

  document.getElementById("btnRefresh")?.addEventListener("click", () => {
    loadTransferredFiles();
    showToast("Transferred files refreshed.", "info");
  });

  // Pagination
  document.getElementById("btnPrevPage")?.addEventListener("click", () => {
    if (currentPage > 1) {
      currentPage--;
      loadTransferredFiles();
    }
  });

  document.getElementById("btnNextPage")?.addEventListener("click", () => {
    currentPage++;
    loadTransferredFiles();
  });

  // Sample Payload Helpers
  document.getElementById("btnSampleText")?.addEventListener("click", () => {
    document.getElementById("fileContentText").value =
      "Antigravity Laboratory Experiment Trace: Protocol Mimicry Testing.\n" +
      "Session Timestamp: " + new Date().toISOString() + "\n" +
      "Payload Data: Structured ASCII text stream with UTF-8 support: ⚡️✓\n" +
      "Evaluation: Loopback socket telemetry validation.";
  });

  document.getElementById("btnSampleVoIP")?.addEventListener("click", () => {
    let voipStream = "";
    for (let i = 1; i <= 20; i++) {
      voipStream += `VOIP_FRAME_${i.toString().padStart(3, '0')}|TS=${Date.now() + i * 20}|RTP_SEQ=${1000 + i}|CODEC=G.711\n`;
    }
    document.getElementById("fileContentText").value = voipStream;
    document.getElementById("protocolSelect").value = "UDP";
    document.getElementById("packetSizeInput").value = "160";
    document.getElementById("intervalMsInput").value = "20.0";
  });

  document.getElementById("btnSampleBinary")?.addEventListener("click", () => {
    let hexBytes = "";
    for (let i = 0; i < 64; i++) {
      hexBytes += ("0" + Math.floor(Math.random() * 256).toString(16)).slice(-2) + " ";
    }
    document.getElementById("fileContentText").value = "HEXSTREAM: " + hexBytes.trim();
    document.getElementById("packetSizeInput").value = "64";
  });

  // File Transfer Form Submit
  const form = document.getElementById("fileTransferForm");
  form?.addEventListener("submit", handleFileTransfer);

  // Modal Close
  document.getElementById("btnCloseModal")?.addEventListener("click", closeModal);
  document.getElementById("fileDetailModal")?.addEventListener("click", (e) => {
    if (e.target.id === "fileDetailModal") closeModal();
  });
}

async function loadTransferredFiles() {
  const tbody = document.getElementById("filesTableBody");
  if (!tbody) return;

  try {
    let url = `/api/files?page=${currentPage}&per_page=${perPage}`;
    if (currentSearch) url += `&search=${encodeURIComponent(currentSearch)}`;
    if (currentProtocol) url += `&protocol=${encodeURIComponent(currentProtocol)}`;
    if (currentStatus) url += `&status=${encodeURIComponent(currentStatus)}`;

    const data = await API.get(url);
    const files = data.files || [];
    const total = data.total || 0;
    const pages = data.pages || 1;

    updateKPIs(files, total);
    renderFilesTable(files);
    updatePagination(total, pages);
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding:24px; color:var(--danger);">Failed to load files: ${err.message}</td></tr>`;
  }
}

function updateKPIs(currentBatch, totalCount) {
  animateCounter("statTotalFiles", totalCount);

  let totalBytes = 0;
  let verifiedCount = 0;

  currentBatch.forEach(f => {
    totalBytes += (f.size_bytes || 0);
    if (f.integrity_verified !== false) verifiedCount++;
  });

  document.getElementById("statTotalBytes").innerText = formatBytes(totalBytes);
  const rate = currentBatch.length > 0 ? Math.round((verifiedCount / currentBatch.length) * 100) : 100;
  document.getElementById("statIntegrityRate").innerText = `${rate}%`;
}

function renderFilesTable(files) {
  const tbody = document.getElementById("filesTableBody");
  if (!tbody) return;

  if (files.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align:center; padding:36px; color:var(--text-muted);">
          No transferred files found. Select or create a file above to initiate a socket transmission!
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = files.map(f => {
    const isCompleted = f.status === "completed";
    const statusBadge = isCompleted ? "badge-green" : "badge-red";
    const integrityBadge = (f.integrity_verified !== false)
      ? `<span class="badge badge-green" title="SHA-256 Verified">✓ MATCH</span>`
      : `<span class="badge badge-red" title="Checksum Mismatch">MISMATCH</span>`;

    const protoBadge = f.transport_protocol === "TCP" ? "badge-blue" : "badge-amber";
    const dateStr = f.created_at ? new Date(f.created_at).toLocaleString() : "-";
    const shaShort = f.sha256 ? `${f.sha256.substring(0, 10)}...${f.sha256.substring(58)}` : "None";

    return `
      <tr>
        <td class="mono" style="font-weight:700;">${f.file_id}</td>
        <td>
          <div style="font-weight:600;">${escapeHtml(f.original_filename || "unnamed")}</div>
          <div style="font-size:11px; color:var(--text-muted);">${f.mime_type || "application/octet-stream"}</div>
        </td>
        <td class="mono">${formatBytes(f.size_bytes || 0)}</td>
        <td><span class="badge ${protoBadge}">${f.transport_protocol || "TCP"}</span></td>
        <td class="mono" title="${f.sha256 || ''}" style="cursor:help;">
          ${shaShort}
        </td>
        <td>${integrityBadge}</td>
        <td style="font-size:12px; color:var(--text-muted);">${dateStr}</td>
        <td>
          <div style="display:flex; gap:6px;">
            <button class="btn btn-secondary btn-sm btn-inspect" data-id="${f.file_id}" title="Inspect Details & DPI Classification">Inspect</button>
            <a href="${API.url(`/api/files/${f.file_id}/download`)}" target="_blank" class="btn btn-secondary btn-sm" title="Download Binary File">Download</a>
            <button class="btn btn-danger btn-sm btn-delete-file" data-id="${f.file_id}" title="Delete Record">✕</button>
          </div>
        </td>
      </tr>
    `;
  }).join("");

  // Attach event handlers
  tbody.querySelectorAll(".btn-inspect").forEach(btn => {
    btn.addEventListener("click", () => inspectFileDetails(btn.dataset.id));
  });

  tbody.querySelectorAll(".btn-delete-file").forEach(btn => {
    btn.addEventListener("click", () => deleteFileRecord(btn.dataset.id));
  });
}

function updatePagination(total, pages) {
  const pageInfo = document.getElementById("pageInfo");
  const btnPrev = document.getElementById("btnPrevPage");
  const btnNext = document.getElementById("btnNextPage");

  if (pageInfo) {
    const start = total === 0 ? 0 : (currentPage - 1) * perPage + 1;
    const end = Math.min(currentPage * perPage, total);
    pageInfo.innerText = `Showing ${start} - ${end} of ${total} records (Page ${currentPage} of ${pages})`;
  }

  if (btnPrev) btnPrev.disabled = (currentPage <= 1);
  if (btnNext) btnNext.disabled = (currentPage >= pages);
}

async function handleFileTransfer(e) {
  e.preventDefault();

  const fileInput = document.getElementById("fileInput");
  const contentText = document.getElementById("fileContentText")?.value || "";
  const protocol = document.getElementById("protocolSelect")?.value || "TCP";
  const packetSize = document.getElementById("packetSizeInput")?.value || "128";
  const intervalMs = document.getElementById("intervalMsInput")?.value || "2.0";

  const btnSubmit = document.getElementById("btnStartTransfer");
  const resultBanner = document.getElementById("transferResultBanner");
  const resultContent = document.getElementById("transferResultContent");

  btnSubmit.disabled = true;
  btnSubmit.innerHTML = `<span class="spinner" style="display:inline-block; width:14px; height:14px; border:2px solid #FFF; border-top-color:transparent; border-radius:50%; animation:spin 0.6s linear infinite; margin-right:6px;"></span> Transmitting over ${protocol}...`;

  try {
    let res;
    if (fileInput.files && fileInput.files.length > 0) {
      // Multipart upload
      const formData = new FormData();
      formData.append("file", fileInput.files[0]);
      formData.append("protocol", protocol);
      formData.append("packet_size", packetSize);
      formData.append("interval_ms", intervalMs);

      res = await API.upload("/api/files/transfer", formData);
    } else {
      // Inline text / JSON upload
      if (!contentText.trim()) {
        throw new Error("Please select a file or enter payload text to transmit.");
      }
      res = await API.post("/api/files/transfer", {
        filename: "manual_transmission.txt",
        content_text: contentText,
        protocol: protocol,
        packet_size: parseInt(packetSize),
        interval_ms: parseFloat(intervalMs)
      });
    }

    showToast("File transmitted successfully over real sockets!", "success");

    // Display rich result banner
    if (resultBanner && resultContent) {
      resultBanner.style.display = "block";
      const f = res.file || {};
      const a = res.analysis || {};
      const c = res.classification || {};

      resultContent.innerHTML = `
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px;">
          <div style="display:flex; align-items:center; gap:8px;">
            <span class="badge badge-green">✓ TRANSMISSION SUCCESSFUL</span>
            <span class="mono" style="font-weight:700;">${f.file_id}</span>
          </div>
          <span style="font-size:12px; color:var(--text-muted);">${f.duration_ms} ms elapsed</span>
        </div>

        <div class="grid grid-3" style="gap:12px; margin-bottom:10px; font-size:13px;">
          <div>
            <strong>File:</strong> ${escapeHtml(f.original_filename)} (${formatBytes(f.size_bytes)})<br>
            <strong>Transport:</strong> ${f.transport_protocol} (${f.source} → ${f.destination})
          </div>
          <div>
            <strong>SHA-256 Checksum:</strong><br>
            <span class="mono" style="font-size:11px; word-break:break-all;">${f.sha256}</span>
          </div>
          <div>
            <strong>DPI Classification:</strong> ${c.category_name || "Unknown"} (${c.confidence || 0}%)<br>
            <strong>Packets Transmitted:</strong> ${a.packet_count || 0} (${formatBytes(a.total_bytes || 0)})
          </div>
        </div>
      `;
    }

    // Refresh table and clear file input
    fileInput.value = "";
    loadTransferredFiles();

  } catch (err) {
    showToast(`Transmission failed: ${err.message}`, "error");
    if (resultBanner && resultContent) {
      resultBanner.style.display = "block";
      resultContent.innerHTML = `
        <div style="color:var(--danger); font-weight:700;">
          ⚠ Transmission Error: ${escapeHtml(err.message)}
        </div>
      `;
    }
  } finally {
    btnSubmit.disabled = false;
    btnSubmit.innerHTML = `<span>Transmit over Sockets</span>`;
  }
}

async function inspectFileDetails(fileId) {
  const modal = document.getElementById("fileDetailModal");
  const modalBody = document.getElementById("modalBody");
  const modalTitle = document.getElementById("modalFileTitle");

  if (!modal || !modalBody) return;

  modal.style.display = "flex";
  modalBody.innerHTML = `<div style="text-align:center; padding:24px;">Loading details for ${fileId}...</div>`;

  try {
    const file = await API.get(`/api/files/${fileId}`);
    modalTitle.innerText = `File Transfer: ${file.original_filename || fileId}`;

    let analysisHtml = `<p style="color:var(--text-muted); font-size:13px;">No feature extraction attached.</p>`;
    if (file.analysis_record) {
      const a = file.analysis_record;
      const c = a.classification || {};
      analysisHtml = `
        <div class="card" style="padding:12px; margin-top:12px; background:var(--bg-card-subtle);">
          <div style="font-weight:700; margin-bottom:8px; font-size:14px;">DPI Traffic Feature Analysis</div>
          <div class="grid grid-3" style="gap:10px; font-size:12px;">
            <div><strong>Mean Size:</strong> ${a.mean_size} B</div>
            <div><strong>Size StdDev:</strong> ${a.size_std_dev}</div>
            <div><strong>Min / Max Size:</strong> ${a.min_size} / ${a.max_size} B</div>
            <div><strong>Mean IPT:</strong> ${a.mean_ipt_ms} ms</div>
            <div><strong>Jitter:</strong> ${a.jitter_ms} ms</div>
            <div><strong>Throughput:</strong> ${a.throughput_kbps} kbps</div>
          </div>
          <div style="margin-top:10px; padding-top:8px; border-top:1px solid var(--border); font-size:13px;">
            <strong>DPI Signature Label:</strong> <span class="badge badge-blue">${c.category_name || "-"} (${c.confidence || 0}%)</span>
          </div>
        </div>
      `;
    }

    modalBody.innerHTML = `
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
        <span class="mono" style="font-size:14px; font-weight:700;">${file.file_id}</span>
        <span class="badge ${file.status === 'completed' ? 'badge-green' : 'badge-red'}">${file.status.toUpperCase()}</span>
      </div>

      <div class="grid grid-2" style="gap:12px; font-size:13px; margin-bottom:14px;">
        <div><strong>Original Filename:</strong> ${escapeHtml(file.original_filename)}</div>
        <div><strong>MIME Type:</strong> ${file.mime_type}</div>
        <div><strong>File Size:</strong> ${formatBytes(file.size_bytes)} (${file.size_bytes} bytes)</div>
        <div><strong>Transport Protocol:</strong> ${file.transport_protocol}</div>
        <div><strong>Transfer Duration:</strong> ${file.duration_ms} ms</div>
        <div><strong>Integrity Check:</strong> ${file.integrity_verified ? '✓ SHA-256 Matched' : '⚠ Failed'}</div>
        <div><strong>Transfer Initiated:</strong> ${file.start_time || file.created_at}</div>
        <div><strong>Storage Path:</strong> <span class="mono" style="font-size:11px;">${file.storage_path || 'data/uploads'}</span></div>
      </div>

      <div style="margin-bottom:14px;">
        <strong style="font-size:12px;">SHA-256 Hash Digest:</strong>
        <div class="mono" style="background:var(--bg-main); padding:8px; border-radius:6px; font-size:11px; word-break:break-all; border:1px solid var(--border); margin-top:4px;">
          ${file.sha256}
        </div>
      </div>

      ${analysisHtml}

      <div style="display:flex; justify-content:flex-end; gap:8px; margin-top:18px;">
        <a href="${API.url(`/api/files/${file.file_id}/download`)}" target="_blank" class="btn btn-primary btn-sm">Download Binary</a>
        <button class="btn btn-secondary btn-sm" id="btnModalClose">Close</button>
      </div>
    `;

    document.getElementById("btnModalClose")?.addEventListener("click", closeModal);

  } catch (err) {
    modalBody.innerHTML = `<div style="color:var(--danger); padding:16px;">Failed to load file details: ${err.message}</div>`;
  }
}

function closeModal() {
  const modal = document.getElementById("fileDetailModal");
  if (modal) modal.style.display = "none";
}

async function deleteFileRecord(fileId) {
  if (!confirm(`Are you sure you want to delete file record ${fileId} and its stored binary file?`)) {
    return;
  }

  try {
    await API.delete(`/api/files/${fileId}`);
    showToast(`File record ${fileId} deleted.`, "success");
    loadTransferredFiles();
  } catch (err) {
    showToast(`Failed to delete record: ${err.message}`, "error");
  }
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
