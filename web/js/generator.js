import { API, showToast } from "./api.js";
import { setupNavigation } from "./nav.js";
import { PacketFlowAnimation } from "./charts.js";

let flowAnim = null;
let pollTimer = null;
let currentExpId = null;

const SAMPLE_TEXT_SHORT = "Antigravity Security Lab: Local telemetry packet stream active on 127.0.0.1.";
const SAMPLE_TEXT_LONG = "SECURITY NOTICE: Deep Packet Inspection classifies traffic strictly on statistical behavioral metrics including packet sizes, inter-arrival time distributions, jitter, and burst density. The heuristic classifier completely ignores underlying ASCII/UTF-8 content.";

// Active file state
let selectedFileData = null;
let preloadedSamples = {};

document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation("generator");

  // Init canvas animation
  const canvas = document.getElementById("flowCanvas");
  if (canvas) {
    canvas.width = canvas.parentElement.clientWidth || 600;
    flowAnim = new PacketFlowAnimation("flowCanvas");
    flowAnim.start();
  }

  // Pre-load authentic laboratory sample files from backend
  try {
    const res = await API.get("/api/files/samples");
    if (res && res.samples) {
      preloadedSamples = res.samples;
    }
  } catch (err) {
    console.warn("Could not pre-load sample files:", err);
  }

  // Handle Mode Toggle
  const modeRadios = document.querySelectorAll('input[name="payload_mode"]');
  modeRadios.forEach(radio => {
    radio.addEventListener("change", (e) => {
      togglePayloadMode(e.target.value);
    });
  });

  // Sample Text Buttons
  document.getElementById("btnSampleShort")?.addEventListener("click", () => {
    const ta = document.getElementById("customTextInput");
    if (ta) {
      ta.value = SAMPLE_TEXT_SHORT;
      updateTextMetrics();
    }
  });

  document.getElementById("btnSampleLong")?.addEventListener("click", () => {
    const ta = document.getElementById("customTextInput");
    if (ta) {
      ta.value = SAMPLE_TEXT_LONG;
      updateTextMetrics();
    }
  });

  // Textarea input event
  document.getElementById("customTextInput")?.addEventListener("input", updateTextMetrics);
  document.getElementById("packetSizeInput")?.addEventListener("input", () => {
    updateTextMetrics();
    updateFileChunkPreview();
    if (flowAnim) {
      flowAnim.configure(parseInt(document.getElementById("packetSizeInput").value) || 512, 60);
    }
  });

  // Protocol Toggle Buttons (TCP vs UDP)
  const btnProtoTcp = document.getElementById("btnProtoTcp");
  const btnProtoUdp = document.getElementById("btnProtoUdp");
  const protocolSelect = document.getElementById("protocolSelect");

  btnProtoTcp?.addEventListener("click", () => {
    btnProtoTcp.classList.add("active");
    btnProtoUdp?.classList.remove("active");
    if (protocolSelect) protocolSelect.value = "TCP";
  });

  btnProtoUdp?.addEventListener("click", () => {
    btnProtoUdp.classList.add("active");
    btnProtoTcp?.classList.remove("active");
    if (protocolSelect) protocolSelect.value = "UDP";
  });

  protocolSelect?.addEventListener("change", (e) => {
    if (e.target.value === "TCP") {
      btnProtoTcp?.classList.add("active");
      btnProtoUdp?.classList.remove("active");
    } else {
      btnProtoUdp?.classList.add("active");
      btnProtoTcp?.classList.remove("active");
    }
  });

  // Supported Category Pills
  const categoryPills = document.querySelectorAll("#fileCategoryPills .category-pill");
  categoryPills.forEach(pill => {
    pill.addEventListener("click", () => {
      categoryPills.forEach(p => p.classList.remove("active"));
      pill.classList.add("active");
      const cat = pill.getAttribute("data-cat");
      handleCategoryPillClick(cat);
    });
  });

  // File Dropzone & File Input
  const dropZone = document.getElementById("fileDropZone");
  const fileInput = document.getElementById("fileTransferInput");

  dropZone?.addEventListener("click", () => {
    fileInput?.click();
  });

  dropZone?.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("drag-over");
  });

  dropZone?.addEventListener("dragleave", () => {
    dropZone.classList.remove("drag-over");
  });

  dropZone?.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("drag-over");
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleUserFileSelected(e.dataTransfer.files[0]);
    }
  });

  fileInput?.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleUserFileSelected(e.target.files[0]);
    }
  });

  // Cancel & Retry buttons
  document.getElementById("btnCancelTransfer")?.addEventListener("click", handleCancelTransfer);
  document.getElementById("btnRetryTransfer")?.addEventListener("click", () => {
    document.getElementById("btnGenerate")?.click();
  });

  // Generation form submit
  document.getElementById("trafficForm")?.addEventListener("submit", handleGenerateSubmit);

  // Initial preview setup
  updateTextMetrics();
  // By default, preselect TXT sample for instant file transfer readiness
  if (preloadedSamples && preloadedSamples.txt) {
    loadSampleIntoUI(preloadedSamples.txt);
  }
});

function togglePayloadMode(mode) {
  const customSection = document.getElementById("customTextSection");
  const fileSection = document.getElementById("fileTransferSection");
  const patternSection = document.getElementById("patternSection");
  const packetCountGroup = document.getElementById("packetCountGroup");
  const directionSection = document.getElementById("directionSection");
  const protoGroup = document.getElementById("protocolSelectGroup");
  const liveNodes = document.getElementById("liveNodeStatusGrid");

  // Mode card highlights
  document.querySelectorAll(".mode-card").forEach(c => c.classList.remove("selected"));
  if (mode === "pattern") {
    document.getElementById("modeCardPattern")?.classList.add("selected");
    customSection?.classList.add("hidden");
    fileSection?.classList.add("hidden");
    patternSection?.classList.remove("hidden");
    packetCountGroup?.classList.remove("hidden");
    directionSection?.classList.remove("hidden");
    protoGroup?.classList.remove("hidden");
    liveNodes?.classList.add("hidden");
  } else if (mode === "custom_text") {
    document.getElementById("modeCardCustomText")?.classList.add("selected");
    customSection?.classList.remove("hidden");
    fileSection?.classList.add("hidden");
    patternSection?.classList.add("hidden");
    packetCountGroup?.classList.add("hidden");
    directionSection?.classList.remove("hidden");
    protoGroup?.classList.remove("hidden");
    liveNodes?.classList.add("hidden");
    updateTextMetrics();
  } else if (mode === "file") {
    document.getElementById("modeCardFile")?.classList.add("selected");
    customSection?.classList.add("hidden");
    fileSection?.classList.remove("hidden");
    patternSection?.classList.add("hidden");
    packetCountGroup?.classList.add("hidden"); // Count is dictated by file size / chunk size
    protoGroup?.classList.add("hidden"); // In file mode, protocol is selected via top toggle buttons
    liveNodes?.classList.remove("hidden");
    updateFileChunkPreview();
  }
}

async function handleCategoryPillClick(category) {
  const labelEl = document.getElementById("selectedCategoryLabel");
  const fileInput = document.getElementById("fileTransferInput");

  if (category === "all") {
    if (labelEl) labelEl.innerText = "Selected category: All supported files";
    if (fileInput) fileInput.accept = ".txt,.csv,.png,.jpg,.jpeg,.pdf,.zip,.bin,.dat";
    return;
  }

  const catNames = {
    txt: "TXT Plain Text",
    csv: "CSV Network Metrics",
    png: "PNG Image",
    pdf: "PDF Document",
    zip: "ZIP Compressed Archive",
    other: "Other Binary Datagram"
  };

  const sample = preloadedSamples[category];
  if (sample) {
    if (labelEl) labelEl.innerText = `Selected category: ${catNames[category] || category.toUpperCase()} (${sample.filename})`;
    loadSampleIntoUI(sample);
    showToast(`Loaded authentic ${sample.category.toUpperCase()} sample (${sample.filename})`, "info");
  } else {
    if (labelEl) labelEl.innerText = `Selected category: ${catNames[category] || category.toUpperCase()}`;
  }
}

function loadSampleIntoUI(sample) {
  selectedFileData = {
    filename: sample.filename,
    category: sample.category,
    mime: sample.mime_type,
    size: sample.size_bytes,
    sha256: sample.sha256,
    base64: sample.content_base64
  };
  displaySelectedFileCard();
}

async function handleUserFileSelected(file) {
  if (!file) return;

  const reader = new FileReader();
  reader.onload = async (e) => {
    const arrayBuf = e.target.result;
    const uint8Arr = new Uint8Array(arrayBuf);
    
    // Convert to binary string for btoa safely
    let binary = "";
    const len = uint8Arr.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(uint8Arr[i]);
    }
    const base64Data = btoa(binary);

    // Compute SHA-256 via Web Crypto
    let sha256Hex = "";
    try {
      const hashBuf = await crypto.subtle.digest("SHA-256", arrayBuf);
      const hashArr = Array.from(new Uint8Array(hashBuf));
      sha256Hex = hashArr.map(b => b.toString(16).padStart(2, "0")).join("");
    } catch {
      sha256Hex = "Computing on server...";
    }

    selectedFileData = {
      filename: file.name,
      size: file.size,
      mime: file.type || "application/octet-stream",
      category: getCategoryFromFilename(file.name),
      sha256: sha256Hex,
      base64: base64Data
    };

    displaySelectedFileCard();
    showToast(`Loaded file: ${file.name} (${formatBytes(file.size)})`, "success");
  };
  reader.readAsArrayBuffer(file);
}

function getCategoryFromFilename(fname) {
  const ext = fname.split(".").pop().toLowerCase();
  if (["txt", "log", "md"].includes(ext)) return "txt";
  if (["csv", "tsv"].includes(ext)) return "csv";
  if (["png"].includes(ext)) return "png";
  if (["pdf"].includes(ext)) return "pdf";
  if (["zip", "tar", "gz"].includes(ext)) return "zip";
  return "other";
}

function displaySelectedFileCard() {
  if (!selectedFileData) return;
  const card = document.getElementById("selectedFileCard");
  if (!card) return;

  card.classList.remove("hidden");

  const icons = {
    txt: "📄",
    csv: "📊",
    png: "🖼️",
    pdf: "📕",
    zip: "📦",
    other: "💾"
  };

  document.getElementById("selectedFileIcon").innerText = icons[selectedFileData.category] || "📁";
  document.getElementById("selectedFileName").innerText = selectedFileData.filename;
  document.getElementById("selectedFileCategoryBadge").innerText = (selectedFileData.category || "BIN").toUpperCase();
  document.getElementById("selectedFileMime").innerText = selectedFileData.mime || "application/octet-stream";
  document.getElementById("selectedFileSize").innerText = formatBytes(selectedFileData.size);
  document.getElementById("selectedFileSha256").innerText = selectedFileData.sha256;

  updateFileChunkPreview();
}

function updateFileChunkPreview() {
  if (!selectedFileData) return;
  const packetSize = parseInt(document.getElementById("packetSizeInput")?.value || "512") || 512;
  const capacity = Math.max(8, packetSize - 16); // 16-byte header
  const chunkCount = Math.ceil(selectedFileData.size / capacity) || 1;

  const chunksEl = document.getElementById("selectedFileChunks");
  if (chunksEl) {
    chunksEl.innerText = `${chunkCount} chunks (at ${packetSize} B/chunk)`;
  }
}

function formatBytes(bytes) {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
}

async function updateTextMetrics() {
  const mode = document.querySelector('input[name="payload_mode"]:checked')?.value;
  if (mode !== "custom_text") return;

  const textInput = document.getElementById("customTextInput");
  const text = textInput ? textInput.value : "";
  const sizeInput = document.getElementById("packetSizeInput");
  const packetSize = parseInt(sizeInput ? sizeInput.value : "128") || 128;

  try {
    const preview = await API.post("/api/text/preview", {
      text: text || "A",
      packet_size: packetSize,
      pad_last: true
    });

    const counterEl = document.getElementById("textMetricsCounter");
    if (counterEl) {
      counterEl.innerText = `${preview.text_length} characters, ${preview.total_utf8_bytes} UTF-8 bytes, ${preview.total_packets} packets (at ${preview.packet_size} B/packet)`;
    }

    renderChunkPreview(preview.chunks);
  } catch (e) {
    // Graceful silent fail on empty typing
  }
}

function renderChunkPreview(chunks) {
  const container = document.getElementById("chunkPreviewGrid");
  if (!container) return;

  if (!chunks || chunks.length === 0) {
    container.innerHTML = `<span style="color:var(--text-muted); font-size:12px;">Enter text above to preview packet fragmentation...</span>`;
    return;
  }

  container.innerHTML = chunks.map(c => `
    <div style="background:hsl(${c.hue}, 80%, 94%); border:1px solid hsl(${c.hue}, 60%, 75%); border-radius:6px; padding:6px 10px; font-size:11px;">
      <div style="font-weight:700; color:hsl(${c.hue}, 80%, 30%); display:flex; justify-content:space-between;">
        <span>Packet #${c.seq}</span>
        <span>${c.packet_size} B</span>
      </div>
      <div style="font-family:var(--font-mono); color:#1E293B; margin-top:3px; word-break:break-all;">
        "${c.preview}"
      </div>
      <div style="font-size:10px; color:var(--text-muted); margin-top:2px;">
        Data: ${c.data_len} B | Pad: ${c.padding_len} B
      </div>
    </div>
  `).join("");
}

async function handleGenerateSubmit(e) {
  e.preventDefault();
  const btn = document.getElementById("btnGenerate");
  const btnCancel = document.getElementById("btnCancelTransfer");
  const btnRetry = document.getElementById("btnRetryTransfer");

  const mode = document.querySelector('input[name="payload_mode"]:checked')?.value || "pattern";
  const proto = document.getElementById("protocolSelect").value;
  const count = parseInt(document.getElementById("packetCountInput").value) || 60;
  const size = parseInt(document.getElementById("packetSizeInput").value) || 512;
  const interval = parseFloat(document.getElementById("intervalInput").value) || 10;
  const pattern = document.getElementById("patternSelect")?.value || "random";
  const direction = document.getElementById("directionSelect").value;
  const customText = document.getElementById("customTextInput")?.value || "";

  if (mode === "file" && !selectedFileData) {
    showToast("Please select or drop a file before initiating transfer.", "warning");
    return;
  }

  // Reset UI
  if (btn) btn.disabled = true;
  btnCancel?.classList.remove("hidden");
  btnRetry?.classList.add("hidden");

  document.getElementById("progressBar").style.width = "0%";
  document.getElementById("progressText").innerText = "0%";
  document.getElementById("liveTraceBody").innerHTML = "";
  document.getElementById("receivedBox").classList.add("hidden");
  document.getElementById("fileResultBox").classList.add("hidden");
  document.getElementById("postGenActions").classList.add("hidden");

  if (flowAnim) {
    flowAnim.configure(size, interval, proto === "TCP" ? "#2563EB" : "#D97706");
  }

  const payload = {
    protocol: proto,
    packet_count: count,
    packet_size: size,
    interval_ms: interval,
    payload_pattern: pattern,
    direction: direction,
    payload_mode: mode
  };

  if (mode === "custom_text") {
    payload.custom_text = customText;
  } else if (mode === "file") {
    payload.filename = selectedFileData.filename;
    payload.file_bytes_base64 = selectedFileData.base64;
    payload.expected_sha256 = selectedFileData.sha256;
  }

  try {
    const res = await API.post("/api/traffic/generate", payload);
    currentExpId = res.experiment_id;
    showToast(`Transmission active on 127.0.0.1 (${currentExpId})`, "info");
    startPollingStatus(currentExpId, mode, customText);
  } catch (err) {
    showToast(`Failed to initiate transmission: ${err.message}`, "error");
    if (btn) btn.disabled = false;
    btnCancel?.classList.add("hidden");
  }
}

async function handleCancelTransfer() {
  if (!currentExpId) return;
  try {
    await API.post(`/api/traffic/${currentExpId}/cancel`);
    showToast("Cancellation signal sent to socket engine.", "info");
  } catch (err) {
    showToast(`Cancel failed: ${err.message}`, "error");
  }
}

function startPollingStatus(expId, mode, customText) {
  if (pollTimer) clearInterval(pollTimer);

  const btn = document.getElementById("btnGenerate");
  const btnCancel = document.getElementById("btnCancelTransfer");
  const btnRetry = document.getElementById("btnRetryTransfer");

  pollTimer = setInterval(async () => {
    try {
      const status = await API.get(`/api/traffic/${expId}/status`);
      const progress = status.progress || 0;
      
      document.getElementById("progressBar").style.width = `${progress}%`;
      document.getElementById("progressText").innerText = `${progress}% (${status.packet_count || 0} packets)`;

      // Update Node Status indicators
      if (status.sender_status) {
        document.getElementById("senderNodeStatus").innerText = status.sender_status;
      }
      if (status.bytes_sent !== undefined) {
        document.getElementById("senderBytesStatus").innerText = `${formatBytes(status.bytes_sent)} sent`;
      }
      if (status.receiver_status) {
        document.getElementById("receiverNodeStatus").innerText = status.receiver_status;
      }
      if (status.bytes_received !== undefined) {
        document.getElementById("receiverBytesStatus").innerText = `${formatBytes(status.bytes_received)} received`;
      }

      // Render recent trace
      if (status.packets && status.packets.length > 0) {
        renderLiveTrace(status.packets);
      }

      if (status.status === "completed") {
        clearInterval(pollTimer);
        if (btn) btn.disabled = false;
        btnCancel?.classList.add("hidden");
        btnRetry?.classList.remove("hidden");
        showToast("Transmission successfully completed on loopback!", "success");

        // Show reassembly if custom text
        if (mode === "custom_text" && status.reassembled_text !== undefined) {
          showReassemblyResult(status);
        }

        // Show reassembly proof if file transfer
        if (mode === "file") {
          showFileTransferResult(status);
        }

        // Action links
        document.getElementById("postGenActions").classList.remove("hidden");
        document.getElementById("linkAnalyzeFeatures").href = `features.html?id=${expId}`;
        document.getElementById("linkApplyMimicry").href = `mimicry.html?id=${expId}`;

      } else if (status.status === "incomplete") {
        clearInterval(pollTimer);
        if (btn) btn.disabled = false;
        btnCancel?.classList.add("hidden");
        btnRetry?.classList.remove("hidden");
        showToast("UDP Transfer Incomplete: Some datagram chunks were lost.", "warning");
        if (mode === "file") {
          showFileTransferResult(status);
        }
      } else if (status.status === "cancelled") {
        clearInterval(pollTimer);
        if (btn) btn.disabled = false;
        btnCancel?.classList.add("hidden");
        btnRetry?.classList.remove("hidden");
        showToast("Transfer was aborted by user.", "info");
      } else if (status.status === "failed") {
        clearInterval(pollTimer);
        if (btn) btn.disabled = false;
        btnCancel?.classList.add("hidden");
        btnRetry?.classList.remove("hidden");
        showToast(`Transmission failed: ${status.error}`, "error");
      }
    } catch (e) {
      console.error("Polling error:", e);
    }
  }, 250);
}

function renderLiveTrace(packets) {
  const tbody = document.getElementById("liveTraceBody");
  if (!tbody) return;

  const recent = packets.slice(-15);
  tbody.innerHTML = recent.map(p => `
    <tr class="trace-row-new">
      <td class="mono">#${p.seq}</td>
      <td class="mono">${p.timestamp}s</td>
      <td><span class="badge ${p.proto === 'TCP' ? 'badge-blue' : 'badge-amber'}">${p.proto}</span></td>
      <td><strong>${p.direction}</strong></td>
      <td class="mono">${p.size} B</td>
      <td class="mono" style="color:var(--text-muted);">${p.crc32}</td>
      <td class="mono" style="background:#F8FAFC; border-radius:4px;">${p.preview}</td>
    </tr>
  `).join("");
}

function showReassemblyResult(status) {
  const box = document.getElementById("receivedBox");
  if (!box) return;

  box.classList.remove("hidden");
  const textEl = document.getElementById("receivedTextContent");
  if (textEl) textEl.innerText = status.reassembled_text || "[No data]";

  const badgeEl = document.getElementById("reassemblyMatchBadge");
  if (badgeEl) {
    if (status.text_match) {
      badgeEl.className = "badge badge-green";
      badgeEl.innerText = "✓ Message Received 100% Correctly (Padding Stripped)";
    } else {
      badgeEl.className = "badge badge-red";
      badgeEl.innerText = "⚠ Discrepancy Detected";
    }
  }

  // UDP report
  const udpEl = document.getElementById("udpAnomalyReport");
  if (status.udp_report && udpEl) {
    udpEl.classList.remove("hidden");
    udpEl.innerHTML = `
      <strong>UDP Transmission Report:</strong> 
      Sent: ${status.udp_report.sent_count} | Received: ${status.udp_report.received_count} | 
      Lost: ${status.udp_report.lost_count} | Duplicates: ${status.udp_report.duplicate_count} | 
      Out of order: ${status.udp_report.out_of_order_count}
    `;
  }
}

function showFileTransferResult(status) {
  const box = document.getElementById("fileResultBox");
  if (!box) return;

  box.classList.remove("hidden");
  document.getElementById("resFileName").innerText = status.filename || (selectedFileData ? selectedFileData.filename : "file.bin");
  document.getElementById("resFileSize").innerText = formatBytes(status.bytes_received || (selectedFileData ? selectedFileData.size : 0));
  document.getElementById("resExpectedHash").innerText = (selectedFileData ? selectedFileData.sha256 : "-");
  document.getElementById("resReceivedHash").innerText = status.file_sha256 || "-";

  const badge = document.getElementById("fileVerificationBadge");
  const dlBtn = document.getElementById("btnDownloadReconstructed");

  if (status.status === "completed" && status.file_match) {
    badge.className = "badge badge-green";
    badge.innerText = "✓ SHA-256 Bit-for-Bit Verified (Lossless Reassembly)";
    if (dlBtn && status.file_id) {
      dlBtn.style.display = "inline-flex";
      dlBtn.href = `/api/files/${status.file_id}/download`;
      dlBtn.download = status.filename || "reconstructed_file";
    }
  } else if (status.status === "incomplete") {
    badge.className = "badge badge-amber";
    badge.innerText = "⚠ UDP Transfer Incomplete (Missing Datagrams - File Rejected)";
    if (dlBtn) dlBtn.style.display = "none";
  } else {
    badge.className = "badge badge-red";
    badge.innerText = "⚠ Integrity Verification Mismatch";
    if (dlBtn) dlBtn.style.display = "none";
  }

  // UDP Anomaly Report for Files
  const udpEl = document.getElementById("fileUdpAnomalyReport");
  if (status.udp_report && udpEl) {
    udpEl.classList.remove("hidden");
    udpEl.innerHTML = `
      <strong>UDP Datagram Report:</strong> 
      Sent: ${status.udp_report.sent_count} | Received: ${status.udp_report.received_count} | 
      Lost: ${status.udp_report.lost_count} | Duplicates: ${status.udp_report.duplicate_count} | 
      Out of order: ${status.udp_report.out_of_order_count}
    `;
  } else if (udpEl) {
    udpEl.classList.add("hidden");
  }
}
