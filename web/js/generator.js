import { API, showToast } from "./api.js";
import { setupNavigation } from "./nav.js";
import { PacketFlowAnimation } from "./charts.js";

let flowAnim = null;
let pollTimer = null;
let currentExpId = null;
let miniChart = null;

const SAMPLE_TEXT_SHORT = "Antigravity Security Lab: Local telemetry packet stream active on 127.0.0.1.";
const SAMPLE_TEXT_LONG = "SECURITY NOTICE: Deep Packet Inspection classifies traffic strictly on statistical behavioral metrics including packet sizes, inter-arrival time distributions, jitter, and burst density. The heuristic classifier completely ignores underlying ASCII/UTF-8 content.";

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation("generator");

  // Init canvas animation
  const canvas = document.getElementById("flowCanvas");
  if (canvas) {
    canvas.width = canvas.parentElement.clientWidth || 600;
    flowAnim = new PacketFlowAnimation("flowCanvas");
    flowAnim.start();
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
    if (flowAnim) {
      flowAnim.configure(parseInt(document.getElementById("packetSizeInput").value) || 512, 60);
    }
  });

  // Generation form submit
  document.getElementById("trafficForm")?.addEventListener("submit", handleGenerateSubmit);

  // Initial preview
  updateTextMetrics();
});

function togglePayloadMode(mode) {
  const customSection = document.getElementById("customTextSection");
  const patternSection = document.getElementById("patternSection");
  const packetCountGroup = document.getElementById("packetCountGroup");

  if (mode === "custom_text") {
    customSection?.classList.remove("hidden");
    patternSection?.classList.add("hidden");
    packetCountGroup?.classList.add("hidden"); // Auto calculated
    updateTextMetrics();
  } else {
    customSection?.classList.add("hidden");
    patternSection?.classList.remove("hidden");
    packetCountGroup?.classList.remove("hidden");
  }
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
  if (btn) btn.disabled = true;

  const mode = document.querySelector('input[name="payload_mode"]:checked')?.value || "pattern";
  const proto = document.getElementById("protocolSelect").value;
  const count = parseInt(document.getElementById("packetCountInput").value) || 60;
  const size = parseInt(document.getElementById("packetSizeInput").value) || 512;
  const interval = parseFloat(document.getElementById("intervalInput").value) || 15;
  const pattern = document.getElementById("patternSelect")?.value || "random";
  const direction = document.getElementById("directionSelect").value;
  const customText = document.getElementById("customTextInput")?.value || "";

  // Reset UI
  document.getElementById("progressBar").style.width = "0%";
  document.getElementById("progressText").innerText = "0%";
  document.getElementById("liveTraceBody").innerHTML = "";
  document.getElementById("receivedBox").classList.add("hidden");

  if (flowAnim) {
    flowAnim.configure(size, interval, "#2563EB");
  }

  try {
    const res = await API.post("/api/traffic/generate", {
      protocol: proto,
      packet_count: count,
      packet_size: size,
      interval_ms: interval,
      payload_pattern: pattern,
      direction: direction,
      payload_mode: mode,
      custom_text: customText
    });

    currentExpId = res.experiment_id;
    showToast(`Transmission started on 127.0.0.1 (${currentExpId})`, "info");
    startPollingStatus(currentExpId, mode, customText);

  } catch (err) {
    showToast(`Failed to generate traffic: ${err.message}`, "error");
    if (btn) btn.disabled = false;
  }
}

function startPollingStatus(expId, mode, customText) {
  if (pollTimer) clearInterval(pollTimer);

  pollTimer = setInterval(async () => {
    try {
      const status = await API.get(`/api/traffic/${expId}/status`);
      const progress = status.progress || 0;
      
      document.getElementById("progressBar").style.width = `${progress}%`;
      document.getElementById("progressText").innerText = `${progress}% (${status.packet_count || 0} packets)`;

      // Render recent trace
      if (status.packets && status.packets.length > 0) {
        renderLiveTrace(status.packets);
      }

      if (status.status === "completed") {
        clearInterval(pollTimer);
        document.getElementById("btnGenerate").disabled = false;
        showToast("Transmission successfully completed on loopback!", "success");

        // Show reassembly if custom text
        if (mode === "custom_text" && status.reassembled_text !== undefined) {
          showReassemblyResult(status);
        }

        // Action links
        document.getElementById("postGenActions").classList.remove("hidden");
        document.getElementById("linkAnalyzeFeatures").href = `features.html?id=${expId}`;
        document.getElementById("linkApplyMimicry").href = `mimicry.html?id=${expId}`;
      } else if (status.status === "failed") {
        clearInterval(pollTimer);
        document.getElementById("btnGenerate").disabled = false;
        showToast(`Generation failed: ${status.error}`, "error");
      }
    } catch (e) {
      console.error("Polling error:", e);
    }
  }, 300);
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
