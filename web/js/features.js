import { API, showToast } from "./api.js";
import { setupNavigation } from "./nav.js";
import { renderSizeHistogram, renderIPTLineChart, renderBurstDonut } from "./charts.js";

let sizeChart = null;
let iptChart = null;
let burstChart = null;

document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation("features");

  const urlParams = new URLSearchParams(window.location.search);
  let expId = urlParams.get("id");

  if (!expId) {
    // Fetch latest experiment
    try {
      const expRes = await API.get("/api/experiments");
      if (expRes.experiments && expRes.experiments.length > 0) {
        expId = expRes.experiments[0].id;
      }
    } catch (e) {
      console.error(e);
    }
  }

  if (expId) {
    loadExperimentFeatures(expId);
  } else {
    showEmptyState();
  }
});

async function loadExperimentFeatures(expId) {
  try {
    document.getElementById("currentExpBadge").innerText = expId;
    const res = await API.get(`/api/features/${expId}`);
    const feat = res.features_before;
    if (!feat) {
      showEmptyState();
      return;
    }

    renderFeatureTable(feat);

    // Render Charts
    if (sizeChart) sizeChart.destroy();
    if (iptChart) iptChart.destroy();
    if (burstChart) burstChart.destroy();

    sizeChart = renderSizeHistogram("sizeHistogramCanvas", feat.size_histogram || {});
    iptChart = renderIPTLineChart("iptTimelineCanvas", feat.ipt_series_sample || []);
    burstChart = renderBurstDonut("burstDonutCanvas", feat.burst_count, feat.packet_count - feat.burst_count);

    // Update navigation button
    const nextBtn = document.getElementById("btnProceedClassifier");
    if (nextBtn) {
      nextBtn.href = `classifier.html?id=${expId}`;
    }

  } catch (err) {
    showToast(`Failed to load features: ${err.message}`, "error");
    showEmptyState();
  }
}

function renderFeatureTable(f) {
  const tbody = document.getElementById("featuresTableBody");
  if (!tbody) return;

  const rows = [
    { name: "Total Packet Count", val: f.packet_count, desc: "Total datagrams in flow" },
    { name: "Total Volume", val: `${f.total_bytes.toLocaleString()} Bytes`, desc: "Aggregate transferred bytes" },
    { name: "Flow Duration", val: `${f.duration} seconds`, desc: "Time delta between first and last packet" },
    { name: "Mean Packet Size", val: `${f.mean_size} B`, desc: "Average size (Standard Dev: ±" + f.std_size + " B)" },
    { name: "Min / Max Packet Size", val: `${f.min_size} B / ${f.max_size} B`, desc: "Lower and upper size boundaries" },
    { name: "Mean Inter-Packet Time (IPT)", val: `${f.mean_ipt_ms} ms`, desc: "Average pacing delay between packets" },
    { name: "Network Jitter", val: `${f.jitter_ms} ms`, desc: "Mean absolute variance of consecutive arrival times" },
    { name: "Burst Groups (<20ms)", val: f.burst_count, desc: "Packet clusters arriving under 20ms threshold" },
    { name: "Mean Burst Length", val: `${f.mean_burst_length} pkts`, desc: "Average consecutive packets per burst cluster" },
    { name: "Packet Throughput Rate", val: `${f.packets_per_sec} pkts/sec`, desc: "Frequency of packet arrival" },
    { name: "Bandwidth Throughput Rate", val: `${(f.bytes_per_sec / 1024).toFixed(1)} KB/sec`, desc: "Bandwidth volume rate" },
    { name: "Forward / Reverse Ratio", val: f.forward_reverse_ratio, desc: "Client-to-server vs echo response balance" },
    { name: "Transport Protocol", val: f.protocol, desc: "Layer 4 socket transport" }
  ];

  tbody.innerHTML = rows.map(r => `
    <tr>
      <td><strong>${r.name}</strong></td>
      <td class="mono" style="font-weight:700; color:var(--primary); font-size:14px;">${r.val}</td>
      <td style="color:var(--text-muted); font-size:12px;">${r.desc}</td>
    </tr>
  `).join("");
}

function showEmptyState() {
  const container = document.getElementById("featuresContainer");
  if (container) {
    container.innerHTML = `
      <div class="card" style="text-align:center; padding:48px;">
        <h3 style="margin-bottom:8px;">No Features Available</h3>
        <p style="color:var(--text-muted); margin-bottom:20px;">Please generate network traffic first or select a saved experiment.</p>
        <a href="generator.html" class="btn btn-primary">Go to Traffic Generator</a>
      </div>
    `;
  }
}
