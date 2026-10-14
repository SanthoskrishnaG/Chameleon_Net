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

  // Populate experiment selector dropdown
  await initExperimentSelector(expId);

  // If no expId in URL, use the first available from selector
  if (!expId) {
    const sel = document.getElementById("expSelector");
    if (sel && sel.value) {
      expId = sel.value;
    }
  }

  if (expId) {
    loadExperimentFeatures(expId);
  } else {
    showEmptyState();
  }
});

async function initExperimentSelector(currentExpId) {
  const sel = document.getElementById("expSelector");
  if (!sel) return;

  try {
    const expRes = await API.get("/api/experiments");
    const experiments = expRes.experiments || [];

    if (experiments.length === 0) {
      sel.innerHTML = `<option value="">No experiments recorded</option>`;
      return;
    }

    sel.innerHTML = experiments.map(exp => {
      const isSelected = exp.id === currentExpId ? "selected" : "";
      const label = `${exp.id} (${exp.config?.protocol || "TCP"}, ${exp.config?.payload_mode || "traffic"})`;
      return `<option value="${exp.id}" ${isSelected}>${label}</option>`;
    }).join("");

    sel.addEventListener("change", (e) => {
      const selectedId = e.target.value;
      if (selectedId) {
        // Update URL query param without full page reload
        const newUrl = new URL(window.location.href);
        newUrl.searchParams.set("id", selectedId);
        window.history.replaceState({}, "", newUrl.toString());
        loadExperimentFeatures(selectedId);
      }
    });

  } catch (err) {
    console.warn("Could not load experiments list for selector:", err);
  }
}

async function loadExperimentFeatures(expId) {
  try {
    const badge = document.getElementById("currentExpBadge");
    if (badge) badge.innerText = expId;

    const sel = document.getElementById("expSelector");
    if (sel && sel.value !== expId) {
      sel.value = expId;
    }

    const res = await API.get(`/api/features/${expId}`);
    const feat = res.features_before;
    if (!feat || feat.packet_count === 0) {
      showEmptyState();
      return;
    }

    renderFeatureTable(feat);

    // Destroy existing Chart.js instances before re-rendering
    if (sizeChart) sizeChart.destroy();
    if (iptChart) iptChart.destroy();
    if (burstChart) burstChart.destroy();

    sizeChart = renderSizeHistogram("sizeHistogramCanvas", feat.size_histogram || {});
    iptChart = renderIPTLineChart("iptTimelineCanvas", feat.ipt_series_sample || []);

    // Accurate burst metrics from API
    const burstTx = feat.transmissions_in_bursts !== undefined ? feat.transmissions_in_bursts : 0;
    const isolatedTx = feat.isolated_transmission_count !== undefined ? feat.isolated_transmission_count : Math.max(0, (feat.packet_count || 0) - burstTx);
    const totalTx = feat.total_transmissions || feat.packet_count || (burstTx + isolatedTx);
    const clusterCount = feat.burst_cluster_count !== undefined ? feat.burst_cluster_count : feat.burst_count;

    burstChart = renderBurstDonut("burstDonutCanvas", burstTx, isolatedTx, totalTx, clusterCount);

    // Update navigation button to carry experiment ID
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

  const totalTx = f.total_transmissions || f.packet_count || 0;
  const burstRatioPct = f.burst_cluster_ratio !== undefined 
    ? (f.burst_cluster_ratio * 100).toFixed(1) 
    : (totalTx > 0 ? (((f.transmissions_in_bursts || 0) / totalTx) * 100).toFixed(1) : "0.0");
  const isoRatioPct = f.isolated_transmission_ratio !== undefined 
    ? (f.isolated_transmission_ratio * 100).toFixed(1) 
    : (totalTx > 0 ? (((f.isolated_transmission_count || 0) / totalTx) * 100).toFixed(1) : "0.0");

  const rows = [
    { name: "Total Packet Count", val: totalTx, desc: "Total datagrams in flow" },
    { name: "Total Volume", val: `${f.total_bytes.toLocaleString()} Bytes`, desc: "Aggregate transferred bytes" },
    { name: "Flow Duration", val: `${f.duration} seconds`, desc: "Time delta between first and last packet" },
    { name: "Mean Packet Size", val: `${f.mean_size} B`, desc: "Average size (Standard Dev: ±" + f.std_size + " B)" },
    { name: "Min / Max Packet Size", val: `${f.min_size} B / ${f.max_size} B`, desc: "Lower and upper size boundaries" },
    { name: "Mean Inter-Packet Time (IPT)", val: `${f.mean_ipt_ms} ms`, desc: "Average pacing delay between packets" },
    { name: "Network Jitter", val: `${f.jitter_ms} ms`, desc: "Mean absolute variance of consecutive arrival times" },
    { name: "Burst Threshold (<20ms)", val: `${f.burst_threshold_ms || 20.0} ms`, desc: "Maximum inter-arrival gap defining a burst cluster" },
    { name: "Burst-Cluster Transmissions", val: `${f.transmissions_in_bursts || 0} (${burstRatioPct}%)`, desc: "Packets belonging to burst clusters (<20ms intervals)" },
    { name: "Isolated Transmissions", val: `${f.isolated_transmission_count || 0} (${isoRatioPct}%)`, desc: "Packets arriving outside burst clusters (>=20ms gap)" },
    { name: "Burst Cluster Count", val: f.burst_cluster_count !== undefined ? f.burst_cluster_count : f.burst_count, desc: "Number of distinct burst clusters (>=2 packets each)" },
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
