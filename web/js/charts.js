/**
 * Charting and Canvas Visualizations (Offline Chart.js & Custom Canvas Animations)
 * Protocol Mimicry Engine Laboratory
 */

/**
 * Semi-circle Animated Confidence Gauge
 */
export function drawConfidenceGauge(canvasId, targetPercent, labelText = "") {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  const width = canvas.width;
  const height = canvas.height;
  const centerX = width / 2;
  const centerY = height - 10;
  const radius = Math.min(centerX, centerY) - 15;

  let currentPercent = 0;
  const duration = 800;
  const startTime = performance.now();

  function render(time) {
    const elapsed = time - startTime;
    const progress = Math.min(elapsed / duration, 1);
    currentPercent = progress * targetPercent;

    ctx.clearRect(0, 0, width, height);

    // Background track (semi-circle from PI to 2*PI)
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, Math.PI, 2 * Math.PI, false);
    ctx.lineWidth = 18;
    ctx.strokeStyle = "#E2E8F0";
    ctx.lineCap = "round";
    ctx.stroke();

    // Value arc
    const endAngle = Math.PI + (currentPercent / 100) * Math.PI;
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, Math.PI, endAngle, false);

    // Color gradient based on confidence
    let strokeColor = "#2563EB";
    if (currentPercent >= 80) strokeColor = "#16A34A";
    else if (currentPercent >= 50) strokeColor = "#D97706";
    else strokeColor = "#DC2626";

    ctx.strokeStyle = strokeColor;
    ctx.lineWidth = 18;
    ctx.lineCap = "round";
    ctx.stroke();

    if (progress < 1) {
      requestAnimationFrame(render);
    }
  }

  requestAnimationFrame(render);
}

/**
 * Size Histogram Chart (Chart.js)
 */
export function renderSizeHistogram(canvasId, histogramData) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !window.Chart) return null;

  const labels = Object.keys(histogramData);
  const data = Object.values(histogramData);

  return new window.Chart(canvas, {
    type: "bar",
    data: {
      labels: labels.map(l => `${l} B`),
      datasets: [{
        label: "Packet Count",
        data: data,
        backgroundColor: "#2563EB",
        borderRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: "#F1F5F9" }
        },
        x: {
          grid: { display: false }
        }
      }
    }
  });
}

/**
 * IPT Timeline Chart (Chart.js)
 */
export function renderIPTLineChart(canvasId, iptSample) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !window.Chart) return null;

  const dataPoints = Array.isArray(iptSample) && iptSample.length > 0 ? iptSample : [0];
  const labels = dataPoints.map((_, i) => `#${i + 1}`);

  return new window.Chart(canvas, {
    type: "line",
    data: {
      labels: labels,
      datasets: [{
        label: "Inter-Packet Time (ms)",
        data: dataPoints,
        borderColor: "#0D9488",
        backgroundColor: "rgba(13, 148, 136, 0.08)",
        fill: true,
        tension: 0.3,
        pointRadius: dataPoints.length === 1 ? 5 : 2,
        pointHoverRadius: 6
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        y: {
          beginAtZero: true,
          suggestedMax: 10,
          grid: { color: "#F1F5F9" }
        },
        x: {
          grid: { display: false },
          ticks: { maxTicksLimit: 12 }
        }
      }
    }
  });
}

/**
 * Burst Donut Chart (Chart.js)
 * Accurately displays the proportion of transmissions in burst clusters vs isolated transmissions.
 */
export function renderBurstDonut(canvasId, burstTransmissions = 0, isolatedTransmissions = 0, totalTransmissions = null, burstClusterCount = null) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !window.Chart) return null;

  const burstTx = Math.max(0, parseInt(burstTransmissions, 10) || 0);
  const isolatedTx = Math.max(0, parseInt(isolatedTransmissions, 10) || 0);
  const total = totalTransmissions !== null && totalTransmissions !== undefined
    ? parseInt(totalTransmissions, 10)
    : (burstTx + isolatedTx);

  const parent = canvas.parentElement;

  // Handle empty or insufficient data gracefully
  if (total <= 0 || (burstTx === 0 && isolatedTx === 0)) {
    canvas.style.display = "none";
    if (parent) {
      let emptyMsg = parent.querySelector(".chart-empty-msg");
      if (!emptyMsg) {
        emptyMsg = document.createElement("div");
        emptyMsg.className = "chart-empty-msg";
        emptyMsg.style.cssText = "display:flex; align-items:center; justify-content:center; height:100%; color:var(--text-muted); font-size:13px; text-align:center; padding:20px;";
        parent.appendChild(emptyMsg);
      }
      emptyMsg.innerText = "No traffic measurements available";
    }
    return null;
  }

  // Restore canvas if previously hidden
  canvas.style.display = "block";
  if (parent) {
    const emptyMsg = parent.querySelector(".chart-empty-msg");
    if (emptyMsg) emptyMsg.remove();
  }

  const burstPctStr = total > 0 ? ((burstTx / total) * 100).toFixed(1) : "0.0";
  const isolatedPctStr = total > 0 ? ((isolatedTx / total) * 100).toFixed(1) : "0.0";

  return new window.Chart(canvas, {
    type: "doughnut",
    data: {
      labels: [
        `Burst Clusters (${burstPctStr}%)`,
        `Isolated (${isolatedPctStr}%)`
      ],
      datasets: [{
        data: [burstTx, isolatedTx],
        backgroundColor: ["#2563EB", "#CBD5E1"],
        hoverBackgroundColor: ["#1D4ED8", "#94A3B8"],
        borderWidth: 2,
        borderColor: "#FFFFFF"
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            boxWidth: 12,
            padding: 14,
            font: { size: 11, family: "'Inter', sans-serif", weight: "500" }
          }
        },
        tooltip: {
          callbacks: {
            label: function(context) {
              const val = context.raw || 0;
              const pct = total > 0 ? ((val / total) * 100).toFixed(1) : "0.0";
              const labelName = context.dataIndex === 0 ? "Burst-Cluster Transmissions" : "Isolated Transmissions";
              return ` ${labelName}: ${val} pkts (${pct}%)`;
            },
            afterBody: function() {
              if (burstClusterCount !== null && burstClusterCount !== undefined) {
                return `Total Clusters: ${burstClusterCount}`;
              }
              return "";
            }
          }
        }
      },
      cutout: "70%"
    }
  });
}

/**
 * Interactive Live Packet-Flow Animation
 * Animates packets moving from Client (left) to Server (right).
 * Packet dot size reflects payload size; spacing reflects interval.
 */
export class PacketFlowAnimation {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext("2d");
    this.particles = [];
    this.animating = false;
    this.speed = 1.0;
    this.lastSpawn = 0;
    this.spawnInterval = 100; // ms
    this.packetSize = 512;
    this.color = "#2563EB";
    this.active = true;
  }

  start() {
    this.animating = true;
    const loop = (t) => {
      if (!this.animating) return;
      this.update(t);
      this.draw();
      requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
  }

  stop() {
    this.animating = false;
  }

  configure(size = 512, intervalMs = 50, color = "#2563EB") {
    this.packetSize = size;
    this.spawnInterval = Math.max(20, intervalMs);
    this.color = color;
  }

  update(currentTime) {
    if (currentTime - this.lastSpawn > this.spawnInterval) {
      this.lastSpawn = currentTime;
      // Spawn new particle
      const radius = Math.max(3, Math.min(10, (this.packetSize / 1460) * 10));
      this.particles.push({
        x: 40,
        y: this.canvas.height / 2,
        radius: radius,
        speed: 3.5 * this.speed,
        color: this.color
      });
    }

    // Move particles
    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i];
      p.x += p.speed;
      if (p.x > this.canvas.width - 40) {
        this.particles.splice(i, 1);
      }
    }
  }

  draw() {
    const { ctx, canvas } = this;
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw connection track line
    ctx.beginPath();
    ctx.moveTo(40, canvas.height / 2);
    ctx.lineTo(canvas.width - 40, canvas.height / 2);
    ctx.strokeStyle = "#E2E8F0";
    ctx.lineWidth = 3;
    ctx.stroke();

    // Draw endpoint nodes
    ctx.fillStyle = "#2563EB";
    ctx.beginPath();
    ctx.arc(40, canvas.height / 2, 7, 0, Math.PI * 2);
    ctx.fill();

    ctx.fillStyle = "#0D9488";
    ctx.beginPath();
    ctx.arc(canvas.width - 40, canvas.height / 2, 7, 0, Math.PI * 2);
    ctx.fill();

    // Draw moving packet dots
    for (const p of this.particles) {
      ctx.fillStyle = p.color;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
      ctx.fill();
    }
  }
}
