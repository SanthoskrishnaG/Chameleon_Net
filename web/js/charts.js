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

  return new window.Chart(canvas, {
    type: "line",
    data: {
      labels: iptSample.map((_, i) => `#${i + 1}`),
      datasets: [{
        label: "Inter-Packet Time (ms)",
        data: iptSample,
        borderColor: "#0D9488",
        backgroundColor: "rgba(13, 148, 136, 0.08)",
        fill: true,
        tension: 0.3,
        pointRadius: 2
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
          grid: { display: false },
          ticks: { maxTicksLimit: 12 }
        }
      }
    }
  });
}

/**
 * Burst Donut Chart (Chart.js)
 */
export function renderBurstDonut(canvasId, burstCount, singlePackets) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !window.Chart) return null;

  return new window.Chart(canvas, {
    type: "doughnut",
    data: {
      labels: ["Burst Clusters (<20ms)", "Isolated Transmissions"],
      datasets: [{
        data: [burstCount, Math.max(1, singlePackets)],
        backgroundColor: ["#2563EB", "#CBD5E1"]
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "bottom" }
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
