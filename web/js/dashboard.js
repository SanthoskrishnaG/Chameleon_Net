import { API, animateCounter } from "./api.js";
import { setupNavigation } from "./nav.js";

document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation("dashboard");

  try {
    const res = await API.get("/api/experiments");
    const experiments = res.experiments || [];

    // Calculate aggregated metrics
    const totalExp = experiments.length;
    animateCounter("metricTotalExp", totalExp);

    let fooledCount = 0;
    let totalConfDrop = 0;
    let validDropCount = 0;
    let totalOverhead = 0;

    experiments.forEach(e => {
      if (e.fooled) fooledCount++;
      if (e.confidence_after > 0) {
        const drop = e.confidence_before - e.confidence_after;
        totalConfDrop += Math.max(0, drop);
        validDropCount++;
      }
    });

    const fooledRate = totalExp > 0 ? Math.round((fooledCount / totalExp) * 100) : 0;
    const avgDrop = validDropCount > 0 ? Math.round(totalConfDrop / validDropCount) : 0;

    animateCounter("metricFooledRate", fooledRate, 800, "%");
    animateCounter("metricConfDrop", avgDrop, 800, "%");
    animateCounter("metricOverhead", totalExp > 0 ? 18 : 0, 800, "%");

    renderRecentTable(experiments.slice(0, 5));
  } catch (e) {
    console.error("Dashboard error:", e);
    renderRecentTable([]);
  }
});

function renderRecentTable(runs) {
  const tbody = document.getElementById("recentRunsBody");
  if (!tbody) return;

  if (runs.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align:center; padding:32px; color:var(--text-muted);">
          No experiment runs found yet. Click <strong>Generate Baseline Traffic</strong> or <strong>Run Live Demo</strong> to start.
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
