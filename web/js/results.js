import { API, showToast } from "./api.js";
import { setupNavigation } from "./nav.js";

let allExperiments = [];

document.addEventListener("DOMContentLoaded", async () => {
  setupNavigation("results");

  loadExperiments();

  // Search input event
  document.getElementById("searchInput")?.addEventListener("input", (e) => {
    filterAndRender(e.target.value);
  });

  // Sort dropdown
  document.getElementById("sortSelect")?.addEventListener("change", (e) => {
    sortAndRender(e.target.value);
  });
});

async function loadExperiments() {
  try {
    const res = await API.get("/api/experiments");
    allExperiments = res.experiments || [];
    renderResultsTable(allExperiments);
  } catch (err) {
    showToast(`Failed to load experiments: ${err.message}`, "error");
  }
}

function filterAndRender(query) {
  const q = query.toLowerCase().trim();
  if (!q) {
    renderResultsTable(allExperiments);
    return;
  }
  const filtered = allExperiments.filter(e => 
    e.id.toLowerCase().includes(q) ||
    e.category_before.toLowerCase().includes(q) ||
    e.category_after.toLowerCase().includes(q) ||
    e.target_profile.toLowerCase().includes(q) ||
    e.protocol.toLowerCase().includes(q)
  );
  renderResultsTable(filtered);
}

function sortAndRender(sortKey) {
  const sorted = [...allExperiments];
  if (sortKey === "id") {
    sorted.sort((a, b) => b.id.localeCompare(a.id));
  } else if (sortKey === "confidence") {
    sorted.sort((a, b) => (b.confidence_after || 0) - (a.confidence_after || 0));
  } else {
    // Default: date descending
    sorted.sort((a, b) => b.created_at.localeCompare(a.created_at));
  }
  renderResultsTable(sorted);
}

function renderResultsTable(records) {
  const tbody = document.getElementById("resultsTableBody");
  if (!tbody) return;

  if (records.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="8" style="text-align:center; padding:36px; color:var(--text-muted);">
          No saved experiments match the criteria.
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = records.map(r => {
    let badgeClass = "badge-gray";
    if (r.fooled) badgeClass = "badge-green";
    else if (r.status_banner === "SIGNATURE SHIFTED") badgeClass = "badge-amber";
    else if (r.status_banner === "CLASSIFIER NOT FOOLED") badgeClass = "badge-red";

    const dateStr = r.created_at ? new Date(r.created_at).toLocaleString() : "-";

    return `
      <tr>
        <td class="mono"><strong>${r.id}</strong></td>
        <td style="font-size:12px; color:var(--text-muted);">${dateStr}</td>
        <td><span class="badge badge-blue">${r.protocol}</span></td>
        <td>${r.category_before} (${r.confidence_before}%)</td>
        <td>${r.target_profile || "-"}</td>
        <td>${r.category_after || "-"} ${r.confidence_after ? `(${r.confidence_after}%)` : ""}</td>
        <td><span class="badge ${badgeClass}">${r.status_banner}</span></td>
        <td>
          <div style="display:flex; gap:6px;">
            <a href="comparison.html?id=${r.id}" class="btn btn-secondary btn-sm">Inspect</a>
            <a target="_blank" href="${API.url(`/api/export/${r.id}?format=html`)}" class="btn btn-secondary btn-sm" title="Printable Report">HTML</a>
            <a href="${API.url(`/api/export/${r.id}?format=csv`)}" class="btn btn-secondary btn-sm" title="Export CSV">CSV</a>
            <button class="btn btn-danger btn-sm btn-delete" data-id="${r.id}" title="Delete">✕</button>
          </div>
        </td>
      </tr>
    `;
  }).join("");

  // Attach delete handlers
  document.querySelectorAll(".btn-delete").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      const id = e.currentTarget.getAttribute("data-id");
      if (confirm(`Delete experiment ${id} and all related CSV traces?`)) {
        try {
          await API.delete(`/api/experiments/${id}`);
          showToast(`Deleted ${id}`, "info");
          loadExperiments();
        } catch (err) {
          showToast(`Delete failed: ${err.message}`, "error");
        }
      }
    });
  });
}
