import { API, showToast, animateCounter } from "./api.js";
import { setupNavigation } from "./nav.js";
import { drawConfidenceGauge, PacketFlowAnimation } from "./charts.js";

let flowAnim = null;
let currentRunId = null;
let pollTimer = null;
let isPaused = false;
let currentSpeed = 1.0;
let savedExpId = null;

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation("demo");

  // Init canvas animation
  const canvas = document.getElementById("demoFlowCanvas");
  if (canvas) {
    canvas.width = canvas.parentElement.clientWidth || 600;
    flowAnim = new PacketFlowAnimation("demoFlowCanvas");
    flowAnim.start();
  }

  // Source selection toggle
  document.querySelectorAll('input[name="demoSource"]').forEach(r => {
    r.addEventListener("change", (e) => {
      const isCustom = e.target.value === "custom_text";
      document.getElementById("demoCustomTextGroup")?.classList.toggle("hidden", !isCustom);
    });
  });

  // Buttons
  document.getElementById("btnStartDemo")?.addEventListener("click", startLiveDemo);
  document.getElementById("btnPauseDemo")?.addEventListener("click", togglePause);
  document.getElementById("btnSpeedDemo")?.addEventListener("click", toggleSpeed);
  document.getElementById("btnRestartDemo")?.addEventListener("click", restartDemo);
  document.getElementById("btnSaveExp")?.addEventListener("click", handleSaveExperiment);
});

async function startLiveDemo() {
  const source = document.querySelector('input[name="demoSource"]:checked')?.value || "random";
  const customText = document.getElementById("demoCustomTextInput")?.value || "Antigravity Live Demo Text Stream";
  const targetProf = document.getElementById("demoTargetProfile")?.value || "voip_call";
  const scenario = document.getElementById("demoScenario")?.value || "deception";
  const transportMode = scenario === "limitation" ? "keep_original" : "convert_transport";

  // Disable start button, enable control buttons
  document.getElementById("btnStartDemo").disabled = true;
  document.getElementById("demoConfigCard").classList.add("hidden");
  document.getElementById("demoActiveCard").classList.remove("hidden");
  document.getElementById("btnPauseDemo").disabled = false;
  document.getElementById("btnSpeedDemo").disabled = false;

  resetStepChecklist();

  try {
    const res = await API.post("/api/demo/run", {
      source_type: source,
      custom_text: customText,
      target_profile: targetProf,
      transport_mode: transportMode,
      speed: currentSpeed,
      packet_count: 50
    });

    currentRunId = res.run_id;
    startPollingDemo(currentRunId);
  } catch (err) {
    showToast(`Failed to start demo: ${err.message}`, "error");
    document.getElementById("btnStartDemo").disabled = false;
  }
}

function startPollingDemo(runId) {
  if (pollTimer) clearInterval(pollTimer);

  pollTimer = setInterval(async () => {
    try {
      const data = await API.get(`/api/demo/${runId}/events`);
      updateDemoUI(data);

      if (data.status === "completed" || data.status === "failed") {
        clearInterval(pollTimer);
        document.getElementById("btnPauseDemo").disabled = true;
        if (data.status === "completed") {
          savedExpId = data.experiment_id || (data.data && data.data.experiment_id);
          document.getElementById("btnSaveExp").classList.remove("hidden");
          showToast("Live Demo Pipeline Completed!", "success");
        }
      }
    } catch (e) {
      console.error("Demo poll error:", e);
    }
  }, 350);
}

function updateDemoUI(data) {
  // Narration
  const narrEl = document.getElementById("demoNarrationText");
  if (narrEl) narrEl.innerText = data.narration;

  // Step Checklist
  const currentStep = data.current_step || 1;
  for (let s = 1; s <= 6; s++) {
    const stepEl = document.getElementById(`demoStepItem_${s}`);
    const checkEl = document.getElementById(`demoStepCheck_${s}`);
    if (!stepEl || !checkEl) continue;

    if (s < currentStep) {
      stepEl.className = "step-item completed";
      checkEl.innerText = "✓";
    } else if (s === currentStep) {
      stepEl.className = "step-item active";
      checkEl.innerText = "●";
    } else {
      stepEl.className = "step-item";
      checkEl.innerText = s;
    }
  }

  // Canvas visual updates
  if (flowAnim) {
    if (currentStep >= 4) {
      // Mimicked VoIP: smaller packets, faster intervals, green dots
      flowAnim.configure(160, 20, "#16A34A");
    } else {
      // Baseline Bulk: larger packets, blue dots
      flowAnim.configure(550, 80, "#2563EB");
    }
  }

  // Dynamic visual cards based on step data
  const extra = data.data || {};

  // Step 2: Extracted Features
  if (extra.features_before) {
    const fb = extra.features_before;
    document.getElementById("demoFeaturesCard").classList.remove("hidden");
    document.getElementById("demoFeatMeanSize").innerText = `${fb.mean_size} B`;
    document.getElementById("demoFeatMeanIPT").innerText = `${fb.mean_ipt_ms} ms`;
    document.getElementById("demoFeatJitter").innerText = `${fb.jitter_ms} ms`;
    document.getElementById("demoFeatBursts").innerText = `${fb.burst_count}`;
  }

  // Step 3: Baseline Classifier
  if (extra.classification_before) {
    const cb = extra.classification_before;
    document.getElementById("demoClassifierCard").classList.remove("hidden");
    document.getElementById("demoBeforeCat").innerText = cb.category_name;
    document.getElementById("demoBeforeConf").innerText = `${cb.confidence}% (${cb.label})`;
    drawConfidenceGauge("demoGaugeCanvasBefore", cb.confidence);
  }

  // Step 4: Mimicry Applied
  if (extra.mimic_result) {
    document.getElementById("demoMimicCard").classList.remove("hidden");
    const ovh = extra.mimic_result.overhead || {};
    document.getElementById("demoOvhBytes").innerText = `+${ovh.extra_bytes_percent}%`;
    document.getElementById("demoOvhDelay").innerText = `+${ovh.added_delay_percent}%`;
  }

  // Step 5: Transformed Classifier
  if (extra.classification_after) {
    const ca = extra.classification_after;
    document.getElementById("demoClassifierAfterCard").classList.remove("hidden");
    document.getElementById("demoAfterCat").innerText = ca.category_name;
    document.getElementById("demoAfterConf").innerText = `${ca.confidence}% (${ca.label})`;
    drawConfidenceGauge("demoGaugeCanvasAfter", ca.confidence);
  }

  // Step 6: Comparison Verdict
  if (extra.comparison) {
    const cmp = extra.comparison;
    const banner = document.getElementById("demoVerdictBanner");
    if (banner) {
      banner.classList.remove("hidden");
      banner.className = `verdict-banner ${cmp.banner_type || 'success'}`;
      banner.innerHTML = `
        <span style="font-size:24px;">${cmp.fooled_target ? '🎯' : '⚠️'}</span>
        <div>
          <div style="font-size:16px; font-weight:800;">${cmp.status_banner}</div>
          <div style="font-size:13px;">${cmp.verdict}</div>
        </div>
      `;
    }
  }
}

function resetStepChecklist() {
  for (let s = 1; s <= 6; s++) {
    const stepEl = document.getElementById(`demoStepItem_${s}`);
    const checkEl = document.getElementById(`demoStepCheck_${s}`);
    if (stepEl) stepEl.className = "step-item";
    if (checkEl) checkEl.innerText = s;
  }
  document.getElementById("demoFeaturesCard")?.classList.add("hidden");
  document.getElementById("demoClassifierCard")?.classList.add("hidden");
  document.getElementById("demoMimicCard")?.classList.add("hidden");
  document.getElementById("demoClassifierAfterCard")?.classList.add("hidden");
  document.getElementById("demoVerdictBanner")?.classList.add("hidden");
  document.getElementById("btnSaveExp")?.classList.add("hidden");
}

async function togglePause() {
  if (!currentRunId) return;
  isPaused = !isPaused;
  const btn = document.getElementById("btnPauseDemo");
  if (btn) btn.innerText = isPaused ? "Resume" : "Pause";
  await API.post(`/api/demo/${currentRunId}/control`, { action: isPaused ? "pause" : "resume" });
}

async function toggleSpeed() {
  if (!currentRunId) return;
  currentSpeed = currentSpeed === 1.0 ? 2.0 : 1.0;
  const btn = document.getElementById("btnSpeedDemo");
  if (btn) btn.innerText = `Speed: ${currentSpeed}x`;
  await API.post(`/api/demo/${currentRunId}/control`, { action: "speed", speed: currentSpeed });
}

function restartDemo() {
  if (pollTimer) clearInterval(pollTimer);
  document.getElementById("btnStartDemo").disabled = false;
  document.getElementById("demoConfigCard").classList.remove("hidden");
  document.getElementById("demoActiveCard").classList.add("hidden");
  resetStepChecklist();
}

function handleSaveExperiment() {
  if (savedExpId) {
    showToast(`Experiment saved as ${savedExpId}! Opening results...`, "success");
    setTimeout(() => {
      window.location.href = `results.html`;
    }, 800);
  }
}
