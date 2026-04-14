const BASE_URL = "https://YOUR-NEW-DOCKER-URL.onrender.com";
const logOutput = document.getElementById("logOutput");
const envBadge = document.getElementById("envBadge");
const repoName = document.getElementById("repoName");
const modeSelect = document.getElementById("modeSelect");
const utcClock = document.getElementById("utcClock");
const connectBtn = document.getElementById("connectBtn");
const connectStrip = document.getElementById("connectStrip");
const repoOverride = document.getElementById("repoOverride");
const mainNav = document.getElementById("mainNav");

const kpiPipelines = document.getElementById("kpiPipelines");
const kpiPassed = document.getElementById("kpiPassed");
const kpiFailed = document.getElementById("kpiFailed");
const kpiRunning = document.getElementById("kpiRunning");
const kpiRate = document.getElementById("kpiRate");

const latestRunMeta = document.getElementById("latestRunMeta");
const latestRunLink = document.getElementById("latestRunLink");
const stagesEl = document.getElementById("stages");
const recentRunsEl = document.getElementById("recentRuns");
const recentRunsPipelinesEl = document.getElementById("recentRunsPipelines");
const artifactList = document.getElementById("artifactList");

const localComponents = document.getElementById("localComponents");
const localDependencies = document.getElementById("localDependencies");
const localVulns = document.getElementById("localVulns");
const localTimestamp = document.getElementById("localTimestamp");
const vulnTotal = document.getElementById("vulnTotal");
const vulnCritical = document.getElementById("vulnCritical");
const vulnHigh = document.getElementById("vulnHigh");
const vulnMedium = document.getElementById("vulnMedium");
const vulnLow = document.getElementById("vulnLow");

const generateBtn = document.getElementById("generateBtn");
const signBtn = document.getElementById("signBtn");
const scanBtn = document.getElementById("scanBtn");
const refreshBtn = document.getElementById("refreshBtn");

function setButtonsDisabled(disabled) {
  [generateBtn, signBtn, scanBtn, refreshBtn].forEach((btn) => {
    btn.disabled = disabled;
  });
}

function appendLog(text) {
  logOutput.textContent = `${text}\n\n${logOutput.textContent}`.trim();
}

async function api(path, method = "GET", body = null) {
  const options = { method, headers: {} };
  if (body) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
 const res = await fetch(`${BASE_URL}${path}`, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.message || data.log || `HTTP ${res.status}`);
  }
  return data;
}

function normalizeStatus(status) {
  const s = String(status || "pending").toLowerCase();
  if (s.includes("success") || s === "completed") return "success";
  if (s.includes("failure") || s.includes("cancel")) return "failure";
  if (s.includes("progress") || s === "running" || s === "queued") return "running";
  return "pending";
}

function renderStages(stages) {
  stagesEl.innerHTML = "";
  const input = stages && stages.length ? stages : [
    { name: "Build", status: "pending" },
    { name: "Generate", status: "pending" },
    { name: "Sign", status: "pending" },
    { name: "Scan", status: "pending" },
    { name: "Report", status: "pending" }
  ];
  for (const stage of input) {
    const status = normalizeStatus(stage.status);
    const div = document.createElement("div");
    div.className = `stage ${status}`;
    div.textContent = `${stage.name} · ${status.toUpperCase()}`;
    stagesEl.appendChild(div);
  }
}

function renderRecentRuns(runs) {
  recentRunsEl.innerHTML = "";
  if (recentRunsPipelinesEl) recentRunsPipelinesEl.innerHTML = "";
  if (!runs || !runs.length) {
    recentRunsEl.innerHTML = "<li>No recent pipelines.</li>";
    if (recentRunsPipelinesEl) recentRunsPipelinesEl.innerHTML = "<li>No recent pipelines.</li>";
    return;
  }
  for (const run of runs) {
    const status = normalizeStatus(run.status);
    const li = document.createElement("li");
    li.innerHTML = `
      <span>#${run.id} · ${run.branch || "-"} · ${run.sha || "-"}</span>
      <span class="tag ${status}">${status.toUpperCase()}</span>
    `;
    li.addEventListener("click", () => {
      if (run.url) window.open(run.url, "_blank", "noopener,noreferrer");
    });
    recentRunsEl.appendChild(li);
    if (recentRunsPipelinesEl) {
      recentRunsPipelinesEl.appendChild(li.cloneNode(true));
      const last = recentRunsPipelinesEl.lastElementChild;
      last.addEventListener("click", () => {
        if (run.url) window.open(run.url, "_blank", "noopener,noreferrer");
      });
    }
  }
}

function renderArtifacts(artifacts) {
  artifactList.innerHTML = "";
  const list = artifacts || [];
  if (!list.length) {
    artifactList.innerHTML = "<li><span>Artifacts</span><span>None</span></li>";
    return;
  }
  for (const item of list) {
    const li = document.createElement("li");
    li.innerHTML = `<span>${item.label}</span><span>${item.path}</span>`;
    artifactList.appendChild(li);
  }
}

function renderDashboard(data) {
  const local = data.local || {};
  const github = data.github || {};
  const totals = github.totals || {};
  const severity = local.severity || {};

  const shownRepo = (repoOverride && repoOverride.value.trim()) || github.repo || "repository";
  repoName.textContent = github.available
    ? `${shownRepo} · live + local mode`
    : "GitHub API unavailable — showing local data only";

  envBadge.textContent =
    `Docker: ${local.has_docker ? "yes" : "no"} | pwsh: ${local.has_pwsh ? "yes" : "no"} | bash: ${local.has_bash ? "yes" : "no"}`;

  kpiPipelines.textContent = String(totals.pipelines || 0);
  kpiPassed.textContent = String(totals.passed || 0);
  kpiFailed.textContent = String(totals.failed || 0);
  kpiRunning.textContent = String(totals.running || 0);
  kpiRate.textContent = `${totals.success_rate || 0}%`;

  localComponents.textContent = String(local.components || 0);
  localDependencies.textContent = String(local.dependencies || 0);
  localVulns.textContent = String(local.vulnerabilities || 0);
  localTimestamp.textContent = local.timestamp || "-";
  if (vulnTotal) vulnTotal.textContent = String(local.vulnerabilities || 0);
  if (vulnCritical) vulnCritical.textContent = String(severity.critical || 0);
  if (vulnHigh) vulnHigh.textContent = String(severity.high || 0);
  if (vulnMedium) vulnMedium.textContent = String(severity.medium || 0);
  if (vulnLow) vulnLow.textContent = String(severity.low || 0);

  const latest = github.latest;
  if (latest) {
    latestRunMeta.textContent = `#${latest.id} · ${latest.branch || "-"} · ${latest.sha || "-"} · ${latest.status || "-"}`;
    latestRunLink.href = latest.url || "#";
    latestRunLink.style.visibility = latest.url ? "visible" : "hidden";
    renderStages(latest.stages || []);
  } else {
    latestRunMeta.textContent = "No latest pipeline available.";
    latestRunLink.style.visibility = "hidden";
    renderStages(null);
  }

  renderRecentRuns(github.recent || []);
  renderArtifacts(local.artifacts || []);
}

async function refreshDashboard() {
  const data = await api("/api/dashboard");
  renderDashboard(data);
}

async function runAction(name, endpoint, payload = null) {
  setButtonsDisabled(true);
  appendLog(`[${new Date().toISOString()}] Running ${name}...`);
  try {
    const result = await api(endpoint, "POST", payload);
    appendLog(result.log || `${name} complete.`);
    await refreshDashboard();
    // Dispatch event for vulnerability scanner to reload after actions
    if (name === "Scan" || name === "Generate") {
      window.dispatchEvent(new CustomEvent('sbom:local-scan-done'));
    }
  } catch (err) {
    appendLog(`ERROR: ${err.message}`);
  } finally {
    setButtonsDisabled(false);
  }
}

generateBtn.addEventListener("click", () => runAction("Generate", "/api/generate", { mode: modeSelect.value }));
signBtn.addEventListener("click", () => runAction("Sign", "/api/sign"));
scanBtn.addEventListener("click", () => runAction("Scan", "/api/scan"));
refreshBtn.addEventListener("click", async () => {
  setButtonsDisabled(true);
  try {
    await refreshDashboard();
    appendLog(`[${new Date().toISOString()}] Dashboard refreshed.`);
  } catch (err) {
    appendLog(`ERROR: ${err.message}`);
  } finally {
    setButtonsDisabled(false);
  }
});

function activateTab(tabName) {
  document.querySelectorAll("#mainNav a").forEach((a) => {
    const active = a.getAttribute("data-tab") === tabName;
    a.classList.toggle("active", active);
  });
  document.querySelectorAll(".tab-content").forEach((el) => {
    el.classList.toggle("active", el.id === `tab-${tabName}`);
  });
}

if (mainNav) {
  mainNav.querySelectorAll("a[data-tab]").forEach((a) => {
    a.addEventListener("click", () => activateTab(a.getAttribute("data-tab")));
  });
}

if (connectBtn) {
  connectBtn.addEventListener("click", () => {
    if (connectStrip) connectStrip.style.display = "none";
    appendLog(`[${new Date().toISOString()}] Connected to Mission Control data sources.`);
    refreshDashboard();
  });
}

if (utcClock) {
  const tick = () => {
    const d = new Date();
    utcClock.textContent = `${d.toISOString().substring(11, 19)} UTC`;
  };
  tick();
  setInterval(tick, 1000);
}

(async () => {
  try {
    activateTab("overview");
    await refreshDashboard();
  } catch (err) {
    appendLog(`ERROR: ${err.message}`);
  }
})();
