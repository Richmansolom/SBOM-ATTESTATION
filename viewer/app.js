const sbomInput = document.getElementById("sbomFile");
const vulnInput = document.getElementById("vulnFile");
const loadBtn = document.getElementById("loadBtn");
const fileQueue = document.getElementById("fileQueue");

const componentsCount = document.getElementById("componentsCount");
const dependenciesCount = document.getElementById("dependenciesCount");
const vulnerabilitiesCount = document.getElementById("vulnerabilitiesCount");
const sbomTimestamp = document.getElementById("sbomTimestamp");
const componentsTableBody = document.getElementById("componentsTableBody");

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function renderFileQueue() {
  const files = [
    { label: "SBOM", file: sbomInput.files?.[0] },
    { label: "Vulnerability report", file: vulnInput.files?.[0] }
  ].filter((entry) => Boolean(entry.file));

  fileQueue.innerHTML = "";
  if (!files.length) {
    fileQueue.innerHTML = "<li>No files selected yet.</li>";
    return;
  }

  for (const { label, file } of files) {
    const li = document.createElement("li");
    li.innerHTML = `
      <strong>${label}:</strong> ${file.name}
      <div class="file-meta">Type: ${file.type || "unknown"} | Size: ${formatSize(file.size)}</div>
    `;
    fileQueue.appendChild(li);
  }
}

function getLicenseText(component) {
  if (!Array.isArray(component.licenses) || component.licenses.length === 0) return "-";
  return component.licenses
    .map((entry) => entry?.license?.id || entry?.license?.name || entry?.expression || "unknown")
    .join(", ");
}

function renderComponentsTable(components) {
  componentsTableBody.innerHTML = "";
  if (!components.length) {
    componentsTableBody.innerHTML = `<tr><td colspan="5" class="empty">No components found in SBOM.</td></tr>`;
    return;
  }

  for (const c of components) {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${c.name || "-"}</td>
      <td>${c.version || "-"}</td>
      <td>${c.type || "-"}</td>
      <td>${c.purl || "-"}</td>
      <td>${getLicenseText(c)}</td>
    `;
    componentsTableBody.appendChild(row);
  }
}

function parseJsonFile(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        resolve(JSON.parse(String(reader.result)));
      } catch (err) {
        reject(new Error(`Invalid JSON in ${file.name}`));
      }
    };
    reader.onerror = () => reject(new Error(`Failed to read ${file.name}`));
    reader.readAsText(file);
  });
}

async function loadSelectedFiles() {
  const sbomFile = sbomInput.files?.[0];
  const vulnFile = vulnInput.files?.[0];

  if (!sbomFile) {
    alert("Please choose an SBOM file first.");
    return;
  }

  try {
    const sbomJson = await parseJsonFile(sbomFile);
    const vulnJson = vulnFile ? await parseJsonFile(vulnFile) : null;

    const components = Array.isArray(sbomJson.components) ? sbomJson.components : [];
    const dependencies = Array.isArray(sbomJson.dependencies) ? sbomJson.dependencies : [];
    const vulns = Array.isArray(vulnJson?.matches) ? vulnJson.matches : [];

    componentsCount.textContent = String(components.length);
    dependenciesCount.textContent = String(dependencies.length);
    vulnerabilitiesCount.textContent = String(vulns.length);
    sbomTimestamp.textContent = sbomJson?.metadata?.timestamp || "-";

    renderComponentsTable(components);
  } catch (error) {
    alert(error.message);
  }
}

sbomInput.addEventListener("change", renderFileQueue);
vulnInput.addEventListener("change", renderFileQueue);
loadBtn.addEventListener("click", loadSelectedFiles);

renderFileQueue();
