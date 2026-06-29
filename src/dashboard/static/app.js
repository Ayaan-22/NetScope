const state = {
  reports: [],
  report: null,
  rows: [],
  sort: { key: "risk_score", dir: "desc" },
};

const colors = {
  critical: "#ff5d62",
  high: "#ff855f",
  medium: "#f2b84b",
  low: "#59d68c",
  info: "#4fb6ff",
  violet: "#a78bfa",
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.classList.remove("hidden");
  clearTimeout(window.__toastTimer);
  window.__toastTimer = setTimeout(() => node.classList.add("hidden"), 4200);
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!response.ok) {
    let message = response.statusText;
    try {
      const payload = await response.json();
      message = payload.detail || message;
    } catch (_) {
      message = response.statusText;
    }
    throw new Error(message);
  }
  return response.json();
}

function formatDate(value) {
  if (!value) return "Unknown";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function riskBand(score) {
  const value = Number(score || 0);
  if (value >= 9) return "critical";
  if (value >= 7.5) return "high";
  if (value >= 5) return "medium";
  return "low";
}

function worstSeverity(row) {
  const order = ["critical", "high", "medium", "low", "info"];
  const severities = (row.vulnerabilities || []).map((v) => String(v.severity || "info").toLowerCase());
  return order.find((item) => severities.includes(item)) || "none";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function loadDefaults() {
  const defaults = await api("/api/defaults");
  $("#version").textContent = `v${await api("/api/health").then((h) => h.version)}`;
  const form = $("#scan-form");
  form.timeout.value = defaults.timeout ?? 1.5;
  form.concurrency.value = defaults.concurrency ?? 500;
  form.batch_size.value = defaults.host_batch_size ?? 20;
  form.use_nmap.value = defaults.use_nmap ? "true" : "false";
}

function networkOptionText(network) {
  const label = network.gateway ? `${network.adapter} via ${network.gateway}` : network.adapter;
  const capped = network.capped ? " capped to /24" : "";
  return `${network.target} | ${label}${capped}`;
}

function applyNetworkTarget(network) {
  if (!network) return;
  const form = $("#scan-form");
  form.target.value = network.target;
  form.authorize_scan.checked = true;
  form.allow_public_targets.checked = false;
  toast(`Target set to ${network.target}`);
}

async function detectLocalNetwork() {
  const button = $("#detect-network");
  const select = $("#network-select");
  button.disabled = true;
  const originalText = button.innerHTML;
  button.innerHTML = '<span class="button-icon">@</span><span>Detecting...</span>';
  try {
    const payload = await api("/api/local-networks");
    const networks = payload.networks || [];
    if (!networks.length) {
      toast("No active private IPv4 network was detected.");
      return;
    }
    select.innerHTML = "";
    for (const network of networks) {
      const option = document.createElement("option");
      option.value = network.target;
      option.textContent = networkOptionText(network);
      option.dataset.network = JSON.stringify(network);
      select.appendChild(option);
    }
    select.classList.toggle("hidden", networks.length <= 1);
    applyNetworkTarget(payload.recommended || networks[0]);
  } catch (error) {
    toast(error.message);
  } finally {
    button.disabled = false;
    button.innerHTML = originalText;
  }
}

async function loadReports(selectLatest = false) {
  state.reports = await api("/api/reports");
  const select = $("#report-select");
  select.innerHTML = "";

  if (!state.reports.length) {
    select.innerHTML = '<option value="">No reports yet</option>';
    renderEmptyReport();
    return;
  }

  for (const report of state.reports) {
    const option = document.createElement("option");
    option.value = report.id;
    option.textContent = `${report.id} | ${report.target || "target"}`;
    select.appendChild(option);
  }

  if (selectLatest || !state.report) {
    select.value = state.reports[0].id;
  } else {
    select.value = state.report.id;
  }
  await loadReport(select.value);
}

async function loadReport(reportId) {
  if (!reportId) return;
  state.report = await api(`/api/reports/${encodeURIComponent(reportId)}`);
  state.rows = state.report.results || [];
  renderReport();
}

async function loadJobs() {
  const jobs = await api("/api/jobs");
  const list = $("#jobs-list");
  if (!jobs.length) {
    list.innerHTML = '<p class="empty">No scan jobs.</p>';
    return;
  }
  list.innerHTML = jobs.slice(0, 8).map((job) => {
    const target = escapeHtml(job.request?.target || "target");
    const status = escapeHtml(job.status);
    const subtitle = job.finished_at || job.started_at || job.created_at;
    const message = escapeHtml(job.message || job.stage || "");
    return `
      <button class="job-item" data-report-id="${escapeHtml(job.report_id || "")}" type="button">
        <span class="job-status ${status}">${status}</span>
        <strong>${target}</strong>
        ${message ? `<em>${message}</em>` : ""}
        <span>${formatDate(subtitle)}</span>
      </button>
    `;
  }).join("");
}

function renderEmptyReport() {
  $("#report-title").textContent = "Report Console";
  $("#metric-hosts").textContent = "0";
  $("#metric-hosts-sub").textContent = "0 targeted";
  $("#metric-ports").textContent = "0";
  $("#metric-services").textContent = "0 services";
  $("#metric-vulns").textContent = "0";
  $("#metric-cves").textContent = "0 unique CVEs";
  $("#metric-risk").textContent = "0";
  $("#metric-critical").textContent = "0 critical CVEs";
  $("#results-body").innerHTML = "";
  $("#result-count").textContent = "0 rows";
  drawAllCharts({ severity_counts: {}, top_services: [], risk_buckets: {} }, []);
}

function renderReport() {
  const meta = state.report.meta || {};
  const analytics = state.report.analytics || {};
  const files = state.report.files || {};

  $("#report-title").textContent = meta.target || state.report.id;
  $("#metric-hosts").textContent = analytics.host_count ?? 0;
  $("#metric-hosts-sub").textContent = `${meta.hosts_targeted ?? meta.hosts_scanned ?? 0} targeted`;
  $("#metric-ports").textContent = state.rows.length;
  $("#metric-services").textContent = `${analytics.top_services?.length || 0} services`;
  $("#metric-vulns").textContent = meta.total_vulnerabilities ?? 0;
  $("#metric-cves").textContent = `${analytics.cve_count ?? 0} unique CVEs`;
  $("#metric-risk").textContent = (meta.high_risk_hosts || []).length;
  $("#metric-critical").textContent = `${analytics.severity_counts?.critical || 0} critical CVEs`;
  $("#severity-total").textContent = `${meta.total_vulnerabilities ?? 0} findings`;
  $("#service-total").textContent = `${state.rows.length} rows`;
  $("#risk-total").textContent = `${state.rows.length} ports`;

  const htmlLink = $("#open-html");
  const jsonLink = $("#download-json");
  htmlLink.href = files.html ? `/api/reports/${state.report.id}/files/html` : "#";
  jsonLink.href = files.json ? `/api/reports/${state.report.id}/files/json` : "#";
  htmlLink.classList.toggle("disabled", !files.html);
  jsonLink.classList.toggle("disabled", !files.json);

  drawAllCharts(analytics, state.rows);
  renderTable();
}

function filteredRows() {
  const query = $("#search-input").value.trim().toLowerCase();
  const severity = $("#severity-filter").value;
  const rows = state.rows.filter((row) => {
    const cves = (row.vulnerabilities || []).map((v) => `${v.cve_id} ${v.description} ${v.severity}`).join(" ");
    const haystack = `${row.host} ${row.hostname} ${row.port} ${row.service} ${row.version} ${row.banner} ${cves}`.toLowerCase();
    const matchesSearch = !query || haystack.includes(query);
    const rowSeverity = worstSeverity(row);
    const matchesSeverity = severity === "all" || rowSeverity === severity;
    return matchesSearch && matchesSeverity;
  });

  rows.sort((a, b) => {
    const key = state.sort.key;
    const av = a[key] ?? "";
    const bv = b[key] ?? "";
    const numberSort = key === "port" || key === "risk_score";
    const cmp = numberSort
      ? Number(av || 0) - Number(bv || 0)
      : String(av).localeCompare(String(bv));
    return state.sort.dir === "asc" ? cmp : -cmp;
  });
  return rows;
}

function renderTable() {
  const rows = filteredRows();
  $("#result-count").textContent = `${rows.length} rows`;
  $("#results-body").innerHTML = rows.map((row, index) => {
    const vulns = row.vulnerabilities || [];
    const band = riskBand(row.risk_score);
    const cveHtml = vulns.length
      ? vulns.slice(0, 3).map((v) => `<span class="cve-pill ${String(v.severity || "info").toLowerCase()}">${escapeHtml(v.cve_id)}</span>`).join(" ")
      : '<span class="muted">None</span>';
    const evidence = row.banner ? escapeHtml(row.banner.slice(0, 90)) : "No banner";
    return `
      <tr data-row-index="${index}">
        <td class="mono">${escapeHtml(row.host)}</td>
        <td><strong>${escapeHtml(row.port)}</strong></td>
        <td>${escapeHtml(row.service)}</td>
        <td>${escapeHtml(row.version)}</td>
        <td><span class="risk-pill ${band}">${Number(row.risk_score || 0).toFixed(1)}</span></td>
        <td class="muted">${evidence}</td>
        <td>${cveHtml}</td>
      </tr>
    `;
  }).join("");

  $$("#results-body tr").forEach((rowNode) => {
    rowNode.addEventListener("click", () => {
      const row = rows[Number(rowNode.dataset.rowIndex)];
      renderDetail(row);
    });
  });
}

function renderDetail(row) {
  if (!row) return;
  const vulns = row.vulnerabilities || [];
  $("#detail-content").innerHTML = `
    <div class="detail-block">
      <h3>${escapeHtml(row.host)}:${escapeHtml(row.port)}</h3>
      <div class="detail-grid">
        <span class="muted">Hostname</span><span>${escapeHtml(row.hostname || "Unknown")}</span>
        <span class="muted">MAC</span><span>${escapeHtml(row.mac_address || "Unknown")}</span>
        <span class="muted">Service</span><span>${escapeHtml(row.service)}</span>
        <span class="muted">Version</span><span>${escapeHtml(row.version)}</span>
        <span class="muted">Risk</span><span>${Number(row.risk_score || 0).toFixed(1)} / 10</span>
      </div>
    </div>
    <div class="detail-block">
      <h3>Banner</h3>
      <div class="banner-text">${escapeHtml(row.banner || "No banner captured.")}</div>
    </div>
    <div class="detail-block">
      <h3>Vulnerabilities</h3>
      ${
        vulns.length
          ? vulns.map((v) => `
            <p>
              <span class="cve-pill ${String(v.severity || "info").toLowerCase()}">${escapeHtml(v.severity || "Info")}</span>
              <strong>${escapeHtml(v.cve_id || "CVE")}</strong><br />
              <span class="muted">${escapeHtml(v.description || "")}</span>
            </p>
          `).join("")
          : '<p class="empty">No matched CVEs.</p>'
      }
    </div>
  `;
}

function canvasContext(id) {
  const canvas = $(id);
  const ratio = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  canvas.width = rect.width * ratio;
  canvas.height = 240 * ratio;
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, rect.width, 240);
  return { ctx, width: rect.width, height: 240 };
}

function drawDonut(id, counts) {
  const { ctx, width, height } = canvasContext(id);
  const entries = ["critical", "high", "medium", "low", "info"].map((key) => [key, counts[key] || 0]);
  const total = entries.reduce((sum, [, count]) => sum + count, 0);
  const cx = width / 2;
  const cy = height / 2;
  const radius = Math.min(width, height) * 0.34;
  let angle = -Math.PI / 2;

  ctx.lineWidth = 30;
  if (!total) {
    ctx.strokeStyle = "#30373d";
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    ctx.stroke();
  } else {
    for (const [key, count] of entries) {
      const next = angle + (count / total) * Math.PI * 2;
      ctx.strokeStyle = colors[key];
      ctx.beginPath();
      ctx.arc(cx, cy, radius, angle, next);
      ctx.stroke();
      angle = next;
    }
  }

  ctx.fillStyle = "#eef2f3";
  ctx.font = "700 28px Segoe UI";
  ctx.textAlign = "center";
  ctx.fillText(String(total), cx, cy + 8);

  $("#severity-legend").innerHTML = entries.map(([key, count]) => (
    `<span><i style="background:${colors[key]}"></i>${key} ${count}</span>`
  )).join("");
}

function drawBars(id, items, color) {
  const { ctx, width, height } = canvasContext(id);
  const rows = items.length ? items : [{ name: "None", count: 0 }];
  const max = Math.max(1, ...rows.map((item) => item.count));
  const left = 96;
  const top = 24;
  const rowH = Math.min(30, (height - top - 18) / rows.length);

  ctx.font = "12px Segoe UI";
  ctx.textBaseline = "middle";
  rows.forEach((item, index) => {
    const y = top + index * rowH;
    const barW = ((width - left - 44) * item.count) / max;
    ctx.fillStyle = "#9aa7ad";
    ctx.textAlign = "right";
    ctx.fillText(String(item.name).slice(0, 13), left - 10, y + rowH / 2);
    ctx.fillStyle = "rgba(255,255,255,.06)";
    ctx.fillRect(left, y + 5, width - left - 42, rowH - 10);
    ctx.fillStyle = color;
    ctx.fillRect(left, y + 5, barW, rowH - 10);
    ctx.fillStyle = "#eef2f3";
    ctx.textAlign = "left";
    ctx.fillText(String(item.count), left + barW + 8, y + rowH / 2);
  });
}

function drawAllCharts(analytics, rows) {
  drawDonut("#severity-chart", analytics.severity_counts || {});
  drawBars("#service-chart", analytics.top_services || [], colors.accent);
  const riskItems = Object.entries(analytics.risk_buckets || {}).map(([name, count]) => ({ name, count }));
  drawBars("#risk-chart", riskItems, colors.violet);
}

function scanPayload(form) {
  const selectedPorts = form.ports.value;
  return {
    target: form.target.value.trim(),
    ports: selectedPorts === "custom" ? form.custom_ports.value.trim() : selectedPorts,
    discover_first: form.discover_first.checked,
    timeout: Number(form.timeout.value),
    concurrency: Number(form.concurrency.value),
    batch_size: Number(form.batch_size.value),
    use_nmap: form.use_nmap.value === "true",
    authorize_scan: form.authorize_scan.checked,
    allow_public_targets: form.allow_public_targets.checked,
    exclude: form.exclude.value.split(",").map((value) => value.trim()).filter(Boolean),
    formats: ["html", "json", "csv"],
  };
}

function bindEvents() {
  $("#scan-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    try {
      const job = await api("/api/scans", {
        method: "POST",
        body: JSON.stringify(scanPayload(event.currentTarget)),
      });
      toast(`Scan queued for ${job.request.target}`);
      await loadJobs();
    } catch (error) {
      toast(error.message);
    }
  });

  $("#scan-form").ports.addEventListener("change", (event) => {
    $("#custom-ports-row").classList.toggle("hidden", event.target.value !== "custom");
  });

  $("#detect-network").addEventListener("click", detectLocalNetwork);
  $("#network-select").addEventListener("change", (event) => {
    const selected = event.target.selectedOptions[0];
    if (selected?.dataset.network) {
      applyNetworkTarget(JSON.parse(selected.dataset.network));
    }
  });

  $("#report-select").addEventListener("change", (event) => loadReport(event.target.value));
  $("#refresh-jobs").addEventListener("click", loadJobs);
  $("#search-input").addEventListener("input", renderTable);
  $("#severity-filter").addEventListener("change", renderTable);
  $("#clear-detail").addEventListener("click", () => {
    $("#detail-content").innerHTML = '<p class="empty">Select a result row.</p>';
  });

  $$("th[data-sort]").forEach((th) => {
    th.addEventListener("click", () => {
      const key = th.dataset.sort;
      state.sort.dir = state.sort.key === key && state.sort.dir === "desc" ? "asc" : "desc";
      state.sort.key = key;
      renderTable();
    });
  });

  $("#jobs-list").addEventListener("click", async (event) => {
    const button = event.target.closest("[data-report-id]");
    const reportId = button?.dataset.reportId;
    if (reportId) {
      $("#report-select").value = reportId;
      await loadReport(reportId);
    }
  });

  window.addEventListener("resize", () => {
    if (state.report) drawAllCharts(state.report.analytics || {}, state.rows);
  });
}

async function boot() {
  bindEvents();
  try {
    await loadDefaults();
    await loadReports(true);
    await loadJobs();
  } catch (error) {
    toast(error.message);
  }

  setInterval(async () => {
    try {
      await loadJobs();
      const running = $$("#jobs-list .job-status").some((node) => ["queued", "running"].includes(node.textContent));
      if (running) await loadReports(false);
    } catch (_) {
      return;
    }
  }, 3000);
}

boot();
