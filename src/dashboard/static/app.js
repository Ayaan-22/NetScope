const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));
const severityOrder = ['critical', 'high', 'medium', 'low', 'info'];
const severityIcons = { critical: '◆', high: '▲', medium: '●', low: '▽', info: 'i' };
const naturalOrder = new Intl.Collator(undefined, { numeric: true });
const state = {
  reports: [], report: null, rows: [], visibleRows: [], jobs: [],
  sort: { key: 'risk_score', dir: 'desc' }, severity: 'all', service: '', band: '', kpi: '',
  page: 0, pageSize: 50, detailIndex: -1, showServices: false, offline: false, hideUnverified: false,
  loading: true, submitting: false, booting: false, reportToken: 0, jobsBusy: false,
};
const searchText = new WeakMap();
const form = $('#scan-form');
const drawer = $('#evidence-drawer');
const mobile = matchMedia('(max-width: 1024px)');
let toastTimer, searchTimer, lastRowTrigger;
let hadActiveJob = false;

function escapeHtml(value) {
  return String(value ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
}
const titleCase = (value) => String(value).charAt(0).toUpperCase() + String(value).slice(1);
function severity(value) {
  const key = String(value || 'info').toLowerCase();
  return severityOrder.includes(key) ? key : 'info';
}
function riskBand(score) {
  const value = Number(score || 0);
  if (value >= 9) return 'critical';
  if (value >= 7.5) return 'high';
  if (value >= 5) return 'medium';
  return 'low';
}
function worstSeverity(row) {
  const values = (row.vulnerabilities || []).map((v) => severity(v.severity));
  return severityOrder.find((key) => values.includes(key)) || 'none';
}
function isUnverified(vulnerability) {
  return /wildcard/i.test(String(vulnerability.match_confidence || '')) || vulnerability.version === '*';
}
function hasUnverified(row) { return (row.vulnerabilities || []).some(isUnverified); }
function overviewRows() { return state.hideUnverified ? state.rows.filter((row) => !hasUnverified(row)) : state.rows; }
function overview() {
  const rows = overviewRows();
  const severityCounts = Object.fromEntries(severityOrder.map((key) => [key, 0]));
  const severityUnverified = { ...severityCounts };
  const buckets = { critical: 0, high: 0, medium: 0, low: 0 };
  const riskUnverified = { ...buckets };
  const matches = rows.flatMap((row) => row.vulnerabilities || []);
  for (const match of matches) {
    severityCounts[severity(match.severity)] += 1;
    if (isUnverified(match)) severityUnverified[severity(match.severity)] += 1;
  }
  for (const row of rows) {
    buckets[riskBand(row.risk_score)] += 1;
    if (hasUnverified(row)) riskUnverified[riskBand(row.risk_score)] += 1;
  }
  const flagged = new Set(state.report?.meta?.high_risk_hosts || []);
  const highRiskRows = rows.filter((row) => Number(row.risk_score) >= 7.5 && flagged.has(row.host));
  return { rows, matches, severityCounts, severityUnverified, buckets, riskUnverified,
    hosts: new Set(rows.map((row) => row.host)), cves: new Set(matches.map((v) => v.cve_id).filter(Boolean)),
    highRiskHosts: new Set(highRiskRows.map((row) => row.host)),
    unverifiedRiskHosts: new Set(highRiskRows.filter(hasUnverified).map((row) => row.host)),
    unverified: matches.filter(isUnverified).length };
}
const plural = (count, singular, many = singular + 's') => count + ' ' + (count === 1 ? singular : many);
function toast(message) {
  $('#toast').textContent = message;
  $('#toast').classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $('#toast').classList.add('hidden'), 4200);
}
async function api(path, options = {}) {
  const response = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...options });
  if (!response.ok) {
    let message = response.statusText;
    try { const payload = await response.json(); message = typeof payload.detail === 'string' ? payload.detail : JSON.stringify(payload.detail || message); } catch (_) { /* Keep HTTP status. */ }
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  return response.json();
}
function setOffline(offline) {
  state.offline = offline;
  $('#offline-banner').classList.toggle('hidden', !offline);
  $('#offline-banner span').textContent = state.report
    ? 'Dashboard API is offline. Showing the last loaded data.'
    : 'Dashboard API is offline. Reconnect to load scan history.';
  updateActivity();
}
function formatDate(value) {
  const date = new Date(value);
  return value && !Number.isNaN(date.getTime()) ? new Intl.DateTimeFormat(undefined, { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false }).format(date) : '';
}
function reportLabel(report) {
  let date = formatDate(report.scan_end || report.generated || report.scan_start);
  if (!date) {
    const match = report.id.match(/(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})/);
    if (match) date = formatDate(match[1] + '-' + match[2] + '-' + match[3] + 'T' + match[4] + ':' + match[5] + ':' + match[6]);
  }
  return (date || 'Saved assessment') + ' · ' + (report.target || 'Unknown target');
}
function setTheme(theme, persist = false) {
  document.documentElement.dataset.theme = theme;
  const label = 'Switch to ' + (theme === 'dark' ? 'light' : 'dark') + ' theme';
  $('#theme-toggle').setAttribute('aria-label', label);
  $('#theme-toggle').title = label;
  if (persist) { try { localStorage.setItem('netscope-theme', theme); } catch (_) { /* Storage may be unavailable. */ } }
}
function setCompact(compact, persist = false) {
  $('#results').classList.toggle('compact', compact);
  $('#compact-toggle').setAttribute('aria-pressed', String(compact));
  $('#compact-toggle').title = compact ? 'Compact rows: 40px. Switch to 44px rows.' : 'Use 40px rows instead of 44px';
  if (persist) { try { localStorage.setItem('netscope-compact', String(compact)); } catch (_) { /* Optional preference. */ } }
  syncStickyHeader();
}
function decorateSelects() {
  $$('select').forEach((select) => {
    if (!select.parentElement.classList.contains('select-control')) {
      const wrapper = document.createElement('span');
      wrapper.className = 'select-control';
      select.before(wrapper); wrapper.append(select);
      wrapper.insertAdjacentHTML('beforeend', '<svg aria-hidden="true"><use href="#i-arrow"/></svg>');
    }
    select.parentElement.classList.toggle('hidden', select.classList.contains('hidden'));
  });
}
function setSetup(open, focus = true) {
  document.body.classList.toggle('setup-open', mobile.matches && open);
  document.body.classList.toggle('setup-collapsed', !open);
  $('#toggle-setup').setAttribute('aria-expanded', String(open));
  const panel = $('#setup-panel');
  panel.toggleAttribute('inert', !open);
  if (mobile.matches && open) {
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'true');
    $('#main').inert = true; $('.topbar').inert = true;
  } else {
    panel.removeAttribute('role'); panel.removeAttribute('aria-modal');
    $('#main').inert = false; $('.topbar').inert = false;
  }
  if (focus) (open ? $('#target') : $('#toggle-setup')).focus();
}

// Format hints only. The server remains authoritative for authorization,
// exclusions, special-use addresses and hostname resolution.
function validateTarget() {
  const input = form.elements.target;
  const value = input.value.trim();
  let hint = 'Enter a host or network to assess.';
  let error = '';
  const ipv4 = (ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) && ip.split('.').every((part) => Number(part) <= 255);
  if (value.includes('/')) {
    const [address, mask, extra] = value.split('/');
    const v6 = address.includes(':');
    let validAddress = ipv4(address);
    if (v6) { try { validAddress = new URL('http://[' + address + ']/').hostname.startsWith('['); } catch (_) { validAddress = false; } }
    let prefix = /^\d+$/.test(mask || '') ? Number(mask) : NaN;
    if (!v6 && ipv4(mask || '')) {
      let bits = mask.split('.').map((part) => Number(part).toString(2).padStart(8, '0')).join('');
      if (bits.startsWith('0') && bits !== '0'.repeat(32)) bits = bits.replace(/[01]/g, (bit) => bit === '0' ? '1' : '0');
      if (/^1*0*$/.test(bits)) prefix = bits.indexOf('0') === -1 ? 32 : bits.indexOf('0');
    }
    const max = v6 ? 128 : 32;
    if (!validAddress || extra !== undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > max) error = 'Enter a valid IP/CIDR, such as 192.168.0.0/24.';
    else {
      const size = 2 ** (max - prefix);
      if (size > 65536) error = 'Network exceeds the existing 65,536-address limit.';
      else { const hosts = size <= 2 ? size : size - (v6 ? 1 : 2); hint = '/' + prefix + ' → ' + hosts.toLocaleString() + (hosts === 1 ? ' host' : ' hosts') + ' before exclusions'; }
    }
  } else if (value) {
    if (/^\d+(\.\d+){3}$/.test(value) && !ipv4(value)) error = 'Enter a valid IPv4 address (each part is 0–255).';
    else if (value.includes(':')) {
      try { new URL('http://[' + value + ']/'); hint = 'Single IPv6 host · Safety checks run before scanning.'; }
      catch (_) { error = 'Enter a valid IPv6 address.'; }
    } else if (!ipv4(value) && !/^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$/i.test(value)) error = 'Enter a valid IP, CIDR or hostname.';
    else hint = ipv4(value) ? 'Single host · Safety checks run before scanning.' : 'Hostname · Resolved locally when you start a scan.';
  }
  input.setCustomValidity(error);
  input.setAttribute('aria-invalid', String(Boolean(error)));
  $('#target-hint').textContent = error || hint;
  $('#target-hint').classList.toggle('form-error', Boolean(error));
  updateReadiness();
  return !error;
}
function readinessReason() {
  if (state.offline) return 'Reconnect to the dashboard API before scanning.';
  if (activeJob()) return 'Wait for the current scan to finish.';
  if (state.submitting) return 'Submitting scan…';
  if (!form.elements.target.value.trim()) return 'Enter a valid target' + (!form.elements.authorize_scan.checked ? ' and tick Authorized.' : '.');
  if (!form.elements.target.validity.valid) return 'Enter a valid target before scanning.';
  if (!form.elements.authorize_scan.checked) return 'Tick Authorized to confirm permission to scan.';
  if (!form.checkValidity()) return 'Check the highlighted scan settings in Advanced.';
  return '';
}
function updateReadiness() {
  const reason = readinessReason();
  $('#start-scan').disabled = Boolean(reason);
  $('#start-scan').title = reason || 'Ready to scan the authorized target';
  $('#scan-readiness').textContent = reason || 'Ready · Authorized target · Runs locally';
}
async function loadDefaults() {
  const [defaults, health] = await Promise.all([api('/api/defaults'), api('/api/health')]);
  $('#version').textContent = 'v' + health.version;
  form.elements.timeout.value = defaults.timeout ?? 1.5;
  form.elements.concurrency.value = defaults.concurrency ?? 500;
  form.elements.batch_size.value = defaults.host_batch_size ?? 20;
  form.elements.use_nmap.checked = Boolean(defaults.use_nmap);
}
function applyNetworkTarget(network) {
  if (!network) return;
  form.elements.target.value = network.target;
  // Preserve the original Use My Network behavior.
  form.elements.authorize_scan.checked = true;
  form.elements.allow_public_targets.checked = false;
  validateTarget();
  toast('Target set to ' + network.target);
}
async function detectLocalNetwork() {
  const button = $('#detect-network');
  button.disabled = true; button.textContent = 'Detecting…';
  try {
    const payload = await api('/api/local-networks');
    const networks = payload.networks || [];
    if (!networks.length) { toast('No active private IPv4 network was detected.'); return; }
    const select = $('#network-select');
    select.replaceChildren(...networks.map((network) => {
      const option = new Option(network.target + ' · ' + network.adapter + (network.gateway ? ' via ' + network.gateway : '') + (network.capped ? ' · capped to /24' : ''), network.target);
      option.dataset.network = JSON.stringify(network);
      return option;
    }));
    select.classList.toggle('hidden', networks.length <= 1);
    decorateSelects();
    select.value = (payload.recommended || networks[0]).target;
    applyNetworkTarget(payload.recommended || networks[0]);
  } catch (error) { toast(error.message); }
  finally { button.disabled = false; button.textContent = 'Use My Network'; }
}
function resetFilters(preserveConfidence = false) {
  state.severity = 'all'; state.service = ''; state.band = ''; state.kpi = ''; state.page = 0;
  if (!preserveConfidence) { state.hideUnverified = false; $('#hide-unverified').checked = false; }
  $('#search-input').value = '';
}
function setLoading(loading) {
  state.loading = loading;
  $('#loading-state').classList.toggle('hidden', !loading);
  $('#results').setAttribute('aria-busy', String(loading));
  if (loading) {
    ['#table-wrap', '#table-scroll-hint', '#empty-state', '#no-matches', '#pagination'].forEach((id) => $(id).classList.add('hidden'));
    $('#result-count').textContent = 'Loading…';
  }
}
async function loadReports(selectLatest = false) {
  const reports = await api('/api/reports');
  state.reports = reports;
  const select = $('#report-select');
  select.replaceChildren(...reports.map((report) => {
    const option = new Option(reportLabel(report), report.id);
    option.title = report.id;
    return option;
  }));
  if (!reports.length) {
    select.add(new Option('No saved assessments', ''));
    select.disabled = true; select.title = 'No saved assessments';
    state.reportToken += 1; state.report = null; state.rows = []; resetFilters();
    drawer.close(); setLoading(false); renderReport(); return;
  }
  select.disabled = false;
  const reportId = !selectLatest && reports.some((r) => r.id === state.report?.id) ? state.report.id : reports[0].id;
  select.value = reportId; select.title = reportId;
  if (reportId !== state.report?.id) await loadReport(reportId);
}
async function loadReport(id) {
  if (!id) return;
  const token = ++state.reportToken;
  const previousId = state.report?.id;
  setLoading(true); drawer.close();
  try {
    const report = await api('/api/reports/' + encodeURIComponent(id));
    if (token !== state.reportToken) return;
    state.report = report; state.rows = report.results || [];
    for (const row of state.rows) {
      const cves = (row.vulnerabilities || []).map((v) => v.cve_id + ' ' + v.description + ' ' + v.severity).join(' ');
      searchText.set(row, [row.host, row.hostname, row.port, row.service, row.version, row.banner, cves].join(' ').toLowerCase());
    }
    resetFilters(); setLoading(false); renderReport(); setOffline(false);
    $('#report-select').value = id; $('#report-select').title = id;
  } catch (error) {
    if (token !== state.reportToken) return;
    setLoading(false);
    if (previousId) { $('#report-select').value = previousId; $('#report-select').title = previousId; }
    setOffline(!error.status || error.status >= 500); renderReport(); toast('Could not load report: ' + error.message);
    throw error;
  }
}
function activeJob() { return state.jobs.find((job) => ['queued', 'running'].includes(job.status)); }
function updateActivity() {
  const job = activeJob();
  const status = $('#scan-status');
  const message = state.offline ? 'API offline' : job ? titleCase(job.stage || job.status) + ' · ' + (job.request?.target || 'scan') : 'Connected · Local only';
  if (status.textContent !== message) status.textContent = message;
  status.classList.toggle('running', Boolean(job));
  updateReadiness();
  $('#start-scan').innerHTML = job ? 'Scan in progress…' : '<svg><use href="#i-plus"/></svg>Start Scan';
  const activity = $('#scan-activity');
  activity.classList.toggle('hidden', !job);
  if (job) {
    const text = [titleCase(job.stage || job.status), job.message || 'Scan in progress', job.request?.target || ''].join(' · ');
    if (activity.dataset.message !== text) {
      activity.dataset.message = text;
      activity.innerHTML = '<div><strong>' + escapeHtml(titleCase(job.stage || job.status)) + '</strong><span>' + escapeHtml(job.message || 'Scan in progress') + ' · <span class="mono">' + escapeHtml(job.request?.target || '') + '</span></span></div><progress aria-label="Scan in progress; percentage is not provided by the scanner"></progress>';
    }
  }
}
async function loadJobs() {
  if (state.jobsBusy) return;
  state.jobsBusy = true;
  try {
    state.jobs = await api('/api/jobs');
    const list = $('#jobs-list');
    const markup = state.jobs.length ? state.jobs.map((job) => {
      const busy = ['queued', 'running'].includes(job.status);
      return '<button class="job-item" data-report-id="' + escapeHtml(job.report_id || '') + '" type="button" title="' + (job.report_id ? 'Open saved scan report' : 'Job has no saved report yet') + '"><span class="job-top"><strong class="mono">' + escapeHtml(job.request?.target || 'Target') + '</strong><span class="job-status ' + (busy ? 'running' : '') + '">' + escapeHtml(job.status) + '</span></span><small>' + escapeHtml(job.message || job.stage || '') + '</small>' + (job.error ? '<small>' + escapeHtml(job.error) + '</small>' : '') + (busy ? '<progress aria-label="Scan in progress; percentage unavailable"></progress>' : '') + '<time>' + escapeHtml(formatDate(job.finished_at || job.started_at || job.created_at)) + '</time></button>';
    }).join('') : '<p class="helper">No scan jobs. New assessments will appear here.</p>';
    if (list.innerHTML !== markup) list.innerHTML = markup;
    updateActivity();
    if (!state.rows.length && !state.loading) renderTable();
    const running = Boolean(activeJob());
    if (hadActiveJob && !running) await loadReports(true);
    hadActiveJob = running;
  } finally { state.jobsBusy = false; }
}
function renderReport() {
  const meta = state.report?.meta || {};
  const files = state.report?.files || {};
  $('#report-title').textContent = state.report ? meta.target || state.report.id : 'Your network, in focus.';
  $('#report-meta').textContent = state.report ? (formatDate(meta.scan_end || meta.generated) || 'Saved assessment') + ' · ' + (meta.hosts_targeted ?? meta.hosts_scanned ?? 0) + ' hosts targeted' : 'Local assessments · Evidence at a glance';
  renderMetrics();
  for (const [id, kind] of [['#open-html', 'html'], ['#download-json', 'json']]) {
    const enabled = Boolean(state.report && files[kind]);
    $(id).href = enabled ? '/api/reports/' + encodeURIComponent(state.report.id) + '/files/' + kind : '#';
    $(id).classList.toggle('disabled', !enabled); $(id).setAttribute('aria-disabled', String(!enabled));
    $(id).tabIndex = enabled ? 0 : -1;
  }
  renderTable(); renderCharts(); updateActivity();
}
function renderMetrics() {
  const meta = state.report?.meta || {};
  const summary = overview();
  const services = new Set(summary.rows.map((row) => row.service || 'unknown'));
  $('#metric-hosts').textContent = summary.hosts.size;
  $('#metric-hosts-sub').textContent = (meta.hosts_targeted ?? meta.hosts_scanned ?? 0) + ' targeted';
  $('#metric-ports').textContent = summary.rows.length;
  $('#metric-services').textContent = services.size + ' services detected';
  $('#metric-vulns').textContent = summary.matches.length;
  $('#metric-cves').textContent = plural(summary.cves.size, 'unique CVE') + (summary.unverified ? ' · ' + summary.unverified + ' unverified' : ' · candidates');
  $('#metric-risk').textContent = summary.highRiskHosts.size;
  $('#metric-critical').textContent = summary.unverifiedRiskHosts.size ? plural(summary.unverifiedRiskHosts.size, 'unverified host') : plural(summary.severityCounts.critical, 'critical CVE match', 'critical CVE matches');
  const totalUnverified = state.rows.reduce((sum, row) => sum + (row.vulnerabilities || []).filter(isUnverified).length, 0);
  const hidden = state.rows.length - summary.rows.length;
  $('#confidence-note').classList.toggle('hidden', !totalUnverified);
  $('#confidence-note').textContent = state.hideUnverified
    ? plural(hidden, 'port') + ' with unverified matches hidden from results and overview. Saved reports and scores are unchanged.'
    : plural(totalUnverified, 'unverified CVE match', 'unverified CVE matches') + ' · Wildcard candidates need product/version verification. Report scores do not confirm exposure.';
  $('#unverified-count').textContent = '(' + totalUnverified + ' matches)';
}
function filteredRows() {
  const query = $('#search-input').value.trim().toLowerCase();
  const highHosts = new Set(state.report?.meta?.high_risk_hosts || []);
  let rows = overviewRows().filter((row) => {
    const vulns = row.vulnerabilities || [];
    return (!query || searchText.get(row)?.includes(query))
      && (state.severity === 'all' || (state.severity === 'none' ? !vulns.length : vulns.some((v) => severity(v.severity) === state.severity)))
      && (!state.service || (row.service || 'unknown') === state.service)
      && (!state.band || riskBand(row.risk_score) === state.band)
      && (state.kpi !== 'vulns' || vulns.length > 0)
      && (state.kpi !== 'risk' || (highHosts.has(row.host) && Number(row.risk_score) >= 7.5));
  });
  if (state.kpi === 'hosts') {
    const hosts = new Map();
    for (const row of rows) if (!hosts.has(row.host) || Number(row.risk_score) > Number(hosts.get(row.host).risk_score)) hosts.set(row.host, row);
    rows = [...hosts.values()];
  }
  rows.sort((a, b) => {
    const key = state.sort.key;
    const av = key === 'cve' ? (a.vulnerabilities || []).map((v) => v.cve_id).join(' ') : a[key] ?? '';
    const bv = key === 'cve' ? (b.vulnerabilities || []).map((v) => v.cve_id).join(' ') : b[key] ?? '';
    const cmp = ['port', 'risk_score'].includes(key) ? Number(av || 0) - Number(bv || 0) : naturalOrder.compare(String(av), String(bv));
    return (state.sort.dir === 'asc' ? cmp : -cmp) || naturalOrder.compare(String(a.host), String(b.host)) || a.port - b.port;
  });
  return rows;
}
function highlight(value) {
  const text = String(value ?? '');
  const query = $('#search-input').value.trim();
  if (!query) return escapeHtml(text);
  let from = 0, output = '';
  const lower = text.toLowerCase();
  for (let at = lower.indexOf(query.toLowerCase()); at !== -1; at = lower.indexOf(query.toLowerCase(), from)) {
    output += escapeHtml(text.slice(from, at)) + '<mark>' + escapeHtml(text.slice(at, at + query.length)) + '</mark>';
    from = at + query.length;
  }
  return output + escapeHtml(text.slice(from));
}
function renderTable() {
  if (state.loading) return;
  const rows = filteredRows();
  state.visibleRows = rows;
  const pages = Math.max(1, Math.ceil(rows.length / state.pageSize));
  state.page = Math.max(0, Math.min(state.page, pages - 1));
  const from = state.page * state.pageSize;
  const page = rows.slice(from, from + state.pageSize);
  $('#result-count').textContent = rows.length + ' of ' + state.rows.length + ' ports';
  $('#table-wrap').classList.toggle('hidden', !rows.length);
  $('#pagination').classList.toggle('hidden', !rows.length);
  $('#empty-state').classList.toggle('hidden', Boolean(state.rows.length));
  $('#no-matches').classList.toggle('hidden', !state.rows.length || Boolean(rows.length));
  const empty = $('#empty-state');
  empty.querySelector('h3').textContent = state.offline && !state.report ? 'Connect to your local dashboard' : activeJob() && !state.report ? 'Assessment in progress' : state.report ? 'No open ports in this assessment' : 'No assessments yet';
  empty.querySelector('p').textContent = activeJob() && !state.report ? 'Results will appear after the scanner finishes and saves the report. Progress is shown above.' : state.report ? 'This saved report contains no open-port results. Select another assessment or review your scan scope.' : 'Set up a local scan to see open ports and matched vulnerabilities here.';
  $('#results-body').innerHTML = page.map((row, index) => {
    const vulns = row.vulnerabilities || [];
    const band = riskBand(row.risk_score), rowSeverity = worstSeverity(row), score = Number(row.risk_score || 0);
    const cve = vulns[0];
    const unverified = hasUnverified(row);
    const confidenceTitle = 'Unverified wildcard match. Verify product and version; the saved score does not confirm a vulnerability.';
    const cveHtml = cve ? '<span class="cve-pill ' + severity(cve.severity) + (isUnverified(cve) ? ' unverified' : '') + '" title="' + escapeHtml((isUnverified(cve) ? confidenceTitle + ' ' : '') + titleCase(severity(cve.severity)) + ' · ' + cve.cve_id) + '"><span aria-hidden="true">' + (isUnverified(cve) ? '?' : severityIcons[severity(cve.severity)]) + '</span><span class="sr-only">' + (isUnverified(cve) ? 'Unverified ' : '') + titleCase(severity(cve.severity)) + ' </span>' + highlight(cve.cve_id) + '</span>' + (vulns.length > 1 ? '<span class="cve-more" title="' + escapeHtml(vulns.slice(1).map((v) => v.cve_id + (isUnverified(v) ? ' (unverified)' : '')).join(', ')) + '">+' + (vulns.length - 1) + '</span>' : '') : '<span class="muted">None</span>';
    return '<tr data-row-index="' + (from + index) + '"' + (rowSeverity !== 'none' ? ' style="--row-color:var(--' + rowSeverity + ')"' : '') + '>'
      + '<td><button class="host-link" aria-label="Inspect ' + escapeHtml(row.host) + ' port ' + escapeHtml(row.port) + '">' + highlight(row.host) + '</button></td>'
      + '<td class="mono">' + highlight(row.port) + '</td><td title="' + escapeHtml(row.service) + '">' + highlight(row.service || 'unknown') + '</td>'
      + '<td class="mono muted" title="' + escapeHtml(row.version) + '">' + highlight(row.version || 'unknown') + '</td>'
      + '<td>' + (score === 0 ? '<span class="risk-none" title="No CVE-based risk score. An open port without a matched CVE is not established safe.">—<span class="sr-only"> No CVE-based score</span></span>' : '<span class="risk-pill ' + band + (unverified ? ' unverified' : '') + '" title="' + (unverified ? confidenceTitle : 'Report score; CVE matches require verification.') + '">' + score.toFixed(1) + ' <span class="band-name">' + band + '</span>' + (unverified ? '<span class="unverified-mark" aria-label="unverified">?</span>' : '') + '</span>') + '</td>'
      + '<td class="mono muted" title="' + escapeHtml(row.banner || 'No banner captured') + '">' + (row.banner ? highlight(row.banner) : 'No banner') + '</td>'
      + '<td><div class="cve-cell">' + cveHtml + '</div></td></tr>';
  }).join('');
  $('#page-info').textContent = (from + 1) + '–' + Math.min(from + state.pageSize, rows.length) + ' · Page ' + (state.page + 1) + '/' + pages;
  $('#prev-page').disabled = state.page === 0; $('#next-page').disabled = state.page >= pages - 1;
  $$('th[data-sort]').forEach((th) => {
    const selected = th.dataset.sort === state.sort.key;
    if (selected) th.setAttribute('aria-sort', state.sort.dir === 'asc' ? 'ascending' : 'descending'); else th.removeAttribute('aria-sort');
    th.querySelector('.sort-icon').textContent = selected ? state.sort.dir === 'asc' ? '↑' : '↓' : '↕';
  });
  renderFilterState(); syncStickyHeader();
}
function renderFilterState() {
  const source = overviewRows();
  const counts = { all: source.length, none: 0, ...Object.fromEntries(severityOrder.map((key) => [key, 0])) };
  for (const row of source) {
    const keys = new Set((row.vulnerabilities || []).map((v) => severity(v.severity)));
    if (!keys.size) counts.none += 1;
    for (const key of keys) counts[key] += 1;
  }
  // Preserve the focused chip while updating counts and pressed states.
  if (!$('#severity-filters').children.length) {
    $('#severity-filters').innerHTML = ['all', ...severityOrder, 'none'].map((key) => '<button class="filter-chip" data-severity="' + key + '" aria-pressed="false">' + (severityOrder.includes(key) ? '<span class="severity-dot ' + key + '"></span>' : '') + '<span>' + (key === 'all' ? 'All ports' : key === 'none' ? 'No CVE' : titleCase(key)) + '</span><span class="count"></span></button>').join('');
  }
  $$('[data-severity]').forEach((button) => {
    button.setAttribute('aria-pressed', String(button.dataset.severity === state.severity));
    button.querySelector('.count').textContent = counts[button.dataset.severity];
  });
  $$('[data-kpi]').forEach((button) => button.setAttribute('aria-pressed', String(state.kpi === button.dataset.kpi)));
  const query = $('#search-input').value.trim();
  const labels = [state.hideUnverified && 'Unverified ports hidden', state.severity !== 'all' && 'CVE severity: ' + (state.severity === 'none' ? 'No matches' : titleCase(state.severity)), state.service && 'Service: ' + state.service, state.band && 'Port risk: ' + titleCase(state.band), state.kpi === 'hosts' && 'One highest-risk port per host', state.kpi === 'vulns' && 'Ports with CVE matches', state.kpi === 'risk' && 'High-risk candidate ports', query && 'Search: ' + query].filter(Boolean);
  $('#active-filter').textContent = labels.join(' · ');
  $('#active-filter').classList.toggle('hidden', !labels.length); $('#clear-filters').classList.toggle('hidden', !labels.length);
}
function renderBars(selector, items, kind) {
  const max = Math.max(1, ...items.map((item) => item.count));
  $(selector).innerHTML = items.length ? items.map(({ name, count, unverified = 0 }) => {
    const selected = kind === 'severity' ? state.severity === name : kind === 'service' ? state.service === name : state.band === name;
    const width = count ? Math.max(kind === 'band' ? 12 : 0, count / max * 100) : 0;
    const qualification = unverified ? '; includes ' + unverified + ' unverified ' + (kind === 'severity' ? 'matches' : 'ports') : '';
    const label = name === 'low' && kind === 'band' ? 'Low / unscored' : name;
    return '<button class="bar-row ' + (kind === 'service' ? 'service-bar' : (kind === 'band' ? 'risk-bar ' : 'severity-bar ') + name) + (unverified ? ' unverified' : '') + '" data-chart-kind="' + kind + '" data-chart-value="' + escapeHtml(name) + '" aria-pressed="' + selected + '" title="' + escapeHtml(count + ' ' + label + qualification + (kind === 'band' ? '. Nonzero bars have a 12% minimum visual width; counts are exact.' : '')) + '" aria-label="Filter ' + (kind === 'severity' ? 'CVE severity' : kind === 'band' ? 'port risk' : 'service') + ' ' + escapeHtml(name) + ': ' + count + (kind === 'severity' ? ' candidate matches' : ' ports') + qualification + '"><span class="bar-label">' + (kind !== 'service' ? '<span class="severity-dot"></span>' : '') + escapeHtml(label) + (unverified ? ' <span class="unverified-mark" aria-hidden="true">?</span>' : '') + '</span><span class="bar-track" aria-hidden="true"><span class="bar-fill" style="width:' + width + '%"></span></span><span class="bar-number">' + count + '</span></button>';
  }).join('') : '<p class="helper">No service observations.</p>';
}
function renderCharts() {
  const focused = document.activeElement?.closest('[data-chart-kind]');
  const focusKey = focused ? [focused.dataset.chartKind, focused.dataset.chartValue] : null;
  const summary = overview();
  renderBars('#severity-chart', severityOrder.map((name) => ({ name, count: summary.severityCounts[name], unverified: summary.severityUnverified[name] })), 'severity');
  $('#severity-total').textContent = plural(summary.matches.length, 'match', 'matches');
  $('#severity-confidence').textContent = summary.unverified ? plural(summary.unverified, 'unverified match', 'unverified matches') + '. Dashed bars include wildcard candidates; verify product and version.' : 'Candidate CVE matches, not confirmed vulnerabilities.';
  // top_services is capped at eight by the API. Build Show all from existing rows.
  const counts = new Map();
  for (const row of summary.rows) counts.set(row.service || 'unknown', (counts.get(row.service || 'unknown') || 0) + 1);
  const services = [...counts].map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count || a.name.localeCompare(b.name));
  renderBars('#service-chart', state.showServices ? services : services.slice(0, 8), 'service');
  $('#show-services').textContent = state.showServices ? 'Top 8' : 'Show all';
  $('#show-services').classList.toggle('hidden', services.length <= 8); $('#show-services').setAttribute('aria-expanded', String(state.showServices));
  renderBars('#risk-chart', ['critical', 'high', 'medium', 'low'].map((name) => ({ name, count: summary.buckets[name], unverified: summary.riskUnverified[name] })), 'band');
  $('#risk-confidence').textContent = (summary.unverified ? 'Dashed bars include unverified port scores. ' : '') + 'Low includes unscored ports; it does not mean safe. Nonzero bars have a 12% minimum width; counts are exact.';
  if (focusKey) $$('[data-chart-kind]').find((button) => button.dataset.chartKind === focusKey[0] && button.dataset.chartValue === focusKey[1])?.focus({ preventScroll: true });
}
function applyFilters() { state.page = 0; renderMetrics(); renderTable(); renderCharts(); }
function copyButton(value, label) {
  return '<button class="icon-button" data-copy="' + escapeHtml(value) + '" aria-label="Copy ' + escapeHtml(label) + '" title="Copy ' + escapeHtml(label) + '"><svg><use href="#i-copy"/></svg></button>';
}
function renderDetail(index) {
  const row = state.visibleRows[index];
  if (!row) return;
  state.detailIndex = index;
  const band = riskBand(row.risk_score), score = Number(row.risk_score || 0), vulns = row.vulnerabilities || [];
  const unverified = hasUnverified(row);
  $('#detail-title').textContent = row.host + ':' + row.port;
  $('#detail-position').textContent = 'Result ' + (index + 1) + ' of ' + state.visibleRows.length;
  $('#prev-detail').disabled = index === 0; $('#next-detail').disabled = index === state.visibleRows.length - 1;
  const fields = [['Host', row.host], ['Port', row.port + '/' + (row.protocol || 'tcp')], ['Hostname', row.hostname || 'Unknown'], ['MAC', row.mac_address || 'Unknown'], ['Service', row.service || 'unknown'], ['Version', row.version || 'unknown'], ['State', row.state || 'open'], ['Observed', row.scan_time || 'Unknown']];
  const boundedScore = Math.max(0, Math.min(score, 10));
  $('#detail-content').innerHTML = (unverified ? '<div class="detail-confidence"><strong>Unverified CVE candidate</strong>Service-wide wildcard matches do not confirm that this product or version is vulnerable. Verify applicability before acting. The report score below is unchanged.</div>' : '')
    + '<section class="detail-block"><div class="risk-summary"><div><p class="helper">' + (unverified ? 'Unverified report port score' : 'Report port risk score') + '</p><span class="risk-value ' + (score ? band : 'muted') + '">' + (score ? score.toFixed(1) + ' <small>/ 10</small>' : '—') + '</span></div>' + (score ? '<span class="risk-pill ' + band + (unverified ? ' unverified' : '') + '">' + titleCase(band) + ' port risk' + (unverified ? ' · unverified' : '') + '</span>' : '<span class="muted">No CVE-based score</span>') + '</div><div class="risk-gauge ' + band + '" role="meter" aria-label="' + (unverified ? 'Unverified report port risk score' : 'Report port risk score') + '" aria-valuemin="0" aria-valuemax="10" aria-valuenow="' + boundedScore + '" aria-valuetext="' + (score ? score.toFixed(1) + ' out of 10, ' + band + (unverified ? ', unverified' : '') : 'No CVE-based score; service safety is unknown') + '"><span style="width:' + boundedScore * 10 + '%"></span></div><p class="helper">Critical ≥9 · High ≥7.5 · Medium ≥5 · Low &lt;5</p></section>'
    + '<section class="detail-block"><h3>Connection details</h3><dl class="detail-grid">' + fields.map(([label, value]) => '<dt>' + label + '</dt><dd class="mono" title="' + escapeHtml(value) + '">' + escapeHtml(label === 'Observed' ? formatDate(value) || 'Unknown' : value) + '</dd><dd>' + copyButton(value, label) + '</dd>').join('') + '</dl></section>'
    + '<section class="detail-block"><div class="panel-title"><h3>Banner &amp; evidence</h3>' + (row.banner ? copyButton(row.banner, 'banner') : '') + '</div><pre class="banner-text">' + escapeHtml(row.banner || 'No banner captured.') + '</pre>' + (Object.keys(row.tls_info || {}).length ? '<h3>TLS details</h3><pre class="banner-text">' + escapeHtml(JSON.stringify(row.tls_info, null, 2)) + '</pre>' : '') + '</section>'
    + '<section class="detail-block"><h3>CVE candidates <span class="muted">(' + vulns.length + ')</span></h3><p class="helper">A CVE match is not proof of exposure. CVE severity may differ from the port risk band.</p>' + (vulns.length ? vulns.map((v) => {
      const level = severity(v.severity), id = String(v.cve_id || 'Unknown CVE');
      const nvd = /^CVE-\d{4}-\d{4,}$/i.test(id) ? 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(id) : '';
      return '<article class="vulnerability"><div class="vulnerability-title"><strong class="mono">' + escapeHtml(id) + '</strong><span class="cve-pill ' + level + (isUnverified(v) ? ' unverified' : '') + '">' + titleCase(level) + ' · CVSS ' + escapeHtml(v.cvss_score ?? 'not supplied') + '</span></div>' + (isUnverified(v) ? '<small>Unverified · wildcard candidate; applicability has not been established.</small>' : '') + '<p>' + escapeHtml(v.description || 'No description supplied.') + '</p>' + (nvd ? '<a href="' + nvd + '" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer">View on NVD ↗</a>' : '') + (v.match_confidence ? '<small>Match confidence: ' + escapeHtml(v.match_confidence) + '</small>' : '') + (v.evidence_version ? '<small>Evidence version: <span class="mono">' + escapeHtml(v.evidence_version) + '</span></small>' : '') + (v.cvss_vector ? '<small class="mono">' + escapeHtml(v.cvss_vector) + '</small>' : '') + '</article>';
    }).join('') : '<p class="muted">No matched CVEs. This does not establish that a service is safe.</p>') + '</section>';
  $$('[data-row-index]').forEach((node) => node.classList.toggle('selected', Number(node.dataset.rowIndex) === index));
  if (!drawer.open) drawer.showModal();
  drawer.scrollTop = 0;
}
function scanPayload(scanForm) {
  const fields = scanForm.elements, selectedPorts = fields.ports.value;
  return {
    target: fields.target.value.trim(), ports: selectedPorts === 'custom' ? fields.custom_ports.value.trim() : selectedPorts,
    discover_first: fields.discover_first.checked, timeout: Number(fields.timeout.value),
    concurrency: Number(fields.concurrency.value), batch_size: Number(fields.batch_size.value),
    use_nmap: fields.use_nmap.checked, authorize_scan: fields.authorize_scan.checked,
    allow_public_targets: fields.allow_public_targets.checked,
    exclude: fields.exclude.value.split(',').map((value) => value.trim()).filter(Boolean),
    formats: ['html', 'json', 'csv'],
  };
}
async function submitScan(event) {
  event.preventDefault();
  if (!validateTarget() || readinessReason()) return;
  state.submitting = true; updateActivity(); $('#scan-error').classList.add('hidden');
  try {
    const job = await api('/api/scans', { method: 'POST', body: JSON.stringify(scanPayload(form)) });
    state.jobs.unshift(job); hadActiveJob = true; updateActivity();
    toast('Scan queued for ' + job.request.target);
    if (mobile.matches) setSetup(false);
    await loadJobs();
  } catch (error) { $('#scan-error').textContent = error.message; $('#scan-error').classList.remove('hidden'); toast(error.message); }
  finally { state.submitting = false; updateActivity(); }
}
// Narrow tables scroll only horizontally. Keep the header visible with the
// page without introducing a second vertical results scroller.
function syncStickyHeader() {
  const wrap = $('#table-wrap'), head = wrap.querySelector('thead');
  $('#table-scroll-hint').classList.toggle('hidden', wrap.classList.contains('hidden') || wrap.scrollWidth <= wrap.clientWidth);
  if (!head || wrap.classList.contains('hidden')) return;
  if (matchMedia('(max-width: 1279px)').matches) {
    const rect = wrap.getBoundingClientRect(), top = $('.topbar').getBoundingClientRect().bottom;
    const y = Math.max(0, Math.min(top - rect.top, rect.height - head.offsetHeight));
    head.style.transform = 'translateY(' + y + 'px)';
    head.style.position = 'relative'; head.style.zIndex = '5';
  } else { head.style.transform = ''; head.style.position = ''; head.style.zIndex = ''; }
}
function trapSetupFocus(event) {
  if (!mobile.matches || !document.body.classList.contains('setup-open') || event.key !== 'Tab') return;
  const nodes = $$('#setup-panel button, #setup-panel input, #setup-panel select, #setup-panel summary').filter((el) => !el.disabled && el.getClientRects().length);
  const first = nodes[0], last = nodes[nodes.length - 1];
  if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
  else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
}
function bindEvents() {
  decorateSelects();
  try { setCompact(localStorage.getItem('netscope-compact') === 'true'); } catch (_) { setCompact(false); }
  setTheme(document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'));
  setSetup(!mobile.matches, false);
  mobile.addEventListener('change', () => setSetup(!mobile.matches, false));
  matchMedia('(prefers-color-scheme: light)').addEventListener('change', (event) => {
    try { if (!localStorage.getItem('netscope-theme')) setTheme(event.matches ? 'light' : 'dark'); } catch (_) { setTheme(event.matches ? 'light' : 'dark'); }
  });
  $('#theme-toggle').addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark', true));
  $('#toggle-setup').addEventListener('click', () => setSetup($('#toggle-setup').getAttribute('aria-expanded') !== 'true'));
  $('#close-setup').addEventListener('click', () => setSetup(false));
  $('#empty-setup').addEventListener('click', () => setSetup(true));
  form.addEventListener('submit', submitScan);
  form.addEventListener('input', updateReadiness);
  form.addEventListener('change', updateReadiness);
  form.elements.target.addEventListener('input', validateTarget);
  form.elements.ports.addEventListener('change', (event) => {
    const custom = event.target.value === 'custom';
    $('#custom-ports-row').classList.toggle('hidden', !custom); form.elements.custom_ports.required = custom;
  });
  $('#detect-network').addEventListener('click', detectLocalNetwork);
  $('#network-select').addEventListener('change', (event) => applyNetworkTarget(JSON.parse(event.target.selectedOptions[0].dataset.network)));
  $('#report-select').addEventListener('change', (event) => loadReport(event.target.value).catch(() => {}));
  $('#refresh-jobs').addEventListener('click', () => loadJobs().catch((error) => { setOffline(true); toast(error.message); }));
  $('#jobs-list').addEventListener('click', (event) => {
    const id = event.target.closest('[data-report-id]')?.dataset.reportId;
    if (id) loadReport(id).then(() => { if (mobile.matches) setSetup(false); }).catch(() => {});
  });
  $('#search-input').addEventListener('input', () => { clearTimeout(searchTimer); searchTimer = setTimeout(applyFilters, 100); });
  $('#hide-unverified').addEventListener('change', (event) => { state.hideUnverified = event.target.checked; applyFilters(); });
  $('#compact-toggle').addEventListener('click', () => setCompact($('#compact-toggle').getAttribute('aria-pressed') !== 'true', true));
  $('#severity-filters').addEventListener('click', (event) => {
    const button = event.target.closest('[data-severity]');
    if (button) { state.severity = button.dataset.severity; applyFilters(); }
  });
  const clear = () => { resetFilters(); applyFilters(); };
  $('#clear-filters').addEventListener('click', clear); $('#reset-search').addEventListener('click', clear);
  $$('[data-kpi]').forEach((button) => button.addEventListener('click', () => {
    const key = button.dataset.kpi, selected = button.getAttribute('aria-pressed') === 'true';
    resetFilters(true); state.kpi = key === 'ports' || selected ? '' : key; applyFilters();
  }));
  $$('th[data-sort]').forEach((th) => th.querySelector('button').addEventListener('click', () => {
    const key = th.dataset.sort;
    state.sort.dir = state.sort.key === key && state.sort.dir === 'desc' ? 'asc' : 'desc'; state.sort.key = key;
    state.page = 0; renderTable();
  }));
  $('#results-body').addEventListener('click', (event) => {
    const node = event.target.closest('[data-row-index]');
    if (node) { lastRowTrigger = node.querySelector('button'); renderDetail(Number(node.dataset.rowIndex)); }
  });
  $('#clear-detail').addEventListener('click', () => drawer.close());
  $('#prev-detail').addEventListener('click', () => renderDetail(state.detailIndex - 1));
  $('#next-detail').addEventListener('click', () => renderDetail(state.detailIndex + 1));
  drawer.addEventListener('close', () => {
    $$('tr.selected').forEach((row) => row.classList.remove('selected'));
    if (lastRowTrigger?.isConnected) lastRowTrigger.focus({ preventScroll: true });
  });
  drawer.addEventListener('click', (event) => { if (event.target === drawer && event.clientX < drawer.getBoundingClientRect().left) drawer.close(); });
  $('#detail-content').addEventListener('click', async (event) => {
    const button = event.target.closest('[data-copy]');
    if (button) {
      try { await navigator.clipboard.writeText(button.dataset.copy); button.setAttribute('aria-label', 'Copied'); button.textContent = '✓'; toast('Copied to clipboard'); }
      catch (_) { toast('Clipboard unavailable. Select and copy the value directly.'); }
    }
  });
  $('#page-size').addEventListener('change', (event) => { state.pageSize = Number(event.target.value); state.page = 0; renderTable(); });
  const changePage = (delta) => { state.page += delta; renderTable(); $('#results').scrollIntoView({ block: 'start' }); };
  $('#prev-page').addEventListener('click', () => changePage(-1)); $('#next-page').addEventListener('click', () => changePage(1));
  $('#analysis').addEventListener('click', (event) => {
    const button = event.target.closest('[data-chart-kind]');
    if (!button) return;
    const key = { severity: 'severity', service: 'service', band: 'band' }[button.dataset.chartKind], value = button.dataset.chartValue;
    state[key] = state[key] === value ? key === 'severity' ? 'all' : '' : value;
    applyFilters(); $('#results').scrollIntoView({ block: 'start' });
  });
  $('#show-services').addEventListener('click', () => { state.showServices = !state.showServices; renderCharts(); });
  $('#retry').addEventListener('click', boot);
  $$('.export-options a').forEach((link) => link.addEventListener('click', (event) => {
    if (link.classList.contains('disabled')) event.preventDefault(); else $('#export-menu').open = false;
  }));
  document.addEventListener('click', (event) => { if (!event.target.closest('#export-menu')) $('#export-menu').open = false; });
  document.addEventListener('keydown', (event) => {
    trapSetupFocus(event);
    const editing = /INPUT|TEXTAREA|SELECT/.test(event.target.tagName) || event.target.isContentEditable;
    if (event.key === 'Escape') {
      $('#export-menu').open = false;
      if (document.body.classList.contains('setup-open')) setSetup(false);
      else if (!drawer.open && event.target === $('#search-input')) { $('#search-input').value = ''; applyFilters(); }
    }
    if (drawer.open && !editing && ['ArrowUp', 'ArrowDown'].includes(event.key)) {
      event.preventDefault(); renderDetail(state.detailIndex + (event.key === 'ArrowUp' ? -1 : 1));
    } else if (!editing && !drawer.open && !document.body.classList.contains('setup-open') && !event.ctrlKey && !event.metaKey && !event.altKey) {
      if (event.key === '/') { event.preventDefault(); $('#search-input').focus(); }
      if (event.key.toLowerCase() === 'r') loadJobs().catch(() => setOffline(true));
    }
  });
  window.addEventListener('scroll', syncStickyHeader, { passive: true }); window.addEventListener('resize', syncStickyHeader);
}
async function boot() {
  if (state.booting) return;
  state.booting = true; $('#retry').disabled = true;
  try { await loadDefaults(); await loadReports(); await loadJobs(); setOffline(false); }
  catch (_) { setLoading(false); setOffline(true); renderReport(); }
  finally { state.booting = false; $('#retry').disabled = false; }
}
bindEvents();
boot();
setInterval(async () => {
  if (state.booting || state.submitting) return;
  try { await loadJobs(); if (state.offline) await boot(); } catch (_) { setOffline(true); }
}, 3000);
