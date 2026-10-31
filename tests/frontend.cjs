/* Optional frontend regression/visual checks. No build step or production deps.
 * Start the dashboard, then run:
 *   node tests/frontend.cjs <screenshot-directory>
 * Resolve Playwright/axe-core normally, or set PLAYWRIGHT_MODULE / AXE_MODULE.
 * CHROMIUM_EXECUTABLE can select an existing local Chrome/Edge binary.
 * Every scan POST and network-detection request is intercepted before the server.
 */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const base = process.env.NETSCOPE_URL || 'http://127.0.0.1:8765';
assert(['127.0.0.1', 'localhost', '[::1]'].includes(new URL(base).hostname), 'Verification must use localhost');
const output = path.resolve(process.argv[2] || 'report_analysis/frontend');
fs.mkdirSync(output, { recursive: true });
let axePath;
try { axePath = require.resolve(process.env.AXE_MODULE || 'axe-core/axe.min.js'); } catch (_) { /* Optional. */ }
const findings = { screenshots: [], checks: [], consoleErrors: [], pageErrors: [], externalRequests: [], scanPosts: [], axe: axePath ? [] : 'Not installed', contrast: [] };
const check = (name) => { findings.checks.push(name); console.log('PASS ' + name); };
const job = { id: 'ui-test-job', status: 'running', stage: 'scanning', message: 'Scanning 254 host(s)', request: { target: '10.100.105.1/24' }, created_at: '2026-07-23T09:08:00Z', started_at: '2026-07-23T09:08:01Z', finished_at: '', error: '', report_id: '', summary: null, paths: {} };

// Fallback data stays entirely inside this test process, outside reports/.
// Its fields match /api/reports/{id}; saved data is preferred when available.
function fixture() {
  const rows = [];
  const add = (service, port, count) => {
    for (let i = 0; i < count; i++) rows.push({ host: '10.100.105.' + ((rows.length % 16) + 1), hostname: 'test-host', mac_address: 'Unknown', port, protocol: 'tcp', state: 'open', service, version: 'unknown', banner: '', tls_info: {}, vulnerabilities: [], risk_score: 0, scan_time: '2026-07-23T09:14:00Z' });
  };
  add('ssh', 22, 1); add('postgresql', 5432, 1); add('http', 443, 1); add('webdav', 80, 1);
  add('microsoft-ds', 445, 14); add('msrpc', 135, 11); add('netbios-ssn', 139, 8);
  rows[0].banner = 'SSH-1.99-Cisco-1.25'; rows[0].version = '1.25'; rows[0].risk_score = 9.8;
  rows[0].vulnerabilities = [{ cve_id: 'CVE-2023-38408', severity: 'Critical', cvss_score: 9.8, description: 'Synthetic SSH finding for frontend verification', match_confidence: 'service-wildcard' }];
  rows[1].version = '9.6.0 or later'; rows[1].risk_score = 7.2;
  rows[1].vulnerabilities = [{ cve_id: 'CVE-2019-9193', severity: 'High', cvss_score: 7.2, description: 'Synthetic PostgreSQL finding for frontend verification', match_confidence: 'service-wildcard' }];
  rows[2].banner = 'TLS TLSv1.2; cipher=ECDHE-RSA-AES128-GCM-SHA256';
  return { id: 'netscope_20260723_141400', meta: { target: '10.100.105.1/24', hosts_targeted: 254, hosts_with_results: 16, hosts_scanned: 16, open_ports: 37, total_vulnerabilities: 2, high_risk_hosts: [rows[0].host], generated: '2026-07-23T09:14:00Z', scan_end: '2026-07-23T09:14:00Z' }, results: rows, analytics: { host_count: 16, cve_count: 2, severity_counts: { critical: 1, high: 1, medium: 0, low: 0, info: 0 }, risk_buckets: { critical: 1, high: 0, medium: 1, low: 35 } }, files: { html: true, json: true, csv: true } };
}
let saved, previews, useFixture = false;
async function contextFor(browser, width, height, theme, mode = 'populated') {
  const context = await browser.newContext({ viewport: { width, height }, colorScheme: theme, timezoneId: 'Asia/Karachi', reducedMotion: 'reduce', permissions: ['clipboard-read', 'clipboard-write'] });
  const control = { mode, offline: mode === 'offline', scanError: '', jobs: mode === 'scanning' ? [job] : [], detail: null, reportDelay: 0, reportFailures: new Set() };
  await context.route('**/*', async (route) => {
    const req = route.request(), url = new URL(req.url());
    if (!['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)) {
      findings.externalRequests.push(req.url()); await route.abort(); return;
    }
    const json = (value, status = 200) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
    if (url.pathname === '/api/scans') {
      findings.scanPosts.push(req.postDataJSON());
      if (control.scanError) return json({ detail: control.scanError }, 400);
      control.jobs = [{ ...job, status: 'queued', stage: 'queued', message: 'Waiting to start', request: req.postDataJSON() }];
      return json(control.jobs[0], 202);
    }
    if (url.pathname === '/api/local-networks') return json({ networks: [{ target: '192.168.50.0/24', adapter: 'Wi-Fi', gateway: '192.168.50.1' }, { target: '192.168.60.0/24', adapter: 'Ethernet', capped: true }] });
    if (control.offline && url.pathname.startsWith('/api/')) return route.abort('connectionrefused');
    if (url.pathname === '/api/jobs') return json(control.jobs);
    if (url.pathname === '/api/reports') return json(mode === 'empty' || mode === 'scanning' ? [] : useFixture ? [{ ...saved.meta, id: saved.id, target: saved.meta.target }] : previews);
    if (url.pathname.startsWith('/api/reports/') && !url.pathname.includes('/files/')) {
      if (control.reportDelay) await new Promise((resolve) => setTimeout(resolve, control.reportDelay));
      const id = decodeURIComponent(url.pathname.split('/')[3]);
      if (control.reportFailures.has(id)) return json({ detail: 'Report not found' }, 404);
      if (control.detail || useFixture) return json(control.detail || saved);
    }
    return route.continue();
  });
  const page = await context.newPage();
  page.on('pageerror', (error) => findings.pageErrors.push(error.message));
  page.on('console', (message) => { if (message.type() === 'error' && !control.offline && !control.scanError && !control.reportFailures.size) findings.consoleErrors.push(message.text()); });
  await page.goto(base);
  await page.waitForFunction(() => document.querySelector('#results').getAttribute('aria-busy') === 'false');
  if (mode === 'scanning') await page.locator('#scan-activity:not(.hidden)').waitFor();
  return { page, context, control };
}
async function contrastCheck(page, label) {
  const failures = await page.evaluate(() => {
    const canvas = document.createElement('canvas'), ctx = canvas.getContext('2d');
    const rgba = (color) => { ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = color; ctx.fillRect(0, 0, 1, 1); return [...ctx.getImageData(0, 0, 1, 1).data].map((v, i) => i === 3 ? v / 255 : v); };
    const blend = (fg, bg) => [0,1,2].map((i) => fg[i] * fg[3] + bg[i] * (1 - fg[3])).concat(1);
    const bgOf = (el) => !el ? [255,255,255,1] : blend(rgba(getComputedStyle(el).backgroundColor), bgOf(el.parentElement));
    const lum = (rgb) => rgb.slice(0,3).map((n) => { const v = n / 255; return v <= .04045 ? v / 12.92 : ((v + .055) / 1.055) ** 2.4; }).reduce((sum, v, i) => sum + v * [.2126,.7152,.0722][i], 0);
    return [...document.querySelectorAll('body *')].filter((el) => el.checkVisibility({ checkVisibilityCSS: true }) && !el.closest('[inert], .sr-only, svg, option, button:disabled, [aria-disabled="true"]') && [...el.childNodes].some((node) => node.nodeType === 3 && node.textContent.trim())).map((el) => {
      const s = getComputedStyle(el), bg = bgOf(el), fg = blend(rgba(s.color), bg);
      const l1 = lum(fg), l2 = lum(bg), ratio = (Math.max(l1,l2) + .05) / (Math.min(l1,l2) + .05);
      const threshold = parseFloat(s.fontSize) >= 24 || (parseFloat(s.fontSize) >= 18.66 && Number(s.fontWeight) >= 700) ? 3 : 4.5;
      return { text: el.textContent.trim().slice(0,70), ratio: Number(ratio.toFixed(2)), threshold };
    }).filter((item) => item.ratio + .02 < item.threshold);
  });
  findings.contrast.push({ label, failures });
  assert.deepEqual(failures, [], 'Text contrast: ' + label);
}
async function a11y(page, label) {
  await contrastCheck(page, label);
  if (axePath) {
    await page.addScriptTag({ path: axePath });
    const result = await page.evaluate(() => axe.run(document, { runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa'] } }));
    findings.axe.push({ label, violations: result.violations });
    assert.equal(result.violations.length, 0, 'axe violations in ' + label);
  }
}
async function screenshot(page, name) {
  await page.screenshot({ path: path.join(output, name + '.png') });
  findings.screenshots.push(name + '.png');
}

(async () => {
  const browser = await chromium.launch({ headless: true, ...(process.env.CHROMIUM_EXECUTABLE ? { executablePath: process.env.CHROMIUM_EXECUTABLE } : {}), args: ['--disable-background-networking'] });
  try {
    // Read saved data over localhost only. No scan endpoints are used.
    const response = await browser.newContext();
    previews = await (await response.request.get(base + '/api/reports')).json();
    const reference = previews.find((report) => report.id === 'netscope_20260723_141400');
    if (reference) {
      saved = await (await response.request.get(base + '/api/reports/' + encodeURIComponent(reference.id))).json();
      previews = [reference, ...previews.filter((report) => report.id !== reference.id)];
    } else { saved = fixture(); useFixture = true; }
    await response.close();
    for (const [width, height] of [[1440,900], [1024,768], [390,844], [1920,1080]]) {
      for (const theme of ['dark', 'light']) for (const mode of ['populated', 'empty', 'scanning']) {
        const { page, context } = await contextFor(browser, width, height, theme, mode);
        const label = mode + '-' + theme + '-' + width + 'x' + height;
        assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), theme);
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Page overflow: ' + label);
        if (mode === 'populated') {
          assert.equal(await page.locator('#results-body tr').count(), Math.min(50, saved.results.length));
          assert.equal(await page.locator('#page-size').inputValue(), '50');
          const rowHeight = await page.locator('#results-body tr').first().evaluate((el) => el.getBoundingClientRect().height);
          assert(rowHeight >= 40 && rowHeight <= 44.5, 'Dense rows: ' + rowHeight);
          if (width === 1920) {
            const visible = await page.locator('#results-body tr').evaluateAll((rows) => rows.filter((row) => row.getBoundingClientRect().bottom <= innerHeight).length);
            assert(visible >= 12, 'At least 12 complete rows above the fold at 1080p; got ' + visible);
          }
          assert(await page.locator('#result-count').textContent().then((v) => v.includes('of ' + saved.results.length)));
          const geometry = await page.evaluate(() => {
            const wrap = document.querySelector('#table-wrap');
            return { nestedVerticalScroll: wrap.scrollHeight > wrap.clientHeight + 1, results: document.querySelector('#results').offsetTop, charts: document.querySelector('#analysis').offsetTop };
          });
          assert.equal(geometry.nestedVerticalScroll, false); assert(geometry.results < geometry.charts);
          await page.evaluate(() => { window.scrollTo(0, document.querySelector('#table-wrap').getBoundingClientRect().top + scrollY + 80); });
          await page.waitForTimeout(30);
          const sticky = await page.evaluate(() => ({ head: document.querySelector('thead th').getBoundingClientRect().top, bar: document.querySelector('.topbar').getBoundingClientRect().bottom }));
          assert(Math.abs(sticky.head - sticky.bar) < 2, 'Sticky header: ' + label);
          await page.evaluate(() => window.scrollTo(0, 0));
          await page.waitForTimeout(30);
        } else {
          assert(await page.locator('#empty-state').isVisible());
          assert.equal(await page.locator('#open-html').getAttribute('aria-disabled'), 'true');
          if (mode === 'scanning') { assert(await page.locator('#scan-activity progress').isVisible()); assert(await page.locator('#start-scan').isDisabled()); assert.match(await page.locator('#empty-state h3').textContent(), /progress/); }
        }
        await a11y(page, label);
        await screenshot(page, label);
        await context.close();
      }
    }
    check('24 populated/empty/scanning screenshots including 1080p; 44px rows, 50-row default, no page overflow or nested table scrolling');

    const { page, context, control } = await contextFor(browser, 1440, 900, 'dark');
    assert.match(await page.locator('[data-severity="all"]').textContent(), /All ports\s*37/);
    assert.match(await page.locator('.filter-label').textContent(), /CVE severity:/);
    assert.equal(await page.locator('#show-services').isVisible(), false);
    assert.match(await page.locator('#metric-critical').textContent(), /unverified/);
    assert.match(await page.locator('#confidence-note').textContent(), /2 unverified CVE matches/);
    assert.equal(await page.locator('.cve-pill.unverified').count(), 2);
    assert.equal(await page.locator('.risk-none').count(), 35);
    assert.equal(await page.locator('.risk-pill.zero').count(), 0);
    assert.match(await page.locator('.cve-pill.unverified').first().getAttribute('title'), /Unverified/);
    const criticalBar = page.locator('#risk-chart [data-chart-value="critical"]');
    assert.match(await criticalBar.getAttribute('aria-label'), /unverified/);
    assert.equal(await criticalBar.locator('.bar-fill').evaluate((el) => el.style.width), '12%');
    await page.locator('#hide-unverified').check();
    assert.match(await page.locator('#result-count').textContent(), /^35 of 37/);
    assert.equal(await page.locator('#metric-vulns').textContent(), '0');
    assert.equal(await page.locator('#metric-risk').textContent(), '0');
    assert.equal(await page.locator('#metric-ports').textContent(), '35');
    assert.equal(await page.locator('.cve-pill.unverified').count(), 0);
    assert.equal(await page.locator('#risk-chart [data-chart-value="critical"] .bar-number').textContent(), '0');
    await screenshot(page, 'unverified-hidden-dark-1440x900');
    await page.locator('[data-kpi="ports"]').click(); assert(await page.locator('#hide-unverified').isChecked());
    await page.locator('#clear-filters').click();
    await page.locator('#compact-toggle').click();
    assert.equal(await page.locator('#results-body tr').first().evaluate((el) => el.getBoundingClientRect().height), 40);
    await screenshot(page, 'compact-dark-1440x900');
    await page.locator('#compact-toggle').click();
    for (const theme of ['dark', 'light']) {
      if (await page.evaluate(() => document.documentElement.dataset.theme) !== theme) await page.locator('#theme-toggle').click();
      await page.locator('#analysis').scrollIntoViewIfNeeded();
      await a11y(page, 'charts-' + theme); await screenshot(page, 'charts-' + theme + '-1440x900');
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.locator('#report-select').click();
      await screenshot(page, 'history-dropdown-' + theme + '-1440x900');
      await page.keyboard.press('Escape');
    }
    await page.locator('#theme-toggle').click();
    await page.locator('#page-size').scrollIntoViewIfNeeded();
    await page.locator('#page-size').click();
    await page.keyboard.press('ArrowDown'); await page.keyboard.press('Enter');
    await page.waitForFunction(() => document.querySelector('#page-size').value === '25');
    await page.locator('#page-size').selectOption('50');
    await page.evaluate(() => window.scrollTo(0, 0));
    check('Unverified chips/score qualifiers, overview filtering, muted unscored ports, minimum bars, 40px compact mode and accurate labels');
    await page.locator('#compact-toggle').focus();
    await page.keyboard.press('/');
    assert.equal(await page.locator('#search-input').evaluate((el) => el === document.activeElement), true);
    await page.locator('#search-input').fill('SSH'); await page.waitForTimeout(150);
    assert(await page.locator('#results-body mark').count() > 0);
    await page.keyboard.press('Escape');
    await page.locator('[data-severity="high"]').click();
    assert(await page.locator('#results-body tr').count() >= 1);
    await page.locator('#results-body .host-link').first().click();
    assert.match(await page.locator('#detail-content').textContent(), /7.2/);
    assert.match(await page.locator('#detail-content').textContent(), /Medium port risk/);
    assert.match(await page.locator('.vulnerability').textContent(), /High/);
    assert.equal(await page.locator('.vulnerability a').first().getAttribute('rel'), 'noopener noreferrer');
    await page.keyboard.press('Escape'); await page.locator('#clear-filters').click();
    await page.locator('#results-body .host-link').first().focus(); await page.keyboard.press('Enter');
    assert.match(await page.locator('.detail-confidence').textContent(), /Unverified/);
    const observed = page.locator('.detail-grid dt').filter({ hasText: /^Observed$/ });
    const observedValue = observed.locator('xpath=following-sibling::dd[1]');
    assert.equal(await observedValue.getAttribute('title'), saved.results.find((row) => row.port === 22).scan_time);
    assert.doesNotMatch(await observedValue.textContent(), /T\d{2}:\d{2}:\d{2}/);
    await page.locator('[aria-label="Copy Observed"]').click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), await observedValue.getAttribute('title'));
    const firstTitle = await page.locator('#detail-title').textContent();
    await page.keyboard.press('ArrowDown'); assert.notEqual(await page.locator('#detail-title').textContent(), firstTitle);
    await page.keyboard.press('ArrowUp'); assert.equal(await page.locator('#detail-title').textContent(), firstTitle);
    await page.locator('[aria-label="Copy Host"]').click();
    assert(await page.evaluate(() => navigator.clipboard.readText()).then((value) => value.length > 0));
    await a11y(page, 'evidence-dark'); await screenshot(page, 'evidence-dark-1440x900');
    await page.keyboard.press('Escape'); assert.equal(await page.locator('#evidence-drawer').evaluate((el) => el.open), false);
    check('Search shortcut/highlighting, severity filter, evidence navigation/Escape/copy, NVD attributes and 7.2 Medium vs High CVE labels');

    await page.locator('[data-kpi="hosts"]').click();
    assert.match(await page.locator('#result-count').textContent(), new RegExp('^' + saved.analytics.host_count + ' of'));
    await page.locator('[data-kpi="vulns"]').click(); assert(await page.locator('#results-body tr').count() >= 2);
    await page.locator('[data-kpi="risk"]').click(); assert(await page.locator('#results-body tr').count() >= 1);
    await page.locator('[data-kpi="ports"]').click();
    await page.locator('#page-size').selectOption('25');
    await page.locator('#next-page').click(); assert.match(await page.locator('#page-info').textContent(), /Page 2/);
    await page.locator('#prev-page').click();
    await page.locator('th[data-sort="port"] button').click(); assert.equal(await page.locator('th[data-sort="port"]').getAttribute('aria-sort'), 'descending');
    await page.locator('th[data-sort="port"] button').click(); assert.equal(await page.locator('th[data-sort="port"]').getAttribute('aria-sort'), 'ascending');
    await page.locator('#service-chart [data-chart-value="ssh"]').click();
    assert.match(await page.locator('#active-filter').textContent(), /Service: ssh/);
    assert.equal(await page.evaluate(() => document.activeElement.dataset.chartValue), 'ssh');
    await page.locator('#clear-filters').click();
    await page.locator('#risk-chart [data-chart-value="medium"]').click();
    assert.match(await page.locator('#results-body').textContent(), /7.2/);
    await page.locator('#clear-filters').click();
    await page.locator('#severity-chart [data-chart-value="high"]').click();
    assert(await page.locator('#results-body tr').count() >= 1);
    await page.locator('#clear-filters').click();
    await page.locator('#search-input').fill('not-a-real-service'); await page.waitForTimeout(150);
    assert(await page.locator('#no-matches').isVisible()); await screenshot(page, 'no-matches-dark-1440x900');
    await page.locator('#reset-search').click();
    check('All KPI and chart filters, sorting, pagination and no-matches state');

    await page.locator('#theme-toggle').click(); await page.reload();
    await page.waitForFunction(() => document.querySelector('#results').getAttribute('aria-busy') === 'false');
    assert.equal(await page.evaluate(() => localStorage.getItem('netscope-theme')), 'light');
    assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), 'light');
    await page.locator('#toggle-setup').click(); assert.equal(await page.locator('#setup-panel').isVisible(), false);
    await page.locator('#toggle-setup').click();
    assert(await page.locator('#start-scan').isDisabled());
    assert.match(await page.locator('#scan-readiness').textContent(), /valid target/);
    await page.locator('#target').fill('192.168.0.0/24');
    assert(await page.locator('#start-scan').isDisabled());
    assert.match(await page.locator('#scan-readiness').textContent(), /Authorized/);
    await screenshot(page, 'scan-not-authorized-light-1440x900');
    await page.locator('[name="authorize_scan"]').check(); assert(await page.locator('#start-scan').isEnabled());
    await screenshot(page, 'scan-ready-light-1440x900');
    await page.locator('[name="authorize_scan"]').uncheck();
    const postCount = findings.scanPosts.length;
    await page.locator('#scan-form').dispatchEvent('submit');
    assert.equal(findings.scanPosts.length, postCount, 'Authorization cannot be bypassed by programmatic submit');
    await page.locator('#detect-network').click();
    await page.waitForFunction(() => document.querySelector('#target').value === '192.168.50.0/24');
    assert.equal(await page.locator('#target').inputValue(), '192.168.50.0/24');
    assert.equal(await page.locator('[name="authorize_scan"]').isChecked(), true);
    assert.equal(await page.locator('[name="allow_public_targets"]').isChecked(), false);
    assert.match(await page.locator('#target-hint').textContent(), /254 hosts/);
    await page.locator('#network-select').selectOption('192.168.60.0/24');
    await page.locator('#target').fill('192.168.0.0/33');
    assert.equal(await page.locator('#target').getAttribute('aria-invalid'), 'true');
    assert(await page.locator('#start-scan').isDisabled());
    await page.locator('#target').fill('192.168.0.0/24');
    assert.equal(await page.locator('#advanced-settings').getAttribute('open'), null);
    await page.locator('#advanced-settings > summary').click();
    await page.locator('#ports').selectOption('custom'); await page.locator('#custom-ports').fill('22,80,443');
    await page.locator('[name="timeout"]').fill('2.5'); await page.locator('[name="concurrency"]').fill('100'); await page.locator('[name="batch_size"]').fill('10');
    await page.locator('[name="use_nmap"]').uncheck(); await page.locator('[name="discover_first"]').check();
    await page.locator('#exclude').fill('192.168.0.1, 192.168.0.50');
    control.scanError = 'Public targets require authorization and public-target consent.';
    await page.locator('#start-scan').click(); await page.locator('#scan-error:not(.hidden)').waitFor();
    assert.match(await page.locator('#scan-error').textContent(), /Public targets/);
    control.scanError = '';
    await page.locator('#start-scan').click(); await page.locator('#scan-activity:not(.hidden)').waitFor();
    const payload = findings.scanPosts.at(-1);
    assert.deepEqual(payload, { target: '192.168.0.0/24', ports: '22,80,443', discover_first: true, timeout: 2.5, concurrency: 100, batch_size: 10, use_nmap: false, authorize_scan: true, allow_public_targets: false, exclude: ['192.168.0.1', '192.168.0.50'], formats: ['html','json','csv'] });
    assert(await page.locator('#start-scan').isDisabled());
    check('Persisted theme, setup collapse, local-network selection, CIDR hint/validation, every form field, original payload and surfaced safety rejection (POST intercepted)');

    control.jobs = [{ ...job, status: 'completed', stage: 'completed', report_id: saved.id }];
    await page.locator('#refresh-jobs').click();
    await page.locator('#scan-activity.hidden').waitFor({ state: 'attached' });
    await page.locator('.job-item[data-report-id="' + saved.id + '"]').click();
    await page.waitForFunction(() => document.querySelector('#results').getAttribute('aria-busy') === 'false');
    assert.equal(await page.locator('#report-select').inputValue(), saved.id);
    control.offline = true;
    await page.locator('#refresh-jobs').click(); await page.locator('#offline-banner:not(.hidden)').waitFor();
    await screenshot(page, 'offline-light-1440x900');
    control.offline = false; await page.locator('#retry').click(); await page.locator('#offline-banner.hidden').waitFor({ state: 'attached' });
    check('Job completion reload, Jobs report navigation and API-offline retry');

    if (!useFixture && previews.length > 1) {
      const other = previews[1];
      await page.locator('#report-select').selectOption(other.id);
      await page.waitForFunction((id) => document.querySelector('#report-select').title === id && document.querySelector('#results').getAttribute('aria-busy') === 'false', other.id);
      assert.match(await page.locator('#report-select option:checked').textContent(), / · /);
      control.reportFailures.add(saved.id);
      await page.locator('#report-select').selectOption(saved.id);
      await page.waitForFunction((id) => document.querySelector('#report-select').value === id && document.querySelector('#results').getAttribute('aria-busy') === 'false', other.id);
      assert.equal(await page.locator('#offline-banner').isVisible(), false);
      control.reportFailures.clear();
      await page.locator('#report-select').selectOption(saved.id);
      await page.waitForFunction(() => document.querySelector('#results').getAttribute('aria-busy') === 'false');
      check('Friendly scan history labels/raw-ID tooltips, report switching and graceful missing-report rollback');
    }

    if (!useFixture) {
      await page.locator('#export-menu summary').click();
      assert.equal(await page.locator('#open-html').getAttribute('href'), '/api/reports/' + saved.id + '/files/html');
      assert.equal(await page.locator('#download-json').getAttribute('href'), '/api/reports/' + saved.id + '/files/json');
      for (const kind of ['html', 'json']) {
        const download = await context.request.get(base + '/api/reports/' + saved.id + '/files/' + kind);
        assert.equal(download.status(), 200);
        if (kind === 'json') assert.deepEqual((await download.json()).results, saved.results);
        else assert.match(await download.text(), /NetScope/);
      }
      await page.locator('#export-menu summary').click();
      check('Export menu retains the existing HTML/JSON file routes and original report data');
    }
    control.reportDelay = 500;
    const loading = page.waitForResponse((response) => response.url().includes('/api/reports/' + saved.id) && !response.url().includes('/files/'));
    await page.locator('#report-select').dispatchEvent('change');
    assert(await page.locator('#loading-state').isVisible());
    assert.equal(await page.locator('#results').getAttribute('aria-busy'), 'true');
    await screenshot(page, 'loading-light-1440x900');
    await loading;
    await page.waitForFunction(() => document.querySelector('#results').getAttribute('aria-busy') === 'false');
    control.reportDelay = 0;
    check('Loading skeleton and aria-busy clear when the selected report arrives');

    // Large reports and adversarial strings are confined to intercepted responses.
    const large = structuredClone(saved);
    large.results = Array.from({ length: 10000 }, (_, i) => ({ ...saved.results[i % saved.results.length], host: '10.0.' + Math.floor(i / 256) + '.' + (i % 256), banner: i === 0 ? '<img src="https://example.invalid/leak" onerror="alert(1)">' : saved.results[i % saved.results.length].banner }));
    large.results[0].vulnerabilities = [0,1,2,3].map((i) => ({ cve_id: 'CVE-2026-' + (1000+i), severity: 'Critical', cvss_score: 9.8, description: '<script>throw Error("XSS")</script>' }));
    control.detail = large;
    await page.selectOption('#report-select', saved.id);
    // Selecting the same option does not dispatch change in every browser.
    await page.locator('#report-select').dispatchEvent('change');
    await page.waitForFunction(() => document.querySelector('#result-count').textContent.includes('10000'));
    assert.equal(await page.locator('#results-body tr').count(), 50);
    await page.locator('#page-size').selectOption('100'); assert.equal(await page.locator('#results-body tr').count(), 100);
    assert.equal(await page.locator('#results-body img').count(), 0); assert(await page.locator('.cve-more').count() > 0);
    await page.locator('#search-input').fill('10.0.1.'); await page.waitForTimeout(200);
    assert.equal(await page.locator('#results-body tr').count(), 100);
    await page.locator('#clear-filters').click();
    check('10,000 rows remain paginated, search works, +N chips and untrusted evidence stays escaped');
    const specific = structuredClone(saved);
    specific.results = [structuredClone(saved.results.find((row) => row.port === 22))];
    specific.results[0].vulnerabilities[0].match_confidence = 'version-boundary';
    specific.results[0].vulnerabilities[0].version = '1.25';
    control.detail = specific;
    await page.locator('#report-select').dispatchEvent('change');
    await page.waitForFunction(() => document.querySelector('#result-count').textContent === '1 of 1 ports');
    assert.equal(await page.locator('#metric-critical').textContent(), '1 critical CVE match');
    assert.equal(await page.locator('.cve-pill.unverified').count(), 0);
    assert.equal(await page.locator('#show-services').isVisible(), false);
    check('Non-wildcard candidates keep their original scores and use singular critical CVE match wording');
    await context.close();

    const narrow = await contextFor(browser, 390, 844, 'light');
    await narrow.page.locator('#toggle-setup').click();
    assert.equal(await narrow.page.locator('#setup-panel').getAttribute('role'), 'dialog');
    await narrow.page.locator('#close-setup').focus(); await narrow.page.keyboard.press('Shift+Tab');
    assert(await narrow.page.locator('#setup-panel').evaluate((el) => el.contains(document.activeElement)));
    await a11y(narrow.page, 'mobile-setup-light'); await screenshot(narrow.page, 'setup-light-390x844');
    await narrow.page.keyboard.press('Escape');
    assert.equal(await narrow.page.locator('#toggle-setup').evaluate((el) => el === document.activeElement), true);
    await narrow.page.locator('#results').scrollIntoViewIfNeeded();
    await narrow.page.evaluate(() => { document.querySelector('#table-wrap').scrollLeft = 400; });
    const hostPosition = await narrow.page.locator('#results-body td:first-child').first().boundingBox();
    assert(hostPosition.x >= 0 && hostPosition.x < 32, 'Sticky host column');
    await narrow.page.locator('#results-body .host-link').first().click();
    await a11y(narrow.page, 'mobile-evidence-light'); await screenshot(narrow.page, 'evidence-light-390x844');
    await narrow.context.close();
    check('Mobile setup overlay/focus containment/return, sticky Host and evidence drawer');

    const offline = await contextFor(browser, 360, 800, 'dark', 'offline');
    assert(await offline.page.locator('#offline-banner').isVisible());
    assert.match(await offline.page.locator('#empty-state h3').textContent(), /Connect/);
    assert(await offline.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    offline.control.offline = false;
    await offline.page.locator('#retry').click();
    await offline.page.locator('#results-body tr').first().waitFor();
    await offline.page.emulateMedia({ colorScheme: 'light' });
    await offline.page.waitForFunction(() => document.documentElement.dataset.theme === 'light');
    assert.equal(await offline.page.evaluate(() => document.documentElement.dataset.theme), 'light');
    await offline.context.close();
    check('First-load API failure/recovery, 360px layout and live system theme preference');

    assert.deepEqual(findings.externalRequests, [], 'No non-localhost requests');
    assert.deepEqual(findings.pageErrors, [], 'No uncaught browser errors');
    assert.deepEqual(findings.consoleErrors, [], 'No unexpected console errors');
    check('No non-localhost requests, uncaught exceptions or unexpected console errors');
    console.log('Screenshots: ' + findings.screenshots.length + '; axe: ' + (axePath ? 'passed' : 'not installed'));
  } finally {
    fs.writeFileSync(path.join(output, 'verification.json'), JSON.stringify(findings, null, 2));
    await browser.close();
  }
})().catch((error) => { console.error(error); process.exitCode = 1; });
