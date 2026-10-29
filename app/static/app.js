/* ═══════════════════════════════════════════════════════════════════════════
   API Sentinel — Multi-Page SPA Frontend
   ═══════════════════════════════════════════════════════════════════════════ */

const H = { 'Content-Type': 'application/json', 'x-user': 'demo-admin', 'x-roles': 'admin,analyst,approver,auditor' };

async function rq(path, opts = {}) {
  const r = await fetch(path, { method: opts.method || 'GET', headers: { ...H, ...(opts.headers || {}) }, ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}) });
  if (!r.ok) throw new Error(`${r.status}: ${await r.text()}`);
  return r.json();
}

// ─── Toast System ──────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const c = document.getElementById('toastContainer');
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => { t.style.opacity = '0'; t.style.transform = 'translateX(30px)'; setTimeout(() => t.remove(), 300); }, 3500);
}

// ─── Animated Counter ──────────────────────────────────────────────────────
function animateValue(el, target) {
  if (!el) return;
  const start = parseInt(el.textContent) || 0;
  if (start === target) return;
  const duration = 600, startTime = performance.now();
  function tick(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    el.textContent = Math.round(start + (target - start) * eased);
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ─── API Layer ─────────────────────────────────────────────────────────────
const api = {
  seed: () => rq('/v1/demo/seed', { method: 'POST' }),
  endpoints: (params = '') => rq('/v1/endpoints?sort=risk_desc&limit=200' + params),
  endpoint: (id) => rq(`/v1/endpoints/${id}`),
  execReport: () => rq('/v1/reports/executive', { method: 'POST', body: { generated_by: 'demo-ciso' } }),
  boardReport: () => rq('/v1/reports/board', { method: 'POST', body: { generated_by: 'demo-ciso' } }),
  audit: (params = '') => rq('/v1/audit/events?limit=50' + params),
  connectors: () => rq('/v1/connectors/status'),
  charts: () => rq('/v1/dashboard/charts'),
  monitoring: () => rq('/v1/monitoring/status'),
  scanNow: (type = 'all') => rq(`/v1/monitoring/scan-now?connector_type=${type}`, { method: 'POST' }),
  govRules: () => rq('/v1/governance/rules'),
  govCompliance: () => rq('/v1/governance/compliance'),
  govEndpoint: (id) => rq(`/v1/governance/compliance/${id}`),
  playbook: (id) => rq(`/v1/ai/remediation-playbook/${id}`, { method: 'POST' }),
  risk: (id) => rq(`/v1/endpoints/${id}/risk`),
  reassess: (id) => rq(`/v1/endpoints/${id}/reassess`, { method: 'POST' }),
  syncKong: () => rq('/v1/connectors/kong/sync', { method: 'POST' }),
  syncGithub: () => rq('/v1/connectors/github/sync', { method: 'POST' }),
  syncSplunk: () => rq('/v1/connectors/splunk/sync', { method: 'POST' }),
  syncNetwork: () => rq('/v1/connectors/network/scan', { method: 'POST' }),
  syncK8s: () => rq('/v1/connectors/k8s/scan', { method: 'POST' }),
  connectSource: (type, url) => rq(`/v1/connectors/${type}/connect`, { method: 'POST', body: { url } }),
  disconnectSource: (type) => rq(`/v1/connectors/${type}/connect`, { method: 'DELETE' }),
  connectorSources: () => rq('/v1/connectors/sources'),
  actions: (params = '') => rq('/v1/remediation/actions?' + params),
  createAction: (eid, type = 'quarantine', reason = 'High-risk zombie containment') => rq('/v1/remediation/actions', { method: 'POST', body: { endpoint_id: eid, action_type: type, reason } }),
  simulateAction: (aid) => rq(`/v1/remediation/actions/${aid}/simulate`, { method: 'POST' }),
  approveAction: (aid) => rq(`/v1/remediation/actions/${aid}/approve`, { method: 'POST', body: { comment: 'Approved by security manager' } }),
  executeAction: (aid) => rq(`/v1/remediation/actions/${aid}/execute`, { method: 'POST', body: { executed_by: 'automation-engine' } }),
  rollbackAction: (aid) => rq(`/v1/remediation/actions/${aid}/rollback`, { method: 'POST', body: { executed_by: 'demo-admin' } }),
  cases: (params = '') => rq('/v1/cases?limit=100' + params),
  createCase: (eid, title, severity, summary) => rq('/v1/cases', { method: 'POST', body: { title, endpoint_id: eid, severity, summary } }),
  caseEvidence: (cid) => rq(`/v1/cases/${cid}/evidence`),
  summarizeCase: (cid) => rq(`/v1/ai/summarize-case/${cid}`, { method: 'POST' }),
  architecture: () => rq('/v1/architecture'),
  alerts: (limit = 50) => rq(`/v1/alerts/history?limit=${limit}`),
  benchmark: () => rq('/v1/benchmark'),
};

// ─── DOM Helpers ───────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const html = str => { const d = document.createElement('div'); d.innerHTML = str; return d; };
let cachedEndpoints = [];

// ─── Charts ────────────────────────────────────────────────────────────────
let charts = {};
const cColors = { critical: '#ef4444', high: '#f87171', medium: '#f59e0b', low: '#10b981', active: '#10b981', deprecated: '#8b5cf6', orphaned: '#f59e0b', zombie: '#ef4444' };

function mkDoughnut(canvasId, labels, data, colors) {
  const el = $(canvasId);
  if (!el) return null;
  return new Chart(el.getContext('2d'), {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 0 }] },
    options: { responsive: true, maintainAspectRatio: false, cutout: '65%', plugins: { legend: { position: 'bottom', labels: { color: '#6b6b6b', padding: 10, usePointStyle: true, pointStyle: 'circle', font: { size: 11 } } } } }
  });
}

function destroyCharts() {
  Object.values(charts).forEach(c => { if (c) c.destroy(); });
  charts = {};
}

// ─── Renderers ─────────────────────────────────────────────────────────────
function stateChip(s) { s = (s || 'unknown').toLowerCase(); return `<span class="chip s-${s}">${s}</span>`; }
function sevChip(s) { s = (s || 'low').toLowerCase(); return `<span class="sev-${s}">${s}</span>`; }

function tlsLabel(t) {
  if (!t || t === 'unknown') return `<span style="color:var(--dim)">unknown</span>`;
  if (t === 'none') return `<span style="color:var(--red);font-weight:700">none</span>`;
  if (t === 'tls_1.0') return `<span style="color:var(--red)">${t}</span>`;
  if (t === 'tls_1.2') return `<span style="color:var(--orange)">${t}</span>`;
  return `<span style="color:var(--green)">${t}</span>`;
}

function authLabel(a) {
  if (a === 'none') return `<span style="color:var(--red);font-weight:700">none</span>`;
  if (a === 'weak') return `<span style="color:var(--orange)">weak</span>`;
  return `<span style="color:var(--green)">${a}</span>`;
}

function statusChip(s) {
  const colors = { requested: 'var(--blue)', simulated: 'var(--cyan)', approved: 'var(--orange)', executed: 'var(--green)', rolled_back: 'var(--purple)', failed: 'var(--red)' };
  return `<span class="chip" style="background:${colors[s] || 'var(--dim)'}22;color:${colors[s] || 'var(--dim)'}; border:1px solid ${colors[s] || 'var(--dim)'}33">${s}</span>`;
}

function fmtDate(d) { if (!d) return '-'; const dt = new Date(d); return dt.toLocaleString('en-IN', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' }); }
function fmtINR(n) { if (!n) return '₹0'; return '₹' + (n >= 100000 ? (n / 100000).toFixed(1) + 'L' : n.toLocaleString('en-IN')); }

// ─── Modal System ──────────────────────────────────────────────────────────
function openModal(title, subtitle, bodyHTML) {
  $('modalTitle').textContent = title;
  $('modalSubtitle').textContent = subtitle || '';
  $('modalBody').innerHTML = bodyHTML;
  $('modalOverlay').classList.add('open');
}
function closeModal() { $('modalOverlay').classList.remove('open'); }
$('modalClose').onclick = closeModal;
$('modalOverlay').onclick = e => { if (e.target === $('modalOverlay')) closeModal(); };

// ─── Endpoint Detail Modal ─────────────────────────────────────────────────
async function showEndpointDetail(ep) {
  openModal(`${ep.method} ${ep.path}`, `${ep.host} · ${ep.env} · ID: ${ep.id}`, '<div style="color:var(--muted)">Loading analysis...</div>');
  const [riskData, playbook] = await Promise.all([
    api.risk(ep.id).catch(() => null),
    api.playbook(ep.id).catch(() => null),
  ]);

  let h = `<div class="modal-grid">
    <div class="modal-stat"><label>Lifecycle</label><div class="val">${stateChip(ep.lifecycle_state)}</div></div>
    <div class="modal-stat"><label>Risk Score</label><div class="val" style="color:var(--red)">${ep.risk_score ?? 'N/A'} <span style="font-size:12px;color:var(--dim)">${ep.risk_severity || ''}</span></div></div>
    <div class="modal-stat"><label>Auth</label><div class="val">${authLabel(ep.auth_type)}</div></div>
    <div class="modal-stat"><label>TLS</label><div class="val">${tlsLabel(ep.tls_status)}</div></div>
    <div class="modal-stat"><label>Owner</label><div class="val" style="font-size:14px">${ep.owner_team || '<span style="color:var(--red)">Unassigned</span>'}</div></div>
    <div class="modal-stat"><label>Data Sensitivity</label><div class="val" style="font-size:14px">${ep.data_sensitivity}</div></div>
    <div class="modal-stat"><label>Gateway (Kong)</label><div class="val" style="font-size:14px;color:${ep.seen_in_gateway ? 'var(--green)' : 'var(--dim)'}">${ep.seen_in_gateway ? 'Active Route' : 'None'}</div></div>
    <div class="modal-stat"><label>SIEM (Splunk)</label><div class="val" style="font-size:14px;color:${ep.seen_in_siem ? 'var(--red)' : 'var(--green)'}">${ep.seen_in_siem ? 'Threat Alert' : 'Clear'}</div></div>
    <div class="modal-stat"><label>Code Spec (GitHub)</label><div class="val" style="font-size:14px;color:${ep.expected_in_code ? 'var(--green)' : 'var(--red)'}">${ep.expected_in_code ? 'Documented' : 'Missing (Undocumented)'}</div></div>
    <div class="modal-stat"><label>Discovered Host</label><div class="val" style="font-size:13px;font-family:'JetBrains Mono'">${ep.host}</div></div>
  </div>`;

  h += `<h3 style="margin:16px 0 8px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;">Multi-Source Evidence Matrix</h3>`;
  h += `<div style="background:var(--surface2);border-radius:8px;padding:12px;border:1px solid var(--border);margin-bottom:12px;">
    <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(200px, 1fr));gap:10px;font-size:12px;">
      <div style="padding:8px;background:var(--surface);border-radius:6px;border-left:3px solid ${ep.seen_in_gateway ? 'var(--green)' : 'var(--border)'}">
        <div style="font-weight:700;margin-bottom:2px">🌐 Kong Gateway</div>
        <div style="color:${ep.seen_in_gateway ? 'var(--green)' : 'var(--muted)'};font-size:11px">${ep.seen_in_gateway ? 'Found: Live route receiving production traffic' : 'Not observed in gateway routes'}</div>
      </div>
      <div style="padding:8px;background:var(--surface);border-radius:6px;border-left:3px solid ${ep.expected_in_code ? 'var(--green)' : 'var(--red)'}">
        <div style="font-weight:700;margin-bottom:2px">📁 GitHub Repositories</div>
        <div style="color:${ep.expected_in_code ? 'var(--green)' : 'var(--red)'};font-size:11px">${ep.expected_in_code ? 'Found: Documented in OpenAPI specification' : 'MISSING: Not found in any repo spec (Orphan/Zombie clue)'}</div>
      </div>
      <div style="padding:8px;background:var(--surface);border-radius:6px;border-left:3px solid ${ep.seen_in_siem ? 'var(--red)' : 'var(--green)'}">
        <div style="font-weight:700;margin-bottom:2px">🚨 Splunk SIEM</div>
        <div style="color:${ep.seen_in_siem ? 'var(--red)' : 'var(--green)'};font-size:11px">${ep.seen_in_siem ? 'FLAGGED: Active threat/anomaly alerts correlated' : 'Clear: No anomalous security signals'}</div>
      </div>
    </div>
  </div>`;

  if (riskData) {
    h += `<h3 style="margin:16px 0 8px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;">Risk Factor Breakdown</h3>`;
    h += `<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px;">`;
    for (const f of (riskData.factors || [])) {
      const pct = Math.min(f.points / 30 * 100, 100);
      const barColor = f.points >= 20 ? 'var(--red)' : f.points >= 10 ? 'var(--orange)' : 'var(--green)';
      h += `<div style="flex:1;min-width:120px;background:var(--surface2);border-radius:8px;padding:8px;border:1px solid var(--border);">
        <div style="font-size:10px;color:var(--dim);text-transform:uppercase">${f.factor}</div>
        <div style="font-size:16px;font-weight:700;color:${barColor}">${f.points}<span style="font-size:11px;color:var(--dim)"> pts</span></div>
        <div style="height:3px;background:var(--surface);border-radius:2px;margin-top:4px"><div style="height:100%;width:${pct}%;background:${barColor};border-radius:2px"></div></div>
        <div style="font-size:10px;color:var(--dim);margin-top:2px">${f.detail}</div>
      </div>`;
    }
    h += `</div>`;
    h += `<div style="font-size:11px;color:var(--dim);font-family:'JetBrains Mono';padding:6px 10px;background:var(--surface2);border-radius:6px">${riskData.explainability}</div>`;
  }

  if (playbook) {
    h += `<h3 style="margin:16px 0 8px;font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;">AI Remediation Playbook <span style="font-size:10px;color:var(--blue)">Priority: ${playbook.priority}</span></h3>`;
    h += `<div style="font-size:11px;color:var(--dim);margin-bottom:8px">Estimated effort: ${playbook.estimated_effort} | Compliance: ${playbook.compliance_score}%</div>`;
    for (const step of playbook.playbook_steps) {
      const isCritical = step.includes('QUARANTINE') || step.includes('IMMEDIATE') || step.includes('COMPLIANCE');
      h += `<div class="playbook-step${isCritical ? ' critical' : ''}">${step}</div>`;
    }
    if (playbook.governance_violations?.length) {
      h += `<div style="margin-top:8px;padding:8px 12px;background:var(--red-glow);border:1px solid rgba(239,68,68,.3);border-radius:8px;font-size:12px;color:var(--red)"><strong>Governance Violations:</strong> ${playbook.governance_violations.join(' · ')}</div>`;
    }
  }

  h += `<div style="margin-top:16px;display:flex;gap:8px;">
    <button class="btn-danger btn-sm" onclick="quickQuarantine(${ep.id})">Quarantine</button>
    <button class="btn-primary btn-sm" onclick="quickCase(${ep.id})">Create Case</button>
    <button class="btn-secondary btn-sm" onclick="quickReassess(${ep.id})">Reassess Risk</button>
  </div>`;

  $('modalBody').innerHTML = h;
}

async function quickQuarantine(eid) {
  try {
    const a = await api.createAction(eid);
    await api.simulateAction(a.id);
    await api.approveAction(a.id);
    await api.executeAction(a.id);
    toast(`Endpoint ${eid} quarantined`, 'success');
    closeModal();
    router.reload();
  } catch (e) { toast(e.message, 'error'); }
}

async function quickCase(eid) {
  try {
    const c = await api.createCase(eid, 'Investigation: Endpoint #' + eid, 'high', 'Auto-created from endpoint detail view');
    toast(`Case #${c.id} created`, 'success');
    closeModal();
    navigate('cases');
  } catch (e) { toast(e.message, 'error'); }
}

async function quickReassess(eid) {
  try {
    const r = await api.reassess(eid);
    toast(`Reassessed: ${r.severity} (${r.risk_score})`, 'info');
    const ep = await api.endpoint(eid);
    showEndpointDetail(ep);
  } catch (e) { toast(e.message, 'error'); }
}

// ─── Button Helper ──────────────────────────────────────────────────────────
function withBtn(btn, label, fn) {
  return async () => {
    if (!btn) return;
    const orig = btn.textContent;
    btn.disabled = true; btn.textContent = label;
    try { await fn(); } catch (e) { toast(e.message, 'error'); }
    finally { btn.disabled = false; btn.textContent = orig; }
  };
}

// ═══════════════════════════════════════════════════════════════════════════
//  ROUTER
// ═══════════════════════════════════════════════════════════════════════════

const pages = {
  dashboard: { title: 'Dashboard', render: renderDashboard },
  endpoints: { title: 'API Endpoints', render: renderEndpointsPage },
  connectors: { title: 'Connectors', render: renderConnectorsPage },
  monitoring: { title: 'Continuous Monitoring', render: renderMonitoringPage },
  cases: { title: 'Investigation Cases', render: renderCasesPage },
  remediation: { title: 'Remediation Actions', render: renderRemediationPage },
  governance: { title: 'Governance & Compliance', render: renderGovernancePage },
  reports: { title: 'Reports & ROI', render: renderReportsPage },
  architecture: { title: 'Architecture', render: renderArchitecturePage },
  audit: { title: 'Audit Trail', render: renderAuditPage },
};

const router = {
  current: 'dashboard',
  reload() { pages[this.current]?.render(); },
};

function navigate(page) {
  if (!pages[page]) page = 'dashboard';
  router.current = page;
  window.location.hash = page;
  destroyCharts();
  $('pageTitle').textContent = pages[page].title;
  document.querySelectorAll('.nav-item').forEach(n => {
    n.classList.toggle('active', n.dataset.page === page);
  });
  $('pageContent').innerHTML = '<div style="text-align:center;padding:40px;color:var(--muted)">Loading...</div>';
  pages[page].render();
}

document.querySelectorAll('.nav-item[data-page]').forEach(n => {
  n.addEventListener('click', e => { e.preventDefault(); navigate(n.dataset.page); });
});

window.addEventListener('hashchange', () => {
  const p = window.location.hash.replace('#', '') || 'dashboard';
  if (p !== router.current) navigate(p);
});

// ─── Global Buttons ────────────────────────────────────────────────────────
$('seedBtn').addEventListener('click', withBtn($('seedBtn'), 'Seeding...', async () => {
  await api.seed();
  currentDashboardSource = 'banking';
  toast('Banking API scenario seeded (16 APIs added). Switched to Banking scope.', 'success');
  router.reload();
}));

$('refreshBtn').addEventListener('click', () => router.reload());

let currentDashboardSource = 'juiceshop'; // 'juiceshop' (default), 'banking', 'all'

function isJuiceShopEndpoint(e) {
  const host = (e.host || '').toLowerCase();
  const svc = (e.service_name || '').toLowerCase();
  const path = (e.path || '').toLowerCase();
  return host.includes('juice-shop') || svc.includes('juice-shop') || path.startsWith('/rest/') || path === '/ftp' || path === '/encryptionkeys';
}

// ═══════════════════════════════════════════════════════════════════════════
//  PAGE: DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════

async function renderDashboard() {
  $('pageContent').innerHTML = `
    <div class="source-banner">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <span style="font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)">Active Scope:</span>
        <div class="source-pills">
          <button class="source-pill ${currentDashboardSource === 'juiceshop' ? 'active' : ''}" data-src="juiceshop" id="pillJuice">
            🧃 OWASP Juice Shop <span class="pill-badge" id="badgeJuiceCount">-</span>
          </button>
          <button class="source-pill ${currentDashboardSource === 'banking' ? 'active' : ''}" data-src="banking" id="pillBanking">
            🏦 Banking Scenario <span class="pill-badge" id="badgeBankCount">-</span>
          </button>
          <button class="source-pill ${currentDashboardSource === 'all' ? 'active' : ''}" data-src="all" id="pillAll">
            🌐 All Combined <span class="pill-badge" id="badgeAllCount">-</span>
          </button>
        </div>
      </div>
      <div id="dashSourceNotice" style="font-size:12px;color:var(--dim)"></div>
    </div>
    <div class="metrics" id="dashMetrics">
      <div class="metric m-blue"><h4>Total APIs</h4><div class="value" id="mTotal">-</div><div class="sub">Discovered endpoints</div></div>
      <div class="metric m-red"><h4>High / Critical</h4><div class="value" id="mHigh">-</div><div class="sub">Requiring attention</div></div>
      <div class="metric m-orange"><h4>Zombies</h4><div class="value" id="mZombie">-</div><div class="sub">Undocumented &amp; active</div></div>
      <div class="metric m-green"><h4>Quarantined</h4><div class="value" id="mQuarantine">-</div><div class="sub">Contained threats</div></div>
    </div>
    <div id="dashBankingAlert"></div>
    <div class="grid" style="margin-top:16px;">
      <div class="card s4">
        <div class="card-header"><h3><span class="dot" style="background:var(--red)"></span> Risk Distribution</h3></div>
        <div class="chart-box"><canvas id="riskChart"></canvas></div>
      </div>
      <div class="card s4">
        <div class="card-header"><h3><span class="dot" style="background:var(--blue)"></span> Lifecycle States</h3></div>
        <div class="chart-box"><canvas id="lifecycleChart"></canvas></div>
      </div>
      <div class="card s4">
        <div class="card-header"><h3><span class="dot" style="background:var(--green)"></span> Compliance</h3></div>
        <div style="text-align:center;margin-bottom:6px;font-size:32px;font-weight:800;font-family:'JetBrains Mono'" id="compScore">-</div>
        <div class="chart-box" style="height:160px"><canvas id="complianceChart"></canvas></div>
      </div>
    </div>
    <div class="grid" style="margin-top:14px;">
      <div class="card s6">
        <div class="card-header"><h3>Top Risks</h3></div>
        <div id="dashTopRisks" style="font-size:13px;color:var(--muted)">Loading...</div>
      </div>
      <div class="card s6">
        <div class="card-header"><h3>Recent Activity</h3></div>
        <div id="dashRecentAudit" class="log" style="max-height:200px">Loading...</div>
      </div>
    </div>
    <div class="grid" style="margin-top:14px;">
      <div class="card s6">
        <div class="card-header"><h3>Connector Status</h3></div>
        <div id="dashConnectors">Loading...</div>
      </div>
      <div class="card s6">
        <div class="card-header"><h3>Monitoring</h3></div>
        <div id="dashMonitoring">Loading...</div>
      </div>
    </div>`;

  try {
    const [endpoints, report, chartData, audit, connectors, monitoring] = await Promise.all([
      api.endpoints(), api.execReport(), api.charts().catch(() => null),
      api.audit('&limit=8'), api.connectors(), api.monitoring().catch(() => null)
    ]);
    cachedEndpoints = endpoints;

    const juiceEndpoints = endpoints.filter(isJuiceShopEndpoint);
    const bankEndpoints = endpoints.filter(e => !isJuiceShopEndpoint(e));

    const jc = $('badgeJuiceCount'), bc = $('badgeBankCount'), ac = $('badgeAllCount');
    if (jc) jc.textContent = juiceEndpoints.length;
    if (bc) bc.textContent = bankEndpoints.length;
    if (ac) ac.textContent = endpoints.length;

    let displayEndpoints = endpoints;
    if (currentDashboardSource === 'juiceshop') {
      displayEndpoints = juiceEndpoints;
    } else if (currentDashboardSource === 'banking') {
      displayEndpoints = bankEndpoints;
    }

    // Source notice
    const sn = $('dashSourceNotice');
    if (sn) {
      if (currentDashboardSource === 'juiceshop') {
        sn.innerHTML = `<span style="color:var(--green)">●</span> Live Repo: <strong style="color:var(--ink)">juice-shop/juice-shop</strong> · 5 connectors synced · Real-time threat correlation`;
      } else if (currentDashboardSource === 'banking') {
        sn.innerHTML = `<span style="color:var(--orange)">●</span> Banking Scenario: <strong style="color:var(--ink)">default-bank</strong> · ${bankEndpoints.length} APIs (Wire transfer &amp; customer export threats)`;
      } else {
        sn.innerHTML = `<span style="color:var(--blue)">●</span> Combined View: ${endpoints.length} APIs across all connected sources and scenarios`;
      }
    }

    // Empty state notice for banking scenario if not seeded
    const ba = $('dashBankingAlert');
    if (ba) {
      if (currentDashboardSource === 'banking' && bankEndpoints.length === 0) {
        ba.innerHTML = `<div style="background:rgba(217,119,6,0.08);border:1px solid rgba(217,119,6,0.25);border-radius:10px;padding:12px 16px;margin-top:12px;display:flex;align-items:center;justify-content:space-between">
          <div><strong style="color:var(--orange)">Banking Scenario Not Seeded:</strong> No banking endpoints currently in the database.</div>
          <button class="btn-primary btn-sm" onclick="$('seedBtn').click()">Seed Scenario</button>
        </div>`;
      } else {
        ba.innerHTML = '';
      }
    }

    // Wire source pill click listeners
    document.querySelectorAll('.source-pill[data-src]').forEach(btn => {
      btn.addEventListener('click', () => {
        currentDashboardSource = btn.dataset.src;
        renderDashboard();
      });
    });

    const totalCount = displayEndpoints.length;
    const highCount = displayEndpoints.filter(e => ['high', 'critical'].includes((e.risk_severity || '').toLowerCase())).length;
    const zombieCount = displayEndpoints.filter(e => e.lifecycle_state === 'zombie').length;
    const quarantineCount = displayEndpoints.filter(e => e.is_quarantined).length;

    animateValue($('mTotal'), totalCount);
    animateValue($('mHigh'), highCount);
    animateValue($('mZombie'), zombieCount);
    animateValue($('mQuarantine'), quarantineCount);

    // Update sidebar badges
    const nb = $('navBadgeEndpoints');
    if (nb) nb.textContent = endpoints.length;

    // Charts based on displayEndpoints
    const rDist = {
      critical: displayEndpoints.filter(e => (e.risk_severity || '').toLowerCase() === 'critical').length,
      high: displayEndpoints.filter(e => (e.risk_severity || '').toLowerCase() === 'high').length,
      medium: displayEndpoints.filter(e => (e.risk_severity || '').toLowerCase() === 'medium').length,
      low: displayEndpoints.filter(e => (e.risk_severity || '').toLowerCase() === 'low').length,
    };
    const lDist = {
      active: displayEndpoints.filter(e => e.lifecycle_state === 'active').length,
      deprecated: displayEndpoints.filter(e => e.lifecycle_state === 'deprecated').length,
      orphaned: displayEndpoints.filter(e => e.lifecycle_state === 'orphaned').length,
      zombie: displayEndpoints.filter(e => e.lifecycle_state === 'zombie').length,
    };
    const compCount = displayEndpoints.filter(e => !['high', 'critical'].includes((e.risk_severity || '').toLowerCase())).length;
    const nonCompCount = displayEndpoints.length - compCount;
    const compScore = displayEndpoints.length ? Math.round((compCount / displayEndpoints.length) * 100) : 100;

    charts.risk = mkDoughnut('riskChart', ['Critical', 'High', 'Medium', 'Low'], [rDist.critical, rDist.high, rDist.medium, rDist.low], [cColors.critical, cColors.high, cColors.medium, cColors.low]);
    charts.lifecycle = mkDoughnut('lifecycleChart', ['Active', 'Deprecated', 'Orphaned', 'Zombie'], [lDist.active, lDist.deprecated, lDist.orphaned, lDist.zombie], [cColors.active, cColors.deprecated, cColors.orphaned, cColors.zombie]);
    const scoreEl = $('compScore');
    if (scoreEl) { scoreEl.textContent = compScore + '%'; scoreEl.style.color = compScore >= 80 ? 'var(--green)' : compScore >= 50 ? 'var(--orange)' : 'var(--red)'; }
    charts.compliance = mkDoughnut('complianceChart', ['Compliant', 'Non-Compliant'], [compCount, nonCompCount], ['#10b981', '#ef4444']);

    // Top Risks for displayEndpoints
    const topRisks = displayEndpoints
      .filter(e => (e.risk_score || 0) > 0)
      .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
      .slice(0, 5);

    if (topRisks.length) {
      $('dashTopRisks').innerHTML = topRisks.map((r, i) =>
        `<div style="padding:8px 0;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px;cursor:pointer" onclick="showEndpointById(${r.id})">
          <strong style="color:var(--red);min-width:20px">#${i + 1}</strong>
          <span style="font-family:'JetBrains Mono';font-size:11px;flex:1">${r.method} ${r.path}</span>
          <span class="sev-${(r.risk_severity || 'medium').toLowerCase()}" style="font-family:'JetBrains Mono'">${r.risk_score ?? '-'}</span>
        </div>`
      ).join('');
    } else {
      $('dashTopRisks').innerHTML = '<div class="empty-state"><div class="icon">📊</div><p>No risk data for this scope.</p></div>';
    }

    // Recent Audit
    if (audit.length) {
      $('dashRecentAudit').textContent = audit.map(e =>
        `[${fmtDate(e.timestamp)}] ${e.event_type} | ${e.entity_type}:${e.entity_id} | ${e.actor}`
      ).join('\n');
    } else { $('dashRecentAudit').textContent = 'No events yet.'; }

    // Connectors
    $('dashConnectors').innerHTML = connectors.map(c => {
      const color = c.status === 'healthy' ? 'var(--green)' : c.status === 'error' ? 'var(--red)' : 'var(--dim)';
      return `<div class="connector-card" style="margin-bottom:6px">
        <span class="status-dot" style="background:${color}"></span>
        <div class="info"><h5>${c.connector_type}</h5><p>${c.status} ${c.connected_url ? '(connected)' : c.use_simulated ? '(simulated)' : ''} ${c.last_sync_at ? '· ' + fmtDate(c.last_sync_at) : ''}</p></div>
      </div>`;
    }).join('') || '<div class="empty-state"><p>No connectors.</p></div>';

    // Monitoring
    if (monitoring?.scan_schedules?.length) {
      $('dashMonitoring').innerHTML = `
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:10px">
          <div style="background:var(--surface2);border-radius:10px;padding:10px;border:1px solid var(--border);text-align:center"><div style="font-size:10px;color:var(--dim);text-transform:uppercase">Health</div><div style="font-size:16px;font-weight:700;color:${monitoring.overall_health === 'healthy' ? 'var(--green)' : 'var(--orange)'}">${monitoring.overall_health}</div></div>
          <div style="background:var(--surface2);border-radius:10px;padding:10px;border:1px solid var(--border);text-align:center"><div style="font-size:10px;color:var(--dim);text-transform:uppercase">New APIs (24h)</div><div style="font-size:16px;font-weight:700;color:var(--blue)">${monitoring.new_apis_last_24h}</div></div>
          <div style="background:var(--surface2);border-radius:10px;padding:10px;border:1px solid var(--border);text-align:center"><div style="font-size:10px;color:var(--dim);text-transform:uppercase">Total Scans</div><div style="font-size:16px;font-weight:700;color:var(--cyan)">${monitoring.total_scans_completed}</div></div>
        </div>`;
    } else { $('dashMonitoring').innerHTML = '<div class="empty-state"><p>No monitoring data.</p></div>'; }
  } catch (e) {
    $('pageContent').innerHTML = `<div class="empty-state"><div class="icon">⚡</div><p>Error loading dashboard: ${e.message}</p><p style="margin-top:8px">Try refreshing or click "Seed Scenario" for banking demo data.</p></div>`;
  }
}


async function showEndpointById(id) {
  let ep = cachedEndpoints.find(e => e.id === id);
  if (!ep) ep = await api.endpoint(id);
  showEndpointDetail(ep);
}

// ═══════════════════════════════════════════════════════════════════════════
//  PAGE: ENDPOINTS
// ═══════════════════════════════════════════════════════════════════════════

async function renderEndpointsPage() {
  $('pageContent').innerHTML = `
    <div style="display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap">
      <div class="search-bar" style="flex:1;min-width:200px"><input type="text" id="epSearch" placeholder="Search endpoints..." /></div>
      <select id="epSource" style="width:160px"><option value="">All Sources</option><option value="juiceshop" selected>🧃 Juice Shop</option><option value="banking">🏦 Banking Demo</option></select>
      <select id="epLifecycle" style="width:140px"><option value="">All Lifecycles</option><option value="active">Active</option><option value="deprecated">Deprecated</option><option value="orphaned">Orphaned</option><option value="zombie">Zombie</option></select>
      <select id="epSeverity" style="width:140px"><option value="">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
      <button class="btn-secondary btn-sm" id="epFilterBtn">Apply</button>
    </div>
    <div class="card">
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th style="width:40px">ID</th><th>Endpoint</th><th>Source</th><th>Owner</th><th>Lifecycle</th><th>Risk</th><th>TLS</th><th>Auth</th><th>SIEM</th><th>Quarantined</th>
          </tr></thead>
          <tbody id="epTableBody"><tr><td colspan="10" style="color:var(--muted)">Loading...</td></tr></tbody>
        </table>
      </div>
      <div style="margin-top:10px;display:flex;justify-content:space-between;align-items:center">
        <div style="font-size:12px;color:var(--dim)" id="epCount">-</div>
      </div>
    </div>`;

  const loadEndpoints = async () => {
    const q = $('epSearch').value;
    const src = $('epSource') ? $('epSource').value : '';
    const lc = $('epLifecycle').value;
    const sev = $('epSeverity').value;
    let params = '';
    if (q) params += `&q=${encodeURIComponent(q)}`;
    if (lc) params += `&lifecycle=${lc}`;
    if (sev) params += `&severity=${sev}`;
    try {
      let eps = await api.endpoints(params);
      cachedEndpoints = eps;
      if (src === 'juiceshop') {
        eps = eps.filter(isJuiceShopEndpoint);
      } else if (src === 'banking') {
        eps = eps.filter(e => !isJuiceShopEndpoint(e));
      }
      const tb = $('epTableBody');
      if (!eps.length) { tb.innerHTML = '<tr><td colspan="10" class="empty-state">No endpoints found for this filter.</td></tr>'; $('epCount').textContent = '0 endpoints'; return; }
      tb.innerHTML = eps.map(e => {
        const isJuice = isJuiceShopEndpoint(e);
        return `
        <tr class="clickable" onclick='showEndpointById(${e.id})'>
          <td style="font-family:'JetBrains Mono';font-size:12px;color:var(--dim)">${e.id}</td>
          <td><div style="font-family:'JetBrains Mono';font-size:12px">${e.method} ${e.path}</div><div style="font-size:11px;color:var(--dim)">${e.host} · ${e.service_name || ''}</div></td>
          <td>${isJuice ? '<span class="chip" style="font-size:9px;background:rgba(200,230,74,0.12);color:var(--accent)">JUICE-SHOP</span>' : '<span class="chip" style="font-size:9px;background:rgba(59,130,246,0.12);color:var(--blue)">BANKING</span>'}</td>
          <td>${e.owner_team || '<span style="color:var(--red);font-size:11px">unassigned</span>'}</td>
          <td>${stateChip(e.lifecycle_state)}</td>
          <td><span class="sev-${(e.risk_severity||'low').toLowerCase()}" style="font-family:'JetBrains Mono'">${e.risk_score ?? '-'}</span></td>
          <td>${tlsLabel(e.tls_status)}</td>
          <td>${authLabel(e.auth_type)}</td>
          <td>${e.seen_in_siem ? '<span style="color:var(--red)">threat</span>' : '<span style="color:var(--dim)">clear</span>'}</td>
          <td>${e.is_quarantined ? '<span style="color:var(--green)">yes</span>' : '<span style="color:var(--dim)">no</span>'}</td>
        </tr>`;
      }).join('');
      $('epCount').textContent = `${eps.length} endpoint${eps.length !== 1 ? 's' : ''}`;
    } catch (e) { toast(e.message, 'error'); }
  };

  $('epFilterBtn').addEventListener('click', loadEndpoints);
  $('epSource').addEventListener('change', loadEndpoints);
  $('epSearch').addEventListener('keydown', e => { if (e.key === 'Enter') loadEndpoints(); });
  loadEndpoints();
}

// ═══════════════════════════════════════════════════════════════════════════
//  PAGE: CONNECTORS
// ═══════════════════════════════════════════════════════════════════════════

async function renderConnectorsPage() {
  const connectable = new Set(['github', 'kong', 'splunk']);
  const connectPlaceholders = {
    github: 'e.g. https://github.com/juice-shop/juice-shop',
    kong:   'e.g. https://juice-shop.herokuapp.com',
    splunk: 'e.g. https://splunk-cloud.com/juice-shop-telemetry',
  };
  const connectLabels = {
    github: '📁 Connect Repository',
    kong:   '🌐 Connect Gateway URL',
    splunk: '🚨 Connect SIEM Ingestion URL',
  };

  const syncFns = {
    kong: { fn: api.syncKong, label: 'API Gateway', desc: 'Kong Gateway — discovers endpoints from API traffic, auth policies, rate limits' },
    github: { fn: api.syncGithub, label: 'Code Repository', desc: 'GitHub/GitLab — matches endpoints against OpenAPI specs and service code' },
    splunk: { fn: api.syncSplunk, label: 'SIEM / Threat Intel', desc: 'Splunk SIEM — correlates threat signals, credential stuffing, data exfil alerts' },
    network: { fn: api.syncNetwork, label: 'Network Scanner', desc: 'Network traffic analysis — discovers shadow APIs via packet inspection, DNS, LB logs' },
    k8s: { fn: api.syncK8s, label: 'K8s / Container', desc: 'Kubernetes — discovers APIs from Ingress resources, Service definitions, pods' },
  };

  $('pageContent').innerHTML = `
    <div style="display:flex;gap:8px;margin-bottom:16px">
      <button class="btn-primary btn-sm" id="syncAllBtn">Sync All Connectors</button>
    </div>
    <div class="grid" id="connectorGrid">
      ${Object.entries(syncFns).map(([key, cfg]) => `
        <div class="card s6" id="conn_${key}">
          <div class="connector-card">
            <span class="status-dot" id="connDot_${key}" style="background:var(--dim)"></span>
            <div class="info">
              <h5>${cfg.label}</h5>
              <p>${cfg.desc}</p>
              <div style="margin-top:6px;font-size:11px;color:var(--dim)" id="connMeta_${key}">-</div>
            </div>
            <button class="btn-secondary btn-sm" id="syncBtn_${key}">Sync</button>
          </div>
          ${connectable.has(key) ? `
          <div id="connSource_${key}" style="margin-top:10px;padding:10px 12px;background:var(--surface);border:1px solid var(--border);border-radius:8px;">
            <div style="font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-bottom:6px">${connectLabels[key] || 'Connect Source'}</div>
            <div id="connSourceConnected_${key}" style="display:none;">
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="color:var(--green);font-size:16px">●</span>
                <a id="connSourceUrl_${key}" href="#" target="_blank" style="font-size:12px;color:var(--cyan);font-family:'JetBrains Mono',monospace;word-break:break-all;flex:1;"></a>
                <button class="btn-secondary btn-sm" id="disconnectBtn_${key}" style="font-size:10px;padding:3px 8px;color:var(--red);border-color:var(--red);">Disconnect</button>
              </div>
            </div>
            <div id="connSourceForm_${key}">
              <div style="display:flex;gap:6px;">
                <input type="text" id="connSourceInput_${key}" placeholder="${connectPlaceholders[key] || 'Enter source URL...'}" style="flex:1;font-size:12px;padding:6px 10px;background:var(--surface2);border:1px solid var(--border);border-radius:6px;color:var(--fg);font-family:'JetBrains Mono',monospace;">
                <button class="btn-primary btn-sm" id="connectBtn_${key}" style="font-size:11px;padding:5px 12px;white-space:nowrap;">Connect</button>
              </div>
            </div>
          </div>` : `
          <div style="margin-top:10px;padding:9px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:8px;display:flex;align-items:center;gap:8px;font-size:11px;">
            <span style="color:var(--green);font-size:14px">●</span>
            <span style="font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)">Target Probe:</span>
            <span style="font-family:'JetBrains Mono',monospace;color:var(--ink)">${key === 'network' ? 'VPC Traffic Mirror (10.0.0.0/16 · prod-mesh)' : 'juice-shop-ns (cluster.local · Ingress)'}</span>
          </div>`}
        </div>`).join('')}
    </div>
    <div class="card" style="margin-top:14px">
      <div class="card-header"><h3>Sync Log</h3></div>
      <div id="connLog" class="log" style="max-height:300px">No sync activity yet.</div>
    </div>`;

  const log = (msg) => { const el = $('connLog'); el.textContent = `[${new Date().toLocaleTimeString()}] ${msg}\n` + el.textContent; };

  // ── Helper: update source UI for a connector ──
  const showConnectedSource = (key, url) => {
    const form = $(`connSourceForm_${key}`);
    const connected = $(`connSourceConnected_${key}`);
    const urlEl = $(`connSourceUrl_${key}`);
    if (!form || !connected || !urlEl) return;
    if (url) {
      form.style.display = 'none';
      connected.style.display = 'block';
      urlEl.textContent = url;
      urlEl.href = url.startsWith('http') ? url : `https://${url}`;
    } else {
      form.style.display = 'block';
      connected.style.display = 'none';
      urlEl.textContent = '';
      urlEl.href = '#';
    }
  };

  // ── Load connector statuses + connected sources ──
  try {
    const statuses = await api.connectors();
    for (const s of statuses) {
      const dot = $(`connDot_${s.connector_type}`);
      const meta = $(`connMeta_${s.connector_type}`);
      if (dot) dot.style.background = s.status === 'healthy' ? 'var(--green)' : s.status === 'error' ? 'var(--red)' : 'var(--dim)';
      if (meta) {
        let label = s.status;
        if (s.connected_url) label += ' (connected)';
        else if (s.connector_type === 'network' || s.connector_type === 'k8s') label += ' (active probe)';
        else if (s.use_simulated) label += ' (simulated)';
        label += s.last_sync_at ? ' · Last sync: ' + fmtDate(s.last_sync_at) : ' · Never synced';
        meta.textContent = label;
      }
      // Show connected source if present
      if (s.connected_url && connectable.has(s.connector_type)) {
        showConnectedSource(s.connector_type, s.connected_url);
      }
    }
  } catch (_) {}

  // ── Wire up Connect / Disconnect buttons ──
  for (const key of connectable) {
    const connectBtn = $(`connectBtn_${key}`);
    const disconnectBtn = $(`disconnectBtn_${key}`);
    const input = $(`connSourceInput_${key}`);

    if (connectBtn && input) {
      connectBtn.addEventListener('click', withBtn(connectBtn, 'Connecting...', async () => {
        const url = input.value.trim();
        if (!url) { toast('Please enter a source URL', 'error'); return; }
        log(`Connecting ${syncFns[key].label} to ${url}...`);
        await api.connectSource(key, url);
        showConnectedSource(key, url);
        log(`✓ ${syncFns[key].label} connected to ${url}`);
        toast(`${syncFns[key].label} connected — click Sync to scan`, 'success');
        const meta = $(`connMeta_${key}`);
        if (meta) meta.textContent = 'connected · Ready to sync';
      }));
      // Also connect on Enter key
      input.addEventListener('keydown', e => {
        if (e.key === 'Enter') connectBtn.click();
      });
    }

    if (disconnectBtn) {
      disconnectBtn.addEventListener('click', async () => {
        disconnectBtn.textContent = '...';
        try {
          await api.disconnectSource(key);
          showConnectedSource(key, null);
          log(`✗ ${syncFns[key].label} disconnected`);
          toast(`${syncFns[key].label} disconnected`, 'info');
          const meta = $(`connMeta_${key}`);
          if (meta) meta.textContent = 'idle (simulated) · Not connected';
          const dot = $(`connDot_${key}`);
          if (dot) dot.style.background = 'var(--dim)';
        } catch (e) { toast(e.message, 'error'); }
        disconnectBtn.textContent = 'Disconnect';
      });
    }
  }

  // ── Individual sync buttons ──
  for (const [key, cfg] of Object.entries(syncFns)) {
    const btn = $(`syncBtn_${key}`);
    if (btn) {
      btn.addEventListener('click', withBtn(btn, 'Syncing...', async () => {
        log(`Starting ${cfg.label} sync...`);
        const result = await cfg.fn();
        const source = result.connected_url ? `from ${result.connected_url}` : (result.used_simulated ? '(simulated)' : '');
        log(`${cfg.label}: ${result.status} — ${result.processed} endpoints processed ${source}`);
        toast(`${cfg.label} sync complete`, 'success');
        const dot = $(`connDot_${key}`);
        if (dot) dot.style.background = 'var(--green)';
        const meta = $(`connMeta_${key}`);
        if (meta) meta.textContent = `healthy${result.connected_url ? ' (connected)' : ''} · Last sync: ${fmtDate(new Date())}`;
      }));
    }
  }

  // ── Sync all ──
  $('syncAllBtn').addEventListener('click', withBtn($('syncAllBtn'), 'Syncing All...', async () => {
    for (const [key, cfg] of Object.entries(syncFns)) {
      log(`Syncing ${cfg.label}...`);
      try {
        const r = await cfg.fn();
        log(`${cfg.label}: ${r.processed} processed`);
        toast(`${cfg.label} sync complete`, 'success');
        const dot = $(`connDot_${key}`);
        if (dot) dot.style.background = 'var(--green)';
      } catch (e) {
        log(`${cfg.label}: ERROR — ${e.message}`);
        toast(`${cfg.label} sync failed`, 'error');
      }
    }
    toast('All connectors synced', 'success');
  }));
}

// ═══════════════════════════════════════════════════════════════════════════
//  PAGE: MONITORING
// ═══════════════════════════════════════════════════════════════════════════

async function renderMonitoringPage() {
  $('pageContent').innerHTML = `
    <div class="metrics" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px">
      <div class="metric m-green"><h4>Overall Health</h4><div class="value" id="monHealth">-</div></div>
      <div class="metric m-blue"><h4>New APIs (24h)</h4><div class="value" id="monNew">-</div></div>
      <div class="metric m-cyan"><h4>Total Scans</h4><div class="value" id="monScans">-</div></div>
      <div class="metric m-purple"><h4>Active Schedules</h4><div class="value" id="monActive">-</div></div>
    </div>
    <div style="margin-bottom:14px;display:flex;gap:8px">
      <button class="btn-primary btn-sm" id="scanNowAll">Run All Scans Now</button>
      <select id="scanNowType" style="width:160px">
        <option value="all">All Connectors</option>
        <option value="kong">Kong Gateway</option>
        <option value="github">GitHub</option>
        <option value="splunk">Splunk SIEM</option>
        <option value="network">Network Scanner</option>
        <option value="k8s">K8s Scanner</option>
      </select>
    </div>
    <div class="card">
      <div class="card-header"><h3>Scan Schedules</h3></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Connector</th><th>Interval</th><th>Status</th><th>Last Run</th><th>Next Run</th><th>APIs Last Run</th><th>Total APIs</th></tr></thead>
          <tbody id="monSchedules"><tr><td colspan="7" style="color:var(--muted)">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>`;

  const loadMon = async () => {
    try {
      const d = await api.monitoring();
      $('monHealth').textContent = d.overall_health;
      $('monHealth').style.color = d.overall_health === 'healthy' ? 'var(--green)' : 'var(--orange)';
      $('monNew').textContent = d.new_apis_last_24h;
      $('monScans').textContent = d.total_scans_completed;
      $('monActive').textContent = d.scan_schedules.filter(s => s.is_active).length;

      if (d.scan_schedules.length) {
        $('monSchedules').innerHTML = d.scan_schedules.map(s => `
          <tr>
            <td style="font-weight:600">${s.connector_type}</td>
            <td>${s.interval_minutes} min</td>
            <td>${s.is_active ? '<span style="color:var(--green)">active</span>' : '<span style="color:var(--red)">inactive</span>'}</td>
            <td style="font-size:12px">${fmtDate(s.last_run_at)}</td>
            <td style="font-size:12px">${fmtDate(s.next_run_at)}</td>
            <td>${s.apis_discovered_last_run ?? 0}</td>
            <td>${s.total_apis_discovered ?? 0}</td>
          </tr>`).join('');
      } else {
        $('monSchedules').innerHTML = '<tr><td colspan="7" class="empty-state">No scan schedules. Seed data first.</td></tr>';
      }
    } catch (e) { toast(e.message, 'error'); }
  };

  $('scanNowAll').addEventListener('click', withBtn($('scanNowAll'), 'Scanning...', async () => {
    const type = $('scanNowType').value;
    const r = await api.scanNow(type);
    toast(`${r.triggered} connector(s) scanned`, 'success');
    await loadMon();
  }));

  loadMon();
}

// ═══════════════════════════════════════════════════════════════════════════
//  PAGE: CASES
// ═══════════════════════════════════════════════════════════════════════════

async function renderCasesPage() {
  $('pageContent').innerHTML = `
    <div style="display:flex;gap:10px;margin-bottom:14px;align-items:center;flex-wrap:wrap">
      <button class="btn-primary btn-sm" id="newCaseBtn">+ New Case</button>
      <select id="caseStatusFilter" style="width:140px"><option value="">All Statuses</option><option value="open">Open</option><option value="in_progress">In Progress</option><option value="resolved">Resolved</option><option value="closed">Closed</option></select>
      <select id="caseSevFilter" style="width:140px"><option value="">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select>
      <button class="btn-secondary btn-sm" id="caseFilterBtn">Apply</button>
    </div>
    <div class="card">
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Endpoint</th><th>Created By</th><th>Created</th><th>Actions</th></tr></thead>
          <tbody id="caseTableBody"><tr><td colspan="8" style="color:var(--muted)">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>
    <div class="card" style="margin-top:14px;display:none" id="caseDetailCard">
      <div class="card-header"><h3 id="caseDetailTitle">Case Detail</h3><button class="btn-secondary btn-sm" onclick="$('caseDetailCard').style.display='none'">Close</button></div>
      <div id="caseDetailBody"></div>
    </div>`;

  const loadCases = async () => {
    let params = '';
    const st = $('caseStatusFilter').value;
    const sv = $('caseSevFilter').value;
    if (st) params += `&status=${st}`;
    if (sv) params += `&severity=${sv}`;
    try {
      const cases = await api.cases(params);
      const tb = $('caseTableBody');
      if (!cases.length) { tb.innerHTML = '<tr><td colspan="8" class="empty-state">No cases found. Create one from the Endpoints page or click "+ New Case".</td></tr>'; return; }
      tb.innerHTML = cases.map(c => `
        <tr>
          <td style="font-family:'JetBrains Mono';font-size:12px">#${c.id}</td>
          <td style="font-weight:600">${c.title}</td>
          <td>${sevChip(c.severity)}</td>
          <td>${statusChip(c.status)}</td>
          <td style="font-family:'JetBrains Mono';font-size:12px">${c.endpoint_id || '-'}</td>
          <td style="font-size:12px">${c.created_by}</td>
          <td style="font-size:12px">${fmtDate(c.created_at)}</td>
          <td>
            <button class="btn-sm btn-secondary" onclick="viewCaseDetail(${c.id})">View</button>
            <button class="btn-sm btn-primary" onclick="aiSummarizeCase(${c.id})">AI Analyze</button>
          </td>
        </tr>`).join('');
    } catch (e) { toast(e.message, 'error'); }
  };

  $('caseFilterBtn').addEventListener('click', loadCases);
  $('newCaseBtn').addEventListener('click', () => showNewCaseModal());
  loadCases();
}

function showNewCaseModal() {
  openModal('Create Investigation Case', 'Link a case to a high-risk endpoint', `
    <div class="form-group"><label>Title</label><input type="text" id="ncTitle" value="Zombie API Investigation" /></div>
    <div class="input-row">
      <div class="form-group"><label>Endpoint ID</label><input type="number" id="ncEndpointId" placeholder="e.g. 2" /></div>
      <div class="form-group"><label>Severity</label><select id="ncSeverity"><option value="critical">Critical</option><option value="high" selected>High</option><option value="medium">Medium</option><option value="low">Low</option></select></div>
    </div>
    <div class="form-group"><label>Summary</label><textarea id="ncSummary">Auto-triggered investigation for zombie API threat detection and containment.</textarea></div>
    <button class="btn-primary" onclick="submitNewCase()">Create Case</button>`);
}

async function submitNewCase() {
  try {
    const eid = parseInt($('ncEndpointId').value);
    const c = await api.createCase(eid, $('ncTitle').value, $('ncSeverity').value, $('ncSummary').value);
    toast(`Case #${c.id} created`, 'success');
    closeModal();
    renderCasesPage();
  } catch (e) { toast(e.message, 'error'); }
}

async function viewCaseDetail(cid) {
  $('caseDetailCard').style.display = 'block';
  $('caseDetailTitle').textContent = `Case #${cid} — Evidence & Analysis`;
  $('caseDetailBody').innerHTML = '<div style="color:var(--muted)">Loading evidence...</div>';

  try {
    const ev = await api.caseEvidence(cid);
    const c = ev.case;
    let h = `<div class="modal-grid">
      <div class="modal-stat"><label>Status</label><div class="val">${statusChip(c.status)}</div></div>
      <div class="modal-stat"><label>Severity</label><div class="val">${sevChip(c.severity)}</div></div>
      <div class="modal-stat"><label>Endpoint ID</label><div class="val" style="font-size:14px">${c.endpoint_id || '-'}</div></div>
      <div class="modal-stat"><label>Created</label><div class="val" style="font-size:14px">${fmtDate(c.created_at)}</div></div>
    </div>`;
    if (c.summary) h += `<div class="detail-section"><h4>Summary</h4><p style="font-size:13px;white-space:pre-wrap">${c.summary}</p></div>`;
    if (ev.artifacts?.length) {
      h += `<div class="detail-section"><h4>Artifacts (${ev.artifacts.length})</h4>`;
      for (const a of ev.artifacts) {
        h += `<div style="margin-bottom:8px;padding:8px;background:var(--surface);border-radius:6px;border:1px solid var(--border)">
          <div style="font-size:11px;color:var(--dim);margin-bottom:4px">${a.artifact_type} · ${a.source_ref} · ${fmtDate(a.created_at)}</div>
          <pre style="font-size:11px;font-family:'JetBrains Mono';white-space:pre-wrap;color:var(--cyan)">${typeof a.content === 'string' ? a.content : JSON.stringify(a.content, null, 2)}</pre>
        </div>`;
      }
      h += `</div>`;
    }
    $('caseDetailBody').innerHTML = h;
    $('caseDetailCard').scrollIntoView({ behavior: 'smooth' });
  } catch (e) { $('caseDetailBody').innerHTML = `<div style="color:var(--red)">Error: ${e.message}</div>`; }
}

async function aiSummarizeCase(cid) {
  toast(`Running AI analysis on Case #${cid}...`, 'info');
  try {
    const result = await api.summarizeCase(cid);
    $('caseDetailCard').style.display = 'block';
    $('caseDetailTitle').textContent = `Case #${cid} — AI Analysis`;
    $('caseDetailBody').innerHTML = `
      <div style="font-size:11px;color:var(--dim);margin-bottom:8px">Model: ${result.model} | Generated at: ${fmtDate(new Date())}</div>
      <div class="log" style="white-space:pre-wrap;font-size:12px;line-height:1.6" id="aiSummaryText"></div>`;

    // Typewriter effect
    const el = $('aiSummaryText');
    const text = result.summary;
    let i = 0;
    await new Promise(resolve => {
      const interval = setInterval(() => {
        el.textContent += text[i];
        i++;
        if (i >= text.length) { clearInterval(interval); resolve(); }
      }, 6);
    });
    toast(`AI analysis complete (${result.model})`, 'success');
    $('caseDetailCard').scrollIntoView({ behavior: 'smooth' });
  } catch (e) { toast(e.message, 'error'); }
}

// ═══════════════════════════════════════════════════════════════════════════
//  PAGE: REMEDIATION
// ═══════════════════════════════════════════════════════════════════════════

async function renderRemediationPage() {
  $('pageContent').innerHTML = `
    <div style="display:flex;gap:10px;margin-bottom:14px;align-items:center;flex-wrap:wrap">
      <button class="btn-danger btn-sm" id="autoQuarantineBtn">Auto-Quarantine Top Threat</button>
      <button class="btn-primary btn-sm" id="newActionBtn">+ New Action</button>
      <select id="actionStatusFilter" style="width:160px"><option value="">All Statuses</option><option value="requested">Requested</option><option value="simulated">Simulated</option><option value="approved">Approved</option><option value="executed">Executed</option><option value="rolled_back">Rolled Back</option></select>
      <button class="btn-secondary btn-sm" id="actionFilterBtn">Apply</button>
    </div>
    <div class="card">
      <div class="card-header"><h3>Remediation Actions</h3></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>Target Endpoint</th><th>Type</th><th>Status</th><th>Requested By</th><th>Created</th><th>Actions</th></tr></thead>
          <tbody id="actionTableBody"><tr><td colspan="7" style="color:var(--muted)">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>
    <div class="card" style="margin-top:14px">
      <div class="card-header"><h3>Remediation Workflow</h3></div>
      <div style="display:flex;gap:4px;align-items:center;padding:8px 0;font-size:12px;">
        <span style="padding:6px 12px;background:var(--blue-glow);color:var(--blue);border-radius:6px;font-weight:600">Request</span>
        <span style="color:var(--dim)">→</span>
        <span style="padding:6px 12px;background:var(--cyan-glow);color:var(--cyan);border-radius:6px;font-weight:600">Simulate</span>
        <span style="color:var(--dim)">→</span>
        <span style="padding:6px 12px;background:var(--orange-glow);color:var(--orange);border-radius:6px;font-weight:600">Approve (Dual)</span>
        <span style="color:var(--dim)">→</span>
        <span style="padding:6px 12px;background:var(--green-glow);color:var(--green);border-radius:6px;font-weight:600">Execute</span>
        <span style="color:var(--dim)">→</span>
        <span style="padding:6px 12px;background:var(--purple-glow);color:var(--purple);border-radius:6px;font-weight:600">Rollback (if needed)</span>
      </div>
      <p style="font-size:11px;color:var(--dim);margin-top:4px">Every action passes through policy-governed dual-approval. No single person can quarantine an endpoint. Full audit trail is maintained with SHA-256 cryptographic signatures.</p>
    </div>`;

  const loadActions = async () => {
    const st = $('actionStatusFilter').value;
    let params = st ? `status=${st}` : '';
    try {
      const actions = await api.actions(params);
      const tb = $('actionTableBody');
      if (!actions.length) { tb.innerHTML = '<tr><td colspan="7" class="empty-state">No remediation actions yet. Quarantine a threat or create an action manually.</td></tr>'; return; }
      tb.innerHTML = actions.map(a => {
        const btns = [];
        if (a.status === 'requested') btns.push(`<button class="btn-sm btn-secondary" onclick="doActionStep(${a.id},'simulate')">Simulate</button>`);
        if (a.status === 'requested' || a.status === 'simulated') btns.push(`<button class="btn-sm btn-secondary" onclick="doActionStep(${a.id},'approve')">Approve</button>`);
        if (a.status === 'approved') btns.push(`<button class="btn-sm btn-success" onclick="doActionStep(${a.id},'execute')">Execute</button>`);
        if (a.status === 'executed') btns.push(`<button class="btn-sm btn-secondary" onclick="doActionStep(${a.id},'rollback')">Rollback</button>`);
        return `<tr>
          <td style="font-family:'JetBrains Mono';font-size:12px">#${a.id}</td>
          <td style="font-family:'JetBrains Mono';font-size:11px">${a.endpoint_identity || 'EP #' + a.endpoint_id}</td>
          <td style="font-weight:600">${a.action_type}</td>
          <td>${statusChip(a.status)}</td>
          <td style="font-size:12px">${a.requested_by}</td>
          <td style="font-size:12px">${fmtDate(a.created_at)}</td>
          <td>${btns.join(' ')}</td>
        </tr>`;
      }).join('');
    } catch (e) { toast(e.message, 'error'); }
  };

  $('actionFilterBtn').addEventListener('click', loadActions);

  $('autoQuarantineBtn').addEventListener('click', withBtn($('autoQuarantineBtn'), 'Working...', async () => {
    const eps = await api.endpoints();
    const target = eps.filter(e => ['high', 'critical'].includes((e.risk_severity || '').toLowerCase()) && !e.is_quarantined).sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))[0];
    if (!target) { toast('No high-risk unquarantined endpoint', 'warning'); return; }
    toast(`Targeting ${target.method} ${target.path} (score: ${target.risk_score})`, 'info');
    const action = await api.createAction(target.id);
    toast('Action requested', 'info');
    await api.simulateAction(action.id);
    toast('Blast radius simulated', 'info');
    await api.approveAction(action.id);
    toast('Dual-approval granted', 'info');
    await api.executeAction(action.id);
    toast(`Endpoint ${target.id} QUARANTINED`, 'success');
    loadActions();
  }));

  $('newActionBtn').addEventListener('click', () => {
    openModal('Create Remediation Action', 'Target a specific endpoint for containment', `
      <div class="input-row">
        <div class="form-group"><label>Endpoint ID</label><input type="number" id="naEndpointId" placeholder="e.g. 2" /></div>
        <div class="form-group"><label>Action Type</label><select id="naType"><option value="quarantine">Quarantine</option><option value="rate_limit">Rate Limit</option><option value="block">Block</option><option value="deprecate">Deprecate</option></select></div>
      </div>
      <div class="form-group"><label>Reason</label><textarea id="naReason">High-risk endpoint requiring containment.</textarea></div>
      <button class="btn-primary" onclick="submitNewAction()">Create Action</button>`);
  });

  loadActions();
}

async function submitNewAction() {
  try {
    const eid = parseInt($('naEndpointId').value);
    const a = await api.createAction(eid, $('naType').value, $('naReason').value);
    toast(`Action #${a.id} created`, 'success');
    closeModal();
    renderRemediationPage();
  } catch (e) { toast(e.message, 'error'); }
}

async function doActionStep(aid, step) {
  try {
    if (step === 'simulate') { await api.simulateAction(aid); toast('Simulation complete', 'info'); }
    else if (step === 'approve') { await api.approveAction(aid); toast('Approved', 'info'); }
    else if (step === 'execute') { await api.executeAction(aid); toast('Executed — endpoint quarantined', 'success'); }
    else if (step === 'rollback') { await api.rollbackAction(aid); toast('Rolled back', 'info'); }
    renderRemediationPage();
  } catch (e) { toast(e.message, 'error'); }
}

// ═══════════════════════════════════════════════════════════════════════════
//  PAGE: GOVERNANCE
// ═══════════════════════════════════════════════════════════════════════════

async function renderGovernancePage() {
  $('pageContent').innerHTML = `
    <div class="metrics" style="grid-template-columns:repeat(4,1fr);margin-bottom:16px">
      <div class="metric m-green"><h4>Compliance Score</h4><div class="value" id="govScore">-</div><div class="sub">Overall percentage</div></div>
      <div class="metric m-blue"><h4>Total Rules</h4><div class="value" id="govRules">-</div></div>
      <div class="metric m-green"><h4>Compliant</h4><div class="value" id="govCompliant">-</div></div>
      <div class="metric m-red"><h4>Non-Compliant</h4><div class="value" id="govNonCompliant">-</div></div>
    </div>
    <div class="grid">
      <div class="card s6">
        <div class="card-header"><h3>Governance Rules</h3></div>
        <div id="govRulesList">Loading...</div>
      </div>
      <div class="card s6">
        <div class="card-header"><h3>Compliance Chart</h3></div>
        <div class="chart-box" style="height:220px"><canvas id="govCompChart"></canvas></div>
      </div>
    </div>
    <div class="card" style="margin-top:14px">
      <div class="card-header"><h3>Per-Endpoint Compliance</h3></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Endpoint</th><th>Compliance</th><th>Violations</th><th>Details</th></tr></thead>
          <tbody id="govEndpointBody"><tr><td colspan="4" style="color:var(--muted)">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>`;

  try {
    const [rules, compliance] = await Promise.all([api.govRules(), api.govCompliance()]);

    animateValue($('govScore'), compliance.aggregate_score ?? 0);
    $('govScore').textContent += '%';
    $('govScore').parentElement.className = `metric ${compliance.aggregate_score >= 80 ? 'm-green' : compliance.aggregate_score >= 50 ? 'm-orange' : 'm-red'}`;
    $('govRules').textContent = rules.length;
    $('govCompliant').textContent = compliance.compliant_endpoints ?? 0;
    $('govNonCompliant').textContent = compliance.non_compliant_endpoints ?? 0;

    // Rules list
    if (rules.length) {
      $('govRulesList').innerHTML = rules.map(r => `
        <div style="padding:8px 0;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:8px">
          <span class="chip" style="background:${r.severity === 'critical' ? 'var(--red-glow)' : r.severity === 'high' ? 'rgba(239,68,68,.08)' : 'var(--orange-glow)'};color:${r.severity === 'critical' ? 'var(--red)' : r.severity === 'high' ? '#f87171' : 'var(--orange)'};">${r.severity}</span>
          <div style="flex:1"><strong style="font-size:13px">${r.name}</strong><div style="font-size:11px;color:var(--dim)">${r.description}</div></div>
          <span class="chip" style="background:${r.is_active ? 'var(--green-glow)' : 'var(--surface2)'};color:${r.is_active ? 'var(--green)' : 'var(--dim)'}">${r.is_active ? 'active' : 'inactive'}</span>
        </div>`).join('');
    } else { $('govRulesList').innerHTML = '<div class="empty-state">No governance rules configured.</div>'; }

    // Compliance chart
    charts.govComp = mkDoughnut('govCompChart', ['Compliant', 'Non-Compliant'],
      [compliance.compliant_endpoints || 0, compliance.non_compliant_endpoints || 0],
      ['#10b981', '#ef4444']);

    // Per-endpoint compliance
    if (compliance.endpoints?.length) {
      $('govEndpointBody').innerHTML = compliance.endpoints.map(ep => {
        const score = ep.compliance_score ?? ep.score ?? 0;
        const vCount = ep.violations?.length || 0;
        const epIdent = ep.method && ep.path ? `${ep.method} ${ep.path}` : (ep.identity ? ep.identity.split('@')[0].trim() : '');
        return `<tr>
          <td style="font-family:'JetBrains Mono';font-size:12px">#${ep.endpoint_id} <strong>${epIdent}</strong></td>
          <td><span style="color:${score >= 80 ? 'var(--green)' : score >= 50 ? 'var(--orange)' : 'var(--red)'};font-weight:700;font-family:'JetBrains Mono'">${score}%</span></td>
          <td>${vCount > 0 ? `<span style="color:var(--red)">${vCount} violation${vCount > 1 ? 's' : ''}</span>` : '<span style="color:var(--green)">none</span>'}</td>
          <td>${ep.violations?.length ? ep.violations.map(v => `<span class="chip" style="background:var(--red-glow);color:var(--red);margin:2px" title="${v.detail || ''}">${v.rule_name || v.rule_type || v.rule || (typeof v === 'string' ? v : 'violation')}</span>`).join(' ') : '<span style="color:var(--green);font-size:11px">✓ Compliant</span>'}</td>
        </tr>`;
      }).join('');
    } else {
      $('govEndpointBody').innerHTML = '<tr><td colspan="4" class="empty-state">No endpoint compliance data. Seed and sync first.</td></tr>';
    }
  } catch (e) { toast(e.message, 'error'); }
}

// ═══════════════════════════════════════════════════════════════════════════
//  PAGE: REPORTS & ROI
// ═══════════════════════════════════════════════════════════════════════════

async function renderReportsPage() {
  $('pageContent').innerHTML = `
    <div style="display:flex;gap:8px;margin-bottom:16px">
      <button class="btn-primary btn-sm" id="genExecReport">Generate Executive Report</button>
      <button class="btn-primary btn-sm" id="genBoardReport">Generate Board Report</button>
    </div>
    <div class="grid">
      <div class="card s6" id="execReportCard">
        <div class="card-header"><h3>Executive Report</h3></div>
        <div id="execReportBody" style="color:var(--muted);font-size:13px">Click "Generate Executive Report" to load.</div>
      </div>
      <div class="card s6" id="roiCard">
        <div class="card-header"><h3>ROI & Risk Delta</h3></div>
        <div id="roiBody" style="color:var(--muted);font-size:13px">Click "Generate Board Report" to load.</div>
      </div>
    </div>
    <div class="card" style="margin-top:14px;display:none" id="boardFullCard">
      <div class="card-header"><h3>Full Board Report</h3></div>
      <div id="boardFullBody"></div>
    </div>`;

  $('genExecReport').addEventListener('click', withBtn($('genExecReport'), 'Generating...', async () => {
    const r = await api.execReport();
    $('execReportBody').innerHTML = `
      <div class="metrics" style="grid-template-columns:repeat(3,1fr);margin-bottom:12px">
        <div class="metric m-blue"><h4>Total Endpoints</h4><div class="value">${r.totals.endpoints}</div></div>
        <div class="metric m-red"><h4>High/Critical</h4><div class="value">${r.totals.high_or_critical}</div></div>
        <div class="metric m-green"><h4>Quarantined</h4><div class="value">${r.totals.quarantined}</div></div>
      </div>
      <div class="detail-section">
        <h4>Lifecycle Breakdown</h4>
        ${Object.entries(r.lifecycle_breakdown || {}).map(([k, v]) => `<div style="display:flex;justify-content:space-between;padding:4px 0;font-size:13px"><span>${stateChip(k)}</span><span style="font-family:'JetBrains Mono';font-weight:700">${v}</span></div>`).join('')}
      </div>
      <div class="detail-section">
        <h4>Severity Breakdown</h4>
        ${Object.entries(r.severity_breakdown || {}).map(([k, v]) => `<div style="display:flex;justify-content:space-between;padding:4px 0;font-size:13px"><span class="sev-${k}">${k}</span><span style="font-family:'JetBrains Mono';font-weight:700">${v}</span></div>`).join('')}
      </div>
      <div class="detail-section">
        <h4>Top Risks</h4>
        ${(r.top_risks || []).map((tr, i) => `<div style="padding:6px 0;border-bottom:1px solid var(--border);font-size:12px"><strong style="color:var(--red)">#${i + 1}</strong> ${tr.identity} — <span class="sev-${tr.severity}">${tr.risk_score} (${tr.severity})</span></div>`).join('')}
      </div>
      <div class="detail-section">
        <h4>Remediation Summary</h4>
        ${Object.entries(r.remediation_summary || {}).map(([k, v]) => `<div style="display:flex;justify-content:space-between;padding:4px 0;font-size:13px"><span>${statusChip(k)}</span><span style="font-family:'JetBrains Mono'">${v}</span></div>`).join('') || '<span style="color:var(--dim)">No actions taken yet.</span>'}
      </div>
      <div style="font-size:10px;color:var(--dim);margin-top:8px">Generated: ${fmtDate(r.generated_at)} by ${r.generated_by}</div>`;
    toast('Executive report generated', 'success');
  }));

  $('genBoardReport').addEventListener('click', withBtn($('genBoardReport'), 'Generating...', async () => {
    const b = await api.boardReport();
    const roi = b.roi_estimate;
    const rd = b.risk_delta;

    $('roiBody').innerHTML = `
      <div style="font-size:13px;margin-bottom:8px"><strong>Risk Delta:</strong> Baseline <span style="color:var(--orange);font-family:'JetBrains Mono'">${rd.baseline_avg_score}</span> → Current <span style="color:var(--green);font-family:'JetBrains Mono'">${rd.current_avg_score}</span> <span style="color:${rd.percentage_drop > 0 ? 'var(--green)' : 'var(--dim)'}">${rd.percentage_drop > 0 ? '↓' + rd.percentage_drop.toFixed(1) + '%' : ''}</span></div>
      <div style="font-size:11px;color:var(--muted);margin-bottom:10px">Zombie APIs Found: <strong style="color:var(--red)">${roi.zombie_apis_found || 0}</strong> | Quarantined: <strong style="color:var(--green)">${roi.endpoints_quarantined || 0}</strong></div>
      <div class="roi-grid">
        <div class="roi-item"><div class="amount" style="color:var(--red)">${fmtINR(roi.direct_loss_exposure_inr)}</div><div class="label">Direct Loss Exposure</div></div>
        <div class="roi-item"><div class="amount" style="color:var(--orange)">${fmtINR(roi.regulatory_fine_exposure_inr)}</div><div class="label">RBI Fine Risk</div></div>
        <div class="roi-item"><div class="amount" style="color:var(--purple)">${fmtINR(roi.reputation_damage_exposure_inr)}</div><div class="label">Reputation Damage</div></div>
      </div>
      <div class="roi-grid" style="margin-top:8px">
        <div class="roi-item"><div class="amount" style="color:var(--green)">${fmtINR(roi.direct_loss_avoided_inr)}</div><div class="label">Direct Loss Avoided</div></div>
        <div class="roi-item"><div class="amount" style="color:var(--green)">${fmtINR(roi.regulatory_fine_avoided_inr)}</div><div class="label">Regulatory Fine Avoided</div></div>
        <div class="roi-item"><div class="amount" style="color:var(--green)">${fmtINR(roi.reputation_damage_avoided_inr)}</div><div class="label">Reputation Damage Avoided</div></div>
      </div>
      <div class="roi-total">
        <div style="font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:4px">Total Risk Mitigated by API Sentinel</div>
        <div class="amount">${fmtINR(roi.estimated_avoided_loss_inr)}</div>
        <div style="font-size:11px;color:var(--dim);margin-top:4px">${roi.assumption || ''}</div>
      </div>`;

    // Full board report
    $('boardFullCard').style.display = 'block';
    $('boardFullBody').innerHTML = `
      <div style="font-size:14px;font-weight:600;margin-bottom:8px">Executive Summary</div>
      <p style="font-size:13px;color:var(--muted);margin-bottom:14px">${b.executive_summary}</p>
      <div class="metrics" style="grid-template-columns:repeat(3,1fr);margin-bottom:14px">
        <div class="metric m-blue"><h4>Total Endpoints</h4><div class="value">${b.kpis.total_endpoints}</div></div>
        <div class="metric m-red"><h4>High/Critical</h4><div class="value">${b.kpis.high_or_critical}</div></div>
        <div class="metric m-green"><h4>Quarantined</h4><div class="value">${b.kpis.quarantined}</div></div>
      </div>
      <div class="detail-section">
        <h4>Recent Remediation Actions</h4>
        ${(b.top_actions || []).length ? b.top_actions.map(a => `<div style="padding:6px 0;border-bottom:1px solid var(--border);font-size:12px">${statusChip(a.status)} <strong>${a.type}</strong> by ${a.requested_by} ${a.executed_at ? '· ' + fmtDate(a.executed_at) : ''}</div>`).join('') : '<span style="color:var(--dim)">No recent actions.</span>'}
      </div>
      <div style="font-size:10px;color:var(--dim);margin-top:10px">Generated: ${fmtDate(b.generated_at)} by ${b.generated_by}</div>`;

    toast('Board report generated', 'success');
  }));
}

// ═══════════════════════════════════════════════════════════════════════════
//  PAGE: AUDIT TRAIL
// ═══════════════════════════════════════════════════════════════════════════

async function renderAuditPage() {
  $('pageContent').innerHTML = `
    <div style="display:flex;gap:10px;margin-bottom:14px;align-items:center;flex-wrap:wrap">
      <div class="search-bar" style="flex:1;min-width:200px"><input type="text" id="auditSearch" placeholder="Search events..." /></div>
      <button class="btn-secondary btn-sm" id="auditSearchBtn">Search</button>
    </div>
    <div class="card">
      <div class="card-header"><h3>Audit Events</h3><span style="font-size:11px;color:var(--dim)" id="auditCount">-</span></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>ID</th><th>Timestamp</th><th>Event Type</th><th>Entity</th><th>Actor</th><th>Signature</th><th>Details</th></tr></thead>
          <tbody id="auditTableBody"><tr><td colspan="7" style="color:var(--muted)">Loading...</td></tr></tbody>
        </table>
      </div>
    </div>`;

  const loadAudit = async () => {
    const q = $('auditSearch').value;
    let params = '';
    if (q) params += `&q=${encodeURIComponent(q)}`;
    try {
      const events = await api.audit(params);
      const tb = $('auditTableBody');
      $('auditCount').textContent = `${events.length} events`;
      if (!events.length) { tb.innerHTML = '<tr><td colspan="7" class="empty-state">No audit events found.</td></tr>'; return; }
      tb.innerHTML = events.map(e => `
        <tr>
          <td style="font-family:'JetBrains Mono';font-size:11px">${e.id}</td>
          <td style="font-size:12px">${fmtDate(e.timestamp)}</td>
          <td style="font-weight:600;font-size:12px">${e.event_type}</td>
          <td style="font-family:'JetBrains Mono';font-size:11px">${e.entity_type}:${e.entity_id}</td>
          <td style="font-size:12px">${e.actor}</td>
          <td style="font-family:'JetBrains Mono';font-size:10px;color:var(--cyan);max-width:120px;overflow:hidden;text-overflow:ellipsis" title="${e.signature}">${e.signature?.slice(0, 16)}...</td>
          <td><button class="btn-sm btn-secondary" onclick='showAuditDetail(${JSON.stringify(e).replace(/'/g, "\\'")})'>View</button></td>
        </tr>`).join('');
    } catch (e) { toast(e.message, 'error'); }
  };

  $('auditSearchBtn').addEventListener('click', loadAudit);
  $('auditSearch').addEventListener('keydown', e => { if (e.key === 'Enter') loadAudit(); });
  loadAudit();
}

function showAuditDetail(event) {
  openModal(`Audit Event #${event.id}`, `${event.event_type} · ${event.entity_type}:${event.entity_id}`, `
    <div class="modal-grid">
      <div class="modal-stat"><label>Actor</label><div class="val" style="font-size:14px">${event.actor}</div></div>
      <div class="modal-stat"><label>Timestamp</label><div class="val" style="font-size:14px">${fmtDate(event.timestamp)}</div></div>
    </div>
    <div class="detail-section">
      <h4>SHA-256 Signature</h4>
      <div style="font-family:'JetBrains Mono';font-size:11px;color:var(--cyan);word-break:break-all">${event.signature}</div>
    </div>
    <div class="detail-section">
      <h4>Before State</h4>
      <pre style="font-size:11px;font-family:'JetBrains Mono';color:var(--orange);white-space:pre-wrap">${JSON.stringify(event.before, null, 2)}</pre>
    </div>
    <div class="detail-section">
      <h4>After State</h4>
      <pre style="font-size:11px;font-family:'JetBrains Mono';color:var(--green);white-space:pre-wrap">${JSON.stringify(event.after, null, 2)}</pre>
    </div>`);
}

// ═══════════════════════════════════════════════════════════════════════════
//  PAGE: ARCHITECTURE
// ═══════════════════════════════════════════════════════════════════════════

async function renderArchitecturePage() {
  $('pageContent').innerHTML = '<div style="text-align:center;padding:40px;color:var(--muted)">Loading architecture...</div>';
  try {
    const arch = await api.architecture();
    let h = `
      <div style="text-align:center;margin-bottom:20px">
        <h2 style="font-size:20px;font-weight:800;background:var(--gradient);-webkit-background-clip:text;-webkit-text-fill-color:transparent">${arch.platform}</h2>
        <p style="font-size:13px;color:var(--muted);margin-top:4px">${arch.description}</p>
      </div>`;

    // Architecture layers
    for (const layer of arch.layers) {
      h += `<div class="card" style="margin-bottom:12px;border-left:3px solid ${layer.color}">
        <div class="card-header"><h3 style="color:${layer.color}">${layer.name}</h3></div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px">`;
      for (const comp of layer.components) {
        h += `<div style="background:var(--surface2);border-radius:8px;padding:10px;border:1px solid var(--border)">
          <div style="font-size:13px;font-weight:600">${comp.icon || '⚙️'} ${comp.name}</div>
          <div style="font-size:11px;color:var(--dim);margin-top:3px">${comp.desc || comp.protocol || comp.type}</div>
        </div>`;
      }
      h += `</div></div>`;
    }

    // Tech stack
    h += `<div class="grid" style="margin-top:14px">
      <div class="card s6">
        <div class="card-header"><h3>Tech Stack</h3></div>
        ${Object.entries(arch.tech_stack).map(([k, v]) => `
          <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);font-size:13px">
            <span style="color:var(--muted);text-transform:capitalize">${k.replace(/_/g, ' ')}</span>
            <span style="font-family:'JetBrains Mono';font-size:11px">${v}</span>
          </div>`).join('')}
      </div>
      <div class="card s6">
        <div class="card-header"><h3>Platform Stats</h3></div>
        <div class="metrics" style="grid-template-columns:repeat(2,1fr)">
          <div class="metric m-blue"><h4>API Routes</h4><div class="value">${arch.api_stats.total_routes}</div></div>
          <div class="metric m-purple"><h4>Models</h4><div class="value">${arch.api_stats.models}</div></div>
          <div class="metric m-green"><h4>Tests</h4><div class="value">${arch.api_stats.test_cases}</div></div>
          <div class="metric m-cyan"><h4>Lines of Code</h4><div class="value" style="font-size:18px">${arch.api_stats.lines_of_code}</div></div>
        </div>
        <div style="margin-top:14px">
          <button class="btn-primary btn-sm" id="runBenchmark">Run Performance Benchmark</button>
          <div id="benchmarkResult" style="margin-top:8px"></div>
        </div>
      </div>
    </div>`;

    $('pageContent').innerHTML = h;

    // Benchmark button
    const benchBtn = $('runBenchmark');
    if (benchBtn) {
      benchBtn.addEventListener('click', withBtn(benchBtn, 'Running...', async () => {
        const b = await api.benchmark();
        $('benchmarkResult').innerHTML = `
          <div style="background:var(--surface2);border-radius:8px;padding:10px;border:1px solid var(--border);font-size:12px">
            <div style="margin-bottom:6px;font-weight:700;color:var(--green)">Performance Results</div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:4px">
              <div>DB Read: <strong style="font-family:'JetBrains Mono'">${b.benchmark.db_read_avg_ms}ms</strong></div>
              <div>Risk Compute: <strong style="font-family:'JetBrains Mono'">${b.benchmark.risk_compute_avg_ms}ms</strong></div>
              <div>Compliance: <strong style="font-family:'JetBrains Mono'">${b.benchmark.compliance_eval_avg_ms}ms</strong></div>
              <div>Endpoints: <strong style="font-family:'JetBrains Mono'">${b.benchmark.current_endpoints}</strong></div>
            </div>
            <div style="margin-top:6px;color:var(--cyan);font-size:11px">
              Throughput: ${b.capacity.api_throughput} | ${b.capacity.risk_throughput} | Max: ${b.capacity.max_endpoints_supported}
            </div>
          </div>`;
        toast('Benchmark complete', 'success');
      }));
    }
  } catch (e) { $('pageContent').innerHTML = `<div class="empty-state"><p>Error: ${e.message}</p></div>`; }
}

// ═══════════════════════════════════════════════════════════════════════════
//  90-SECOND AUTO-DEMO
// ═══════════════════════════════════════════════════════════════════════════
let demoRunning = false, demoAbort = false;

const DEMO_STEPS = [
  { duration: 4000, page: 'dashboard', narration: "🚨 ALERT: We just found 4 zombie APIs in your bank — unauthenticated, undocumented, handling HIGH-SENSITIVITY customer data with ZERO encryption. One is an active wire-transfer endpoint. Estimated exposure: ₹38 LAKH in regulatory fines alone. Let's fix this in 90 seconds." },
  { duration: 10000, page: 'dashboard', narration: "STEP 1: DISCOVERY — API Sentinel seeds your infrastructure. 5 connectors pull data from API Gateway, Code Repos, SIEM, Network traffic, and K8s clusters...", action: async () => {
    currentDashboardSource = 'banking';
    await api.seed();
    toast('Infrastructure scanned: 16+ APIs discovered', 'success');
  } },
  { duration: 12000, page: 'connectors', narration: "STEP 2: MULTI-SOURCE CORRELATION — Cross-referencing gateway traffic with code specs and SIEM alerts. Watch each connector sync in real-time...", action: async () => {
    for (const [name, fn] of [['Kong', api.syncKong], ['GitHub', api.syncGithub], ['Splunk', api.syncSplunk], ['Network', api.syncNetwork], ['K8s', api.syncK8s]]) {
      await fn(); toast(`${name} sync complete`, 'success');
    }
  }},
  { duration: 6000, page: 'endpoints', narration: "STEP 3: RISK SCORING — Each endpoint scored on 7 factors: exposure, authentication, data sensitivity, rate limiting, encryption (TLS), lifecycle state, and threat signals." },
  { duration: 5000, page: 'endpoints', narration: "STEP 4: THREAT DETECTED — Opening a zombie API with NO auth, exposing high-sensitivity customer data. Risk: CRITICAL.", action: async () => {
    const eps = await api.endpoints();
    cachedEndpoints = eps;
    const zombie = eps.find(e => e.lifecycle_state === 'zombie' && e.risk_severity === 'critical') || eps.find(e => e.lifecycle_state === 'zombie') || eps[0];
    if (zombie) showEndpointDetail(zombie);
  }},
  { duration: 14000, page: 'remediation', narration: "STEP 5: REMEDIATION — Policy-governed workflow: Request → Simulate blast radius → Dual-approval → Execute containment. No single person can act alone.", action: async () => {
    closeModal();
    const eps = await api.endpoints();
    const target = eps.filter(e => ['high', 'critical'].includes((e.risk_severity || '').toLowerCase()) && !e.is_quarantined).sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))[0];
    if (target) {
      const a = await api.createAction(target.id);
      toast('Quarantine requested', 'info');
      await api.simulateAction(a.id);
      toast('Blast radius simulated', 'info');
      await api.approveAction(a.id);
      toast('Dual-approval granted', 'info');
      await api.executeAction(a.id);
      toast(`Endpoint ${target.id} QUARANTINED`, 'success');
    }
  }},
  { duration: 14000, page: 'cases', narration: "STEP 6: AI INVESTIGATION — Creating investigation case with AI-powered analysis. The system generates a remediation playbook with prioritized steps...", action: async () => {
    const eps = await api.endpoints();
    const target = eps.filter(e => ['high', 'critical'].includes((e.risk_severity || '').toLowerCase())).sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))[0];
    if (target) {
      const c = await api.createCase(target.id, 'Zombie API Investigation', 'critical', 'Auto-triggered by threat detection');
      toast(`Case #${c.id} created`, 'info');
      await api.summarizeCase(c.id);
      toast('AI analysis complete', 'success');
    }
  }},
  { duration: 8000, page: 'reports', narration: "STEP 7: BOARD REPORT — Real-time ROI: Direct loss prevented + RBI regulatory fine avoided + reputation damage mitigated. Concrete numbers for the board.", action: async () => {
    const btn = $('genBoardReport');
    if (btn) btn.click();
  }},
  { duration: 6000, page: 'governance', narration: "STEP 8: GOVERNANCE — Continuous compliance monitoring. 6 governance rules enforce auth, TLS, ownership, rate limiting, documentation, and threat-clear requirements." },
  { duration: 4000, page: 'architecture', narration: "STEP 9: ARCHITECTURE — 39 API routes, 20 data models, 5 connectors, on-premises AI, Docker-ready, RBAC + multi-tenant isolation. Production-ready for any PSU bank." },
  { duration: 4000, page: 'dashboard', narration: "✅ RESULT: In 90 seconds, API Sentinel discovered 4 zombie APIs, quarantined the #1 threat, generated an AI investigation, prevented ₹38L+ in potential losses, and enforced governance — all with a cryptographic audit trail. Your bank is now protected." },
];

async function runDemo() {
  if (demoRunning) return;
  demoRunning = true; demoAbort = false;
  const bar = $('narrationBar');
  bar.classList.add('active');

  const totalDuration = DEMO_STEPS.reduce((s, step) => s + step.duration, 0);
  let elapsed = 0;

  for (let i = 0; i < DEMO_STEPS.length; i++) {
    if (demoAbort) break;
    const step = DEMO_STEPS[i];
    $('stepIndicator').textContent = `${i + 1}/${DEMO_STEPS.length}`;

    // Navigate to target page
    if (step.page) navigate(step.page);

    // Wait a beat for page to render
    await new Promise(r => setTimeout(r, 300));

    // Typewriter narration
    const narEl = $('narrationText');
    narEl.textContent = '';
    const text = step.narration;
    let charIdx = 0;
    const typeSpeed = Math.max(15, Math.min(40, step.duration / text.length * 0.6));
    const typePromise = new Promise(resolve => {
      const iv = setInterval(() => {
        if (demoAbort || charIdx >= text.length) { clearInterval(iv); resolve(); return; }
        narEl.textContent += text[charIdx++];
      }, typeSpeed);
    });

    // Run action in parallel
    if (step.action) {
      step.action().then(() => {
        // Reload current page to show results
        if (!demoAbort) router.reload();
      }).catch(() => {});
    }

    await new Promise(resolve => {
      const timer = setTimeout(resolve, step.duration);
      const checkAbort = setInterval(() => { if (demoAbort) { clearTimeout(timer); clearInterval(checkAbort); resolve(); } }, 100);
    });
    await typePromise;

    elapsed += step.duration;
    const remaining = Math.max(0, Math.ceil((totalDuration - elapsed) / 1000));
    $('demoTimer').textContent = remaining + 's';
    $('progressFill').style.width = Math.round((elapsed / totalDuration) * 100) + '%';
  }

  bar.classList.remove('active');
  demoRunning = false;
  if (!demoAbort) toast('Demo complete! Explore all pages.', 'success');
}

$('demoBtn').addEventListener('click', () => { if (!demoRunning) runDemo(); });
$('stopDemo').addEventListener('click', () => { demoAbort = true; });

// ═══════════════════════════════════════════════════════════════════════════
//  INITIAL LOAD
// ═══════════════════════════════════════════════════════════════════════════
const startPage = window.location.hash.replace('#', '') || 'dashboard';
navigate(startPage);
