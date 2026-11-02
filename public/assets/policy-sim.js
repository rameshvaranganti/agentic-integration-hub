/* Agent Policy Simulator — runs entirely in the browser. Nothing is sent to a server. */
(function () {
  'use strict';
  const $ = (s, r) => (r || document).querySelector(s);
  const root = $('#policySim');
  if (!root) return;

  /* ---------------- default policy ---------------- */
  const DEFAULT_POLICY = {
    policy: 'enterprise-agents-demo',
    version: '1.0',
    default: 'deny',
    tools: {
      get_invoice: { kind: 'read' },
      create_payment_request: { kind: 'write' },
      get_purchase_order: { kind: 'read' },
      get_goods_receipts: { kind: 'read' },
      post_goods_receipt: { kind: 'write' },
      get_leave_balance: { kind: 'read' },
      get_salary: { kind: 'read' },
      update_employee: { kind: 'write' },
      confirm_delivery: { kind: 'read' }
    },
    agents: {
      'finance-agent': { tools: ['get_invoice', 'create_payment_request'] },
      'procurement-agent': { tools: ['get_purchase_order', 'get_goods_receipts', 'post_goods_receipt'] },
      'hr-assistant': { tools: ['get_leave_balance'] },
      'partner-agent': { tools: ['confirm_delivery'], external: true }
    },
    rules: [
      { id: 'R1', effect: 'deny', when: { calls_per_minute: { '>': 20 } }, reason: 'More than 20 calls per minute. Possible loop or runaway agent.', alert: true },
      { id: 'R2', effect: 'deny', when: { delegation_depth: { '>': 2 } }, reason: 'Delegation chain is deeper than 2 agent hops.' },
      { id: 'R3', effect: 'deny', when: { 'agent.external': true, agent_card_signed: false }, reason: 'External agent without a verified, signed Agent Card.', alert: true },
      { id: 'R4', effect: 'deny', when: { 'tool.kind': 'write', instruction_source: { in: ['document', 'tool_output', 'partner_message'] } }, reason: 'A write action was triggered by instructions found in content the agent read, not by the user. Treated as possible prompt injection.', alert: true },
      { id: 'P1', effect: 'deny', when: { tool: 'create_payment_request', 'user.role': { not_in: ['ap_clerk', 'ap_manager'] } }, reason: 'Only accounts-payable roles may request payments.' },
      { id: 'P2', effect: 'deny', when: { tool: 'create_payment_request', 'supplier.status': 'blocked' }, reason: 'Supplier is blocked for payment.' },
      { id: 'P3', effect: 'deny', when: { tool: 'create_payment_request', bank_changed_days: { '<': 30 } }, reason: 'Supplier bank details changed in the last 30 days. Route to master-data verification.', alert: true },
      { id: 'P4', effect: 'deny', when: { tool: 'create_payment_request', po_match: false }, reason: 'Invoice has no three-way match with purchase order and goods receipt.' },
      { id: 'P5', effect: 'approve', when: { tool: 'create_payment_request', amount: { '>': 10000 } }, approver: 'ap_manager (not the requester)', reason: 'Payments above 10,000 need four-eyes approval.' },
      { id: 'P6', effect: 'allow', when: { tool: 'create_payment_request', amount: { '<=': 10000 } }, reason: 'Matched payment within the agent\'s limit.' },
      { id: 'H1', effect: 'deny', when: { tool: { in: ['get_leave_balance', 'get_salary', 'update_employee'] }, target: 'other_employee' }, reason: 'Employee data: only the signed-in user or their direct reports.' },
      { id: 'G1', effect: 'approve', when: { tool: 'post_goods_receipt' }, approver: 'warehouse_user', reason: 'Inventory postings need confirmation by a warehouse user.' },
      { id: 'A1', effect: 'allow', when: { 'tool.kind': 'read' }, reason: 'Read-only tool within the agent\'s scope.' }
    ]
  };

  /* ---------------- scenarios ---------------- */
  const BASE = { agent: 'finance-agent', 'user.role': 'ap_clerk', tool: 'create_payment_request', instruction_source: 'user', amount: 4200, 'supplier.status': 'active', bank_changed_days: 400, po_match: true, target: 'self', delegation_depth: 1, calls_per_minute: 3, agent_card_signed: true };
  const SCENARIOS = [
    { name: 'Small matched payment', expect: 'allow', req: {} },
    { name: 'Large payment', expect: 'approve', req: { amount: 48000 } },
    { name: 'Wrong agent pays', expect: 'deny', req: { agent: 'procurement-agent', 'user.role': 'buyer' } },
    { name: 'Bank-detail fraud', expect: 'deny', req: { amount: 9800, bank_changed_days: 6 } },
    { name: 'Prompt injection', expect: 'deny', req: { instruction_source: 'document', amount: 2500 } },
    { name: 'Own leave balance', expect: 'allow', req: { agent: 'hr-assistant', 'user.role': 'employee', tool: 'get_leave_balance', target: 'self' } },
    { name: 'Colleague\'s leave', expect: 'deny', req: { agent: 'hr-assistant', 'user.role': 'employee', tool: 'get_leave_balance', target: 'other_employee' } },
    { name: 'Salary via HR agent', expect: 'deny', req: { agent: 'hr-assistant', 'user.role': 'employee', tool: 'get_salary', target: 'self' } },
    { name: 'Goods receipt posting', expect: 'approve', req: { agent: 'procurement-agent', 'user.role': 'buyer', tool: 'post_goods_receipt' } },
    { name: 'Unsigned partner agent', expect: 'deny', req: { agent: 'partner-agent', 'user.role': 'buyer', tool: 'confirm_delivery', agent_card_signed: false } },
    { name: 'Runaway loop', expect: 'deny', req: { agent: 'procurement-agent', 'user.role': 'buyer', tool: 'get_purchase_order', calls_per_minute: 45 } },
    { name: 'Deep delegation', expect: 'deny', req: { agent: 'procurement-agent', 'user.role': 'buyer', tool: 'get_goods_receipts', delegation_depth: 4 } }
  ];

  const ROLES = ['ap_clerk', 'ap_manager', 'buyer', 'warehouse_user', 'employee', 'hr_partner'];
  const SOURCES = { user: 'The user asked for it', document: 'Text in a document the agent read', tool_output: 'Output of another tool', partner_message: 'Message from a partner agent' };
  const TARGETS = { self: 'The signed-in user', direct_report: 'A direct report', other_employee: 'Another employee' };

  let policy = clone(DEFAULT_POLICY);
  function clone(o) { return JSON.parse(JSON.stringify(o)); }
  function esc(s) { return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

  /* ---------------- engine ---------------- */
  function fieldValue(req, path) {
    if (path === 'agent.external') { const a = policy.agents[req.agent]; return !!(a && a.external); }
    if (path === 'tool.kind') { const t = policy.tools[req.tool]; return t ? t.kind : undefined; }
    return req[path];
  }
  function test(actual, cond) {
    if (cond === null || typeof cond !== 'object' || Array.isArray(cond)) return actual === cond;
    return Object.keys(cond).every(op => {
      const v = cond[op];
      switch (op) {
        case '>': return typeof actual === 'number' && actual > v;
        case '>=': return typeof actual === 'number' && actual >= v;
        case '<': return typeof actual === 'number' && actual < v;
        case '<=': return typeof actual === 'number' && actual <= v;
        case '!=': return actual !== v;
        case 'in': return Array.isArray(v) && v.includes(actual);
        case 'not_in': return Array.isArray(v) && !v.includes(actual);
        default: throw new Error('Unknown operator "' + op + '"');
      }
    });
  }
  function evaluate(req) {
    const trace = [];
    const agentDef = policy.agents[req.agent];
    if (!agentDef) {
      trace.push({ id: 'S0', effect: 'deny', matched: true, reason: 'Agent is not registered in the policy.' });
      return { decision: 'deny', matched: [trace[0]], trace, alert: true };
    }
    const inScope = Array.isArray(agentDef.tools) && agentDef.tools.includes(req.tool);
    trace.push({ id: 'S0', effect: 'scope', matched: !inScope, reason: inScope ? 'Tool is in this agent\'s allow-list.' : 'Tool is not in this agent\'s allow-list, so it is filtered out of tools/list and the call is refused.' });
    if (!inScope) return { decision: 'deny', matched: [{ id: 'S0', effect: 'deny', reason: trace[0].reason }], trace, alert: false };
    const matched = [];
    (policy.rules || []).forEach(r => {
      const when = r.when || {};
      const hit = Object.keys(when).every(k => test(fieldValue(req, k), when[k]));
      trace.push({ id: r.id, effect: r.effect, matched: hit, reason: r.reason });
      if (hit) matched.push(r);
    });
    const by = e => matched.filter(r => r.effect === e);
    let decision, winners;
    if (by('deny').length) { decision = 'deny'; winners = by('deny'); }
    else if (by('approve').length) { decision = 'approve'; winners = by('approve'); }
    else if (by('allow').length) { decision = 'allow'; winners = by('allow'); }
    else { decision = policy.default === 'allow' ? 'allow' : 'deny'; winners = [{ id: 'DEFAULT', effect: decision, reason: 'No rule matched, so the policy default (' + (policy.default || 'deny') + ') applies.' }]; }
    return { decision, matched: winners, trace, alert: winners.some(r => r.alert) };
  }

  /* ---------------- UI ---------------- */
  const form = $('#psForm');
  const els = {
    agent: $('#psAgent'), role: $('#psRole'), tool: $('#psTool'), source: $('#psSource'),
    amount: $('#psAmount'), supplier: $('#psSupplier'), bank: $('#psBank'), po: $('#psPo'),
    target: $('#psTarget'), depth: $('#psDepth'), cpm: $('#psCpm'), signed: $('#psSigned'),
    out: $('#psResult'), traceBody: $('#psTrace'), audit: $('#psAudit'), editor: $('#psPolicy'), polMsg: $('#psPolicyMsg'),
    presets: $('#psPresets')
  };
  function fill(sel, values, labels) {
    const cur = sel.value;
    sel.innerHTML = values.map(v => '<option value="' + esc(v) + '">' + esc(labels ? labels[v] : v) + '</option>').join('');
    if (values.includes(cur)) sel.value = cur;
  }
  function populate() {
    fill(els.agent, Object.keys(policy.agents));
    fill(els.tool, Object.keys(policy.tools));
    fill(els.role, ROLES);
    fill(els.source, Object.keys(SOURCES), SOURCES);
    fill(els.target, Object.keys(TARGETS), TARGETS);
  }
  function setReq(r) {
    const v = Object.assign({}, BASE, r);
    if (policy.agents[v.agent]) els.agent.value = v.agent;
    if (policy.tools[v.tool]) els.tool.value = v.tool;
    els.role.value = v['user.role']; els.source.value = v.instruction_source;
    els.amount.value = v.amount; els.supplier.value = v['supplier.status']; els.bank.value = v.bank_changed_days;
    els.po.checked = !!v.po_match; els.target.value = v.target; els.depth.value = v.delegation_depth;
    els.cpm.value = v.calls_per_minute; els.signed.checked = !!v.agent_card_signed;
  }
  function getReq() {
    return {
      agent: els.agent.value, 'user.role': els.role.value, tool: els.tool.value, instruction_source: els.source.value,
      amount: Number(els.amount.value), 'supplier.status': els.supplier.value, bank_changed_days: Number(els.bank.value),
      po_match: els.po.checked, target: els.target.value, delegation_depth: Number(els.depth.value),
      calls_per_minute: Number(els.cpm.value), agent_card_signed: els.signed.checked
    };
  }
  function toggleGroups(req) {
    const pay = req.tool === 'create_payment_request';
    const hr = ['get_leave_balance', 'get_salary', 'update_employee'].includes(req.tool);
    const ext = !!(policy.agents[req.agent] && policy.agents[req.agent].external);
    root.querySelectorAll('[data-show=pay]').forEach(e => { e.hidden = !pay; });
    root.querySelectorAll('[data-show=hr]').forEach(e => { e.hidden = !hr; });
    root.querySelectorAll('[data-show=ext]').forEach(e => { e.hidden = !ext; });
  }
  const LABEL = { allow: 'Allow', deny: 'Deny', approve: 'Approval required' };
  const NEXT = {
    allow: 'The gateway forwards the call to the managed API or integration flow. The downstream API and system of record still apply their own authorization.',
    approve: 'The call is paused. An approval request with the evidence and trace goes to the approver; if nobody responds within 24 hours it escalates. It never defaults to approve.',
    deny: 'The call is refused and the agent receives a structured error it can explain to the user. The attempt is logged with its trace ID.'
  };
  function traceId() { const a = new Uint8Array(6); (window.crypto || window.msCrypto).getRandomValues(a); return Array.from(a, b => b.toString(16).padStart(2, '0')).join(''); }
  function argsSummary(req) {
    if (req.tool === 'create_payment_request') return { amount: req.amount, supplier_status: req['supplier.status'], po_match: req.po_match, bank_changed_days: req.bank_changed_days };
    if (['get_leave_balance', 'get_salary', 'update_employee'].includes(req.tool)) return { target: req.target };
    return {};
  }
  function render() {
    const req = getReq();
    toggleGroups(req);
    let res;
    try { res = evaluate(req); } catch (e) { els.out.innerHTML = '<p class="ps-err">Policy error: ' + esc(e.message) + '</p>'; return; }
    const d = res.decision;
    const rules = res.matched.map(r => '<li><code>' + esc(r.id) + '</code> ' + esc(r.reason || '') + (r.approver ? ' <span class="small">Approver: ' + esc(r.approver) + '</span>' : '') + '</li>').join('');
    els.out.innerHTML =
      '<div class="ps-decision ' + d + '"><span class="ps-badge">' + LABEL[d] + (res.alert ? ' + security alert' : '') + '</span>' +
      '<span class="ps-who"><b>' + esc(req.agent) + '</b> → <code>' + esc(req.tool) + '</code> for <b>' + esc(req['user.role']) + '</b></span></div>' +
      '<h3 class="ps-h">Why</h3><ul class="ps-why">' + rules + '</ul>' +
      '<h3 class="ps-h">What happens next</h3><p class="ps-next">' + NEXT[d] + (res.alert ? ' A security alert is raised for review.' : '') + '</p>' +
      '<p class="small ps-enf">Decided by the policy engine at the MCP / A2A gateway; re-checked downstream by API management and the system of record.</p>';
    els.traceBody.innerHTML = res.trace.map(t => {
      const cls = t.effect === 'scope' ? (t.matched ? 'deny' : 'allow') : t.effect;
      const status = t.effect === 'scope' ? (t.matched ? 'out of scope' : 'in scope') : (t.matched ? 'matched' : '–');
      return '<tr class="' + (t.matched ? 'hit' : '') + '"><td><code>' + esc(t.id) + '</code></td><td><span class="dec ' + cls + '">' + esc(t.effect) + '</span></td><td>' + esc(status) + '</td><td>' + esc(t.reason || '') + '</td></tr>';
    }).join('');
    const audit = {
      trace_id: traceId(), timestamp: new Date().toISOString(), policy: policy.policy + '@' + (policy.version || '1'),
      user_role: req['user.role'], agent: req.agent, tool: req.tool, args: argsSummary(req), instruction_source: req.instruction_source,
      delegation_depth: req.delegation_depth, decision: d, rules: res.matched.map(r => r.id),
      approver: (res.matched.find(r => r.approver) || {}).approver || null, alert: res.alert
    };
    els.audit.textContent = JSON.stringify(audit, null, 2);
  }

  function markPreset(i) { els.presets.querySelectorAll('button').forEach((b, j) => b.setAttribute('aria-pressed', String(i === j))); }
  els.presets.innerHTML = SCENARIOS.map((s, i) => '<button type="button" class="ps-preset" aria-pressed="false" data-i="' + i + '">' + esc(s.name) + '<span class="dec ' + s.expect + '">' + LABEL[s.expect].replace(' required', '') + '</span></button>').join('');
  els.presets.addEventListener('click', e => {
    const b = e.target.closest('button[data-i]'); if (!b) return;
    const i = Number(b.dataset.i); setReq(SCENARIOS[i].req); markPreset(i); render();
  });
  form.addEventListener('input', () => { markPreset(-1); render(); });
  form.addEventListener('change', () => { markPreset(-1); render(); });

  /* policy editor */
  function showPolicy() { els.editor.value = JSON.stringify(policy, null, 2); }
  $('#psApply').addEventListener('click', () => {
    try {
      const p = JSON.parse(els.editor.value);
      if (!p || typeof p !== 'object' || !p.agents || !p.tools || !Array.isArray(p.rules)) throw new Error('A policy needs "tools", "agents" and a "rules" array.');
      p.rules.forEach((r, i) => { if (!r.id || !['allow', 'deny', 'approve'].includes(r.effect)) throw new Error('Rule ' + (i + 1) + ' needs an "id" and an effect of allow, deny or approve.'); });
      policy = p; populate(); render();
      els.polMsg.textContent = 'Policy applied. The decision above now uses your rules.'; els.polMsg.className = 'small ps-ok';
    } catch (e) { els.polMsg.textContent = 'Could not apply: ' + e.message; els.polMsg.className = 'small ps-err'; }
  });
  $('#psReset').addEventListener('click', () => { policy = clone(DEFAULT_POLICY); populate(); showPolicy(); render(); els.polMsg.textContent = 'Default policy restored.'; els.polMsg.className = 'small ps-ok'; });
  $('#psCopyAudit').addEventListener('click', async () => { try { await navigator.clipboard.writeText(els.audit.textContent); $('#psCopyAudit').textContent = 'Copied'; } catch (e) { $('#psCopyAudit').textContent = 'Copy unavailable'; } });

  /* share link */
  $('#psShare').addEventListener('click', async () => {
    const q = new URLSearchParams(Object.entries(getReq()).map(([k, v]) => [k, String(v)]));
    const url = location.origin + location.pathname + '?' + q.toString();
    try { await navigator.clipboard.writeText(url); $('#psShare').textContent = 'Link copied'; } catch (e) { history.replaceState(null, '', url); $('#psShare').textContent = 'Link in address bar'; }
    setTimeout(() => { $('#psShare').textContent = 'Copy link to this scenario'; }, 2500);
  });
  function fromQuery() {
    const q = new URLSearchParams(location.search); if (!q.has('tool')) return null;
    const num = ['amount', 'bank_changed_days', 'delegation_depth', 'calls_per_minute'], bool = ['po_match', 'agent_card_signed'];
    const r = {}; q.forEach((v, k) => { if (!(k in BASE)) return; r[k] = num.includes(k) ? Number(v) : bool.includes(k) ? v === 'true' : v; });
    return r;
  }

  populate(); showPolicy();
  const shared = fromQuery();
  if (shared) { setReq(shared); markPreset(-1); } else { setReq(SCENARIOS[0].req); markPreset(0); }
  render();

})();
