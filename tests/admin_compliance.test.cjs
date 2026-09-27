const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const html = fs.readFileSync(path.join(__dirname, '../internal/api/web/index.html'), 'utf8');
const flush = () => new Promise(resolve => setImmediate(resolve));

function consoleUI() {
  const nodes = new Map();
  const session = new Map([['admin_token', 'token']]);
  const document = {
    activeElement: null,
    getElementById(id) { if (!nodes.has(id)) nodes.set(id, element(id)); return nodes.get(id); },
    createElement: element,
    querySelectorAll() { return []; }, querySelector() { return null; }
  };
  function element(id = '') {
    const classes = new Set();
    let markup = '';
    return {
      id, textContent: '', value: '', disabled: false, children: [], style: {}, validity: { valid: true },
      get innerHTML() { return markup; },
      set innerHTML(value) { markup = value; this.children = []; },
      classList: { add(name) { classes.add(name); }, remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); }, toggle() {} },
      appendChild(child) { this.children.push(child); }, addEventListener() {}, setAttribute() {}, removeAttribute() {},
      focus() { document.activeElement = this; }
    };
  }
  const context = vm.createContext({
    URLSearchParams, document,
    localStorage: { getItem() { return null; }, setItem() {} },
    sessionStorage: { getItem(key) { return session.get(key) || null; }, setItem(key, value) { session.set(key, value); }, removeItem(key) { session.delete(key); } },
    window: { addEventListener() {} },
    console: { error() {} }, setTimeout() {}, clearTimeout() {}, setInterval() {}, clearInterval() {}
  });
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], context);
  return { nodes, context, document, session, run(code) { return vm.runInContext(code, context); } };
}

const entry = (id = 'message-1') => ({ id, sender: 'urn:sender', recipient: 'urn:recipient',
  stored_at: 1700000000, expiry: 1700000001, policy_hash: 'policy-hash', policy_epoch: 3, content_type: 'application/json' });

test('compliance history has a direct navigation entry and reflects signed mode independently of legacy mode', async () => {
  const ui = consoleUI();
  assert.match(html, /id="complianceNav"[^>]*switchView\('compliance', this\)/);
  assert.match(html, /id="pane-compliance"/);
  ui.run(`state.latestOverview = {platform_mode:'compliance', v2_policy_mode:'private',
    compliance_retention_days:17, compliance_messages_count:2}; renderCompliancePolicyValues();
    apiCall = () => Promise.resolve({entries:[],total:0});
    switchView('compliance', document.getElementById('complianceNav'));`);
  await flush();
  assert.equal(ui.run('state.activeView'), 'compliance');
  assert.equal(ui.nodes.get('compliancePolicyMode').textContent, 'private');
  assert.equal(ui.nodes.get('complianceRetentionCurrent').textContent, '17 天');
  assert.equal(ui.nodes.get('complianceArchiveCount').textContent, 2);
  ui.run("state.latestOverview.v2_policy_mode=''; renderCompliancePolicyValues()");
  assert.equal(ui.nodes.get('compliancePolicyMode').textContent, '未启用 v2 签名策略');
  ui.run("state.lang='en'; renderCompliancePolicyValues()");
  assert.equal(ui.nodes.get('compliancePolicyMode').textContent, 'v2 signed policy disabled');
});

test('history uses exact server filters, metadata only, and bounded platform-wide pagination', async () => {
  const ui = consoleUI(); ui.context.entry = { ...entry(), plaintext: 'must-not-cache-this-body' };
  ui.context.calls = [];
  ui.run(`apiCall = (url, method, query) => {
    calls.push({url,method,query}); return Promise.resolve({entries:[entry],total:52,limit:25,offset:query.offset});
  };
  document.getElementById('complianceSender').value=' urn:SenderExact ';
  document.getElementById('complianceRecipient').value=' urn:ReceiverExact ';
  filterComplianceMessages({preventDefault(){}});`);
  await flush();
  assert.deepEqual(JSON.parse(JSON.stringify(ui.context.calls[0])), { url:'/api/v1/admin/compliance/messages', method:'GET',
    query:{sender:'urn:SenderExact',recipient:'urn:ReceiverExact',limit:25,offset:0} });
  assert.equal(ui.nodes.get('compliancePrevPage').disabled, true);
  assert.equal(ui.nodes.get('complianceNextPage').disabled, false);
  assert.match(ui.nodes.get('complianceTableBody').children[0].innerHTML, /message-1[\s\S]*urn:sender[\s\S]*urn:recipient/);
  assert.doesNotMatch(ui.run('JSON.stringify(state)'), /must-not-cache/);
  await ui.run('changeCompliancePage(1)');
  await ui.run('changeCompliancePage(1)');
  assert.equal(ui.context.calls[1].query.offset, 25);
  assert.equal(ui.context.calls[2].query.offset, 50);
  assert.equal(ui.nodes.get('compliancePrevPage').disabled, false);
  assert.equal(ui.nodes.get('complianceNextPage').disabled, true);
  ui.run('changeCompliancePage(1)');
  assert.equal(ui.context.calls.length, 3, 'cannot page past the last result');
  await ui.run('resetComplianceFilters()');
  assert.equal(ui.context.calls[3].query.offset, 0);
  assert.equal(ui.context.calls[3].query.sender, '');
  assert.equal(ui.context.calls[3].query.recipient, '');
});

test('out-of-order history replies cannot replace a newer filter or its status', async () => {
  const ui = consoleUI(); ui.context.entry = entry('new-result'); ui.context.resolvers = [];
  ui.run(`apiCall = () => new Promise((resolve,reject) => resolvers.push({resolve,reject}));`);
  const oldLoad = ui.run('refreshComplianceMessages()');
  const newLoad = ui.run("document.getElementById('complianceSender').value='urn:new'; filterComplianceMessages({preventDefault(){}})");
  ui.run('resolvers[1].resolve({entries:[entry],total:1})');
  await newLoad;
  ui.run("resolvers[0].reject(new Error('stale failure'))");
  await oldLoad;
  assert.equal(ui.run('state.complianceEntries[0].id'), 'new-result');
  assert.equal(ui.nodes.get('complianceStatus').textContent, '合规消息历史已读取');
  assert.equal(ui.run('state.complianceLoading'), false);
});

test('history read failures remove old rows and show a visible error', async () => {
  const ui = consoleUI(); ui.context.entry = entry();
  ui.run('apiCall = () => Promise.resolve({entries:[entry],total:1})');
  await ui.run('refreshComplianceMessages()');
  ui.run("apiCall = () => Promise.reject(new Error('archive unavailable'))");
  await ui.run('refreshComplianceMessages()');
  assert.equal(ui.run('state.complianceEntries.length'), 0);
  assert.equal(ui.nodes.get('complianceTableBody').children.length, 0);
  assert.match(ui.nodes.get('complianceStatus').textContent, /读取失败.*archive unavailable/);
  assert.equal(ui.nodes.get('complianceNextPage').disabled, true);
});

test('message body is requested on inspection and rendered as text with escaped metadata', async () => {
  const ui = consoleUI();
  const attack = '<img src=x onerror=globalThis.pwned=true>';
  ui.context.detail = { ...entry(), sender: attack, policy_hash: attack,
    plaintext: JSON.stringify({ text: attack, secret: 'body-only-secret' }) };
  ui.context.calls = [];
  ui.run(`apiCall = (url, method, query) => { calls.push({url,method,query}); return Promise.resolve(detail); };`);
  assert.equal(ui.context.calls.length, 0);
  await ui.run("showComplianceDetails('message-1')");
  assert.equal(ui.context.calls[0].url, '/api/v1/admin/compliance/messages/detail');
  assert.equal(ui.context.calls[0].query.id, 'message-1');
  assert.match(ui.nodes.get('complianceDetailMeta').innerHTML, /&lt;img/);
  assert.ok(!ui.nodes.get('complianceDetailMeta').innerHTML.includes('<img'));
  assert.equal(ui.nodes.get('compliancePlaintext').textContent, JSON.stringify(JSON.parse(ui.context.detail.plaintext), null, 2));
  assert.equal(ui.nodes.get('compliancePlaintext').innerHTML, '');
  assert.doesNotMatch(ui.run('JSON.stringify(state)'), /body-only-secret/);
  ui.run('closeDrawer()');
  assert.equal(ui.nodes.get('compliancePlaintext').textContent, '');
  assert.equal(ui.nodes.get('drawerContent').innerHTML, '');
});

test('closed, replaced, and logged-out detail requests cannot reveal delayed plaintext', async () => {
  const ui = consoleUI(); ui.context.resolvers = []; ui.context.entry = entry();
  ui.run('apiCall = () => new Promise(resolve => resolvers.push(resolve))');
  const closed = ui.run("showComplianceDetails('message-1')");
  ui.run("closeDrawer(); resolvers[0]({...entry,plaintext:'closed-secret'})");
  await closed;
  assert.equal(ui.nodes.get('compliancePlaintext').textContent, '');
  const oldDetail = ui.run("showComplianceDetails('message-1')");
  const currentDetail = ui.run("showComplianceDetails('message-2')");
  ui.run("resolvers[2]({...entry,id:'message-2',plaintext:'new-body'})");
  await currentDetail;
  ui.run("resolvers[1]({...entry,plaintext:'old-secret'})");
  await oldDetail;
  assert.equal(ui.nodes.get('compliancePlaintext').textContent, 'new-body');
  const afterLogout = ui.run("showComplianceDetails('message-3')");
  ui.run("clearToken(false); resolvers[3]({...entry,id:'message-3',plaintext:'logout-secret'})");
  await afterLogout;
  assert.equal(ui.nodes.get('compliancePlaintext').textContent, '');
  assert.equal(ui.nodes.get('drawerContent').innerHTML, '');
  assert.equal(ui.session.has('admin_token'), false);
});

test('body read errors clear the prior body and show that retention may have expired', async () => {
  const ui = consoleUI(); ui.context.detail = { ...entry(), plaintext: 'first-body' };
  ui.run('apiCall = () => Promise.resolve(detail)');
  await ui.run("showComplianceDetails('message-1')");
  ui.run("apiCall = () => Promise.reject(new Error('not found'))");
  await ui.run("showComplianceDetails('message-2')");
  assert.equal(ui.nodes.get('compliancePlaintext').textContent, '');
  assert.equal(ui.nodes.get('complianceDetailMeta').innerHTML, '');
  assert.match(ui.nodes.get('complianceDetailStatus').textContent, /正文读取失败.*保留期.*not found/);
});

test('retention rejects invalid days and saving a larger integer uses its separate API', async () => {
  const ui = consoleUI(); ui.context.calls = [];
  ui.run(`refreshOverview = () => {}; apiCall = (url,method,query) => {
    calls.push({url,method,query}); return Promise.resolve({ok:true,compliance_retention_days:query.days});
  };`);
  const input = ui.run("document.getElementById('complianceRetentionInput')");
  for (const invalid of ['', '-1', '1.5', '36501', 'NaN', 'Infinity', '9007199254740992']) {
    input.value = invalid;
    ui.run('submitComplianceRetention()');
  }
  assert.equal(ui.context.calls.length, 0);
  assert.match(ui.nodes.get('complianceRetentionStatus').textContent, /0–36500/);
  input.value = '36500';
  await ui.run('submitComplianceRetention()');
  assert.deepEqual(JSON.parse(JSON.stringify(ui.context.calls[0])), {
    url:'/api/v1/admin/config/set-compliance-retention',method:'POST',query:{days:36500}
  });
  assert.equal(ui.run('state.complianceRetentionDays'), 36500);
  assert.equal(input.disabled, false);
  assert.match(ui.nodes.get('complianceRetentionStatus').textContent, /已保存.*36500/);
});

test('shorter and zero retention require an explicit history deletion confirmation', async () => {
  const ui = consoleUI(); ui.context.calls = []; ui.context.prompts = [];
  ui.run(`refreshOverview = () => {};
    showConfirmModal = (_title,prompt,callback) => { prompts.push(prompt); globalThis.proceed = callback; };
    apiCall = (url,method,query) => { calls.push({url,method,query}); return Promise.resolve({ok:true,compliance_retention_days:query.days}); };
    document.getElementById('complianceRetentionInput').value='10'; submitComplianceRetention();`);
  assert.equal(ui.context.calls.length, 0);
  assert.match(ui.context.prompts[0], /30 天.*10 天.*立即永久删除/);
  await ui.run('proceed()');
  assert.equal(ui.context.calls[0].query.days, 10);
  ui.run("document.getElementById('complianceRetentionInput').value='0'; submitComplianceRetention()");
  assert.equal(ui.context.calls.length, 1);
  assert.match(ui.context.prompts[1], /停止新消息.*立即永久删除所有/);
  await ui.run('proceed()');
  assert.equal(ui.context.calls[1].query.days, 0);
});

test('polling preserves focused and dirty retention drafts, and failed saves retain the current policy', async () => {
  const ui = consoleUI();
  const input = ui.run("document.getElementById('complianceRetentionInput')");
  ui.run('state.latestOverview = {v2_policy_mode:"compliance",compliance_retention_days:30}; renderCompliancePolicyValues()');
  input.value = '17'; ui.document.activeElement = input;
  ui.run('renderCompliancePolicyValues()');
  assert.equal(input.value, '17');
  ui.run('complianceRetentionChanged()'); ui.document.activeElement = null;
  ui.run('state.latestOverview.compliance_retention_days=25; renderCompliancePolicyValues()');
  assert.equal(input.value, '17', 'a blurred dirty draft also survives polling');
  ui.run(`showConfirmModal = (_title,_prompt,callback) => callback();
    apiCall = () => Promise.reject(new Error('disk full')); submitComplianceRetention();`);
  await flush();
  assert.equal(ui.run('state.complianceRetentionDays'), 25);
  assert.equal(input.value, '17');
  assert.equal(input.disabled, false);
  assert.match(ui.nodes.get('complianceRetentionStatus').textContent, /保存失败.*disk full/);
});

test('overview replies started before a retention save cannot roll back the displayed policy', async () => {
  const ui = consoleUI();
  ui.run(`apiCall = () => new Promise(resolve => { globalThis.oldOverview = resolve; });
    renderOverview = data => { globalThis.renderedDays = data.compliance_retention_days; };`);
  const oldOverview = ui.run('refreshOverview()');
  ui.run(`refreshOverview = () => {}; apiCall = (_url,_method,query) => Promise.resolve({ok:true,compliance_retention_days:query.days});`);
  await ui.run('saveComplianceRetention(45)');
  ui.run('oldOverview({compliance_retention_days:30})');
  await oldOverview;
  assert.equal(ui.context.renderedDays, undefined);
  assert.equal(ui.run('state.complianceRetentionDays'), 45);
});

test('archive identifiers remain inert in table markup and inspection handlers', async () => {
  const ui = consoleUI();
  const attack = '\"><img src=x onerror=globalThis.pwned=true>\'\\;globalThis.pwned=true;//';
  ui.context.entry = { ...entry(attack), sender: attack, recipient: attack };
  ui.run('apiCall = () => Promise.resolve({entries:[entry],total:1})');
  await ui.run('refreshComplianceMessages()');
  const markup = ui.nodes.get('complianceTableBody').children[0].innerHTML;
  assert.ok(!markup.includes('<img'));
  assert.match(markup, /&lt;img/);
  const encodedHandler = markup.match(/onclick="([^"]*)"/)[1];
  const entities = { '&quot;':'"', '&#39;':"'", '&lt;':'<', '&gt;':'>', '&amp;':'&' };
  const handler = encodedHandler.replace(/&(?:quot|lt|gt|amp);|&#39;/g, entity => entities[entity]);
  ui.run('showComplianceDetails = id => { globalThis.openedID = id; }');
  ui.run(handler);
  assert.equal(ui.context.openedID, attack);
  assert.equal(ui.context.pwned, undefined);
});

test('logout invalidates an in-flight archive list request', async () => {
  const ui = consoleUI(); ui.context.entry = entry();
  ui.run('apiCall = () => new Promise(resolve => { globalThis.reply = resolve; })');
  const load = ui.run('refreshComplianceMessages()');
  ui.run('clearToken(false); reply({entries:[entry],total:1})');
  await load;
  assert.equal(ui.run('state.complianceEntries.length'), 0);
  assert.equal(ui.nodes.get('complianceTableBody').children.length, 0);
  assert.equal(ui.run('state.complianceLoading'), false);
});
