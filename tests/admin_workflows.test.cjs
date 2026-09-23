const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function consoleUI() {
  const nodes = new Map();
  function element() {
    return {
      innerHTML: '', textContent: '', value: '', checked: false, disabled: false,
      style: {}, children: [],
      classList: { add() {}, remove() {}, contains() { return false; }, toggle() {} },
      appendChild(child) { this.children.push(child); },
      addEventListener() {}, setAttribute() {}, focus() {}
    };
  }
  const context = vm.createContext({
    URLSearchParams,
    localStorage: { getItem() { return null; }, setItem() {} },
    sessionStorage: { getItem() { return 'token'; }, setItem() {}, removeItem() {} },
    window: { addEventListener() {} },
    document: {
      getElementById(id) { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); },
      createElement: element, querySelectorAll() { return []; }
    }
  });
  const html = fs.readFileSync(path.join(__dirname, '../internal/api/web/index.html'), 'utf8');
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], context);
  return { nodes, context, run(code) { return vm.runInContext(code, context); } };
}

const flush = () => new Promise(resolve => setImmediate(resolve));

const editable = (overrides = {}) => {
  const settings = {
    'registry.ttl_hours': 24,
    'mq.default_ttl_days': 7,
    'mq.max_msgs_per_urn': 500,
    'relay.enabled': true,
    'relay.max_reservations': 1000,
    'relay.max_circuit_duration': '2m',
    ...overrides
  };
  return {
    revision: 'revision-1', settings,
    fields: [
      { key: 'registry.ttl_hours', type: 'integer', min: 1, max: 8760 },
      { key: 'mq.default_ttl_days', type: 'integer', min: 1, max: 3650 },
      { key: 'mq.max_msgs_per_urn', type: 'integer', min: 1, max: 100000 },
      { key: 'relay.enabled', type: 'boolean' },
      { key: 'relay.max_reservations', type: 'integer', min: 1, max: 100000 },
      { key: 'relay.max_circuit_duration', type: 'duration', options: ['30s', '1m', '2m', '5m'] }
    ]
  };
};

test('forwarding policy sends the selected value and waits for confirmation', async () => {
  const ui = consoleUI();
  const toggle = ui.nodes.get('policyForwardToggle') || ui.run("document.getElementById('policyForwardToggle')");
  toggle.checked = true;
  ui.context.calls = [];
  ui.run(`showToast = () => {}; refreshOverview = () => {};
    showConfirmModal = (_title, _text, callback) => { globalThis.confirmForward = callback; };
    apiCall = (url, method, query, body) => {
      calls.push({url, method, body});
      return Promise.resolve({forward_to_storage_platforms:body.forward_to_storage_platforms});
    };
    toggleForwardPolicy();`);
  assert.equal(toggle.checked, false, 'visual state stays at the old value until confirmation');
  assert.equal(ui.context.calls.length, 0);
  ui.run('confirmForward()');
  await flush();
  assert.deepEqual(ui.context.calls.map(call => [call.url, call.method, call.body.forward_to_storage_platforms]),
    [['/api/v1/admin/config/forwarding', 'PUT', true]]);
  assert.equal(toggle.checked, true);
  assert.equal(toggle.disabled, false);
});

test('storage confirmation states the target and uses an exact-value request', async () => {
  const ui = consoleUI();
  const toggle = ui.run("document.getElementById('policyStoreToggle')");
  toggle.checked = true;
  ui.context.calls = [];
  ui.run(`showToast = () => {}; refreshOverview = () => {};
    showConfirmModal = (_title, prompt, callback) => { globalThis.storagePrompt = prompt; globalThis.confirmStore = callback; };
    apiCall = (url, method, query, body) => {
      calls.push({url, method, body});
      return Promise.resolve({store_user_data:body.store_user_data,changed:false});
    };
    toggleStorePolicy();`);
  assert.match(ui.context.storagePrompt, /允许存储离线信封/);
  assert.equal(ui.context.calls.length, 0);
  ui.run('confirmStore()');
  await flush();
  assert.deepEqual(ui.context.calls.map(call => [call.url, call.method, call.body.store_user_data]),
    [['/api/v1/admin/config/storage', 'PUT', true]]);
  assert.equal(toggle.checked, true);
  assert.equal(toggle.disabled, false);
});

test('storage recovery waits for a restarted process and matching policy', async () => {
  const ui = consoleUI();
  ui.context.observed = [];
  ui.context.scheduled = [];
  ui.run(`state.storageRecoveryTarget = true;
    state.storageRecoveryBaseline = 100;
    state.storageRecoveryStartedAt = Date.now() - 5000;
    state.storageRecoverySequence = 1;
    setTimeout = callback => scheduled.push(callback);
    hideManagedModal = () => observed.push('verified');
    renderOverview = () => {}; refreshRegistry = () => {}; refreshMQ = () => {}; showToast = () => {};
    globalThis.uptimes = [106, 1];
    fetch = () => Promise.resolve({ok:true,status:200,json:() => Promise.resolve({uptime_seconds:uptimes.shift(),stores_user_data:true})});`);
  await ui.run('pollStorageRecovery(1)');
  assert.equal(ui.context.observed.length, 0, 'old process response is not recovery');
  assert.equal(ui.context.scheduled.length, 1);
  await ui.context.scheduled[0]();
  assert.deepEqual(Array.from(ui.context.observed), ['verified']);
});

test('storage recovery honors the server restart_pending flag', async () => {
  const ui = consoleUI();
  ui.context.observed = [];
  ui.context.scheduled = [];
  ui.run(`state.storageRecoveryTarget = false;
    state.storageRecoveryBaseline = 10;
    state.storageRecoveryStartedAt = Date.now() - 5000;
    state.storageRecoverySequence = 1;
    setTimeout = callback => scheduled.push(callback);
    hideManagedModal = () => observed.push('verified');
    renderOverview = () => {}; refreshRegistry = () => {}; refreshMQ = () => {}; showToast = () => {};
    globalThis.pending = [true, false];
    fetch = () => Promise.resolve({ok:true,status:200,json:() => Promise.resolve({
      uptime_seconds:1, stores_user_data:false, restart_pending:pending.shift()
    })});`);
  await ui.run('pollStorageRecovery(1)');
  assert.equal(ui.context.observed.length, 0, 'old process remains pending despite its low uptime');
  await ui.context.scheduled[0]();
  assert.deepEqual(Array.from(ui.context.observed), ['verified']);
});

test('mailbox inventory shows all storage classes and history-only URNs can be opened', async () => {
  const ui = consoleUI();
  ui.context.opened = [];
  ui.run(`showMQDetails = urn => opened.push(urn);
    apiCall = url => Promise.resolve(url.endsWith('/summary')
      ? {pending:{messages:3,bytes:1024},history:{messages:9,bytes:2048},expired:{messages:2,bytes:512}}
      : {queues:[]});
    refreshMQ();`);
  await flush();
  assert.equal(ui.nodes.get('mqSummaryPending').textContent, 3);
  assert.equal(ui.nodes.get('mqSummaryHistory').textContent, 9);
  assert.equal(ui.nodes.get('mqSummaryExpired').textContent, 2);
  assert.equal(ui.nodes.get('mqSummaryHistoryBytes').textContent, '2.0 KB');
  ui.run("document.getElementById('mailboxLookupURN')").value = ' urn:history-only ';
  ui.context.event = { preventDefault() {} };
  ui.run('openMailboxLookup(event)');
  assert.deepEqual(Array.from(ui.context.opened), ['urn:history-only']);
});

test('message drawer pages through results and confirms one-envelope deletion', async () => {
  const ui = consoleUI();
  ui.context.calls = [];
  ui.context.prompts = [];
  ui.run(`currentDetailURN = 'urn:receiver';
    showConfirmModal = (_title, prompt, callback) => { prompts.push(prompt); callback(); };
    showToast = () => {}; refreshMQ = () => {};
    apiCall = (url, method, query) => {
      calls.push({url, method, query});
      if (method === 'DELETE') return Promise.resolve({ok:true,deleted:1});
      return Promise.resolve({entries:[{id:'msg-1',sender:'urn:sender',payload:'00',size:1,stored_at:1}],total:30});
    };
    loadDetailMessages();`);
  await flush();
  assert.equal(ui.nodes.get('mqNextPage').disabled, false);
  assert.match(ui.nodes.get('drawerMQMessagesList').children[0].innerHTML, /deleteMQMessage/);
  ui.run('changeMQMessagePage(1)');
  await flush();
  assert.equal(ui.nodes.get('mqPrevPage').disabled, false);
  assert.equal(ui.context.calls[1].query.offset, 25);
  ui.run("deleteMQMessage('msg-1')");
  await flush();
  assert.match(ui.context.prompts[0], /msg-1/);
  assert.equal(ui.context.calls[2].url, '/api/v1/admin/mq/messages');
  assert.equal(ui.context.calls[2].method, 'DELETE');
  assert.equal(ui.context.calls[2].query.urn, 'urn:receiver');
  assert.equal(ui.context.calls[2].query.id, 'msg-1');
});

test('full encrypted payload is fetched only on explicit inspection', async () => {
  const ui = consoleUI();
  ui.context.calls = [];
  ui.run(`apiCall = (url, method, query) => {
    calls.push({url, query});
    return Promise.resolve({payload:'ciphertext-hex'});
  };`);
  const output = ui.run("document.getElementById('payloadOutput')");
  const button = ui.run("document.getElementById('payloadButton')");
  assert.equal(ui.context.calls.length, 0);
  ui.context.output = output;
  ui.context.button = button;
  ui.run("revealMQPayload('urn:receiver', 'msg-1', output, button)");
  await flush();
  assert.equal(ui.context.calls[0].url, '/api/v1/admin/mq/messages/detail');
  assert.equal(ui.context.calls[0].query.id, 'msg-1');
  assert.equal(output.children[0].value, 'ciphertext-hex');
});

test('config editor validates changed fields only and protects focused or dirty input from refresh', async () => {
  const ui = consoleUI();
  ui.context.editable = editable({ 'mq.max_msgs_per_urn': 0 });
  ui.context.calls = [];
  ui.run(`state.configEditable = editable; renderConfigEditor();
    apiCall = url => { calls.push(url); return Promise.resolve(editable); };`);
  ui.run("document.getElementById('configRelayMax').value = '2000'; configDraftChanged()");
  assert.deepEqual(JSON.parse(JSON.stringify(ui.run('buildConfigChanges()'))), { 'relay.max_reservations': 2000 });
  await ui.run('refreshConfig()');
  assert.equal(ui.context.calls.length, 0, 'background refresh preserves a dirty draft');
  ui.run('resetConfigDraft()');
  ui.context.document.activeElement = ui.nodes.get('configRegistryTTL');
  await ui.run('refreshConfig()');
  assert.equal(ui.context.calls.length, 0, 'background refresh preserves a focused control');
  ui.context.document.activeElement = null;
  await ui.run('refreshConfig()');
  assert.equal(ui.context.calls.length, 1);
});

test('in-flight config refresh cannot overwrite input begun after the request', async () => {
  const ui = consoleUI();
  ui.context.editable = editable();
  ui.context.newEditable = editable({ 'registry.ttl_hours': 36 });
  ui.run(`state.configEditable = editable; renderConfigEditor();
    apiCall = () => new Promise(resolve => { globalThis.resolveConfig = resolve; });`);
  const refresh = ui.run('refreshConfig()');
  ui.run("document.getElementById('configRegistryTTL').value='48'; configDraftChanged()");
  ui.run('resolveConfig(newEditable)');
  await refresh;
  assert.equal(ui.nodes.get('configRegistryTTL').value, '48');
  assert.equal(ui.nodes.get('configCurrentRegistryTTL').textContent, '24');
  assert.match(ui.nodes.get('configStatus').textContent, /草稿尚未提交/);
});

test('config preview shows server diff and submits the exact reviewed revision and token only after confirmation', async () => {
  const ui = consoleUI();
  ui.context.editable = editable();
  ui.context.calls = [];
  ui.run(`state.configEditable = editable; renderConfigEditor();
    showConfirmModal = (_title, prompt, callback) => { globalThis.configPrompt = prompt; globalThis.confirmConfig = callback; };
    startConfigRecovery = (settings) => { globalThis.recoveryExpected = settings; state.configRecoveryExpected = settings; };
    apiCall = (url, method, query, body) => {
      calls.push({url, method, body});
      if (url.endsWith('/preview')) return Promise.resolve({expected_revision:'revision-1',
        confirmation_token:'proof-123', confirmation_expires_at:Date.now()/1000+300,
        changes:[{key:'mq.max_msgs_per_urn',current:500,target:250,impact_zh:'后续消息可能被拒收',impact_en:'Future messages may be rejected'}],
        affected:{registry_entries:2,mq_queues:5,mq_messages:42,connected_peers:3,mq_queues_at_or_above_target_limit:4}});
      return Promise.resolve({ok:true,changed:true,restart_pending:true,settings:{...editable.settings,'mq.max_msgs_per_urn':250}});
    };`);
  ui.run("document.getElementById('configMQMax').value='250'; configDraftChanged(); previewConfigChanges()");
  await flush();
  assert.equal(ui.context.calls.length, 1);
  assert.deepEqual(JSON.parse(JSON.stringify(ui.context.calls[0].body)),
    { expected_revision: 'revision-1', changes: { 'mq.max_msgs_per_urn': 250 } });
  assert.match(ui.nodes.get('configAffected').textContent, /4/);
  assert.match(ui.nodes.get('configDiff').children[0].children[1].textContent, /拒收/);
  ui.run('confirmEditableConfig()');
  assert.equal(ui.context.calls.length, 1, 'confirmation dialog precedes PUT');
  assert.match(ui.context.configPrompt, /后续消息可能被拒收/);
  ui.run('confirmConfig()');
  await flush();
  assert.equal(ui.context.calls[1].method, 'PUT');
  assert.deepEqual(JSON.parse(JSON.stringify(ui.context.calls[1].body)),
    { expected_revision:'revision-1', changes:{'mq.max_msgs_per_urn':250}, confirmation_token:'proof-123' });
  assert.equal(ui.context.recoveryExpected['mq.max_msgs_per_urn'], 250);
});

test('lost config PUT response starts verification without resubmitting', async () => {
  const ui = consoleUI();
  ui.context.editable = editable();
  ui.context.calls = [];
  ui.run(`state.configEditable = editable; renderConfigEditor();
    state.configPreview = {expected_revision:'revision-1',confirmation_token:'proof',requestedChanges:{'registry.ttl_hours':48}};
    startConfigRecovery = (settings, _uptime, uncertain) => {
      globalThis.recoveryExpected = settings;
      globalThis.recoveryUncertain = uncertain;
      state.configRecoveryExpected = settings;
    };
    apiCall = (url, method, query, body) => { calls.push({url, method, body}); return Promise.reject(new TypeError('connection closed')); };`);
  ui.run("document.getElementById('configRegistryTTL').value='48'; configDraftChanged()");
  // A preview remains valid for this exact draft after simulating confirmation.
  ui.run("state.configPreview = {expected_revision:'revision-1',confirmation_token:'proof',requestedChanges:{'registry.ttl_hours':48}}; applyEditableConfig(state.configPreview)");
  await flush();
  assert.equal(ui.context.calls.length, 1);
  assert.equal(ui.context.recoveryUncertain, true);
  assert.equal(ui.context.recoveryExpected['registry.ttl_hours'], 48);
  assert.match(ui.nodes.get('configStatus').textContent, /结果未知/);
});

test('stale config revision reloads server current values while preserving the draft', async () => {
  const ui = consoleUI();
  ui.context.editable = editable();
  ui.context.newEditable = editable({ 'registry.ttl_hours': 36 });
  ui.run(`state.configEditable = editable; renderConfigEditor();
    apiCall = url => url.endsWith('/preview')
      ? Promise.reject(Object.assign(new Error('stale'), {status:409}))
      : Promise.resolve(newEditable);`);
  ui.run("document.getElementById('configRegistryTTL').value='48'; configDraftChanged(); previewConfigChanges()");
  await flush();
  assert.equal(ui.nodes.get('configRegistryTTL').value, '48');
  assert.equal(ui.nodes.get('configCurrentRegistryTTL').textContent, '36');
  assert.match(ui.nodes.get('configStatus').textContent, /草稿已保留/);
  assert.equal(ui.run('state.configPreview'), null);
});

test('config recovery waits for restart and verifies settings through an independent read-back', async () => {
  const ui = consoleUI();
  ui.context.editable = editable();
  ui.context.scheduled = [];
  ui.context.observed = [];
  ui.run(`state.configEditable = editable; renderConfigEditor();
    state.configRecoveryExpected = {...editable.settings, 'registry.ttl_hours':48};
    state.configBusy = true;
    state.storageRecoveryBaseline = 100;
    state.storageRecoveryStartedAt = Date.now()-5000;
    state.storageRecoverySequence = 1;
    setTimeout = callback => scheduled.push(callback);
    hideManagedModal = () => observed.push('verified');
    renderOverview = () => {}; refreshRegistry = () => {}; refreshMQ = () => {}; showToast = () => {};
    globalThis.overviews = [{restart_pending:true}, {restart_pending:false}, {restart_pending:false}];
    globalThis.readbacks = [editable, {...editable, settings:{...editable.settings,'registry.ttl_hours':48}}];
    fetch = url => Promise.resolve({ok:true,status:200,json:() => Promise.resolve(
      url.endsWith('/overview') ? {...overviews.shift(), uptime_seconds:1} : readbacks.shift())});`);
  await ui.run('pollStorageRecovery(1)');
  assert.equal(ui.context.observed.length, 0);
  await ui.context.scheduled.shift()();
  assert.equal(ui.context.observed.length, 0, 'unmatched read-back is not success');
  await ui.context.scheduled.shift()();
  assert.deepEqual(Array.from(ui.context.observed), ['verified']);
  assert.equal(ui.run('state.configBusy'), false);
  assert.equal(ui.nodes.get('configCurrentRegistryTTL').textContent, '48');
  assert.match(ui.nodes.get('configStatus').textContent, /已复读核实/);
});

test('expired config preview cannot open a save confirmation', () => {
  const ui = consoleUI();
  ui.context.editable = editable();
  ui.run(`state.configEditable = editable; renderConfigEditor();
    state.configPreview = { confirmation_expires_at:1, changes:[] };
    showConfirmModal = () => { throw new Error('must not confirm expired preview'); };
    confirmEditableConfig();`);
  assert.equal(ui.run('state.configPreview'), null);
  assert.match(ui.nodes.get('configStatus').textContent, /预览已过期/);
});

test('expanded diagnostics render only allowlisted read-only values', async () => {
  const ui = consoleUI();
  ui.run(`apiCall = () => Promise.resolve({
    Platform:{Mode:'compliance',DataDir:'SENSITIVE-DATA-PATH'},
    Identity:{KeysDir:'SENSITIVE-KEY-PATH'},
    API:{ListenAddr:':8080',RateLimitRate:10,RateLimitBurst:20,
      TLSCert:'SENSITIVE-CERT-PATH',TLSKey:'SENSITIVE-TLS-KEY',AdminToken:'SENSITIVE-TOKEN'},
    Registry:{PersistDB:'SENSITIVE-REGISTRY-PATH'}
  }); refreshConfigDiagnostics();`);
  await flush();
  assert.equal(ui.nodes.get('configDiagMode').textContent, 'compliance');
  assert.equal(ui.nodes.get('configDiagAPIListen').textContent, ':8080');
  assert.equal(ui.nodes.get('configDiagRate').textContent, 10);
  assert.equal(ui.nodes.get('configDiagTLS').textContent, '启用');
  const rendered = Array.from(ui.nodes.values()).map(node => node.textContent).join(' ');
  assert.doesNotMatch(rendered, /SENSITIVE-/);
  assert.doesNotMatch(ui.run('JSON.stringify(state.configDiagnostics)'), /SENSITIVE-/);
});
