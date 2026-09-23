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
