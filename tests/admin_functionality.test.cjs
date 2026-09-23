const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function consoleUI() {
  const nodes = new Map();
  const persistent = new Map();
  const session = new Map();
  function element() {
    return {
      innerHTML: '', textContent: '', value: '', checked: false, style: {}, children: [],
      classList: { add() {}, remove() {}, contains() { return false; } },
      appendChild(child) { this.children.push(child); }, addEventListener() {}
    };
  }
  const context = vm.createContext({
    URLSearchParams,
    localStorage: {
      getItem(key) { return persistent.get(key) || null; },
      setItem(key, value) { persistent.set(key, value); }
    },
    sessionStorage: {
      getItem(key) { return session.get(key) || null; },
      setItem(key, value) { session.set(key, value); },
      removeItem(key) { session.delete(key); }
    },
    window: { addEventListener() {} },
    document: {
      getElementById(id) { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); },
      createElement: element, querySelectorAll() { return []; }
    }
  });
  const html = fs.readFileSync(path.join(__dirname, '../internal/api/web/index.html'), 'utf8');
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], context);
  return { nodes, persistent, session, context, run(code) { return vm.runInContext(code, context); } };
}

test('console charts use only observed samples and capacity indicators use server settings', () => {
  const ui = consoleUI();
  ui.context.overview = {connected_peers:2, registry_count:3, mq_messages_count:4, uptime_seconds:60,
    registry_ttl_hours:12, mq_max_msgs_per_urn:500, peer_id:'self', platform_mode:'compliance',
    stores_user_data:true, forward_to_storage_platforms:true, listen_addrs:[],
    memory_alloc_mb:32, memory_sys_mb:64, go_version:'go1.26.8', goroutines:5,
    history_retention_days:30};
  ui.run('countUp = () => {}; drawSparkline = () => {}; renderOverview(overview);');
  assert.equal(ui.run('state.sparkHistory.peers.length'), 1);
  assert.equal(ui.run('state.sparkHistory.peers[0]'), 2);
  assert.equal(ui.nodes.get('platformModeIndicator').textContent, '配置模式: compliance');

  ui.run(`state.registryData = [{URN:'urn:test', PeerID:'peer', Addrs:[], RelayAddrs:[],
      ExpiresAt:Math.floor(Date.now()/1000) + 6*3600}]; renderRegistryTable();
    state.mqData = [{recipient:'urn:test', count:200, total_size:1000,
      oldest_at:1, newest_at:1}]; renderMQTable();`);
  assert.match(ui.nodes.get('registryTableBody').children[0].innerHTML, /width: 50%;/);
  assert.match(ui.nodes.get('mqTableBody').children[0].innerHTML, /200 \/ 500 \(40%\)/);

  const retentionInput = ui.nodes.get('policyRetentionInput');
  retentionInput.value = '17';
  ui.context.document.activeElement = retentionInput;
  ui.run('renderOverview(overview)');
  assert.equal(retentionInput.value, '17', 'polling must not overwrite a focused edit');
  ui.context.document.activeElement = null;
  ui.run('renderOverview(overview)');
  assert.equal(retentionInput.value, 30);
});

test('retention form uses the complete numeric value and rejects fractions', async () => {
  const ui = consoleUI();
  ui.run("document.getElementById('policyRetentionInput')");
  const input = ui.nodes.get('policyRetentionInput');
  input.validity = { valid: true };
  ui.context.sentDays = [];
  ui.run(`showToast = () => {}; refreshOverview = () => {};
    apiCall = (_url, _method, query) => { sentDays.push(query.days); return Promise.resolve({ok:true}); };`);
  input.value = '1.9';
  ui.run('updateRetentionDays()');
  assert.equal(ui.context.sentDays.length, 0);
  input.value = '1e3';
  ui.run('updateRetentionDays()');
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(Array.from(ui.context.sentDays), [1000]);
});

test('admin token remains in the tab session and API errors accept plain text', async () => {
  const ui = consoleUI();
  ui.nodes.set('adminTokenInput', { value: 'secret' });
  ui.run('verifyHealthAndLoad = () => {}; saveToken();');
  assert.equal(ui.session.get('admin_token'), 'secret');
  assert.equal(ui.persistent.has('admin_token'), false);

  ui.context.fetch = () => Promise.resolve({ status: 500, ok: false, text: () => Promise.resolve('disk full') });
  await assert.rejects(ui.run("apiCall('/api/v1/admin/config')"), /disk full/);
  ui.run('clearToken(false)');
  assert.equal(ui.session.has('admin_token'), false);
});

test('batch operations wait for every request and report partial failures', async () => {
  const ui = consoleUI();
  ui.context.feedback = [];
  ui.run(`showConfirmModal = (_title, _message, proceed) => proceed();
    showToast = (message, type) => feedback.push({message, type});
    refreshRegistry = () => {}; refreshMQ = () => {};
    apiCall = (_url, _method, query) => query.urn === 'good'
      ? Promise.resolve({deleted:2}) : Promise.reject(new Error('failed'));
    state.selectedRegistryURNs.add('good'); state.selectedRegistryURNs.add('bad');
    state.selectedMQURNs.add('good'); state.selectedMQURNs.add('bad');
    batchEvictNodes(); batchClearQueues();`);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(ui.context.feedback.length, 2);
  assert.ok(ui.context.feedback.every(item => item.type === 'error'));
  assert.match(ui.context.feedback[0].message, /成功 1，失败 1/);
  assert.match(ui.context.feedback[1].message, /删除 2 封/);
});
