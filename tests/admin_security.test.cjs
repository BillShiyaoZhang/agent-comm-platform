const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function consoleUI() {
  const nodes = new Map();
  function element() {
    return { innerHTML: '', value: '', style: {}, children: [], classList: { add() {}, remove() {} },
      appendChild(child) { this.children.push(child); }, addEventListener() {} };
  }
  const context = vm.createContext({
    localStorage: { getItem() { return null; } },
    sessionStorage: { getItem() { return null; }, setItem() {}, removeItem() {} },
    window: { addEventListener() {} },
    document: { getElementById(id) { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); },
      createElement: element, querySelectorAll() { return []; } }, setTimeout() {}, clearTimeout() {},
  });
  const html = fs.readFileSync(path.join(__dirname, '../internal/api/web/index.html'), 'utf8');
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], context);
  return { context, nodes, run(code) { return vm.runInContext(code, context); } };
}

const attack = '\"><img src=x onerror=globalThis.pwned=true>\'\\;globalThis.pwned=true;//';
function assertTextOnly(markup) {
  assert.ok(!markup.includes('<img'), markup);
  assert.ok(markup.includes('&lt;img'), markup);
}

test('registry metadata and protocol names cannot inject markup into admin tables or drawers', () => {
  const ui = consoleUI(); ui.context.attack = attack;
  ui.run(`state.registryData = [{URN:attack, PeerID:attack, Addrs:[attack], RelayAddrs:[attack], ExpiresAt:2000000000}]; renderRegistryTable(); showNodeDetails(attack);`);
  assertTextOnly(ui.nodes.get('registryTableBody').children[0].innerHTML);
  assertTextOnly(ui.nodes.get('drawerContent').innerHTML);
  ui.run(`state.peersData = [{peer_id:attack, addrs:[attack], protocols:[attack], conn_count:1}]; renderPeersTable(); showPeerDetails(attack);`);
  assertTextOnly(ui.nodes.get('peersTableBody').children[0].innerHTML);
  assertTextOnly(ui.nodes.get('drawerContent').innerHTML);
});

test('HTML-encoded JavaScript arguments remain data after browser attribute decoding', () => {
  const ui = consoleUI(); ui.context.attack = attack;
  const encoded = ui.run('jsArg(attack)');
  assert.ok(!/[<>"']/.test(encoded));
  const entities = { '&quot;':'"', '&#39;':"'", '&lt;':'<', '&gt;':'>', '&amp;':'&' };
  const decoded = encoded.replace(/&(?:quot|lt|gt|amp);|&#39;/g, entity => entities[entity]);
  ui.context.receive = value => assert.equal(value, attack);
  ui.run(`receive(${decoded})`);
  assert.equal(ui.context.pwned, undefined);
});

test('message IDs, mailbox names and audit messages are displayed as text', async () => {
  const ui = consoleUI(); ui.context.attack = attack;
  ui.run(`state.mqData = [{recipient:attack,count:1,total_size:1,oldest_at:1,newest_at:1}]; renderMQTable();
    state.logsData = [{timestamp:1,level:attack,source:attack,message:attack,details:attack}]; renderLogsStream();
    apiCall = () => Promise.resolve([{id:attack,sender:attack,payload:attack,size:1,stored_at:1}]); loadDetailMessages();`);
  await new Promise(resolve => setImmediate(resolve));
  assertTextOnly(ui.nodes.get('mqTableBody').children[0].innerHTML);
  assertTextOnly(ui.nodes.get('logStreamContainer').children[0].innerHTML);
  assertTextOnly(ui.nodes.get('drawerMQMessagesList').children[0].innerHTML);
});
