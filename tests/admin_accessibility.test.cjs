const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function consoleUI() {
  const nodes = new Map();
  const listeners = new Map();
  const document = {
    activeElement: null,
    title: '',
    getElementById(id) {
      if (!nodes.has(id)) nodes.set(id, element(id));
      return nodes.get(id);
    },
    querySelectorAll(selector) {
      if (selector.includes('.app-container')) {
        return ['app', 'mobile', 'beian', 'drawer', 'drawerOverlay'].map(id => this.getElementById(id));
      }
      return [];
    },
    querySelector(selector) {
      return selector === '.menu-item.active' ? this.getElementById('activeNav') : null;
    }
  };
  function element(id) {
    const classes = new Set();
    const handlers = new Map();
    return {
      id, inert: false, children: [], focusableChildren: [], style: {},
      classList: {
        add(name) { classes.add(name); },
        remove(name) { classes.delete(name); },
        contains(name) { return classes.has(name); },
        toggle(name, force) {
          const on = force === undefined ? !classes.has(name) : force;
          if (on) classes.add(name); else classes.delete(name);
          return on;
        }
      },
      focus() { document.activeElement = this; },
      contains(target) { return this === target || this.children.includes(target); },
      querySelectorAll() { return this.focusableChildren; },
      addEventListener(type, handler) { handlers.set(type, handler); },
      fire(type) { handlers.get(type)?.(); }
    };
  }
  document.body = element('body');
  document.activeElement = document.body;
  const auth = document.getElementById('authModal');
  const token = document.getElementById('adminTokenInput');
  const login = document.getElementById('authSubmit');
  auth.children = auth.focusableChildren = [token, login];
  const confirm = document.getElementById('confirmModal');
  const cancel = document.getElementById('btnConfirmCancel');
  const proceed = document.getElementById('btnConfirmProceed');
  confirm.children = confirm.focusableChildren = [cancel, proceed];

  const context = vm.createContext({
    document,
    window: { addEventListener(type, listener) { listeners.set(type, listener); } },
    localStorage: { getItem() { return null; }, setItem() {} },
    sessionStorage: { getItem() { return null; }, removeItem() {} },
    setInterval() { return 1; }, clearInterval() {}
  });
  const html = fs.readFileSync(path.join(__dirname, '../internal/api/web/index.html'), 'utf8');
  vm.runInContext(html.match(/<script>([\s\S]*?)<\/script>/)[1], context);
  return { document, nodes, listeners, run(code) { return vm.runInContext(code, context); } };
}

test('authorization dialog focuses its token field, blocks background, and restores focus', () => {
  const ui = consoleUI();
  ui.listeners.get('DOMContentLoaded')();
  assert.equal(ui.nodes.get('authModal').classList.contains('active'), true);
  assert.equal(ui.document.activeElement, ui.nodes.get('adminTokenInput'));
  for (const id of ['app', 'mobile', 'beian', 'drawer', 'drawerOverlay']) {
    assert.equal(ui.nodes.get(id).inert, true, `${id} should be inert`);
  }

  const login = ui.nodes.get('authSubmit');
  login.focus();
  let prevented = false;
  ui.listeners.get('keydown')({ key: 'Tab', shiftKey: false, preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(ui.document.activeElement, ui.nodes.get('adminTokenInput'));

  ui.run("hideManagedModal('authModal')");
  assert.equal(ui.nodes.get('authModal').classList.contains('active'), false);
  assert.equal(ui.nodes.get('app').inert, false);
  assert.equal(ui.document.activeElement, ui.nodes.get('activeNav'));

  const logout = ui.document.getElementById('logout');
  logout.focus();
  ui.run("showManagedModal('authModal', 'adminTokenInput')");
  ui.run("hideManagedModal('authModal')");
  assert.equal(ui.document.activeElement, logout);
});

test('confirmation dialog traps Tab and returns focus to its triggering control', () => {
  const ui = consoleUI();
  ui.listeners.get('DOMContentLoaded')();
  ui.run("hideManagedModal('authModal')");
  const trigger = ui.document.getElementById('dangerAction');
  trigger.focus();
  ui.run("showConfirmModal('Confirm', 'Delete data?', () => {})");
  assert.equal(ui.document.activeElement, ui.nodes.get('btnConfirmCancel'));
  assert.equal(ui.nodes.get('app').inert, true);

  let prevented = false;
  ui.nodes.get('btnConfirmProceed').focus();
  ui.listeners.get('keydown')({ key: 'Tab', shiftKey: false, preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(ui.document.activeElement, ui.nodes.get('btnConfirmCancel'));

  prevented = false;
  ui.listeners.get('keydown')({ key: 'Tab', shiftKey: true, preventDefault() { prevented = true; } });
  assert.equal(prevented, true);
  assert.equal(ui.document.activeElement, ui.nodes.get('btnConfirmProceed'));

  ui.run('closeConfirmModal()');
  assert.equal(ui.nodes.get('app').inert, false);
  assert.equal(ui.document.activeElement, trigger);
});

test('successful storage confirmation moves focus into the reboot overlay', async () => {
  const ui = consoleUI();
  ui.listeners.get('DOMContentLoaded')();
  ui.run("hideManagedModal('authModal')");
  const toggle = ui.document.getElementById('policyStoreToggle');
  toggle.checked = true;
  toggle.focus();
  ui.run('apiCall = () => Promise.resolve({changed:true,store_user_data:true}); fetch = () => new Promise(() => {}); refreshOverview = () => {}; toggleStorePolicy()');
  assert.equal(ui.document.activeElement, ui.nodes.get('btnConfirmCancel'));

  ui.nodes.get('btnConfirmProceed').fire('click');
  assert.equal(ui.document.activeElement, toggle);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(ui.nodes.get('rebootingOverlay').classList.contains('active'), true);
  assert.equal(ui.document.activeElement, ui.nodes.get('rebootingOverlay'));
  assert.equal(ui.nodes.get('app').inert, true);
});

test('expired token dismisses confirmation before opening authorization', () => {
  const ui = consoleUI();
  ui.listeners.get('DOMContentLoaded')();
  ui.run("hideManagedModal('authModal')");
  const trigger = ui.document.getElementById('dangerAction');
  trigger.focus();
  ui.run("showConfirmModal('Confirm', 'Delete data?', () => {}); clearToken(false)");
  assert.equal(ui.nodes.get('confirmModal').classList.contains('active'), false);
  assert.equal(ui.nodes.get('authModal').classList.contains('active'), true);
  assert.equal(ui.document.activeElement, ui.nodes.get('adminTokenInput'));
  assert.equal(ui.nodes.get('app').inert, true);
  assert.equal(ui.run('confirmProceedCallback === null'), true);
  assert.equal(ui.run('activeManagedModal().id'), 'authModal');
});
