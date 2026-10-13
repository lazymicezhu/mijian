'use strict';

const element = id => document.getElementById(id);
const PAGE_SIZE = 30;
const timeFormat = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'Asia/Hong_Kong', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
});
let authenticated = false;
let busy = false;
let activeTab = 'messages';
let messageFilter = '';
let requestVersion = 0;
let pagination = { messages: { offset: 0, next: null }, events: { offset: 0, next: null } };

function timestamp(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '未记录' : timeFormat.format(date);
}

function visitor(value) {
  return value && value !== 'unknown' ? value : '未记录';
}

function status(id, text = '', error = false) {
  const target = element(id);
  target.textContent = text;
  target.dataset.error = String(error);
}

function setBusy(value) {
  busy = value;
  for (const id of ['admin-password', 'admin-login-button', 'admin-logout', 'messages-tab', 'events-tab', 'refresh-records', 'message-filter', 'filter-button', 'clear-filter']) {
    element(id).disabled = value;
  }
  for (const button of element('records-container').querySelectorAll('button')) button.disabled = value;
  element('previous-page').disabled = value || pagination[activeTab].offset === 0;
  element('next-page').disabled = value || pagination[activeTab].next === null;
}

async function api(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST', credentials: 'same-origin', cache: 'no-store',
      ...(body === undefined ? {} : { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
    });
  } catch {
    throw new Error('连接失败，请检查网络后重试。');
  }
  let data;
  try { data = await response.json(); }
  catch { throw new Error('暂时无法读取，请稍后重试。'); }
  if (!response.ok) {
    const error = new Error(data.error || '操作失败，请重试。');
    error.status = response.status;
    throw error;
  }
  return data;
}

function closeMessage() {
  if (element('message-dialog').open) element('message-dialog').close();
  element('dialog-text').textContent = '';
  element('dialog-meta').textContent = '';
  status('dialog-status');
}

function showLogin(message = '') {
  authenticated = false;
  closeMessage();
  element('records-container').replaceChildren();
  element('admin-dashboard').hidden = true;
  element('admin-loading').hidden = true;
  element('admin-logout').hidden = true;
  element('admin-login').hidden = false;
  element('admin-password').value = '';
  status('admin-login-status', message, Boolean(message));
}

function showDashboard() {
  authenticated = true;
  element('admin-loading').hidden = true;
  element('admin-login').hidden = true;
  element('admin-dashboard').hidden = false;
  element('admin-logout').hidden = false;
}

function resetPagination() {
  pagination = { messages: { offset: 0, next: null }, events: { offset: 0, next: null } };
}

function cell(row, value, className = '') {
  const result = document.createElement('td');
  result.textContent = String(value ?? '未记录');
  if (className) result.className = className;
  row.append(result);
  return result;
}

function action(label, handler) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'text-button';
  button.textContent = label;
  button.addEventListener('click', handler);
  return button;
}

function renderRecords(items) {
  const container = element('records-container');
  container.replaceChildren();
  if (!items.length) {
    const empty = document.createElement('p');
    empty.className = 'empty-records';
    empty.textContent = activeTab === 'messages' ? '还没有创建记录。' : '还没有解密记录。';
    container.append(empty);
    return;
  }
  const table = document.createElement('table');
  const caption = document.createElement('caption');
  caption.hidden = true;
  caption.textContent = activeTab === 'messages' ? '文字创建记录' : '文字解密记录';
  table.append(caption);
  const head = document.createElement('thead');
  const heading = document.createElement('tr');
  const columns = activeTab === 'messages'
    ? ['创建时间（UTC+8）', '访客编号', 'IP', '消息编号', '内容大小', '查看次数', '操作']
    : ['查看时间（UTC+8）', '访客编号', 'IP', '消息编号', '访问者'];
  for (const title of columns) {
    const th = document.createElement('th');
    th.scope = 'col';
    th.textContent = title;
    heading.append(th);
  }
  head.append(heading);
  table.append(head);
  const body = document.createElement('tbody');
  for (const item of items) {
    const row = document.createElement('tr');
    cell(row, timestamp(activeTab === 'messages' ? item.createdAt : item.viewedAt), 'time-cell');
    cell(row, visitor(item.visitorId), 'code-cell');
    cell(row, item.ip || '未记录', 'code-cell ip-cell');
    if (activeTab === 'messages') {
      cell(row, item.id, 'code-cell');
      cell(row, `${Number(item.byteLength).toLocaleString('zh-CN')} 字节`);
      cell(row, item.viewCount);
      const actions = cell(row, '');
      const wrap = document.createElement('div');
      wrap.className = 'row-actions';
      wrap.append(action('查看原文', () => openMessage(item.id)), action('查看记录', () => filterEvents(item.id)));
      actions.append(wrap);
    } else {
      cell(row, item.messageId, 'code-cell');
      cell(row, item.actor === 'admin' ? '管理员' : '访客');
    }
    body.append(row);
  }
  table.append(body);
  container.append(table);
}

async function loadRecords() {
  const page = pagination[activeTab];
  element('messages-tab').setAttribute('aria-pressed', String(activeTab === 'messages'));
  element('events-tab').setAttribute('aria-pressed', String(activeTab === 'events'));
  element('message-filter-form').hidden = activeTab !== 'events';
  element('records-container').replaceChildren();
  element('page-label').textContent = `第 ${Math.floor(page.offset / PAGE_SIZE) + 1} 页 · 每页最多 30 条`;
  status('records-status', '正在读取…');
  const params = new URLSearchParams({ offset: String(page.offset) });
  if (activeTab === 'events' && messageFilter) params.set('messageId', messageFilter);
  const version = requestVersion;
  const data = await api(`/api/admin/${activeTab}?${params}`);
  if (version !== requestVersion) return;
  page.next = Number.isInteger(data.nextOffset) && data.nextOffset > page.offset ? data.nextOffset : null;
  renderRecords(Array.isArray(data.items) ? data.items : []);
  status('records-status', activeTab === 'events' && messageFilter ? `消息：${messageFilter}` : '');
}

async function refreshRecords(change) {
  if (busy || !authenticated) return;
  if (change) change();
  setBusy(true);
  const version = requestVersion;
  try { await loadRecords(); }
  catch (error) {
    if (version !== requestVersion) return;
    if (error.status === 401) showLogin('登录已过期，请重新输入管理员密码。');
    else status('records-status', error.message, true);
  } finally { if (version === requestVersion) setBusy(false); }
}

function filterEvents(id) {
  return refreshRecords(() => {
    activeTab = 'events';
    messageFilter = id;
    element('message-filter').value = id;
    pagination.events = { offset: 0, next: null };
  });
}

async function openMessage(id) {
  if (busy || !authenticated) return;
  setBusy(true);
  element('dialog-text').textContent = '';
  element('dialog-meta').textContent = `消息：${id}`;
  status('dialog-status', '正在读取…');
  element('message-dialog').showModal();
  const version = requestVersion;
  try {
    const data = await api(`/api/admin/messages/${encodeURIComponent(id)}`);
    if (version !== requestVersion || !element('message-dialog').open) return;
    element('dialog-meta').textContent = `消息：${id} · 创建于 ${timestamp(data.createdAt)}（UTC+8）`;
    element('dialog-text').textContent = data.text;
    status('dialog-status', '此次查看已记入解密记录。');
  } catch (error) {
    if (version !== requestVersion) return;
    if (error.status === 401) showLogin('登录已过期，请重新输入管理员密码。');
    else status('dialog-status', error.message, true);
  } finally { if (version === requestVersion) setBusy(false); }
}

async function initialize() {
  if (busy) return;
  setBusy(true);
  const version = requestVersion;
  try {
    const data = await api('/api/admin/session');
    if (version !== requestVersion) return;
    if (data.authenticated) {
      showDashboard();
      await loadRecords();
    } else showLogin();
  } catch (error) {
    if (version === requestVersion) showLogin(error.message);
  } finally { if (version === requestVersion) setBusy(false); }
}

element('admin-login-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (busy) return;
  const password = element('admin-password').value;
  if (!password) return status('admin-login-status', '请输入管理员密码。', true);
  setBusy(true);
  const version = requestVersion;
  element('admin-login-button').textContent = '正在进入…';
  status('admin-login-status');
  try {
    await api('/api/admin/login', { password });
    if (version !== requestVersion) return;
    element('admin-password').value = '';
    resetPagination();
    showDashboard();
    await loadRecords();
  } catch (error) {
    if (version !== requestVersion) return;
    if (authenticated) status('records-status', error.message, true);
    else status('admin-login-status', error.message, true);
  } finally {
    element('admin-login-button').textContent = '进入后台';
    if (version === requestVersion) setBusy(false);
  }
});

element('admin-logout').addEventListener('click', async () => {
  if (busy) return;
  setBusy(true);
  const version = requestVersion;
  try {
    await api('/api/admin/logout', {});
    if (version !== requestVersion) return;
    resetPagination();
    activeTab = 'messages';
    messageFilter = '';
    element('message-filter').value = '';
    showLogin();
  } catch (error) { if (version === requestVersion) status('records-status', error.message, true); }
  finally { if (version === requestVersion) setBusy(false); }
});

for (const tab of ['messages', 'events']) {
  element(`${tab}-tab`).addEventListener('click', () => refreshRecords(() => { activeTab = tab; }));
}
element('refresh-records').addEventListener('click', () => refreshRecords(() => {
  pagination[activeTab] = { offset: 0, next: null };
}));
element('previous-page').addEventListener('click', () => refreshRecords(() => {
  pagination[activeTab].offset = Math.max(0, pagination[activeTab].offset - PAGE_SIZE);
}));
element('next-page').addEventListener('click', () => {
  if (pagination[activeTab].next !== null) refreshRecords(() => { pagination[activeTab].offset = pagination[activeTab].next; });
});
element('message-filter-form').addEventListener('submit', event => {
  event.preventDefault();
  const id = element('message-filter').value.trim();
  if (id && !/^[A-Za-z0-9_-]{16}$/.test(id)) return status('records-status', '请输入完整的 16 位消息编号。', true);
  filterEvents(id);
});
element('clear-filter').addEventListener('click', () => filterEvents(''));
element('close-dialog').addEventListener('click', closeMessage);
element('message-dialog').addEventListener('close', () => {
  element('dialog-text').textContent = '';
  element('dialog-meta').textContent = '';
  status('dialog-status');
});
window.addEventListener('pagehide', () => {
  requestVersion += 1;
  showLogin();
  setBusy(false);
});
window.addEventListener('pageshow', event => { if (event.persisted) initialize(); });
initialize();
