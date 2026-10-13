'use strict';

const element = (id) => document.getElementById(id);
const panels = ['loading', 'login', 'compose', 'message', 'error'];
const encoder = new TextEncoder();
const MAX_BYTES = 100000;
let authenticated = false;
let busy = false;
let generatedUrl = '';
let openedText = '';

function shareText() {
  return generatedUrl ? `密文请点击链接查看：${generatedUrl}` : '';
}

function status(name, message = '', error = false) {
  const target = element(`${name}-status`);
  target.textContent = message;
  target.dataset.error = String(error);
}

function showPanel(name, intro) {
  for (const panel of panels) element(`${panel}-panel`).hidden = panel !== name;
  const hideHeading = name === 'login' || name === 'loading';
  element('page-header').hidden = hideHeading;
  element('intro').hidden = hideHeading;
  element('intro').textContent = intro;
  element('logout').hidden = !authenticated;
}

function validText() {
  const text = element('message-input').value;
  return /\S/u.test(text) && encoder.encode(text).length <= MAX_BYTES;
}

function setBusy(value) {
  busy = value;
  for (const id of ['password', 'message-input', 'login-button', 'logout', 'copy-link', 'copy-message', 'retry-button']) {
    element(id).disabled = value;
  }
  element('create-button').disabled = value || !validText();
}

async function api(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST',
      credentials: 'same-origin',
      cache: 'no-store',
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

function showLogin(message = '') {
  authenticated = false;
  openedText = '';
  element('message-content').textContent = '';
  showPanel('login', '');
  status('login', message, Boolean(message));
  element('password').focus();
}

function showError(message, retry = true) {
  showPanel('error', '暂时无法打开。');
  element('page-error').textContent = message;
  element('retry-button').hidden = !retry;
}

async function openCurrentPage() {
  const path = window.location.pathname;
  if (path === '/') {
    showPanel('compose', '输入文字，生成一个可以分享的短链接。');
    status('compose');
    element('message-input').focus();
    return;
  }
  const match = /^\/m\/([A-Za-z0-9_-]+)\/?$/.exec(path);
  if (!match) {
    showError('这个页面不存在，请检查链接是否完整。', false);
    return;
  }
  showPanel('loading', '正在打开文字…');
  element('loading-panel').firstElementChild.textContent = '正在读取…';
  try {
    const message = await api(`/api/messages/${encodeURIComponent(match[1])}`);
    openedText = message.text;
    element('message-content').textContent = openedText;
    status('message');
    showPanel('message', '链接中的文字');
  } catch (error) {
    if (error.status === 401) showLogin('登录已过期，请重新输入访问密码。');
    else if (error.status === 404) showError('没有找到这条文字，链接可能有误或内容已被删除。', false);
    else showError(error.message);
  }
}

async function initialize() {
  if (busy) return;
  setBusy(true);
  try {
    const session = await api('/api/session');
    authenticated = Boolean(session.authenticated);
    if (authenticated) await openCurrentPage();
    else showLogin();
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
    if (!element('login-panel').hidden) element('password').focus();
  }
}

element('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy) return;
  const password = element('password').value;
  if (!password) return status('login', '请输入访问密码。', true);
  setBusy(true);
  element('login-button').textContent = '正在进入…';
  status('login');
  try {
    await api('/api/login', { password });
    element('password').value = '';
    authenticated = true;
    await openCurrentPage();
  } catch (error) {
    status('login', error.message, true);
  } finally {
    element('login-button').textContent = '进入';
    setBusy(false);
    if (!element('login-panel').hidden) element('password').focus();
  }
});

element('message-input').addEventListener('input', () => {
  generatedUrl = '';
  element('result').hidden = true;
  element('result-link').removeAttribute('href');
  element('result-link').textContent = '';
  const tooLarge = encoder.encode(element('message-input').value).length > MAX_BYTES;
  status('compose', tooLarge ? '文字过长，请缩短后再生成链接（最多约 3 万个汉字）。' : '', tooLarge);
  element('create-button').disabled = busy || !validText();
});

element('compose-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  if (busy) return;
  const text = element('message-input').value;
  if (!/\S/u.test(text)) return status('compose', '请先输入要分享的文字。', true);
  if (encoder.encode(text).length > MAX_BYTES) return status('compose', '文字过长，请缩短后再生成链接。', true);
  setBusy(true);
  element('create-button').textContent = '正在生成并复制…';
  status('compose');
  element('result').hidden = true;
  try {
    const message = await api('/api/messages', { text });
    const url = new URL(message.url, window.location.origin);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('链接生成失败，请重试。');
    generatedUrl = url.href;
    element('result-link').textContent = shareText();
    element('result-link').href = generatedUrl;
    element('result').hidden = false;
    try {
      await navigator.clipboard.writeText(shareText());
      status('compose', '链接已生成并复制。');
    } catch {
      status('compose', '链接已生成，自动复制未成功，请点击“复制链接”。');
    }
  } catch (error) {
    if (error.status === 401) showLogin('登录已过期，请重新输入访问密码。');
    else status('compose', error.message, true);
  } finally {
    element('create-button').textContent = '生成链接并复制';
    setBusy(false);
    if (!element('login-panel').hidden) element('password').focus();
  }
});

async function copy(text, target, name, label) {
  if (!text || busy) return;
  try {
    await navigator.clipboard.writeText(text);
    status(name, `已复制${label}。`);
  } catch {
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(target);
    selection.removeAllRanges();
    selection.addRange(range);
    status(name, `已选中${label}，请手动复制。`);
  }
}

element('copy-link').addEventListener('click', () => copy(shareText(), element('result-link'), 'compose', '链接'));
element('copy-message').addEventListener('click', () => copy(openedText, element('message-content'), 'message', '文字'));
element('retry-button').addEventListener('click', initialize);
element('logout').addEventListener('click', async () => {
  if (busy) return;
  setBusy(true);
  try {
    await api('/api/logout', {});
    generatedUrl = '';
    openedText = '';
    element('message-input').value = '';
    element('result-link').textContent = '';
    element('result-link').removeAttribute('href');
    element('result').hidden = true;
    element('password').value = '';
    showLogin();
  } catch (error) {
    showError(error.message);
  } finally {
    setBusy(false);
    if (!element('login-panel').hidden) element('password').focus();
  }
});

window.addEventListener('pagehide', () => {
  openedText = '';
  element('message-content').textContent = '';
});
window.addEventListener('pageshow', (event) => {
  if (event.persisted) {
    showPanel('loading', '正在检查登录状态…');
    initialize();
  }
});

initialize();
