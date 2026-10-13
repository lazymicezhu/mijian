import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes, randomInt } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { startServer } from '../server.mjs';

const PASSWORD = 'test-only-共享密码-2026';
const UNKNOWN_ID = 'AAAAAAAAAAAAAAAA';

async function fixture(t, overrides = {}) {
  const dataDir = await mkdtemp(join(tmpdir(), 'aes-links-test-'));
  let app;
  let options = { dev: true, dataDir, accessPassword: PASSWORD, ...overrides };
  t.after(async () => {
    try { if (app) await app.close(); }
    finally { await rm(dataDir, { recursive: true, force: true }); }
  });
  for (let attempt = 0; attempt < 10; attempt++) {
    options.port = randomInt(20000, 65000);
    // Model the HTTP hop from a TLS proxy; fetch supplies the actual Host header.
    if (!options.dev && !overrides.publicUrl) options.publicUrl = `https://127.0.0.1:${options.port}`;
    try { app = await startServer(options); break; }
    catch (error) { if (error.code !== 'EADDRINUSE' || attempt === 9) throw error; }
  }
  return {
    dataDir,
    get app() { return app; },
    async restart(changes = {}) {
      await app.close();
      app = undefined;
      options = { ...options, ...changes };
      app = await startServer(options);
    },
  };
}

async function request(f, path, options = {}) {
  const hasJson = Object.hasOwn(options, 'json');
  const body = hasJson ? JSON.stringify(options.json) : options.raw;
  const method = options.method ?? (body === undefined ? 'GET' : 'POST');
  const headers = { Connection: 'close', ...options.headers };
  if (method === 'POST') headers.Origin = options.origin ?? f.app.config.origin;
  if (hasJson) headers['Content-Type'] = 'application/json';
  if (options.cookie) headers.Cookie = options.cookie;
  const response = await fetch(`http://127.0.0.1:${f.app.config.port}${path}`, {
    method, headers, body, signal: AbortSignal.timeout(10000),
  });
  const text = await response.text();
  return { response, data: text ? JSON.parse(text) : null };
}

async function login(f, password = PASSWORD, requestOptions = {}) {
  const result = await request(f, '/api/login', { json: { password }, ...requestOptions });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  const setCookie = result.response.headers.get('set-cookie');
  assert.ok(setCookie);
  return { ...result, setCookie, cookie: setCookie.split(';')[0] };
}

async function createMessage(f, cookie, text) {
  const result = await request(f, '/api/messages', { cookie, json: { text } });
  assert.equal(result.response.status, 201, JSON.stringify(result.data));
  assert.match(result.data.id, /^[A-Za-z0-9_-]{16}$/);
  assert.equal(result.data.url, `${f.app.config.origin}/m/${result.data.id}`);
  return result.data;
}

test('authentication, Chinese text round-trip, access control, and encrypted storage', async (t) => {
  const f = await fixture(t);
  let cookie, id;
  const text = '  你好，世界！\n第二行：🔐 👩🏽‍💻\t保留空格  \n<script>alert("仅作为文字")</script>\n';

  await t.test('anonymous requests cannot create or read messages', async () => {
    const session = await request(f, '/api/session');
    assert.deepEqual(session.data, { authenticated: false });
    assert.equal((await request(f, '/api/messages', { json: { text } })).response.status, 401);
    assert.equal((await request(f, `/api/messages/${UNKNOWN_ID}`)).response.status, 401);
  });

  await t.test('wrong passwords do not issue a session; a correct password does', async () => {
    const wrong = await request(f, '/api/login', { json: { password: 'wrong-password' } });
    assert.equal(wrong.response.status, 401);
    assert.equal(wrong.response.headers.get('set-cookie'), null);
    const result = await login(f);
    cookie = result.cookie;
    assert.match(result.setCookie, /^aes_links_preview=[A-Za-z0-9_-]{43};/);
    assert.match(result.setCookie, /; Path=\//);
    assert.match(result.setCookie, /; HttpOnly/);
    assert.match(result.setCookie, /; SameSite=Lax/);
    assert.match(result.setCookie, /; Max-Age=2592000/);
    assert.deepEqual((await request(f, '/api/session', { cookie })).data, { authenticated: true });
    const db = new DatabaseSync(join(f.dataDir, 'messages.sqlite'));
    try {
      const row = db.prepare('SELECT token_hash, expires_at FROM sessions').get();
      const token = cookie.split('=')[1];
      assert.equal(row.token_hash, createHash('sha256').update(token).digest('hex'));
      assert.notEqual(row.token_hash, token);
      assert.ok(row.expires_at > Date.now() + 29 * 86400000);
    } finally { db.close(); }
  });

  await t.test('Chinese, emoji, markup, newlines, and whitespace round-trip exactly', async () => {
    const message = await createMessage(f, cookie, text);
    id = message.id;
    const result = await request(f, `/api/messages/${id}`, { cookie });
    assert.equal(result.response.status, 200);
    assert.equal(result.data.text, text);
    assert.ok(Number.isFinite(Date.parse(result.data.createdAt)));
    assert.equal(result.response.headers.get('cache-control'), 'no-store');
    assert.equal(result.response.headers.get('referrer-policy'), 'no-referrer');
    assert.equal(result.response.headers.get('x-content-type-options'), 'nosniff');
    assert.equal((await request(f, `/api/messages/${id}`)).response.status, 401);
  });

  await t.test('database stores ciphertext and encrypts identical texts differently', async () => {
    const second = await createMessage(f, cookie, text);
    assert.notEqual(second.id, id);
    const db = new DatabaseSync(join(f.dataDir, 'messages.sqlite'));
    try {
      const firstRow = db.prepare('SELECT * FROM messages WHERE id = ?').get(id);
      const secondRow = db.prepare('SELECT * FROM messages WHERE id = ?').get(second.id);
      assert.equal(firstRow.iv.length, 12);
      assert.equal(firstRow.tag.length, 16);
      assert.notDeepEqual(firstRow.iv, secondRow.iv);
      assert.notDeepEqual(firstRow.ciphertext, secondRow.ciphertext);
      assert.equal(Buffer.from(firstRow.ciphertext).includes(Buffer.from(text)), false);
    } finally { db.close(); }
    for (const name of (await readdir(f.dataDir)).filter(name => name.startsWith('messages.sqlite'))) {
      assert.equal((await readFile(join(f.dataDir, name))).includes(Buffer.from(text)), false, `plaintext leaked in ${name}`);
    }
  });

  await t.test('forged origins cannot log in, create, or log out', async () => {
    for (const [path, json] of [['/api/login', { password: PASSWORD }], ['/api/messages', { text }], ['/api/logout', {}]]) {
      assert.equal((await request(f, path, { cookie, json, origin: 'https://other.example' })).response.status, 403);
    }
    assert.deepEqual((await request(f, '/api/session', { cookie })).data, { authenticated: true });
  });

  await t.test('unknown and malformed IDs return 404 only after authentication', async () => {
    assert.equal((await request(f, `/api/messages/${UNKNOWN_ID}`, { cookie })).response.status, 404);
    assert.equal((await request(f, '/api/messages/not-valid!', { cookie })).response.status, 404);
  });

  await t.test('tampered ciphertext fails closed without returning plaintext or a stack', async () => {
    const db = new DatabaseSync(join(f.dataDir, 'messages.sqlite'));
    try {
      const row = db.prepare('SELECT ciphertext FROM messages WHERE id = ?').get(id);
      const changed = Buffer.from(row.ciphertext);
      changed[0] ^= 1;
      db.prepare('UPDATE messages SET ciphertext = ? WHERE id = ?').run(changed, id);
    } finally { db.close(); }
    const result = await request(f, `/api/messages/${id}`, { cookie });
    assert.equal(result.response.status, 500);
    assert.deepEqual(Object.keys(result.data), ['error']);
    assert.equal(JSON.stringify(result.data).includes(text), false);
    assert.doesNotMatch(result.data.error, /Error|stack|at /);
  });

  await t.test('logout revokes the old cookie on the server', async () => {
    const result = await request(f, '/api/logout', { cookie, json: {} });
    assert.equal(result.response.status, 200);
    assert.match(result.response.headers.get('set-cookie'), /Max-Age=0/);
    assert.deepEqual((await request(f, '/api/session', { cookie })).data, { authenticated: false });
    assert.equal((await request(f, `/api/messages/${id}`, { cookie })).response.status, 401);
    assert.equal((await request(f, '/api/messages', { cookie, json: { text } })).response.status, 401);
  });
});

test('JSON, content type, text types, UTF-8 limits, and overall body limits are enforced', async (t) => {
  const f = await fixture(t);
  const { cookie } = await login(f);
  assert.equal((await request(f, '/api/messages', { cookie, raw: 'not JSON', headers: { 'Content-Type': 'application/json' } })).response.status, 400);
  assert.equal((await request(f, '/api/messages', { cookie, json: [] })).response.status, 400);
  assert.equal((await request(f, '/api/messages', { cookie, json: null })).response.status, 400);
  assert.equal((await request(f, '/api/messages', { cookie, raw: '{}', headers: { 'Content-Type': 'text/plain' } })).response.status, 415);
  for (const text of [null, 42, {}, '', ' \n\t ']) {
    assert.equal((await request(f, '/api/messages', { cookie, json: { text } })).response.status, 400);
  }
  assert.equal((await request(f, '/api/messages', { cookie, json: { text: '中'.repeat(33334) } })).response.status, 413);
  assert.equal((await request(f, '/api/messages', { cookie, json: { text: 'a'.repeat(610001) } })).response.status, 413);
  const boundaryText = 'a'.repeat(100000);
  const message = await createMessage(f, cookie, boundaryText);
  assert.equal((await request(f, `/api/messages/${message.id}`, { cookie })).data.text, boundaryText);
});

test('messages and sessions survive restart; password rotation revokes old sessions', async (t) => {
  const f = await fixture(t);
  const { cookie } = await login(f);
  const text = '重启后仍然可以阅读 🔑\n  密码更新不会丢失这条文字。';
  const message = await createMessage(f, cookie, text);
  await f.restart();
  assert.deepEqual((await request(f, '/api/session', { cookie })).data, { authenticated: true });
  assert.equal((await request(f, `/api/messages/${message.id}`, { cookie })).data.text, text);
  const newPassword = 'replacement-共享密码-2026';
  await f.restart({ accessPassword: newPassword });
  assert.deepEqual((await request(f, '/api/session', { cookie })).data, { authenticated: false });
  assert.equal((await request(f, `/api/messages/${message.id}`, { cookie })).response.status, 401);
  assert.equal((await request(f, '/api/login', { json: { password: PASSWORD } })).response.status, 401);
  const fresh = await login(f, newPassword);
  assert.equal((await request(f, `/api/messages/${message.id}`, { cookie: fresh.cookie })).data.text, text);
});

test('expired sessions are rejected even when the browser still sends the cookie', async (t) => {
  const f = await fixture(t);
  const { cookie } = await login(f);
  const db = new DatabaseSync(join(f.dataDir, 'messages.sqlite'));
  try { db.prepare('UPDATE sessions SET expires_at = ?').run(Date.now() - 1); }
  finally { db.close(); }
  assert.deepEqual((await request(f, '/api/session', { cookie })).data, { authenticated: false });
  assert.equal((await request(f, '/api/messages', { cookie, json: { text: '会话过期' } })).response.status, 401);
});

test('production refuses an HTTP public origin', async () => {
  const dataDir = await mkdtemp(join(tmpdir(), 'aes-links-http-test-'));
  try {
    await assert.rejects(startServer({
      dev: false, dataDir, port: randomInt(20000, 65000), accessPassword: PASSWORD,
      encryptionKey: randomBytes(32).toString('base64'), publicUrl: 'http://example.test',
    }), /HTTPS/);
  } finally { await rm(dataDir, { recursive: true, force: true }); }
});

test('production cookies are secure and trusted proxy rate limits isolate client IPs', async (t) => {
  const f = await fixture(t, {
    dev: false, encryptionKey: randomBytes(32).toString('base64'), trustProxy: 'loopback',
  });
  assert.equal(f.app.config.bindHost, '127.0.0.1');
  const headers = {};
  assert.equal((await request(f, '/api/login', { headers, json: { password: PASSWORD } })).response.status, 403);
  assert.equal((await request(f, '/api/login', { headers: { ...headers, 'X-Real-IP': '1.2.3.4, 5.6.7.8' }, json: { password: PASSWORD } })).response.status, 403);
  for (let attempt = 0; attempt < 10; attempt++) {
    const result = await request(f, '/api/login', { headers: { ...headers, 'X-Real-IP': '192.0.2.10' }, json: { password: 'wrong-password' } });
    assert.equal(result.response.status, 401, JSON.stringify(result.data));
  }
  assert.equal((await request(f, '/api/login', { headers: { ...headers, 'X-Real-IP': '192.0.2.10' }, json: { password: PASSWORD } })).response.status, 429);
  const result = await login(f, PASSWORD, { headers: { ...headers, 'X-Real-IP': '192.0.2.11' } });
  assert.match(result.setCookie, /^__Host-aes_links=/);
  assert.match(result.setCookie, /; Secure/);
  assert.match(result.setCookie, /; HttpOnly/);
  assert.match(result.setCookie, /; SameSite=Lax/);
});
