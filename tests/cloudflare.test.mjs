import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';

const PASSWORD = 'test-only-共享密码-2026';
const ADMIN_PASSWORD = 'test-only-independent-admin-2026';
const ORIGIN = 'https://mijian.example';
const UNKNOWN_ID = 'AAAAAAAAAAAAAAAA';
const ROOT = fileURLToPath(new URL('../', import.meta.url));

async function fixture(t, overrides = {}) {
  const dataDir = await mkdtemp(join(tmpdir(), 'mijian-d1-test-'));
  let bindings = {
    ACCESS_PASSWORD: PASSWORD,
    ENCRYPTION_KEY: randomBytes(32).toString('base64'),
    PUBLIC_URL: ORIGIN,
    ...overrides,
  };
  let withDatabase = true;
  const options = () => convertV4MiniflareOptions({
    modulesRoot: ROOT,
    modules: [
      { type: 'ESModule', path: join(ROOT, 'tests/fixtures/cloudflare-worker.mjs') },
      { type: 'ESModule', path: join(ROOT, 'lib/cloudflare-app.mjs') },
    ],
    compatibilityDate: '2026-01-01',
    bindings,
    d1Databases: withDatabase ? { DB: '00000000-0000-4000-8000-000000000001' } : {},
    resourcePersistencePath: dataDir,
    telemetry: { enabled: false },
  });
  let mf;
  t.after(async () => {
    try { if (mf) await mf.dispose(); }
    finally { await rm(dataDir, { recursive: true, force: true }); }
  });
  mf = new Miniflare(options());
  const db = await mf.getD1Database('DB');
  const migrationNames = (await readdir(join(ROOT, 'migrations'))).filter(name => name.endsWith('.sql')).sort();
  for (const name of migrationNames) {
    const migration = await readFile(join(ROOT, 'migrations', name), 'utf8');
    const statements = migration.replace(/^\s*--.*$/gm, '').split(';').map(sql => sql.trim()).filter(Boolean);
    await db.batch(statements.map(sql => db.prepare(sql)));
  }
  return {
    get mf() { return mf; },
    get bindings() { return bindings; },
    get db() { return mf.getD1Database('DB'); },
    async restart(changes = {}, { database = true } = {}) {
      await mf.dispose();
      bindings = { ...bindings, ...changes };
      withDatabase = database;
      mf = new Miniflare(options());
      await mf.ready;
    },
  };
}

async function request(f, path, options = {}) {
  const hasJson = Object.hasOwn(options, 'json');
  const body = hasJson ? JSON.stringify(options.json) : options.raw;
  const method = options.method ?? (body === undefined ? 'GET' : 'POST');
  const headers = { Connection: 'close', 'CF-Connecting-IP': options.ip ?? '192.0.2.10', ...options.headers };
  if (method === 'POST' && options.origin !== null) headers.Origin = options.origin ?? ORIGIN;
  if (hasJson) headers['Content-Type'] = 'application/json';
  if (options.cookie) headers.Cookie = options.cookie;
  const response = await f.mf.dispatchFetch(`${options.host ?? ORIGIN}${path}`, { method, headers, body });
  const text = await response.text();
  return { response, data: text ? JSON.parse(text) : null };
}

async function login(f, password = PASSWORD, options = {}) {
  const result = await request(f, '/api/login', { json: { password }, ...options });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  const setCookie = responseCookies(result.response).find(value => value.startsWith('__Host-aes_links='));
  assert.ok(setCookie);
  return { ...result, setCookie, cookie: setCookie.split(';')[0], visitorCookie: visitorCookie(result.response) };
}

function responseCookies(response) {
  return response.headers.getSetCookie();
}

function visitorCookie(response) {
  return responseCookies(response).find(value => value.startsWith('__Host-mijian_visitor='))?.split(';')[0];
}

async function adminLogin(f, password = ADMIN_PASSWORD, options = {}) {
  const result = await request(f, '/api/admin/login', { json: { password }, ...options });
  assert.equal(result.response.status, 200, JSON.stringify(result.data));
  const setCookie = responseCookies(result.response).find(value => value.startsWith('__Host-mijian_admin='));
  assert.ok(setCookie);
  return { ...result, setCookie, cookie: setCookie.split(';')[0], visitorCookie: visitorCookie(result.response) };
}

async function createMessage(f, cookie, text, options = {}) {
  const result = await request(f, '/api/messages', { cookie, json: { text }, ...options });
  assert.equal(result.response.status, 201, JSON.stringify(result.data));
  assert.match(result.data.id, /^[A-Za-z0-9_-]{16}$/);
  assert.equal(result.data.url, `${ORIGIN}/m/${result.data.id}`);
  return result.data;
}

test('Cloudflare D1 authentication, encrypted text, and access control', async (t) => {
  const f = await fixture(t);
  let cookie, id;
  const text = '  你好，世界！\n第二行：🔐 👩🏽‍💻\t保留空格  \n<script>alert("仅作为文字")</script>\n';

  await t.test('anonymous requests cannot create or read messages', async () => {
    assert.deepEqual((await request(f, '/api/session')).data, { authenticated: false });
    assert.equal((await request(f, '/api/messages', { json: { text } })).response.status, 401);
    assert.equal((await request(f, `/api/messages/${UNKNOWN_ID}`)).response.status, 401);
  });

  await t.test('wrong passwords are refused and valid login issues a secure hashed session', async () => {
    const wrong = await request(f, '/api/login', { json: { password: 'wrong-password' } });
    assert.equal(wrong.response.status, 401);
    assert.equal(wrong.response.headers.get('set-cookie'), null);
    const result = await login(f);
    cookie = result.cookie;
    assert.match(result.setCookie, /^__Host-aes_links=[A-Za-z0-9_-]{43};/);
    for (const flag of [/; Path=\//, /; HttpOnly/, /; Secure/, /; SameSite=Lax/, /; Max-Age=2592000/]) {
      assert.match(result.setCookie, flag);
    }
    assert.doesNotMatch(result.setCookie, /Domain=/i);
    assert.deepEqual((await request(f, '/api/session', { cookie })).data, { authenticated: true });
    const row = await (await f.db).prepare('SELECT token_hash, expires_at FROM sessions').first();
    const token = cookie.split('=')[1];
    assert.equal(row.token_hash, createHash('sha256').update(token).digest('hex'));
    assert.notEqual(row.token_hash, token);
    assert.ok(row.expires_at > Date.now() + 29 * 86400000);
  });

  await t.test('Chinese, emoji, markup, and whitespace round-trip exactly', async () => {
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

  await t.test('D1 stores authenticated ciphertext and fresh nonces for identical text', async () => {
    const second = await createMessage(f, cookie, text);
    assert.notEqual(second.id, id);
    const db = await f.db;
    const firstRow = await db.prepare('SELECT * FROM messages WHERE id = ?').bind(id).first();
    const secondRow = await db.prepare('SELECT * FROM messages WHERE id = ?').bind(second.id).first();
    assert.equal(firstRow.iv.length, 12);
    assert.equal(firstRow.tag.length, 16);
    assert.notDeepEqual(firstRow.iv, secondRow.iv);
    assert.notDeepEqual(firstRow.ciphertext, secondRow.ciphertext);
    assert.equal(Buffer.from(firstRow.ciphertext).includes(Buffer.from(text)), false);
    const keyMetadata = await db.prepare("SELECT value FROM metadata WHERE name = 'key_id'").first();
    assert.equal(keyMetadata.value, createHash('sha256').update(Buffer.from(f.bindings.ENCRYPTION_KEY, 'base64')).digest('hex'));
    const dump = JSON.stringify(await db.prepare('SELECT * FROM metadata').all());
    assert.equal(dump.includes(PASSWORD), false);
    assert.equal(dump.includes(f.bindings.ENCRYPTION_KEY), false);
  });

  await t.test('Cloudflare can decrypt the original Node AES-GCM storage format', async () => {
    const legacyId = randomBytes(12).toString('base64url');
    const legacyText = '原 Node 版本加密的文字，迁移后仍可阅读 🔑';
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', Buffer.from(f.bindings.ENCRYPTION_KEY, 'base64'), iv);
    cipher.setAAD(Buffer.from(legacyId));
    const ciphertext = Buffer.concat([cipher.update(legacyText, 'utf8'), cipher.final()]);
    await (await f.db).prepare('INSERT INTO messages (id, iv, ciphertext, tag, created_at) VALUES (?, ?, ?, ?, ?)')
      .bind(legacyId, [...iv], [...ciphertext], [...cipher.getAuthTag()], Date.now()).run();
    const result = await request(f, `/api/messages/${legacyId}`, { cookie });
    assert.equal(result.response.status, 200);
    assert.equal(result.data.text, legacyText);
  });

  await t.test('forged or missing origins and an unexpected host cannot change data', async () => {
    for (const [path, json] of [['/api/login', { password: PASSWORD }], ['/api/messages', { text }], ['/api/logout', {}]]) {
      for (const origin of ['https://other.example', null]) {
        assert.equal((await request(f, path, { cookie, json, origin })).response.status, 403);
      }
    }
    assert.equal((await request(f, '/api/session', { cookie, host: 'https://other.example' })).response.status, 403);
    assert.equal((await request(f, '/api/session', { cookie, host: 'https://old-preview.mijian.pages.dev' })).response.status, 403);
    assert.deepEqual((await request(f, '/api/session', { cookie })).data, { authenticated: true });
  });

  await t.test('unknown and malformed IDs return 404 after authentication', async () => {
    assert.equal((await request(f, `/api/messages/${UNKNOWN_ID}`, { cookie })).response.status, 404);
    assert.equal((await request(f, '/api/messages/not-valid!', { cookie })).response.status, 404);
  });

  await t.test('encrypted messages and sessions survive worker restart', async () => {
    await f.restart();
    assert.deepEqual((await request(f, '/api/session', { cookie })).data, { authenticated: true });
    assert.equal((await request(f, `/api/messages/${id}`, { cookie })).data.text, text);
  });

  await t.test('changing the shared password invalidates old sessions without losing messages', async () => {
    const originalCookie = cookie;
    const nextPassword = 'replacement-共享密码-2026';
    await f.restart({ ACCESS_PASSWORD: nextPassword });
    assert.deepEqual((await request(f, '/api/session', { cookie })).data, { authenticated: false });
    assert.equal((await request(f, `/api/messages/${id}`, { cookie })).response.status, 401);
    assert.equal((await request(f, '/api/login', { json: { password: PASSWORD } })).response.status, 401);
    ({ cookie } = await login(f, nextPassword));
    assert.equal((await request(f, `/api/messages/${id}`, { cookie })).data.text, text);
    await f.restart({ ACCESS_PASSWORD: PASSWORD });
    assert.deepEqual((await request(f, '/api/session', { cookie: originalCookie })).data, { authenticated: false });
    assert.deepEqual((await request(f, '/api/session', { cookie })).data, { authenticated: false });
    ({ cookie } = await login(f));
    assert.equal((await request(f, `/api/messages/${id}`, { cookie })).data.text, text);
  });

  await t.test('tampered ciphertext fails closed without exposing text or an exception', async () => {
    const db = await f.db;
    const row = await db.prepare('SELECT ciphertext FROM messages WHERE id = ?').bind(id).first();
    const changed = Buffer.from(row.ciphertext);
    changed[0] ^= 1;
    await db.prepare('UPDATE messages SET ciphertext = ? WHERE id = ?').bind([...changed], id).run();
    const result = await request(f, `/api/messages/${id}`, { cookie });
    assert.equal(result.response.status, 500);
    assert.deepEqual(Object.keys(result.data), ['error']);
    assert.equal(JSON.stringify(result.data).includes(text), false);
    assert.doesNotMatch(result.data.error, /Error|stack|at /);
  });

  await t.test('logout revokes the session on the server', async () => {
    const result = await request(f, '/api/logout', { cookie, json: {} });
    assert.equal(result.response.status, 200);
    assert.match(result.response.headers.get('set-cookie'), /Max-Age=0/);
    assert.deepEqual((await request(f, '/api/session', { cookie })).data, { authenticated: false });
    assert.equal((await request(f, '/api/messages', { cookie, json: { text } })).response.status, 401);
  });
});

test('Cloudflare validates JSON, content type, and UTF-8 message size', async (t) => {
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

test('Cloudflare rejects expired and malformed session cookies', async (t) => {
  const f = await fixture(t);
  const { cookie } = await login(f);
  await (await f.db).prepare('UPDATE sessions SET expires_at = ?').bind(Date.now() - 1).run();
  for (const rejected of [cookie, '__Host-aes_links=bad-token', '__Host-aes_links=' + randomBytes(32).toString('base64url')]) {
    assert.deepEqual((await request(f, '/api/session', { cookie: rejected })).data, { authenticated: false });
    assert.equal((await request(f, '/api/messages', { cookie: rejected, json: { text: '会话过期' } })).response.status, 401);
  }
});

test('Cloudflare missing or wrong encryption keys fail closed and preserve existing data', async (t) => {
  const f = await fixture(t);
  const { cookie } = await login(f);
  const originalKey = f.bindings.ENCRYPTION_KEY;
  const message = await createMessage(f, cookie, '密钥配置错误不能覆盖已有内容。');
  const before = await (await f.db).prepare('SELECT * FROM messages WHERE id = ?').bind(message.id).first();
  for (const key of ['', 'invalid-base64', randomBytes(32).toString('base64')]) {
    await f.restart({ ENCRYPTION_KEY: key });
    const result = await request(f, `/api/messages/${message.id}`, { cookie });
    assert.equal(result.response.status, 503);
    assert.deepEqual(Object.keys(result.data), ['error']);
    assert.equal((await request(f, '/api/messages', { cookie, json: { text: '不能写入' } })).response.status, 503);
    assert.deepEqual(await (await f.db).prepare('SELECT * FROM messages WHERE id = ?').bind(message.id).first(), before);
  }
  await f.restart({ ENCRYPTION_KEY: originalKey });
  assert.equal((await request(f, `/api/messages/${message.id}`, { cookie })).data.text, '密钥配置错误不能覆盖已有内容。');
  assert.equal((await (await f.db).prepare('SELECT COUNT(*) AS count FROM messages').first()).count, 1);
});

test('Cloudflare refuses incomplete configuration and local preview mode on a public site', async (t) => {
  const f = await fixture(t);
  await f.restart({}, { database: false });
  assert.equal((await request(f, '/api/session')).response.status, 503);
  await f.restart({ ACCESS_PASSWORD: '' });
  assert.equal((await request(f, '/api/login', { json: { password: PASSWORD } })).response.status, 503);
  await f.restart({ ACCESS_PASSWORD: PASSWORD, LOCAL_DEV: 'true' });
  assert.equal((await request(f, '/api/session')).response.status, 503);
  await f.restart({ LOCAL_DEV: '', PUBLIC_URL: 'http://mijian.example' });
  assert.equal((await request(f, '/api/session')).response.status, 503);
  await f.restart({ PUBLIC_URL: '' });
  assert.equal((await request(f, '/api/session')).response.status, 503);
  await f.restart({ PUBLIC_URL: ORIGIN });
  assert.equal((await request(f, '/api/session', { host: 'http://mijian.example' })).response.status, 403);
  assert.deepEqual((await request(f, '/api/session')).data, { authenticated: false });
});

test('Cloudflare D1 login limits persist after restart and isolate different clients', async (t) => {
  const f = await fixture(t);
  const blockedIp = '192.0.2.50';
  for (let attempt = 0; attempt < 10; attempt++) {
    assert.equal((await request(f, '/api/login', { ip: blockedIp, json: { password: 'wrong-password' } })).response.status, 401);
  }
  await f.restart();
  const blocked = await request(f, '/api/login', { ip: blockedIp, json: { password: PASSWORD } });
  assert.equal(blocked.response.status, 429);
  assert.ok(Number(blocked.response.headers.get('retry-after')) > 0);
  await login(f, PASSWORD, { ip: '192.0.2.51' });
  const rows = await (await f.db).prepare('SELECT rate_key FROM rate_limits').all();
  assert.equal(JSON.stringify(rows).includes(blockedIp), false);
  await (await f.db).prepare('UPDATE rate_limits SET expires_at = ?').bind(Date.now() - 1).run();
  await login(f, PASSWORD, { ip: blockedIp });
});

test('Cloudflare D1 creation limits persist after restart and apply per session', async (t) => {
  const f = await fixture(t);
  const { cookie } = await login(f);
  for (let index = 0; index < 60; index++) {
    await createMessage(f, cookie, `第 ${index + 1} 条合成测试内容`);
  }
  await f.restart();
  const blocked = await request(f, '/api/messages', { cookie, json: { text: '第 61 条' } });
  assert.equal(blocked.response.status, 429);
  assert.ok(Number(blocked.response.headers.get('retry-after')) > 0);
  const another = await login(f, PASSWORD, { ip: '192.0.2.20' });
  await createMessage(f, another.cookie, '另一个会话仍可创建内容');
  assert.equal((await (await f.db).prepare('SELECT COUNT(*) AS count FROM messages').first()).count, 61);
  await (await f.db).prepare('UPDATE rate_limits SET expires_at = ?').bind(Date.now() - 1).run();
  await createMessage(f, cookie, '限流时间过后恢复创建');
});

test('admin authentication is separate from public access and has an eight-hour secure session', async (t) => {
  const f = await fixture(t, { ADMIN_PASSWORD });
  const visitor = await login(f);
  const message = await createMessage(f, visitor.cookie, '仅经正确权限读取的内容');
  for (const cookie of [undefined, visitor.cookie]) {
    assert.deepEqual((await request(f, '/api/admin/session', { cookie })).data, { authenticated: false });
    for (const path of ['/api/admin/messages', '/api/admin/events', `/api/admin/messages/${message.id}`]) {
      assert.equal((await request(f, path, { cookie })).response.status, 401);
    }
  }
  for (const password of ['incorrect-admin-password', PASSWORD]) {
    const result = await request(f, '/api/admin/login', { json: { password } });
    assert.equal(result.response.status, 401);
    assert.equal(result.response.headers.get('set-cookie'), null);
  }
  const admin = await adminLogin(f);
  assert.match(admin.setCookie, /^__Host-mijian_admin=[A-Za-z0-9_-]{43};/);
  for (const flag of [/; Path=\//, /; HttpOnly/, /; Secure/, /; SameSite=Lax/, /; Max-Age=28800/]) {
    assert.match(admin.setCookie, flag);
  }
  assert.doesNotMatch(admin.setCookie, /Domain=/i);
  const row = await (await f.db).prepare('SELECT * FROM admin_sessions').first();
  const token = admin.cookie.split('=')[1];
  assert.equal(row.token_hash, createHash('sha256').update(token).digest('hex'));
  assert.ok(row.expires_at > Date.now() + 7 * 60 * 60 * 1000);
  assert.ok(row.expires_at <= Date.now() + 8 * 60 * 60 * 1000);
  assert.deepEqual((await request(f, '/api/admin/session', { cookie: admin.cookie })).data, { authenticated: true });
  assert.deepEqual((await request(f, '/api/session', { cookie: admin.cookie })).data, { authenticated: false });
  assert.equal((await request(f, `/api/messages/${message.id}`, { cookie: admin.cookie })).response.status, 401);
  assert.equal((await request(f, '/api/messages', { cookie: admin.cookie, json: { text: '缺少公开会话' } })).response.status, 401);
  for (const origin of ['https://other.example', null]) {
    assert.equal((await request(f, '/api/admin/login', { json: { password: ADMIN_PASSWORD }, origin })).response.status, 403);
    assert.equal((await request(f, '/api/admin/logout', { cookie: admin.cookie, json: {}, origin })).response.status, 403);
  }
  assert.deepEqual((await request(f, '/api/admin/session', { cookie: admin.cookie })).data, { authenticated: true });
});

test('visitor identity survives logout and audit records contain creator and successful reader details', async (t) => {
  const f = await fixture(t, { ADMIN_PASSWORD });
  const author = await login(f, PASSWORD, { ip: '192.0.2.70' });
  assert.match(author.visitorCookie, /^__Host-mijian_visitor=[A-Za-z0-9_-]{16}$/);
  const authorId = author.visitorCookie.split('=')[1];
  const visitorHeader = responseCookies(author.response).find(value => value.startsWith('__Host-mijian_visitor='));
  for (const flag of [/; Path=\//, /; HttpOnly/, /; Secure/, /; SameSite=Lax/, /; Max-Age=15552000/]) {
    assert.match(visitorHeader, flag);
  }
  const db = await f.db;
  const authorSession = await db.prepare('SELECT visitor_id FROM session_visitors WHERE token_hash = ?')
    .bind(createHash('sha256').update(author.cookie.split('=')[1]).digest('hex')).first();
  assert.equal(authorSession.visitor_id, authorId);

  const plaintext = '审计只保存访客编号和 IP，不复制这段原文 🔐';
  // Omitting the visitor cookie must not change the identity attached to an active session.
  const message = await createMessage(f, author.cookie, plaintext, {
    ip: '192.0.2.71', headers: { 'X-Forwarded-For': '198.51.100.200' },
  });
  const activity = await db.prepare('SELECT * FROM message_activity WHERE message_id = ?').bind(message.id).first();
  assert.equal(activity.visitor_id, authorId);
  assert.equal(activity.ip, '192.0.2.71');
  assert.equal(activity.byte_length, Buffer.byteLength(plaintext));
  assert.equal(JSON.stringify(activity).includes(plaintext), false);

  const logout = await request(f, '/api/logout', { cookie: `${author.cookie}; ${author.visitorCookie}`, json: {} });
  assert.equal(logout.response.status, 200);
  assert.equal(responseCookies(logout.response).some(value => value.startsWith('__Host-mijian_visitor=') && value.includes('Max-Age=0')), false);
  const returning = await login(f, PASSWORD, { cookie: author.visitorCookie, ip: '192.0.2.70' });
  assert.equal(returning.visitorCookie, author.visitorCookie);

  const reader = await login(f, PASSWORD, { ip: '192.0.2.80' });
  const readerId = reader.visitorCookie.split('=')[1];
  assert.notEqual(readerId, authorId);
  const earliest = Date.now();
  const read = await request(f, `/api/messages/${message.id}`, {
    cookie: reader.cookie, ip: '192.0.2.81', headers: { 'X-Forwarded-For': '198.51.100.200' },
  });
  assert.equal(read.data.text, plaintext);
  const event = await db.prepare('SELECT * FROM access_events WHERE message_id = ?').bind(message.id).first();
  assert.equal(event.visitor_id, readerId);
  assert.equal(event.ip, '192.0.2.81');
  assert.equal(event.actor, 'visitor');
  assert.ok(event.viewed_at >= earliest && event.viewed_at <= Date.now());
  assert.equal(JSON.stringify(event).includes(plaintext), false);

  assert.equal((await request(f, `/api/messages/${message.id}`)).response.status, 401);
  assert.equal((await request(f, `/api/messages/${UNKNOWN_ID}`, { cookie: reader.cookie })).response.status, 404);
  assert.equal((await request(f, '/api/messages/bad-id', { cookie: reader.cookie })).response.status, 404);
  assert.equal((await db.prepare('SELECT COUNT(*) AS count FROM access_events').first()).count, 1);

  const admin = await adminLogin(f, ADMIN_PASSWORD, { ip: '192.0.2.90' });
  const adminRead = await request(f, `/api/admin/messages/${message.id}`, { cookie: admin.cookie, ip: '192.0.2.91' });
  assert.equal(adminRead.response.status, 200);
  assert.equal(adminRead.data.text, plaintext);
  const adminEvent = await db.prepare('SELECT * FROM access_events ORDER BY id DESC LIMIT 1').first();
  assert.equal(adminEvent.actor, 'admin');
  assert.equal(adminEvent.visitor_id, admin.visitorCookie.split('=')[1]);
  assert.equal(adminEvent.ip, '192.0.2.91');

  const row = await db.prepare('SELECT ciphertext FROM messages WHERE id = ?').bind(message.id).first();
  const tampered = Buffer.from(row.ciphertext);
  tampered[0] ^= 1;
  await db.prepare('UPDATE messages SET ciphertext = ? WHERE id = ?').bind([...tampered], message.id).run();
  assert.equal((await request(f, `/api/messages/${message.id}`, { cookie: reader.cookie })).response.status, 500);
  assert.equal((await request(f, `/api/admin/messages/${message.id}`, { cookie: admin.cookie })).response.status, 500);
  assert.equal((await db.prepare('SELECT COUNT(*) AS count FROM access_events').first()).count, 2);
});

test('message creation and its audit metadata commit atomically; failed audit writes disclose no plaintext', async (t) => {
  const f = await fixture(t, { ADMIN_PASSWORD });
  const { cookie } = await login(f);
  const db = await f.db;
  await db.prepare("CREATE TRIGGER test_reject_activity BEFORE INSERT ON message_activity BEGIN SELECT RAISE(ABORT, 'synthetic audit write failure'); END").run();
  const rejected = await request(f, '/api/messages', { cookie, json: { text: '必须与元数据一起保存' } });
  assert.equal(rejected.response.status, 500);
  assert.equal((await db.prepare('SELECT COUNT(*) AS count FROM messages').first()).count, 0);
  assert.equal((await db.prepare('SELECT COUNT(*) AS count FROM message_activity').first()).count, 0);
  await db.prepare('DROP TRIGGER test_reject_activity').run();
  const plaintext = '只有审计记录成功保存才能返回的原文';
  const message = await createMessage(f, cookie, plaintext);
  await db.prepare("CREATE TRIGGER test_reject_event BEFORE INSERT ON access_events BEGIN SELECT RAISE(ABORT, 'synthetic event write failure'); END").run();
  const failedRead = await request(f, `/api/messages/${message.id}`, { cookie });
  assert.equal(failedRead.response.status, 500);
  assert.equal(JSON.stringify(failedRead.data).includes(plaintext), false);
  assert.equal((await db.prepare('SELECT COUNT(*) AS count FROM access_events').first()).count, 0);
  await db.prepare('DROP TRIGGER test_reject_event').run();
  assert.equal((await request(f, `/api/messages/${message.id}`, { cookie })).data.text, plaintext);
  assert.equal((await db.prepare('SELECT COUNT(*) AS count FROM access_events').first()).count, 1);
});

test('admin lists paginate newest-first, filter access events, and omit message plaintext', async (t) => {
  const f = await fixture(t, { ADMIN_PASSWORD });
  const visitor = await login(f);
  const admin = await adminLogin(f);
  const messages = [];
  const db = await f.db;
  for (let index = 0; index < 32; index++) {
    const message = await createMessage(f, visitor.cookie, `管理分页合成内容 ${index + 1}`);
    // Fixed increasing times make the expected order deterministic even on a fast runtime.
    await db.prepare('UPDATE messages SET created_at = ? WHERE id = ?').bind(1700000000000 + index, message.id).run();
    messages.push(message);
    assert.equal((await request(f, `/api/messages/${message.id}`, { cookie: visitor.cookie })).response.status, 200);
  }
  const firstMessages = await request(f, '/api/admin/messages', { cookie: admin.cookie });
  assert.equal(firstMessages.response.status, 200);
  assert.equal(firstMessages.data.items.length, 30);
  assert.equal(firstMessages.data.nextOffset, 30);
  assert.deepEqual(firstMessages.data.items.map(item => item.id), messages.slice(2).reverse().map(item => item.id));
  const secondMessages = await request(f, '/api/admin/messages?offset=30', { cookie: admin.cookie });
  assert.deepEqual(secondMessages.data.items.map(item => item.id), messages.slice(0, 2).reverse().map(item => item.id));
  assert.equal(secondMessages.data.nextOffset, null);
  for (const item of firstMessages.data.items) {
    assert.equal(item.visitorId, visitor.visitorCookie.split('=')[1]);
    assert.equal(item.ip, '192.0.2.10');
    assert.ok(item.byteLength > 0);
    assert.equal(item.viewCount, 1);
    assert.ok(Number.isFinite(Date.parse(item.createdAt)));
    assert.equal(Object.hasOwn(item, 'text'), false);
  }
  assert.equal(JSON.stringify(firstMessages.data).includes('管理分页合成内容'), false);

  const firstEvents = await request(f, '/api/admin/events', { cookie: admin.cookie });
  assert.equal(firstEvents.data.items.length, 30);
  assert.equal(firstEvents.data.nextOffset, 30);
  assert.deepEqual(firstEvents.data.items.map(item => item.messageId), messages.slice(2).reverse().map(item => item.id));
  const secondEvents = await request(f, '/api/admin/events?offset=30', { cookie: admin.cookie });
  assert.equal(secondEvents.data.items.length, 2);
  assert.equal(secondEvents.data.nextOffset, null);
  for (const item of firstEvents.data.items) {
    assert.equal(item.actor, 'visitor');
    assert.equal(item.visitorId, visitor.visitorCookie.split('=')[1]);
    assert.ok(Number.isFinite(Date.parse(item.viewedAt)));
  }
  const filtered = await request(f, `/api/admin/events?messageId=${messages[0].id}`, { cookie: admin.cookie });
  assert.equal(filtered.data.items.length, 1);
  assert.equal(filtered.data.items[0].messageId, messages[0].id);
  assert.equal(filtered.data.nextOffset, null);
  assert.deepEqual((await request(f, `/api/admin/events?messageId=${UNKNOWN_ID}`, { cookie: admin.cookie })).data, { items: [], nextOffset: null });
  for (const offset of ['-1', '1.5', 'oops', '1000001']) {
    for (const path of ['/api/admin/messages', '/api/admin/events']) {
      assert.equal((await request(f, `${path}?offset=${offset}`, { cookie: admin.cookie })).response.status, 400);
    }
  }
  assert.equal((await request(f, '/api/admin/events?messageId=bad-id', { cookie: admin.cookie })).response.status, 400);
  assert.equal((await db.prepare('SELECT COUNT(*) AS count FROM access_events').first()).count, 32);
  assert.equal((await request(f, '/api/events', { cookie: visitor.cookie })).response.status, 404);
});

test('admin password configuration is independent and fails closed without breaking public access', async (t) => {
  const f = await fixture(t);
  const visitor = await login(f);
  for (const password of ['', 'a'.repeat(11), PASSWORD, 'a'.repeat(1025)]) {
    await f.restart({ ADMIN_PASSWORD: password });
    assert.equal((await request(f, '/api/admin/session')).response.status, 503);
    assert.equal((await request(f, '/api/admin/login', { json: { password } })).response.status, 503);
    assert.deepEqual((await request(f, '/api/session', { cookie: visitor.cookie })).data, { authenticated: true });
  }
  await f.restart({ ADMIN_PASSWORD });
  await adminLogin(f);
});

test('admin and public password rotation, logout, and expiry revoke only the relevant sessions', async (t) => {
  const f = await fixture(t, { ADMIN_PASSWORD });
  const visitor = await login(f);
  const originalAdmin = await adminLogin(f);
  const replacementPassword = 'replacement-public-共享密码-2026';
  await f.restart({ ACCESS_PASSWORD: replacementPassword });
  assert.deepEqual((await request(f, '/api/session', { cookie: visitor.cookie })).data, { authenticated: false });
  assert.deepEqual((await request(f, '/api/admin/session', { cookie: originalAdmin.cookie })).data, { authenticated: true });
  const freshVisitor = await login(f, replacementPassword);
  const replacementAdminPassword = 'replacement-independent-admin-2026';
  await f.restart({ ADMIN_PASSWORD: replacementAdminPassword });
  assert.deepEqual((await request(f, '/api/admin/session', { cookie: originalAdmin.cookie })).data, { authenticated: false });
  assert.deepEqual((await request(f, '/api/session', { cookie: freshVisitor.cookie })).data, { authenticated: true });
  const replacementAdmin = await adminLogin(f, replacementAdminPassword);
  await f.restart({ ADMIN_PASSWORD });
  for (const cookie of [originalAdmin.cookie, replacementAdmin.cookie]) {
    assert.deepEqual((await request(f, '/api/admin/session', { cookie })).data, { authenticated: false });
  }
  const admin = await adminLogin(f);
  const bothCookies = `${admin.cookie}; ${freshVisitor.cookie}`;
  assert.equal((await request(f, '/api/admin/logout', { cookie: bothCookies, json: {} })).response.status, 200);
  assert.deepEqual((await request(f, '/api/admin/session', { cookie: bothCookies })).data, { authenticated: false });
  assert.deepEqual((await request(f, '/api/session', { cookie: bothCookies })).data, { authenticated: true });
  const expiringAdmin = await adminLogin(f);
  await (await f.db).prepare('UPDATE admin_sessions SET expires_at = ?').bind(Date.now() - 1).run();
  assert.deepEqual((await request(f, '/api/admin/session', { cookie: expiringAdmin.cookie })).data, { authenticated: false });
  assert.equal((await request(f, '/api/admin/messages', { cookie: expiringAdmin.cookie })).response.status, 401);
  assert.deepEqual((await request(f, '/api/session', { cookie: freshVisitor.cookie })).data, { authenticated: true });
});
