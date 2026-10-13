const SESSION_SECONDS = 30 * 24 * 60 * 60;
const ADMIN_SESSION_SECONDS = 8 * 60 * 60;
const VISITOR_SECONDS = 180 * 24 * 60 * 60;
const PAGE_SIZE = 30;
const MAX_TEXT_BYTES = 100000;
const MAX_BODY_BYTES = 610000;
const ID_PATTERN = /^[A-Za-z0-9_-]{16}$/;
const SESSION_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const encoder = new TextEncoder();

class HttpError extends Error {
  constructor(status, message, retryAfter) {
    super(message);
    this.status = status;
    this.retryAfter = retryAfter;
  }
}

const bytes = value => encoder.encode(value);
const hex = value => Array.from(new Uint8Array(value), byte => byte.toString(16).padStart(2, '0')).join('');
const sha256 = async value => hex(await crypto.subtle.digest('SHA-256', value));
const randomBytes = size => crypto.getRandomValues(new Uint8Array(size));
const base64 = value => btoa(String.fromCharCode(...value));
const randomToken = size => base64(randomBytes(size)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
const authInput = password => bytes(`mijian-auth-v1\0${password}`);
const adminAuthInput = password => bytes(`mijian-admin-auth-v1\0${password}`);

function securityHeaders(secure) {
  const headers = new Headers({
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  });
  if (secure) headers.set('Strict-Transport-Security', 'max-age=31536000');
  return headers;
}

function json(status, data, secure, extraHeaders = {}) {
  const headers = securityHeaders(secure);
  for (const [name, value] of Object.entries(extraHeaders)) {
    for (const item of Array.isArray(value) ? value : [value]) headers.append(name, item);
  }
  return new Response(JSON.stringify(data), { status, headers });
}

async function configuration(request, env) {
  const url = new URL(request.url);
  const local = env.LOCAL_DEV === 'true';
  if (local && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) {
    throw new HttpError(503, '本地预览配置不能用于此访问地址。');
  }
  if (!local && url.protocol !== 'https:') throw new HttpError(403, '请使用 HTTPS 访问本站。');
  if (!env.DB || typeof env.DB.prepare !== 'function' || typeof env.DB.batch !== 'function') {
    throw new HttpError(503, '网站数据库尚未配置。');
  }
  const password = env.ACCESS_PASSWORD;
  if (typeof password !== 'string' || bytes(password).length < 8 || bytes(password).length > 1024) {
    throw new HttpError(503, '网站访问密码尚未正确配置。');
  }
  const encodedKey = env.ENCRYPTION_KEY;
  let rawKey;
  try {
    if (typeof encodedKey !== 'string') throw new Error();
    rawKey = Uint8Array.from(atob(encodedKey), character => character.charCodeAt(0));
    if (rawKey.length !== 32 || base64(rawKey) !== encodedKey) throw new Error();
  } catch {
    throw new HttpError(503, '网站加密密钥尚未正确配置。');
  }

  // A fixed production origin also blocks archived Pages deployment URLs, whose
  // old password configuration must never become an alternate login endpoint.
  if (!local && (typeof env.PUBLIC_URL !== 'string' || !env.PUBLIC_URL)) {
    throw new HttpError(503, '请配置 PUBLIC_URL 为网站正式 HTTPS 域名。');
  }
  let origin = url.origin;
  if (env.PUBLIC_URL) {
    let publicUrl;
    try {
      publicUrl = new URL(env.PUBLIC_URL);
      if (publicUrl.protocol !== 'https:' || publicUrl.username || publicUrl.password ||
          publicUrl.pathname !== '/' || publicUrl.search || publicUrl.hash) throw new Error();
    } catch {
      throw new HttpError(503, '网站域名尚未正确配置。');
    }
    origin = publicUrl.origin;
  }
  if (url.origin !== origin || (request.headers.has('Host') && request.headers.get('Host') !== url.host)) {
    throw new HttpError(403, '访问地址不正确。');
  }
  const [encryptionKey, hmacKey, keyId] = await Promise.all([
    crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt', 'decrypt']),
    crypto.subtle.importKey('raw', rawKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']),
    sha256(rawKey),
  ]);
  const signature = await crypto.subtle.sign('HMAC', hmacKey, authInput(password));
  return { db: env.DB, origin, local, encryptionKey, hmacKey, keyId, signature,
    authVersion: hex(signature), cookieName: local ? 'aes_links_preview' : '__Host-aes_links',
    visitorCookieName: local ? 'mijian_visitor_preview' : '__Host-mijian_visitor' };
}

async function adminConfiguration(config, env) {
  const password = env.ADMIN_PASSWORD;
  if (typeof password !== 'string' || bytes(password).length < 12 || bytes(password).length > 1024 || password === env.ACCESS_PASSWORD) {
    throw new HttpError(503, '请配置独立的管理员密码，至少 12 字节且不能与访问密码相同。');
  }
  const signature = await crypto.subtle.sign('HMAC', config.hmacKey, adminAuthInput(password));
  return { ...config, admin: true, signature, authVersion: hex(signature),
    cookieName: config.local ? 'mijian_admin_preview' : '__Host-mijian_admin' };
}

async function validateAdminVersion(config) {
  const current = await config.db.prepare("SELECT value FROM metadata WHERE name = 'admin_auth_version'").first();
  if (current?.value === config.authVersion) return;
  await config.db.batch([
    config.db.prepare(`DELETE FROM admin_sessions WHERE auth_version != ?1
      AND NOT EXISTS (SELECT 1 FROM metadata WHERE name = 'admin_auth_version' AND value = ?1)`)
      .bind(config.authVersion),
    config.db.prepare(`INSERT INTO metadata (name, value) VALUES ('admin_auth_version', ?)
      ON CONFLICT(name) DO UPDATE SET value = excluded.value WHERE metadata.value != excluded.value`)
      .bind(config.authVersion),
  ]);
}

async function validateDatabaseKey(config) {
  // The conditional insert and subsequent read also handle simultaneous first visits.
  const results = await config.db.batch([
    config.db.prepare('INSERT INTO metadata (name, value) VALUES (?, ?) ON CONFLICT(name) DO NOTHING')
      .bind('key_id', config.keyId),
    config.db.prepare('SELECT name, value FROM metadata WHERE name IN (?, ?)').bind('key_id', 'auth_version'),
  ]);
  const metadata = new Map((results[1]?.results ?? []).map(row => [row.name, row.value]));
  if (metadata.get('key_id') !== config.keyId) {
    throw new HttpError(503, '加密密钥与数据库不匹配，请联系网站管理员。');
  }
  if (metadata.get('auth_version') !== config.authVersion) {
    // Remove old cookies permanently: changing a password back must not revive them.
    // Recheck the version inside the transaction in case another request updated it.
    await config.db.batch([
      config.db.prepare(`DELETE FROM sessions WHERE auth_version != ?1
        AND NOT EXISTS (SELECT 1 FROM metadata WHERE name = 'auth_version' AND value = ?1)`)
        .bind(config.authVersion),
      config.db.prepare(`INSERT INTO metadata (name, value) VALUES ('auth_version', ?)
        ON CONFLICT(name) DO UPDATE SET value = excluded.value WHERE metadata.value != excluded.value`)
        .bind(config.authVersion),
    ]);
  }
}

async function readJson(request) {
  if ((request.headers.get('Content-Type') ?? '').split(';', 1)[0].trim().toLowerCase() !== 'application/json') {
    throw new HttpError(415, '请使用 JSON 格式提交。');
  }
  if (Number(request.headers.get('Content-Length')) > MAX_BODY_BYTES) {
    throw new HttpError(413, '提交内容过长。');
  }
  const reader = request.body?.getReader();
  if (!reader) throw new HttpError(400, '提交内容格式不正确。');
  let size = 0;
  const chunks = [];
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel().catch(() => {});
        throw new HttpError(413, '提交内容过长。');
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, '请求读取失败。');
  } finally {
    reader.releaseLock();
  }
  const buffer = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.byteLength; }
  try {
    const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(buffer));
    if (!data || typeof data !== 'object' || Array.isArray(data)) throw new Error();
    return data;
  } catch {
    throw new HttpError(400, '提交内容格式不正确。');
  }
}

function cookie(config, token, clear = false) {
  return `${config.cookieName}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${clear ? 0 : config.admin ? ADMIN_SESSION_SECONDS : SESSION_SECONDS}${config.local ? '' : '; Secure'}`;
}

function readCookie(request, name) {
  const raw = (request.headers.get('Cookie') ?? '').split(';').map(part => part.trim())
    .find(part => part.startsWith(`${name}=`));
  return raw ? raw.slice(name.length + 1) : null;
}

function visitorFromRequest(request, config) {
  const value = readCookie(request, config.visitorCookieName);
  return value && ID_PATTERN.test(value) ? value : null;
}

function visitorCookie(config, visitorId) {
  return `${config.visitorCookieName}=${visitorId}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${VISITOR_SECONDS}${config.local ? '' : '; Secure'}`;
}

function clientIp(request, config) {
  return request.headers.get('CF-Connecting-IP') ?? (config.local ? '127.0.0.1' : null);
}

async function session(request, config) {
  const token = readCookie(request, config.cookieName);
  if (!token) return null;
  if (!SESSION_PATTERN.test(token)) return null;
  const tokenHash = await sha256(bytes(token));
  const query = config.admin
    ? 'SELECT token_hash, visitor_id FROM admin_sessions WHERE token_hash = ? AND expires_at > ? AND auth_version = ?'
    : `SELECT s.token_hash, v.visitor_id FROM sessions s LEFT JOIN session_visitors v ON v.token_hash = s.token_hash
      WHERE s.token_hash = ? AND s.expires_at > ? AND s.auth_version = ?`;
  return config.db.prepare(query)
    .bind(tokenHash, Date.now(), config.authVersion).first();
}

async function requireSession(request, config) {
  const active = await session(request, config);
  if (!active) throw new HttpError(401, config.admin ? '请先登录管理后台。' : '请先输入访问密码。');
  return active;
}

async function ensureVisitor(request, config, active) {
  if (ID_PATTERN.test(active.visitor_id ?? '')) return active.visitor_id;
  const visitorId = visitorFromRequest(request, config) ?? randomToken(12);
  // Sessions created before the audit migration acquire an ID on first use.
  await config.db.prepare('INSERT INTO session_visitors (token_hash, visitor_id) VALUES (?, ?) ON CONFLICT(token_hash) DO NOTHING')
    .bind(active.token_hash, visitorId).run();
  const stored = await config.db.prepare('SELECT visitor_id FROM session_visitors WHERE token_hash = ?').bind(active.token_hash).first();
  if (!stored || !ID_PATTERN.test(stored.visitor_id)) throw new Error('Missing visitor');
  return stored.visitor_id;
}

async function rateLimit(config, key, limit, duration) {
  const now = Date.now();
  // One SQLite statement prevents parallel edge requests from losing increments.
  const row = await config.db.prepare(`
    INSERT INTO rate_limits (rate_key, count, expires_at) VALUES (?1, 1, ?2)
    ON CONFLICT(rate_key) DO UPDATE SET
      count = CASE WHEN rate_limits.expires_at <= ?3 THEN 1 ELSE MIN(rate_limits.count + 1, ?4) END,
      expires_at = CASE WHEN rate_limits.expires_at <= ?3 THEN excluded.expires_at ELSE rate_limits.expires_at END
    RETURNING count, expires_at
  `).bind(key, now + duration, now, limit + 1).first();
  if (!row) throw new Error('Missing rate limit result');
  if (row.count > limit) {
    throw new HttpError(429, '操作太频繁，请稍后再试。', Math.max(1, Math.ceil((row.expires_at - now) / 1000)));
  }
}

async function login(request, config) {
  const prefix = config.admin ? 'admin-login' : 'login';
  const ip = clientIp(request, config) ?? 'unknown';
  const ipKey = hex(await crypto.subtle.sign('HMAC', config.hmacKey, bytes(`mijian-${prefix}-ip-v1\0${ip}`)));
  await rateLimit(config, `${prefix}-ip:${ipKey}`, 10, 15 * 60000);
  await rateLimit(config, `${prefix}-global`, 60, 60000);
  const { password } = await readJson(request);
  if (typeof password !== 'string' || !password.length || bytes(password).length > 1024) {
    throw new HttpError(400, '请输入有效的访问密码。');
  }
  if (!await crypto.subtle.verify('HMAC', config.hmacKey, config.signature, config.admin ? adminAuthInput(password) : authInput(password))) {
    throw new HttpError(401, '密码不正确，请重试。');
  }
  const old = await session(request, config);
  const token = randomToken(32);
  const tokenHash = await sha256(bytes(token));
  const visitorId = (ID_PATTERN.test(old?.visitor_id ?? '') ? old.visitor_id : null) ?? visitorFromRequest(request, config) ?? randomToken(12);
  const table = config.admin ? 'admin_sessions' : 'sessions';
  const statements = [];
  if (old) statements.push(config.db.prepare(`DELETE FROM ${table} WHERE token_hash = ?`).bind(old.token_hash));
  if (config.admin) {
    statements.push(config.db.prepare('INSERT INTO admin_sessions (token_hash, expires_at, auth_version, visitor_id) VALUES (?, ?, ?, ?)')
      .bind(tokenHash, Date.now() + ADMIN_SESSION_SECONDS * 1000, config.authVersion, visitorId));
  } else {
    statements.push(config.db.prepare('INSERT INTO sessions (token_hash, expires_at, auth_version) VALUES (?, ?, ?)')
      .bind(tokenHash, Date.now() + SESSION_SECONDS * 1000, config.authVersion));
    statements.push(config.db.prepare('INSERT INTO session_visitors (token_hash, visitor_id) VALUES (?, ?)').bind(tokenHash, visitorId));
  }
  await config.db.batch(statements);
  return json(200, { ok: true }, !config.local, { 'Set-Cookie': [cookie(config, token), visitorCookie(config, visitorId)] });
}

function blob(value) {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new Error('Invalid encrypted content');
}

async function createMessage(request, config) {
  const active = await requireSession(request, config);
  await rateLimit(config, `create:${active.token_hash}`, 60, 60000);
  const { text } = await readJson(request);
  if (typeof text !== 'string' || !text.trim()) throw new HttpError(400, '请先输入要分享的文字。');
  const plaintext = bytes(text);
  if (plaintext.length > MAX_TEXT_BYTES) throw new HttpError(413, '文字过长，请分成几条分享。');
  const id = randomToken(12);
  const iv = randomBytes(12);
  const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: bytes(id), tagLength: 128 }, config.encryptionKey, plaintext));
  // Keep the original Node/SQLite layout: ciphertext and 16-byte tag in separate BLOBs.
  const ciphertext = encrypted.slice(0, -16);
  const tag = encrypted.slice(-16);
  const visitorId = await ensureVisitor(request, config, active);
  await config.db.batch([
    config.db.prepare('INSERT INTO messages (id, iv, ciphertext, tag, created_at) VALUES (?, ?, ?, ?, ?)')
      .bind(id, iv.buffer, ciphertext.buffer, tag.buffer, Date.now()),
    config.db.prepare('INSERT INTO message_activity (message_id, visitor_id, ip, byte_length) VALUES (?, ?, ?, ?)')
      .bind(id, visitorId, clientIp(request, config), plaintext.length),
  ]);
  return json(201, { id, url: `${config.origin}/m/${id}` }, !config.local, { 'Set-Cookie': visitorCookie(config, visitorId) });
}

async function readMessage(request, config, id) {
  const active = await requireSession(request, config);
  if (!ID_PATTERN.test(id)) throw new HttpError(404, '这条内容不存在，或链接不完整。');
  const row = await config.db.prepare('SELECT iv, ciphertext, tag, created_at FROM messages WHERE id = ?').bind(id).first();
  if (!row) throw new HttpError(404, '这条内容不存在，或链接不完整。');
  const iv = blob(row.iv), ciphertext = blob(row.ciphertext), tag = blob(row.tag);
  if (iv.length !== 12 || tag.length !== 16 || ciphertext.length > MAX_TEXT_BYTES) throw new Error('Invalid encrypted content');
  const encrypted = new Uint8Array(ciphertext.length + tag.length);
  encrypted.set(ciphertext);
  encrypted.set(tag, ciphertext.length);
  const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: bytes(id), tagLength: 128 }, config.encryptionKey, encrypted);
  const text = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
  const createdAt = new Date(row.created_at).toISOString();
  const visitorId = await ensureVisitor(request, config, active);
  await config.db.prepare('INSERT INTO access_events (message_id, viewed_at, visitor_id, ip, actor) VALUES (?, ?, ?, ?, ?)')
    .bind(id, Date.now(), visitorId, clientIp(request, config), config.admin ? 'admin' : 'visitor').run();
  return json(200, { text, createdAt }, !config.local,
    { 'Set-Cookie': visitorCookie(config, visitorId) });
}

function pageOffset(url) {
  const raw = url.searchParams.get('offset') ?? '0';
  if (!/^\d+$/.test(raw) || !Number.isSafeInteger(Number(raw)) || Number(raw) > 1000000) {
    throw new HttpError(400, '分页位置不正确。');
  }
  return Number(raw);
}

async function listMessages(request, config) {
  await requireSession(request, config);
  const offset = pageOffset(new URL(request.url));
  const result = await config.db.prepare(`SELECT m.id, m.created_at, a.visitor_id, a.ip,
    COALESCE(a.byte_length, length(m.ciphertext)) AS byte_length,
    (SELECT COUNT(*) FROM access_events e WHERE e.message_id = m.id) AS view_count
    FROM messages m LEFT JOIN message_activity a ON a.message_id = m.id
    ORDER BY m.created_at DESC, m.id DESC LIMIT ? OFFSET ?`).bind(PAGE_SIZE + 1, offset).all();
  const rows = result.results ?? [];
  const items = rows.slice(0, PAGE_SIZE).map(row => ({
    id: row.id, createdAt: new Date(row.created_at).toISOString(), visitorId: row.visitor_id ?? 'unknown',
    ip: row.ip ?? null, byteLength: row.byte_length, viewCount: row.view_count,
  }));
  return json(200, { items, nextOffset: rows.length > PAGE_SIZE ? offset + PAGE_SIZE : null }, !config.local);
}

async function listEvents(request, config) {
  await requireSession(request, config);
  const url = new URL(request.url);
  const offset = pageOffset(url);
  const messageId = url.searchParams.get('messageId');
  if (messageId !== null && !ID_PATTERN.test(messageId)) throw new HttpError(400, '密文编号不正确。');
  const query = `SELECT id, message_id, viewed_at, visitor_id, ip, actor FROM access_events
    ${messageId === null ? '' : 'WHERE message_id = ?'} ORDER BY id DESC LIMIT ? OFFSET ?`;
  const values = messageId === null ? [PAGE_SIZE + 1, offset] : [messageId, PAGE_SIZE + 1, offset];
  const result = await config.db.prepare(query).bind(...values).all();
  const rows = result.results ?? [];
  const items = rows.slice(0, PAGE_SIZE).map(row => ({
    id: row.id, messageId: row.message_id, viewedAt: new Date(row.viewed_at).toISOString(),
    visitorId: row.visitor_id, ip: row.ip ?? null, actor: row.actor,
  }));
  return json(200, { items, nextOffset: rows.length > PAGE_SIZE ? offset + PAGE_SIZE : null }, !config.local);
}

async function logout(request, config) {
  await readJson(request);
  const active = await session(request, config);
  if (active) {
    const table = config.admin ? 'admin_sessions' : 'sessions';
    await config.db.prepare(`DELETE FROM ${table} WHERE token_hash = ?`).bind(active.token_hash).run();
  }
  return json(200, { ok: true }, !config.local, { 'Set-Cookie': cookie(config, '', true) });
}

async function handleAdmin(request, baseConfig, env, path) {
  const config = await adminConfiguration(baseConfig, env);
  await validateAdminVersion(config);
  if (request.method === 'GET' && path === '/api/admin/session') {
    return json(200, { authenticated: Boolean(await session(request, config)) }, !config.local);
  }
  if (request.method === 'POST' && path === '/api/admin/login') return login(request, config);
  if (request.method === 'POST' && path === '/api/admin/logout') return logout(request, config);
  if (request.method === 'GET' && path === '/api/admin/messages') return listMessages(request, config);
  if (request.method === 'GET' && path === '/api/admin/events') return listEvents(request, config);
  if (request.method === 'GET' && path.startsWith('/api/admin/messages/')) {
    return readMessage(request, config, path.slice('/api/admin/messages/'.length));
  }
  throw new HttpError(404, '请求的功能不存在。');
}

async function cleanup(config) {
  const now = Date.now();
  await config.db.batch([
    config.db.prepare('DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM sessions WHERE expires_at <= ? LIMIT 100)').bind(now),
    config.db.prepare('DELETE FROM admin_sessions WHERE token_hash IN (SELECT token_hash FROM admin_sessions WHERE expires_at <= ? LIMIT 100)').bind(now),
    config.db.prepare('DELETE FROM rate_limits WHERE rate_key IN (SELECT rate_key FROM rate_limits WHERE expires_at <= ? LIMIT 100)').bind(now),
  ]);
}

export async function handleApi(request, env, ctx = {}) {
  const secure = new URL(request.url).protocol === 'https:';
  try {
    const config = await configuration(request, env);
    if (!['GET', 'POST'].includes(request.method)) throw new HttpError(405, '不支持此操作。');
    if (request.method === 'POST' && request.headers.get('Origin') !== config.origin) {
      throw new HttpError(403, '请求来源不正确，请从本站页面操作。');
    }
    await validateDatabaseKey(config);
    if (randomBytes(1)[0] === 0) {
      // Bounded maintenance keeps expired records from accumulating, without extra services.
      const pending = cleanup(config).catch(() => {});
      if (typeof ctx.waitUntil === 'function') ctx.waitUntil(pending);
      else await pending;
    }
    const path = new URL(request.url).pathname;
    if (path === '/api/admin' || path.startsWith('/api/admin/')) return await handleAdmin(request, config, env, path);
    if (request.method === 'GET' && path === '/api/session') {
      return json(200, { authenticated: Boolean(await session(request, config)) }, !config.local);
    }
    if (request.method === 'POST' && path === '/api/login') return await login(request, config);
    if (request.method === 'POST' && path === '/api/logout') return await logout(request, config);
    if (request.method === 'POST' && path === '/api/messages') return await createMessage(request, config);
    if (request.method === 'GET' && path.startsWith('/api/messages/')) {
      return await readMessage(request, config, path.slice('/api/messages/'.length));
    }
    throw new HttpError(404, '请求的功能不存在。');
  } catch (error) {
    const status = error instanceof HttpError ? error.status : 500;
    const message = error instanceof HttpError ? error.message : '服务暂时不可用，请稍后再试。';
    if (!(error instanceof HttpError)) {
      // Do not log exception messages: platform errors may contain SQL or user data.
      const name = typeof error?.name === 'string' && /^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(error.name) ? error.name : 'Error';
      console.error('Mijian API error:', name);
    }
    return json(status, { error: message }, secure,
      error instanceof HttpError && error.retryAfter ? { 'Retry-After': String(error.retryAfter) } : {});
  }
}
