import http from 'node:http';
import { readFile, writeFile, mkdir, chmod, rename } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, createHash, createHmac, createCipheriv, createDecipheriv, scrypt, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';
import { DatabaseSync } from 'node:sqlite';
import { isIP } from 'node:net';

process.umask(0o077);
const ROOT = dirname(fileURLToPath(import.meta.url));
const scryptAsync = promisify(scrypt);
const SESSION_SECONDS = 30 * 24 * 60 * 60;
const MAX_TEXT_BYTES = 100000;
const MAX_BODY_BYTES = 610000;
const ID_PATTERN = /^[A-Za-z0-9_-]{16}$/;
const SESSION_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const hash = value => createHash('sha256').update(value).digest('hex');
const derivePassword = (password, salt) => scryptAsync(password, salt, 64, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function saveInstance(path, instance) {
  await writeFile(`${path}.tmp`, JSON.stringify(instance, null, 2), { mode: 0o600 });
  await rename(`${path}.tmp`, path);
  await chmod(path, 0o600);
}

async function configuration(options) {
  const dev = Boolean(options.dev);
  const port = Number(options.port ?? process.env.PORT ?? (dev ? 8877 : 3000));
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('PORT 必须是有效端口。');
  const dataDir = resolve(options.dataDir ?? process.env.DATA_DIR ?? resolve(ROOT, '.data'));
  await mkdir(dataDir, { recursive: true, mode: 0o700 });
  await chmod(dataDir, 0o700);
  const password = options.accessPassword ?? process.env.ACCESS_PASSWORD;
  if (password !== undefined && (Buffer.byteLength(password) < 8 || Buffer.byteLength(password) > 1024)) {
    throw new Error('访问密码须为 8 至 1024 字节。');
  }
  let key, salt, passwordHash, previewPassword;
  if (dev) {
    const instancePath = resolve(dataDir, 'instance.json');
    if (existsSync(instancePath)) {
      const instance = JSON.parse(await readFile(instancePath, 'utf8'));
      if (!/^[a-f0-9]{64}$/.test(instance.key) || !/^[a-f0-9]{32}$/.test(instance.salt) || !/^[a-f0-9]{128}$/.test(instance.passwordHash)) {
        throw new Error('本地配置损坏，请保留数据并检查 instance.json。');
      }
      key = Buffer.from(instance.key, 'hex');
      salt = Buffer.from(instance.salt, 'hex');
      passwordHash = Buffer.from(instance.passwordHash, 'hex');
      if (password !== undefined) {
        const updated = await derivePassword(password, salt);
        if (!timingSafeEqual(updated, passwordHash)) {
          passwordHash = updated;
          await saveInstance(instancePath, { ...instance, passwordHash: passwordHash.toString('hex') });
        }
      }
    } else {
      if (existsSync(resolve(dataDir, 'messages.sqlite'))) throw new Error('数据库已存在但密钥配置缺失，不能自动生成新密钥。');
      key = randomBytes(32);
      salt = randomBytes(16);
      const initialPassword = password ?? `demo-${randomBytes(5).toString('hex')}`;
      passwordHash = await derivePassword(initialPassword, salt);
      await saveInstance(instancePath, { key: key.toString('hex'), salt: salt.toString('hex'), passwordHash: passwordHash.toString('hex') });
      if (password === undefined) previewPassword = initialPassword;
    }
  } else {
    const encodedKey = options.encryptionKey ?? process.env.ENCRYPTION_KEY;
    if (!password || !encodedKey) throw new Error('正式运行需设置 ACCESS_PASSWORD、ENCRYPTION_KEY 和 PUBLIC_URL。');
    key = Buffer.from(encodedKey, 'base64');
    if (key.length !== 32 || key.toString('base64') !== encodedKey) throw new Error('ENCRYPTION_KEY 必须是 32 字节随机密钥的标准 Base64。');
    salt = createHmac('sha256', key).update('aes-links-password-salt-v1').digest().subarray(0, 16);
    passwordHash = await derivePassword(password, salt);
  }
  const origin = dev ? `http://127.0.0.1:${port}` : (options.publicUrl ?? process.env.PUBLIC_URL);
  if (!origin) throw new Error('请设置 PUBLIC_URL。');
  const url = new URL(origin);
  if ((!dev && url.protocol !== 'https:') || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('PUBLIC_URL 必须是无路径的 HTTPS 域名。');
  }
  return { dev, port, dataDir, key, salt, passwordHash, previewPassword, origin: url.origin, host: url.host,
    bindHost: dev ? '127.0.0.1' : (options.host ?? process.env.HOST ?? '127.0.0.1'),
    trustLoopbackProxy: !dev && (options.trustProxy ?? process.env.TRUST_PROXY) === 'loopback',
    authVersion: hash(passwordHash), cookieName: dev ? 'aes_links_preview' : '__Host-aes_links' };
}

function readJson(req) {
  if (!(req.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) {
    throw new HttpError(415, '请使用 JSON 格式提交。');
  }
  if (Number(req.headers['content-length']) > MAX_BODY_BYTES) {
    req.resume();
    throw new HttpError(413, '提交内容过长。');
  }
  return new Promise((resolveBody, reject) => {
    const chunks = [];
    let size = 0, finished = false;
    const fail = error => { if (!finished) { finished = true; reject(error); } };
    req.on('data', chunk => {
      if (finished) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) { fail(new HttpError(413, '提交内容过长。')); return; }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (finished) return;
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error();
        finished = true;
        resolveBody(body);
      } catch { fail(new HttpError(400, '提交内容格式不正确。')); }
    });
    req.on('aborted', () => fail(new HttpError(400, '请求已中断。')));
    req.on('error', () => fail(new HttpError(400, '请求读取失败。')));
  });
}

export async function startServer(options = {}) {
  const config = await configuration(options);
  const databasePath = resolve(config.dataDir, 'messages.sqlite');
  const db = new DatabaseSync(databasePath);
  await chmod(databasePath, 0o600);
  db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, iv BLOB NOT NULL, ciphertext BLOB NOT NULL, tag BLOB NOT NULL, created_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, auth_version TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS session_expiry ON sessions(expires_at);`);
  const keyId = hash(config.key);
  const existingKey = db.prepare('SELECT value FROM metadata WHERE name = ?').get('key_id');
  if (existingKey && existingKey.value !== keyId) { db.close(); throw new Error('密钥与已有数据库不匹配，已停止启动以保护已有内容。'); }
  if (!existingKey) db.prepare('INSERT INTO metadata (name,value) VALUES (?,?)').run('key_id', keyId);
  db.prepare('DELETE FROM sessions WHERE auth_version != ? OR expires_at <= ?').run(config.authVersion, Date.now());

  const attempts = new Map();
  const creationRates = new Map();
  let runningLogins = 0;
  let globalLoginWindow = { start: Date.now(), count: 0 };
  function rateLimit(map, id, limit, duration) {
    const now = Date.now();
    let entry = map.get(id);
    if (!entry && map.size >= 10000) throw new HttpError(429, '请求较多，请稍后再试。');
    if (!entry || now >= entry.until) { entry = { count: 0, until: now + duration }; map.set(id, entry); }
    entry.count++;
    if (entry.count > limit) {
      const error = new HttpError(429, '操作太频繁，请稍后再试。');
      error.retryAfter = Math.max(1, Math.ceil((entry.until - now) / 1000));
      throw error;
    }
  }
  const cleanup = setInterval(() => {
    const now = Date.now();
    db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(now);
    for (const map of [attempts, creationRates]) for (const [id, entry] of map) if (entry.until <= now) map.delete(id);
  }, 60000).unref();

  function cookie(token, clear = false) {
    return `${config.cookieName}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${clear ? 0 : SESSION_SECONDS}${config.dev ? '' : '; Secure'}`;
  }
  function session(req) {
    const raw = (req.headers.cookie ?? '').split(';').map(part => part.trim()).find(part => part.startsWith(`${config.cookieName}=`));
    if (!raw) return null;
    const token = raw.slice(config.cookieName.length + 1);
    if (!SESSION_PATTERN.test(token)) return null;
    const tokenHash = hash(token);
    return db.prepare('SELECT token_hash FROM sessions WHERE token_hash = ? AND expires_at > ? AND auth_version = ?')
      .get(tokenHash, Date.now(), config.authVersion) ?? null;
  }
  function requireSession(req) {
    const active = session(req);
    if (!active) throw new HttpError(401, '请先输入访问密码。');
    return active;
  }
  function json(res, status, data) {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify(data));
  }
  const server = http.createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    if (!config.dev) res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    try {
      if (req.headers.host !== config.host) throw new HttpError(403, '访问地址不正确。');
      const path = new URL(req.url, config.origin).pathname;
      if (!['GET', 'HEAD', 'POST'].includes(req.method)) throw new HttpError(405, '不支持此操作。');
      if (req.method === 'POST' && req.headers.origin !== config.origin) throw new HttpError(403, '请求来源不正确，请从本站页面操作。');
      if (req.method === 'GET' && path === '/api/session') return json(res, 200, { authenticated: Boolean(session(req)) });

      if (req.method === 'POST' && path === '/api/login') {
        let ip = req.socket.remoteAddress ?? 'unknown';
        if (config.trustLoopbackProxy) {
          if (!['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(ip)) throw new HttpError(403, '请通过网站入口访问。');
          const realIp = req.headers['x-real-ip'];
          if (typeof realIp !== 'string' || !isIP(realIp)) throw new HttpError(403, '代理配置不正确。');
          ip = realIp;
        }
        rateLimit(attempts, ip, 10, 15 * 60000);
        if (Date.now() - globalLoginWindow.start > 60000) globalLoginWindow = { start: Date.now(), count: 0 };
        if (++globalLoginWindow.count > 60 || runningLogins >= 3) throw new HttpError(429, '登录请求较多，请稍后再试。');
        runningLogins++;
        try {
          const { password } = await readJson(req);
          if (typeof password !== 'string' || !password.length || Buffer.byteLength(password) > 1024) throw new HttpError(400, '请输入有效的访问密码。');
          const candidate = await derivePassword(password, config.salt);
          if (!timingSafeEqual(candidate, config.passwordHash)) throw new HttpError(401, '密码不正确，请重试。');
          const old = session(req);
          if (old) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(old.token_hash);
          const token = randomBytes(32).toString('base64url');
          db.prepare('INSERT INTO sessions (token_hash,expires_at,auth_version) VALUES (?,?,?)').run(hash(token), Date.now() + SESSION_SECONDS * 1000, config.authVersion);
          attempts.delete(ip);
          res.setHeader('Set-Cookie', cookie(token));
          return json(res, 200, { ok: true });
        } finally { runningLogins--; }
      }
      if (req.method === 'POST' && path === '/api/logout') {
        await readJson(req);
        const active = session(req);
        if (active) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(active.token_hash);
        res.setHeader('Set-Cookie', cookie('', true));
        return json(res, 200, { ok: true });
      }
      if (req.method === 'POST' && path === '/api/messages') {
        const active = requireSession(req);
        rateLimit(creationRates, active.token_hash, 60, 60000);
        const { text } = await readJson(req);
        if (typeof text !== 'string' || !text.trim()) throw new HttpError(400, '请先输入要分享的文字。');
        if (Buffer.byteLength(text, 'utf8') > MAX_TEXT_BYTES) throw new HttpError(413, '文字过长，请分成几条分享。');
        const id = randomBytes(12).toString('base64url');
        const iv = randomBytes(12);
        const cipher = createCipheriv('aes-256-gcm', config.key, iv);
        cipher.setAAD(Buffer.from(id));
        const ciphertext = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
        db.prepare('INSERT INTO messages (id,iv,ciphertext,tag,created_at) VALUES (?,?,?,?,?)').run(id, iv, ciphertext, cipher.getAuthTag(), Date.now());
        return json(res, 201, { id, url: `${config.origin}/m/${id}` });
      }
      if (req.method === 'GET' && path.startsWith('/api/messages/')) {
        requireSession(req);
        const id = path.slice('/api/messages/'.length);
        if (!ID_PATTERN.test(id)) throw new HttpError(404, '这条内容不存在，或链接不完整。');
        const row = db.prepare('SELECT * FROM messages WHERE id = ?').get(id);
        if (!row) throw new HttpError(404, '这条内容不存在，或链接不完整。');
        const decipher = createDecipheriv('aes-256-gcm', config.key, row.iv);
        decipher.setAAD(Buffer.from(id));
        decipher.setAuthTag(row.tag);
        const text = Buffer.concat([decipher.update(row.ciphertext), decipher.final()]).toString('utf8');
        return json(res, 200, { text, createdAt: new Date(row.created_at).toISOString() });
      }
      if (path.startsWith('/api/')) throw new HttpError(404, '请求的功能不存在。');
      if (req.method === 'GET' || req.method === 'HEAD') {
        const files = { '/app.js': ['app.js', 'text/javascript; charset=utf-8'], '/style.css': ['style.css', 'text/css; charset=utf-8'] };
        const item = path === '/' || /^\/m\/[^/]+$/.test(path) ? ['index.html', 'text/html; charset=utf-8'] : files[path];
        if (item) {
          const data = await readFile(resolve(ROOT, 'public', item[0]));
          res.writeHead(200, { 'Content-Type': item[1] });
          return res.end(req.method === 'HEAD' ? undefined : data);
        }
        if (path === '/favicon.ico') { res.writeHead(204); return res.end(); }
      }
      throw new HttpError(404, '页面不存在。');
    } catch (error) {
      if (res.destroyed || res.writableEnded) return;
      const status = error instanceof HttpError ? error.status : 500;
      if (status === 429) res.setHeader('Retry-After', String(error.retryAfter ?? 60));
      if (status === 500) console.error('请求处理失败：', error.code ?? error.name);
      json(res, status, { error: status === 500 ? '暂时无法处理，请稍后再试。' : error.message });
    }
  });
  server.requestTimeout = 15000;
  server.headersTimeout = 10000;
  server.keepAliveTimeout = 5000;
  try {
    await new Promise((resolveListen, reject) => { server.once('error', reject); server.listen(config.port, config.bindHost, resolveListen); });
  } catch (error) { clearInterval(cleanup); db.close(); throw error; }
  return { server, config, async close() { clearInterval(cleanup); await new Promise(resolveClose => server.close(resolveClose)); db.close(); } };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const app = await startServer({ dev: process.argv.includes('--dev') });
    console.log(`本地预览：${app.config.origin}`);
    if (app.config.previewPassword) console.log(`首次预览密码：${app.config.previewPassword}`);
    const stop = async () => { await app.close(); process.exit(0); };
    process.once('SIGINT', stop);
    process.once('SIGTERM', stop);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
