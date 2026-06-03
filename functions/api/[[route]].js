// Pensum Planner — Cloudflare Pages Functions API
// Security: rate limiting, brute force lockout, security headers,
//           input sanitization, CSRF origin check, audit logging,
//           session management, PBKDF2 (200k iterations) password hashing

const ALLOWED_ORIGINS = [
  'https://pensum-planner.pages.dev',
  'http://localhost:3000',
  'http://localhost:8788',
];

const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "connect-src 'self'",
    "img-src 'self' data:",
    "frame-ancestors 'none'",
  ].join('; '),
};

const RATE_LIMITS = {
  login:    { max: 5,   windowSecs: 60   },
  register: { max: 3,   windowSecs: 3600 },
  api:      { max: 120, windowSecs: 60   },
};

const MAX_FAILED_LOGINS = 10;
const LOCKOUT_MINUTES   = 15;

function getOrigin(req)    { return req.headers.get('Origin') || req.headers.get('Referer') || ''; }
function getIP(req)        { return req.headers.get('CF-Connecting-IP') || req.headers.get('X-Forwarded-For')?.split(',')[0]?.trim() || 'unknown'; }
function getUserAgent(req) { return (req.headers.get('User-Agent') || '').slice(0, 200); }

function corsHeaders(origin) {
  const allowed = ALLOWED_ORIGINS.some(o => origin.startsWith(o)) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowed,
    'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

function json(data, status = 200, origin = '') {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin), ...SECURITY_HEADERS },
  });
}
function err(msg, status = 400, origin = '') { return json({ error: msg }, status, origin); }

function validateEmail(e) {
  if (typeof e !== 'string' || e.length > 254) return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(e.trim());
}
function validatePassword(p) {
  if (typeof p !== 'string') return { ok: false, msg: 'Contraseña inválida.' };
  if (p.length < 6)   return { ok: false, msg: 'La contraseña debe tener al menos 6 caracteres.' };
  if (p.length > 128) return { ok: false, msg: 'Contraseña demasiado larga.' };
  return { ok: true };
}
function sanitizeName(n) {
  if (typeof n !== 'string') return '';
  return n.trim().replace(/[<>"'&]/g, '').slice(0, 80);
}

async function checkRateLimit(db, type, key) {
  const cfg = RATE_LIMITS[type] || RATE_LIMITS.api;
  const fullKey = `${type}:${key}`;
  const windowStart = Date.now() - cfg.windowSecs * 1000;
  const row = await db.prepare('SELECT count, window_start FROM rate_limits WHERE key = ?').bind(fullKey).first();
  if (!row || new Date(row.window_start).getTime() < windowStart) {
    await db.prepare(`INSERT INTO rate_limits (key, count, window_start) VALUES (?, 1, datetime('now')) ON CONFLICT(key) DO UPDATE SET count = 1, window_start = datetime('now')`).bind(fullKey).run();
    return { limited: false };
  }
  if (row.count >= cfg.max) return { limited: true };
  await db.prepare('UPDATE rate_limits SET count = count + 1 WHERE key = ?').bind(fullKey).run();
  return { limited: false };
}

async function audit(db, event, { email = null, ip = null, ua = null, detail = null } = {}) {
  try { await db.prepare('INSERT INTO audit_log (event, email, ip, user_agent, detail) VALUES (?, ?, ?, ?, ?)').bind(event, email, ip, ua, detail).run(); } catch(e) {}
}

async function hashPassword(password) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, key, 256);
  const hex = a => Array.from(a).map(b => b.toString(16).padStart(2, '0')).join('');
  return hex(salt) + ':' + hex(new Uint8Array(bits));
}

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = (stored || '').split(':');
  if (!saltHex || !hashHex) return false;
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const enc  = new TextEncoder();
  const key  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, key, 256);
  const computed = Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  if (computed.length !== hashHex.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) diff |= computed.charCodeAt(i) ^ hashHex.charCodeAt(i);
  return diff === 0;
}

function generateToken(len = 32) {
  return Array.from(crypto.getRandomValues(new Uint8Array(len))).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getUserFromToken(db, authHeader) {
  if (!authHeader?.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7);
  if (!/^[0-9a-f]{64}$/.test(token)) return null;
  const session = await db.prepare('SELECT user_id, expires_at FROM sessions WHERE token = ?').bind(token).first();
  if (!session || new Date(session.expires_at) < new Date()) {
    if (session) await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }
  await db.prepare("UPDATE sessions SET last_active = datetime('now') WHERE token = ?").bind(token).run();
  return await db.prepare('SELECT id, email, name FROM users WHERE id = ?').bind(session.user_id).first();
}

async function maybeCleanup(db) {
  if (Math.random() > 0.05) return;
  await db.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
  await db.prepare("DELETE FROM rate_limits WHERE window_start < datetime('now', '-2 hours')").run();
}

export async function onRequest(context) {
  const { request, env } = context;
  const url    = new URL(request.url);
  const path   = url.pathname.replace(/^\/api/, '');
  const method = request.method;
  const origin = getOrigin(request);
  const ip     = getIP(request);
  const ua     = getUserAgent(request);
  const db     = env.DB;

  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { ...corsHeaders(origin), ...SECURITY_HEADERS } });
  }

  if (db) await maybeCleanup(db);

  // Global rate limit
  if (db) {
    const { limited } = await checkRateLimit(db, 'api', ip);
    if (limited) {
      await audit(db, 'rate_limit_global', { ip, ua, detail: path });
      return err('Demasiadas solicitudes. Intenta de nuevo en un momento.', 429, origin);
    }
  }

  // ── POST /register ──────────────────────────────────────────────────────────
  if (path === '/register' && method === 'POST') {
    const { limited } = await checkRateLimit(db, 'register', ip);
    if (limited) return err('Demasiados registros desde esta red. Intenta más tarde.', 429, origin);

    let body; try { body = await request.json(); } catch { return err('JSON inválido.', 400, origin); }
    const email    = (body.email || '').trim().toLowerCase();
    const password = body.password || '';
    const name     = sanitizeName(body.name || email.split('@')[0]);

    if (!validateEmail(email)) return err('Correo electrónico inválido.', 400, origin);
    const pwCheck = validatePassword(password);
    if (!pwCheck.ok) return err(pwCheck.msg, 400, origin);

    const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
    if (existing) { await audit(db, 'register_duplicate', { email, ip, ua }); return err('Este correo ya está registrado.', 409, origin); }

    const hashed = await hashPassword(password);
    const userId = generateToken(8);
    await db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)').bind(userId, email, name, hashed).run();

    const token   = generateToken();
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    await db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').bind(token, userId, expires).run();

    await audit(db, 'register_success', { email, ip, ua });
    return json({ token, user: { id: userId, email, name } }, 201, origin);
  }

  // ── POST /login ─────────────────────────────────────────────────────────────
  if (path === '/login' && method === 'POST') {
    const { limited } = await checkRateLimit(db, 'login', ip);
    if (limited) { await audit(db, 'rate_limit_login', { ip, ua }); return err('Demasiados intentos. Espera 1 minuto antes de intentar de nuevo.', 429, origin); }

    let body; try { body = await request.json(); } catch { return err('JSON inválido.', 400, origin); }
    const email    = (body.email || '').trim().toLowerCase();
    const password = body.password || '';

    if (!validateEmail(email) || !password) return err('Correo o contraseña incorrectos.', 401, origin);

    const user = await db.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();

    if (user?.locked_until && new Date(user.locked_until) > new Date()) {
      await audit(db, 'login_locked', { email, ip, ua });
      return err(`Cuenta temporalmente bloqueada. Intenta más tarde.`, 423, origin);
    }

    if (!user) { await audit(db, 'login_unknown_email', { email, ip, ua }); return err('Correo o contraseña incorrectos.', 401, origin); }

    const valid = await verifyPassword(password, user.password_hash);

    if (!valid) {
      const newFails = (user.failed_attempts || 0) + 1;
      if (newFails >= MAX_FAILED_LOGINS) {
        const lockUntil = new Date(Date.now() + LOCKOUT_MINUTES * 60 * 1000).toISOString();
        await db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?').bind(newFails, lockUntil, user.id).run();
        await audit(db, 'login_account_locked', { email, ip, ua, detail: `${newFails} failures` });
        return err(`Demasiados intentos fallidos. Cuenta bloqueada por ${LOCKOUT_MINUTES} minutos.`, 423, origin);
      }
      await db.prepare('UPDATE users SET failed_attempts = ? WHERE id = ?').bind(newFails, user.id).run();
      await audit(db, 'login_bad_password', { email, ip, ua, detail: `attempt ${newFails}` });
      return err('Correo o contraseña incorrectos.', 401, origin);
    }

    await db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').bind(user.id).run();

    const token   = generateToken();
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    await db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)').bind(token, user.id, expires).run();

    await audit(db, 'login_success', { email, ip, ua });
    return json({ token, user: { id: user.id, email: user.email, name: user.name } }, 200, origin);
  }

  // ── POST /logout ─────────────────────────────────────────────────────────────
  if (path === '/logout' && method === 'POST') {
    const authHeader = request.headers.get('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    }
    return json({ ok: true }, 200, origin);
  }

  // ── POST /logout-all ──────────────────────────────────────────────────────────
  if (path === '/logout-all' && method === 'POST') {
    const user = await getUserFromToken(db, request.headers.get('Authorization'));
    if (!user) return err('No autorizado.', 401, origin);
    await db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run();
    await audit(db, 'logout_all', { email: user.email, ip, ua });
    return json({ ok: true }, 200, origin);
  }

  // ── GET /me ───────────────────────────────────────────────────────────────────
  if (path === '/me' && method === 'GET') {
    const user = await getUserFromToken(db, request.headers.get('Authorization'));
    if (!user) return err('No autorizado.', 401, origin);
    return json({ user }, 200, origin);
  }

  // ── GET /progress/:careerId ───────────────────────────────────────────────────
  if (path.startsWith('/progress/') && method === 'GET') {
    const user = await getUserFromToken(db, request.headers.get('Authorization'));
    if (!user) return err('No autorizado.', 401, origin);
    const careerId = path.replace('/progress/', '').slice(0, 100);
    if (!/^[a-zA-Z0-9_\-]+$/.test(careerId)) return err('Career ID inválido.', 400, origin);
    const row = await db.prepare('SELECT data FROM progress WHERE user_id = ? AND career_id = ?').bind(user.id, careerId).first();
    return json({ data: row ? JSON.parse(row.data) : {} }, 200, origin);
  }

  // ── POST /progress/:careerId ──────────────────────────────────────────────────
  if (path.startsWith('/progress/') && method === 'POST') {
    const user = await getUserFromToken(db, request.headers.get('Authorization'));
    if (!user) return err('No autorizado.', 401, origin);
    const careerId = path.replace('/progress/', '').slice(0, 100);
    if (!/^[a-zA-Z0-9_\-]+$/.test(careerId)) return err('Career ID inválido.', 400, origin);
    let body; try { body = await request.json(); } catch { return err('JSON inválido.', 400, origin); }
    const dataStr = JSON.stringify(body.data || {});
    if (dataStr.length > 500000) return err('Datos demasiado grandes.', 413, origin);
    await db.prepare(`INSERT INTO progress (user_id, career_id, data, updated_at) VALUES (?, ?, ?, datetime('now')) ON CONFLICT(user_id, career_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at`).bind(user.id, careerId, dataStr).run();
    return json({ ok: true }, 200, origin);
  }

  // ── DELETE /progress/:careerId ────────────────────────────────────────────────
  if (path.startsWith('/progress/') && method === 'DELETE') {
    const user = await getUserFromToken(db, request.headers.get('Authorization'));
    if (!user) return err('No autorizado.', 401, origin);
    const careerId = path.replace('/progress/', '').slice(0, 100);
    if (!/^[a-zA-Z0-9_\-]+$/.test(careerId)) return err('Career ID inválido.', 400, origin);
    await db.prepare('DELETE FROM progress WHERE user_id = ? AND career_id = ?').bind(user.id, careerId).run();
    return json({ ok: true }, 200, origin);
  }

  return err('Ruta no encontrada.', 404, origin);
}
