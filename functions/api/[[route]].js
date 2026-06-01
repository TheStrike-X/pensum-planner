// Pensum Planner — Cloudflare Pages Functions API
// Handles: register, login, logout, progress CRUD

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS },
  });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

// ── Crypto helpers ────────────────────────────────────────────────────────────

async function hashPassword(password) {
  const encoder = new TextEncoder();
  // Use PBKDF2 for password hashing (available in Workers crypto)
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hashArray = Array.from(new Uint8Array(bits));
  const saltArray = Array.from(salt);
  return saltArray.map(b => b.toString(16).padStart(2, '0')).join('') + ':' +
         hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyPassword(password, stored) {
  const [saltHex, hashHex] = stored.split(':');
  const salt = new Uint8Array(saltHex.match(/.{2}/g).map(b => parseInt(b, 16)));
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial, 256
  );
  const hashArray = Array.from(new Uint8Array(bits));
  const computed = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return computed === hashHex;
}

function generateToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ── Session helpers ───────────────────────────────────────────────────────────

async function getUserFromToken(db, authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7);
  const session = await db.prepare(
    'SELECT user_id, expires_at FROM sessions WHERE token = ?'
  ).bind(token).first();
  if (!session) return null;
  if (new Date(session.expires_at) < new Date()) {
    await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }
  const user = await db.prepare(
    'SELECT id, email, name FROM users WHERE id = ?'
  ).bind(session.user_id).first();
  return user || null;
}

// ── Route handler ─────────────────────────────────────────────────────────────

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api/, '');
  const method = request.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: CORS });
  }

  const db = env.DB;

  // ── POST /register ──────────────────────────────────────────────────────────
  if (path === '/register' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return err('Invalid JSON'); }
    const { email, password, name } = body;
    if (!email || !password) return err('Email and password are required');
    if (password.length < 6) return err('Password must be at least 6 characters');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return err('Invalid email');

    const existing = await db.prepare('SELECT id FROM users WHERE email = ?')
      .bind(email.toLowerCase()).first();
    if (existing) return err('Email already registered', 409);

    const hashed = await hashPassword(password);
    const userId = generateToken().slice(0, 16);
    await db.prepare('INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)')
      .bind(userId, email.toLowerCase(), name || email.split('@')[0], hashed).run();

    const token = generateToken();
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    await db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
      .bind(token, userId, expires).run();

    return json({ token, user: { id: userId, email: email.toLowerCase(), name: name || email.split('@')[0] } }, 201);
  }

  // ── POST /login ─────────────────────────────────────────────────────────────
  if (path === '/login' && method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return err('Invalid JSON'); }
    const { email, password } = body;
    if (!email || !password) return err('Email and password are required');

    const user = await db.prepare('SELECT * FROM users WHERE email = ?')
      .bind(email.toLowerCase()).first();
    if (!user) return err('Invalid email or password', 401);

    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) return err('Invalid email or password', 401);

    const token = generateToken();
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
    await db.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
      .bind(token, user.id, expires).run();

    return json({ token, user: { id: user.id, email: user.email, name: user.name } });
  }

  // ── POST /logout ────────────────────────────────────────────────────────────
  if (path === '/logout' && method === 'POST') {
    const authHeader = request.headers.get('Authorization');
    if (authHeader?.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      await db.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    }
    return json({ ok: true });
  }

  // ── GET /me ─────────────────────────────────────────────────────────────────
  if (path === '/me' && method === 'GET') {
    const user = await getUserFromToken(db, request.headers.get('Authorization'));
    if (!user) return err('Unauthorized', 401);
    return json({ user });
  }

  // ── GET /progress/:careerId ─────────────────────────────────────────────────
  if (path.startsWith('/progress/') && method === 'GET') {
    const user = await getUserFromToken(db, request.headers.get('Authorization'));
    if (!user) return err('Unauthorized', 401);
    const careerId = path.replace('/progress/', '');
    const row = await db.prepare(
      'SELECT data FROM progress WHERE user_id = ? AND career_id = ?'
    ).bind(user.id, careerId).first();
    return json({ data: row ? JSON.parse(row.data) : {} });
  }

  // ── POST /progress/:careerId ────────────────────────────────────────────────
  if (path.startsWith('/progress/') && method === 'POST') {
    const user = await getUserFromToken(db, request.headers.get('Authorization'));
    if (!user) return err('Unauthorized', 401);
    const careerId = path.replace('/progress/', '');
    let body;
    try { body = await request.json(); } catch { return err('Invalid JSON'); }
    const dataStr = JSON.stringify(body.data || {});
    await db.prepare(`
      INSERT INTO progress (user_id, career_id, data, updated_at)
      VALUES (?, ?, ?, datetime('now'))
      ON CONFLICT(user_id, career_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
    `).bind(user.id, careerId, dataStr).run();
    return json({ ok: true });
  }

  // ── DELETE /progress/:careerId ──────────────────────────────────────────────
  if (path.startsWith('/progress/') && method === 'DELETE') {
    const user = await getUserFromToken(db, request.headers.get('Authorization'));
    if (!user) return err('Unauthorized', 401);
    const careerId = path.replace('/progress/', '');
    await db.prepare('DELETE FROM progress WHERE user_id = ? AND career_id = ?')
      .bind(user.id, careerId).run();
    return json({ ok: true });
  }

  return err('Not found', 404);
}
