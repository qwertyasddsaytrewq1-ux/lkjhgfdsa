'use strict';

const path      = require('path');
const fs        = require('fs');
const crypto    = require('crypto');
const express   = require('express');
const Database  = require('better-sqlite3');

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const PORT        = parseInt(process.env.PORT || '8080', 10);
const ADMIN_TOKEN = process.env.ADMIN_TOKEN;
const DB_PATH     = process.env.DATABASE_PATH || '/data/panel.db';

if (!ADMIN_TOKEN || ADMIN_TOKEN.length < 4) {
  console.error('FATAL: ADMIN_TOKEN missing or too short.');
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Ensure DB directory exists
// ---------------------------------------------------------------------------
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// ---------------------------------------------------------------------------
// DB init
// ---------------------------------------------------------------------------
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS keys (
    key         TEXT PRIMARY KEY,
    game        TEXT NOT NULL DEFAULT 'PUBG',
    serial      TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    banned      INTEGER NOT NULL DEFAULT 0,
    note        TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_keys_serial ON keys(serial);

  CREATE TABLE IF NOT EXISTS logs (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,
    key     TEXT,
    serial  TEXT,
    ip      TEXT,
    ok      INTEGER NOT NULL,
    reason  TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
`);

const stmts = {
  getKey:      db.prepare(`SELECT * FROM keys WHERE key = ?`),
  bindSerial:  db.prepare(`UPDATE keys SET serial = ? WHERE key = ?`),
  resetSerial: db.prepare(`UPDATE keys SET serial = NULL WHERE key = ?`),
  insertKey:   db.prepare(`INSERT INTO keys (key, game, created_at, expires_at, note)
                           VALUES (?, ?, ?, ?, ?)`),
  banKey:      db.prepare(`UPDATE keys SET banned = 1 WHERE key = ?`),
  unbanKey:    db.prepare(`UPDATE keys SET banned = 0 WHERE key = ?`),
  extendKey:   db.prepare(`UPDATE keys SET expires_at = ? WHERE key = ?`),
  delKey:      db.prepare(`DELETE FROM keys WHERE key = ?`),
  listKeys:    db.prepare(`SELECT * FROM keys ORDER BY created_at DESC LIMIT 500`),
  logLogin:    db.prepare(`INSERT INTO logs (ts, key, serial, ip, ok, reason)
                           VALUES (?, ?, ?, ?, ?, ?)`),
  listLogs:    db.prepare(`SELECT * FROM logs ORDER BY id DESC LIMIT 500`),
};

// ---------------------------------------------------------------------------
// Express
// ---------------------------------------------------------------------------
const app = express();
app.set('trust proxy', true);
app.use(express.urlencoded({ extended: false, limit: '16kb' }));
app.use(express.json({ limit: '16kb' }));

// ---------------------------------------------------------------------------
// Rate limiter on /connect — 20 req / 60s per IP
// ---------------------------------------------------------------------------
const RL_WINDOW_MS = 60_000;
const RL_MAX       = 20;
const rlBuckets    = new Map();

function rateLimit(req, res, next) {
  const ip  = req.ip || 'unknown';
  const now = Date.now();
  let b = rlBuckets.get(ip);
  if (!b || now - b.t > RL_WINDOW_MS) {
    b = { c: 0, t: now };
    rlBuckets.set(ip, b);
  }
  b.c++;
  if (b.c > RL_MAX) {
    return res.status(429).json({ status: false, reason: 'rate limited' });
  }
  next();
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, b] of rlBuckets) {
    if (now - b.t > RL_WINDOW_MS * 2) rlBuckets.delete(ip);
  }
}, 60_000).unref();

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function fmtExpUTC(ts) {
  const d = new Date(ts * 1000);
  const p = n => String(n).padStart(2, '0');
  return `${d.getUTCFullYear()}-${p(d.getUTCMonth() + 1)}-${p(d.getUTCDate())} ` +
         `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
}

function safeLog(key, serial, ip, ok, reason) {
  try {
    stmts.logLogin.run(Date.now(), key || null, serial || null, ip || null,
                       ok ? 1 : 0, reason || null);
  } catch (e) {
    console.error('log write failed:', e.message);
  }
}

function genKey() {
  const hex = crypto.randomBytes(8).toString('hex').toUpperCase();
  return `CARR-${hex.slice(0,4)}-${hex.slice(4,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}`;
}

// ---------------------------------------------------------------------------
// POST /connect — the client's login endpoint
// ---------------------------------------------------------------------------
app.post('/connect', rateLimit, (req, res) => {
  const { game, user_key, serial } = req.body || {};
  const ip = req.ip || 'unknown';

  if (!user_key || !serial) {
    safeLog(user_key, serial, ip, 0, 'missing fields');
    return res.json({ status: false, reason: 'missing fields' });
  }

  let row;
  try {
    row = stmts.getKey.get(user_key);
  } catch (e) {
    console.error('db error:', e.message);
    return res.status(500).json({ status: false, reason: 'server error' });
  }

  if (!row) {
    safeLog(user_key, serial, ip, 0, 'key not found');
    return res.json({ status: false, reason: 'Key not found' });
  }
  if (row.banned) {
    safeLog(user_key, serial, ip, 0, 'banned');
    return res.json({ status: false, reason: 'Key banned' });
  }
  if (game && row.game && row.game !== game) {
    safeLog(user_key, serial, ip, 0, 'wrong game');
    return res.json({ status: false, reason: 'Key not for this game' });
  }

  const now = Math.floor(Date.now() / 1000);
  if (now >= row.expires_at) {
    safeLog(user_key, serial, ip, 0, 'expired');
    return res.json({ status: false, reason: 'Key expired' });
  }

  if (!row.serial) {
    try {
      stmts.bindSerial.run(serial, user_key);
    } catch (e) {
      console.error('bind failed:', e.message);
      return res.status(500).json({ status: false, reason: 'server error' });
    }
  } else if (row.serial !== serial) {
    safeLog(user_key, serial, ip, 0, 'device mismatch');
    return res.json({ status: false, reason: 'Key bound to another device' });
  }

  const token = crypto.randomBytes(24).toString('hex');
  safeLog(user_key, serial, ip, 1, null);

  return res.json({
    status: true,
    data: {
      token,
      rng: now,
      EXP: fmtExpUTC(row.expires_at)
    }
  });
});

// ---------------------------------------------------------------------------
// Admin auth
// ---------------------------------------------------------------------------
function adminAuth(req, res, next) {
  const t = req.headers['x-admin-token'];
  if (!t || t !== ADMIN_TOKEN) {
    return res.status(401).json({ ok: false, reason: 'unauthorized' });
  }
  next();
}

// ---------------------------------------------------------------------------
// Admin endpoints
// ---------------------------------------------------------------------------
app.post('/admin/create', adminAuth, (req, res) => {
  const days = Math.max(1, parseInt(req.body.days || '30', 10));
  const game = (req.body.game || 'PUBG').toString();
  const note = (req.body.note || '').toString().slice(0, 200);

  const key = genKey();
  const now = Math.floor(Date.now() / 1000);
  const exp = now + days * 86400;

  try {
    stmts.insertKey.run(key, game, now, exp, note);
  } catch (e) {
    return res.status(500).json({ ok: false, reason: e.message });
  }
  res.json({ ok: true, key, game, days, expires: fmtExpUTC(exp) });
});

app.get('/admin/list', adminAuth, (_req, res) => {
  const rows = stmts.listKeys.all().map(r => ({
    ...r,
    expires_human: fmtExpUTC(r.expires_at),
    expired: Math.floor(Date.now() / 1000) >= r.expires_at
  }));
  res.json({ ok: true, count: rows.length, keys: rows });
});

app.post('/admin/ban', adminAuth, (req, res) => {
  const r = stmts.banKey.run(req.body.key || '');
  res.json({ ok: true, changed: r.changes });
});

app.post('/admin/unban', adminAuth, (req, res) => {
  const r = stmts.unbanKey.run(req.body.key || '');
  res.json({ ok: true, changed: r.changes });
});

app.post('/admin/reset_device', adminAuth, (req, res) => {
  const r = stmts.resetSerial.run(req.body.key || '');
  res.json({ ok: true, changed: r.changes });
});

app.post('/admin/extend', adminAuth, (req, res) => {
  const days = Math.max(1, parseInt(req.body.days || '30', 10));
  const key  = req.body.key;
  const row  = stmts.getKey.get(key);
  if (!row) return res.json({ ok: false, reason: 'no such key' });

  const now  = Math.floor(Date.now() / 1000);
  const base = Math.max(row.expires_at, now);
  const exp  = base + days * 86400;

  stmts.extendKey.run(exp, key);
  res.json({ ok: true, key, expires: fmtExpUTC(exp) });
});

app.post('/admin/delete', adminAuth, (req, res) => {
  const r = stmts.delKey.run(req.body.key || '');
  res.json({ ok: true, changed: r.changes });
});

app.get('/admin/logs', adminAuth, (_req, res) => {
  res.json({ ok: true, logs: stmts.listLogs.all() });
});

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------
app.get('/health', (_req, res) => {
  let dbOk = true;
  try { db.prepare('SELECT 1').get(); } catch { dbOk = false; }
  res.json({ ok: dbOk, db: DB_PATH, uptime: process.uptime(), t: Date.now() });
});

// ---------------------------------------------------------------------------
// 404 + errors
// ---------------------------------------------------------------------------
app.use((_req, res) => res.status(404).json({ status: false, reason: 'not found' }));
app.use((err, _req, res, _next) => {
  console.error('unhandled:', err);
  res.status(500).json({ status: false, reason: 'server error' });
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`panel listening on :${PORT}`);
  console.log(`db path: ${DB_PATH}`);
});

function shutdown(sig) {
  console.log(`received ${sig}, shutting down...`);
  server.close(() => {
    try { db.pragma('wal_checkpoint(TRUNCATE)'); db.close(); } catch {}
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 8000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
