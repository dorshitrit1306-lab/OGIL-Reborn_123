'use strict';
const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT) || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data', 'db.json');
const SESSION_MS = 30 * 24 * 3600 * 1000;
const ONLINE_MS = 90 * 1000;

// Permissions a staff member can be given one by one. Owner and admins hold all of them.
const PERMISSIONS = [
  'manage_users',
  'manage_shop',
  'manage_codes',
  'manage_content',
  'manage_servers',
  'manage_tournaments',
  'manage_stats',
  'view_audit'
];

const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function rand(n) {
  let s = '';
  for (let i = 0; i < n; i++) s += ALPHABET[crypto.randomInt(ALPHABET.length)];
  return s;
}
const uid = () => crypto.randomUUID();
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
function safeEq(a, b) {
  return crypto.timingSafeEqual(Buffer.from(sha(a)), Buffer.from(sha(b)));
}

function defaults() {
  return {
    meta: { ownerClaimed: false, setupCode: rand(8), gameKey: crypto.randomBytes(18).toString('hex') },
    users: [],
    sessions: {},
    codes: [],
    audit: [],
    shop: [
      {
        id: uid(), name: 'Full Pack', tag: 'כל הסקינים', price: 10, oldPrice: null, highlight: false,
        desc: 'כל הסקינים שיצרנו עד היום.',
        features: ['גישה מלאה לכל הסקינים הקיימים', 'עדיפות בכניסה לשרתים', 'גישה לעדכונים עתידיים', 'רול Full Pack בדיסקורד']
      },
      {
        id: uid(), name: 'Ultimate Pack', tag: 'כולל הכל', price: 20, oldPrice: null, highlight: true,
        desc: 'כל מה שיש ב-Full Pack, בתוספת סקינים ופריטים ייחודיים.',
        features: ['גישה מלאה לכל הסקינים + סקינים ייחודיים', 'עדיפות בכניסה לשרתים', 'גישה לעדכונים עתידיים', 'רול Ultimate Pack בדיסקורד']
      }
    ],
    servers: [],
    tournaments: [],
    builds: [],
    community: [
      { id: uid(), kind: 'discord', name: 'Discord', handle: '', url: '' },
      { id: uid(), kind: 'tiktok', name: 'TikTok', handle: '', url: '' },
      { id: uid(), kind: 'youtube', name: 'YouTube', handle: '', url: '' }
    ],
    news: {
      badge: 'חדש',
      title: 'OGIL Reborn',
      subtitle: 'הפרויקט חזר. האם אתה מוכן?',
      body: 'הצטרפו לקהילה ושחקו עכשיו.',
      buttonText: 'שחק עכשיו'
    }
  };
}

let db;
function save() {
  fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DATA_FILE);
}
function load() {
  try {
    db = Object.assign(defaults(), JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')));
  } catch (e) {
    db = defaults();
    save();
  }
}
load();


if (process.env.RESET_OWNER && db.meta.resetDone !== process.env.RESET_OWNER) {
  for (const u of db.users) {
    if (u.role === 'owner') {
      u.role = 'player';
      u.permissions = [];
    }
  }
  db.meta.ownerClaimed = false;
  db.meta.setupCode = rand(8);
  db.meta.resetDone = process.env.RESET_OWNER;
  db.sessions = {};
  save();
  console.log('Owner reset done. Use the new setup code below to become the owner.');
}
/* ---------- helpers ---------- */

const isOwner = (u) => u.role === 'owner';
const isAdmin = (u) => u.role === 'owner' || u.role === 'admin';
const can = (u, perm) => isAdmin(u) || (u.permissions || []).includes(perm);
const effective = (u) => (isAdmin(u) ? PERMISSIONS.slice() : (u.permissions || []).slice());

function me(u) {
  return {
    id: u.id,
    username: u.username,
    role: u.role,
    permissions: effective(u),
    canGrant: isAdmin(u),
    items: u.items || [],
    createdAt: u.createdAt
  };
}

function str(v, max) {
  return typeof v === 'string' ? v.trim().slice(0, max) : '';
}
function num(v, min, max, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}
function isHttp(u) {
  return typeof u === 'string' && /^https?:\/\/[^\s]+$/i.test(u);
}

function audit(by, action, detail) {
  db.audit.push({ at: new Date().toISOString(), by: by.username, action, detail: str(detail || '', 200) });
  if (db.audit.length > 500) db.audit.splice(0, db.audit.length - 500);
}

function newSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  db.sessions[sha(token)] = { userId: user.id, at: Date.now() };
  // Drop expired sessions
  for (const [k, s] of Object.entries(db.sessions)) {
    if (Date.now() - s.at > SESSION_MS) delete db.sessions[k];
  }
  return token;
}

const seen = new Map(); // userId -> last request time (memory only)

function hashPw(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  return { salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') };
}
function checkPw(pw, u) {
  const h = crypto.scryptSync(pw, u.salt, 64);
  const b = Buffer.from(u.hash, 'hex');
  return b.length === h.length && crypto.timingSafeEqual(h, b);
}

const failures = new Map();
const blocked = (key) => {
  const f = failures.get(key);
  return Boolean(f && f.reset > Date.now() && f.n >= 8);
};
const fail = (key) => {
  const now = Date.now();
  const f = failures.get(key);
  if (!f || f.reset < now) failures.set(key, { n: 1, reset: now + 10 * 60 * 1000 });
  else f.n++;
};

/* ---------- middleware ---------- */

const app = express();
app.disable('x-powered-by');
// Hosting platforms put a proxy in front of the app. Set TRUST_PROXY=1 there so
// the login limiter sees the real client address. Leave it unset when running locally.
if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY) || 1);
app.use(express.json({ limit: '100kb' }));

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const s = token && db.sessions[sha(token)];
  if (!s || Date.now() - s.at > SESSION_MS) return res.status(401).json({ error: 'צריך להתחבר מחדש.' });
  const user = db.users.find((u) => u.id === s.userId);
  if (!user || user.banned) return res.status(401).json({ error: 'החשבון חסום או לא קיים.' });
  req.user = user;
  req.tokenHash = sha(token);
  seen.set(user.id, Date.now());
  next();
}

const need = (perm) => (req, res, next) =>
  can(req.user, perm) ? next() : res.status(403).json({ error: 'אין לך הרשאה לפעולה הזאת.' });

const onlineCount = () => {
  const now = Date.now();
  let n = 0;
  for (const t of seen.values()) if (now - t < ONLINE_MS) n++;
  return n;
};

/* ---------- accounts ---------- */

app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/register', (req, res) => {
  const username = str(req.body.username, 20);
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  if (!/^[A-Za-z0-9_֐-׿]{3,20}$/.test(username)) {
    return res.status(400).json({ error: 'שם משתמש: 3 עד 20 תווים, אותיות, מספרים או _.' });
  }
  if (password.length < 6 || password.length > 100) {
    return res.status(400).json({ error: 'הסיסמה צריכה להיות באורך 6 תווים לפחות.' });
  }
  const key = 'reg:' + req.ip;
  if (blocked(key)) return res.status(429).json({ error: 'יותר מדי ניסיונות. נסה שוב בעוד כמה דקות.' });
  if (db.users.some((u) => u.username.toLowerCase() === username.toLowerCase())) {
    return res.status(409).json({ error: 'שם המשתמש תפוס.' });
  }

  let role = 'player';
  const code = str(req.body.setupCode, 40);
  if (code) {
    if (db.meta.ownerClaimed || !db.meta.setupCode || !safeEq(code.toUpperCase(), db.meta.setupCode)) {
      fail(key);
      return res.status(403).json({ error: 'קוד ההקמה שגוי או שכבר נוצל.' });
    }
    role = 'owner';
  }

  const { salt, hash } = hashPw(password);
  const user = {
    id: uid(), username, salt, hash, role, permissions: [], banned: false, items: [],
    stats: { points: 0, wins: 0, losses: 0 }, createdAt: new Date().toISOString()
  };
  db.users.push(user);
  if (role === 'owner') {
    db.meta.ownerClaimed = true;
    db.meta.setupCode = null;
    audit(user, 'owner_claimed', '');
  }
  const token = newSession(user);
  save();
  res.json({ token, me: me(user) });
});

app.post('/api/login', (req, res) => {
  const username = str(req.body.username, 20).toLowerCase();
  const password = typeof req.body.password === 'string' ? req.body.password : '';
  const key = 'login:' + req.ip + ':' + username;
  if (blocked(key)) return res.status(429).json({ error: 'יותר מדי ניסיונות. נסה שוב בעוד כמה דקות.' });
  const user = db.users.find((u) => u.username.toLowerCase() === username);
  if (!user || !checkPw(password, user)) {
    fail(key);
    return res.status(401).json({ error: 'שם משתמש או סיסמה שגויים.' });
  }
  if (user.banned) return res.status(403).json({ error: 'החשבון חסום.' });
  const token = newSession(user);
  save();
  res.json({ token, me: me(user) });
});

app.post('/api/logout', auth, (req, res) => {
  delete db.sessions[req.tokenHash];
  save();
  res.json({ ok: true });
});

app.get('/api/me', auth, (req, res) => res.json(me(req.user)));

app.post('/api/ping', auth, (req, res) => res.json({ online: onlineCount() }));

/* ---------- content everyone can read ---------- */

const tState = (t) => {
  const now = Date.now();
  const s = Date.parse(t.startsAt);
  const e = t.endsAt ? Date.parse(t.endsAt) : s + 3 * 3600 * 1000;
  return now < s ? 'upcoming' : now <= e ? 'live' : 'ended';
};

app.get('/api/overview', auth, (req, res) => {
  res.json({ news: db.news, community: db.community, online: onlineCount(), totalUsers: db.users.length });
});

app.get('/api/leaderboard', auth, (req, res) => {
  const key = ['points', 'wins', 'losses'].includes(req.query.sort) ? req.query.sort : 'points';
  const players = db.users
    .filter((u) => !u.banned)
    .map((u) => ({ username: u.username, points: u.stats.points, wins: u.stats.wins, losses: u.stats.losses }))
    .sort((a, b) => b[key] - a[key] || a.username.localeCompare(b.username))
    .slice(0, 200)
    .map((p, i) => Object.assign({ rank: i + 1 }, p));
  res.json({ total: db.users.filter((u) => !u.banned).length, players });
});

app.post('/api/redeem', auth, (req, res) => {
  const code = str(req.body.code, 40).toUpperCase();
  const key = 'redeem:' + req.user.id;
  if (blocked(key)) return res.status(429).json({ error: 'יותר מדי ניסיונות. נסה שוב בעוד כמה דקות.' });
  const entry = db.codes.find((c) => c.code === code && !c.usedBy);
  if (!entry) {
    fail(key);
    return res.status(404).json({ error: 'הקוד לא נמצא או שכבר נוצל.' });
  }
  entry.usedBy = req.user.username;
  entry.usedAt = new Date().toISOString();
  req.user.items = Array.from(new Set((req.user.items || []).concat(entry.itemId)));
  save();
  res.json({ ok: true, me: me(req.user) });
});

/* ---------- collections: shop, servers, tournaments, builds, community ---------- */

function cleanShop(b) {
  const name = str(b.name, 40);
  if (!name) return { error: 'חסר שם.' };
  return {
    value: {
      name, tag: str(b.tag, 30), desc: str(b.desc, 200),
      price: num(b.price, 0, 100000, 0),
      oldPrice: b.oldPrice == null || b.oldPrice === '' ? null : num(b.oldPrice, 0, 100000, null),
      features: Array.isArray(b.features) ? b.features.map((f) => str(f, 80)).filter(Boolean).slice(0, 8) : [],
      highlight: Boolean(b.highlight)
    }
  };
}
function cleanServer(b) {
  const name = str(b.name, 60);
  if (!name) return { error: 'חסר שם.' };
  const capacity = Math.round(num(b.capacity, 1, 1000, 20));
  return {
    value: {
      name, playlist: str(b.playlist, 60),
      players: Math.min(Math.round(num(b.players, 0, 1000, 0)), capacity),
      capacity, joinable: b.joinable !== false
    }
  };
}
function cleanTournament(b) {
  const name = str(b.name, 60);
  if (!name) return { error: 'חסר שם.' };
  if (!b.startsAt || Number.isNaN(Date.parse(b.startsAt))) return { error: 'תאריך התחלה לא תקין.' };
  const endsAt = b.endsAt && !Number.isNaN(Date.parse(b.endsAt)) ? new Date(b.endsAt).toISOString() : '';
  return { value: { name, desc: str(b.desc, 200), prize: str(b.prize, 60), startsAt: new Date(b.startsAt).toISOString(), endsAt } };
}
function cleanBuild(b) {
  const name = str(b.name, 60);
  if (!name) return { error: 'חסר שם.' };
  if (!isHttp(b.url)) return { error: 'הקישור צריך להתחיל ב-http או https.' };
  return { value: { name, version: str(b.version, 20), url: b.url.trim().slice(0, 500) } };
}
function cleanCommunity(b) {
  const kind = ['discord', 'youtube', 'tiktok', 'instagram', 'other'].includes(b.kind) ? b.kind : 'other';
  const name = str(b.name, 30);
  if (!name) return { error: 'חסר שם.' };
  const url = str(b.url, 500);
  if (url && !isHttp(url)) return { error: 'הקישור צריך להתחיל ב-http או https.' };
  return { value: { kind, name, handle: str(b.handle, 40), url } };
}

const COLLECTIONS = {
  shop: { perm: 'manage_shop', clean: cleanShop },
  servers: { perm: 'manage_servers', clean: cleanServer },
  tournaments: { perm: 'manage_tournaments', clean: cleanTournament },
  builds: { perm: 'manage_content', clean: cleanBuild },
  community: { perm: 'manage_content', clean: cleanCommunity }
};

app.get('/api/:col(shop|servers|tournaments|builds|community)', auth, (req, res) => {
  const col = req.params.col;
  let items = db[col];
  if (col === 'tournaments') items = items.map((t) => Object.assign({}, t, { state: tState(t) }));
  res.json({ items });
});

app.post('/api/admin/:col(shop|servers|tournaments|builds|community)', auth, (req, res) => {
  const col = req.params.col;
  const c = COLLECTIONS[col];
  if (!can(req.user, c.perm)) return res.status(403).json({ error: 'אין לך הרשאה לפעולה הזאת.' });
  if (db[col].length >= 200) return res.status(400).json({ error: 'הגעת למגבלת הפריטים.' });
  const r = c.clean(req.body);
  if (r.error) return res.status(400).json({ error: r.error });
  const item = Object.assign({ id: uid() }, r.value);
  db[col].push(item);
  audit(req.user, col + '_add', item.name);
  save();
  res.json(item);
});

app.put('/api/admin/:col(shop|servers|tournaments|builds|community)/:id', auth, (req, res) => {
  const col = req.params.col;
  const c = COLLECTIONS[col];
  if (!can(req.user, c.perm)) return res.status(403).json({ error: 'אין לך הרשאה לפעולה הזאת.' });
  const item = db[col].find((x) => x.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'לא נמצא.' });
  const r = c.clean(req.body);
  if (r.error) return res.status(400).json({ error: r.error });
  Object.assign(item, r.value);
  audit(req.user, col + '_edit', item.name);
  save();
  res.json(item);
});

app.delete('/api/admin/:col(shop|servers|tournaments|builds|community)/:id', auth, (req, res) => {
  const col = req.params.col;
  const c = COLLECTIONS[col];
  if (!can(req.user, c.perm)) return res.status(403).json({ error: 'אין לך הרשאה לפעולה הזאת.' });
  const item = db[col].find((x) => x.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'לא נמצא.' });
  db[col] = db[col].filter((x) => x.id !== item.id);
  audit(req.user, col + '_delete', item.name);
  save();
  res.json({ ok: true });
});

app.put('/api/admin/news', auth, need('manage_content'), (req, res) => {
  db.news = {
    badge: str(req.body.badge, 40), title: str(req.body.title, 60), subtitle: str(req.body.subtitle, 100),
    body: str(req.body.body, 200), buttonText: str(req.body.buttonText, 30) || 'שחק עכשיו'
  };
  audit(req.user, 'news_edit', db.news.title);
  save();
  res.json(db.news);
});

/* ---------- redeem codes ---------- */

app.get('/api/admin/codes', auth, need('manage_codes'), (req, res) => {
  res.json({ items: db.codes.slice(-200).reverse() });
});

app.post('/api/admin/codes', auth, need('manage_codes'), (req, res) => {
  const item = db.shop.find((s) => s.id === req.body.itemId);
  if (!item) return res.status(400).json({ error: 'בחר פריט מהחנות.' });
  const count = Math.round(num(req.body.count, 1, 50, 1));
  const made = [];
  for (let i = 0; i < count; i++) {
    const code = rand(4) + '-' + rand(4) + '-' + rand(4);
    db.codes.push({ code, itemId: item.id, createdBy: req.user.username, createdAt: new Date().toISOString(), usedBy: null, usedAt: null });
    made.push(code);
  }
  if (db.codes.length > 5000) db.codes.splice(0, db.codes.length - 5000);
  audit(req.user, 'codes_create', count + ' x ' + item.name);
  save();
  res.json({ codes: made });
});

/* ---------- users, roles and permissions ---------- */

app.get('/api/admin/users', auth, (req, res) => {
  if (!can(req.user, 'manage_users') && !isAdmin(req.user)) return res.status(403).json({ error: 'אין לך הרשאה לפעולה הזאת.' });
  res.json({
    items: db.users.map((u) => ({
      id: u.id, username: u.username, role: u.role, permissions: u.permissions || [],
      banned: u.banned, items: (u.items || []).length, stats: u.stats, createdAt: u.createdAt
    }))
  });
});

// Only the owner can make someone an admin or take it away.
app.post('/api/admin/users/:id/role', auth, (req, res) => {
  if (!isOwner(req.user)) return res.status(403).json({ error: 'רק הבעלים יכול למנות או להסיר מנהלים.' });
  const target = db.users.find((u) => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'משתמש לא נמצא.' });
  if (isOwner(target)) return res.status(400).json({ error: 'לא ניתן לשנות את הבעלים.' });
  const role = req.body.role;
  if (!['admin', 'staff', 'player'].includes(role)) return res.status(400).json({ error: 'תפקיד לא תקין.' });
  target.role = role;
  if (role !== 'staff') target.permissions = [];
  if (role === 'staff' && !(target.permissions || []).length) target.role = 'player';
  audit(req.user, 'role_set', target.username + ' -> ' + role);
  save();
  res.json({ ok: true });
});

// Owner and admins can hand out individual permissions. Admins cannot touch other admins.
app.post('/api/admin/users/:id/permissions', auth, (req, res) => {
  if (!isAdmin(req.user)) return res.status(403).json({ error: 'רק הבעלים והמנהלים יכולים לתת הרשאות.' });
  const target = db.users.find((u) => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'משתמש לא נמצא.' });
  if (isAdmin(target)) return res.status(400).json({ error: 'למנהלים כבר יש את כל ההרשאות.' });
  if (!Array.isArray(req.body.permissions)) return res.status(400).json({ error: 'בקשה לא תקינה.' });
  const perms = Array.from(new Set(req.body.permissions.filter((p) => PERMISSIONS.includes(p))));
  target.permissions = perms;
  target.role = perms.length ? 'staff' : 'player';
  audit(req.user, 'permissions_set', target.username + ': ' + (perms.join(', ') || 'none'));
  save();
  res.json({ ok: true });
});

app.post('/api/admin/users/:id/ban', auth, need('manage_users'), (req, res) => {
  const target = db.users.find((u) => u.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'משתמש לא נמצא.' });
  if (target.id === req.user.id) return res.status(400).json({ error: 'לא ניתן לחסום את עצמך.' });
  if (isOwner(target) || (isAdmin(target) && !isOwner(req.user))) {
    return res.status(403).json({ error: 'אין לך הרשאה לחסום את המשתמש הזה.' });
  }
  target.banned = Boolean(req.body.banned);
  if (target.banned) {
    for (const [k, s] of Object.entries(db.sessions)) if (s.userId === target.id) delete db.sessions[k];
  }
  audit(req.user, target.banned ? 'ban' : 'unban', target.username);
  save();
  res.json({ ok: true });
});

app.post('/api/admin/stats', auth, need('manage_stats'), (req, res) => {
  const target = db.users.find((u) => u.username.toLowerCase() === str(req.body.username, 20).toLowerCase());
  if (!target) return res.status(404).json({ error: 'משתמש לא נמצא.' });
  target.stats = {
    points: Math.round(num(req.body.points, 0, 1e9, 0)),
    wins: Math.round(num(req.body.wins, 0, 1e9, 0)),
    losses: Math.round(num(req.body.losses, 0, 1e9, 0))
  };
  audit(req.user, 'stats_set', target.username);
  save();
  res.json({ ok: true });
});

app.get('/api/admin/audit', auth, need('view_audit'), (req, res) => {
  res.json({ items: db.audit.slice(-200).reverse() });
});

/* ---------- reports from your own game server ---------- */

// Your game server posts match results here with the header x-game-key.
app.post('/api/report', (req, res) => {
  const key = req.headers['x-game-key'];
  if (typeof key !== 'string' || !safeEq(key, db.meta.gameKey)) return res.status(401).json({ error: 'unauthorized' });
  const user = db.users.find((u) => u.username.toLowerCase() === str(req.body.username, 20).toLowerCase());
  if (!user) return res.status(404).json({ error: 'unknown user' });
  user.stats.points += Math.round(num(req.body.points, 0, 100000, 0));
  if (req.body.win) user.stats.wins += 1;
  else user.stats.losses += 1;
  save();
  res.json({ ok: true });
});

/* ---------- errors ---------- */

app.use((req, res) => res.status(404).json({ error: 'לא נמצא.' }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'בקשה לא תקינה.' });
  console.error(err);
  res.status(500).json({ error: 'שגיאה בשרת.' });
});

if (require.main === module) {
  app.listen(PORT, () => {
    console.log('OGIL Reborn server is running on port ' + PORT);
    if (!db.meta.ownerClaimed) {
      console.log('');
      console.log('Owner setup code: ' + db.meta.setupCode);
      console.log('Register in the launcher with this code to become the owner.');
    }
    console.log('Game key for /api/report: ' + db.meta.gameKey);
  });
}

module.exports = { app };
