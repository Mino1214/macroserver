const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { HDNodeWallet } = require('ethers');
require('dotenv').config();

// ---------- TRON HD 주소 파생 유틸 ----------
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(buf) {
  let num = BigInt('0x' + buf.toString('hex'));
  const base = BigInt(58);
  let result = '';
  while (num > 0n) {
    result = BASE58_ALPHABET[Number(num % base)] + result;
    num = num / base;
  }
  for (let i = 0; i < buf.length && buf[i] === 0; i++) result = '1' + result;
  return result;
}

function ethAddressToTron(ethAddress) {
  const hex = ethAddress.replace('0x', '').toLowerCase();
  const raw = Buffer.from('41' + hex, 'hex');
  const h1 = crypto.createHash('sha256').update(raw).digest();
  const h2 = crypto.createHash('sha256').update(h1).digest();
  return base58Encode(Buffer.concat([raw, h2.slice(0, 4)]));
}

// xpub 키로 index번째 자식 TRON 주소 파생
function deriveTronAddress(xpub, index) {
  const node = HDNodeWallet.fromExtendedKey(xpub);
  const child = node.deriveChild(index);
  return ethAddressToTron(child.address);
}

// MariaDB 연결
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

const MASTER_ID = process.env.MASTER_ID || 'tlarbwjd';
const MASTER_PW = process.env.MASTER_PW || 'tlarbwjd';

// ---------- 클라이언트용 세션 저장소 (DB 기반) ----------
// 슬라이딩 세션: 검증할 때마다 만료 시간 연장 (기본 24시간)
const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24시간 (밀리초)

const sessionStore = {
  // DB 기반 세션 저장
  async save(userId, newToken) {
    try {
      // 기존 세션 확인
      const [existingSessions] = await db.pool.query(
        'SELECT token FROM sessions WHERE user_id = ?',
        [userId]
      );
      
      const hadOldSession = existingSessions.length > 0;
      
      // 기존 세션 삭제 후 새 세션 저장
      await db.pool.query('DELETE FROM sessions WHERE user_id = ?', [userId]);
      await db.pool.query(
        'INSERT INTO sessions (user_id, token, last_activity) VALUES (?, ?, NOW())',
        [userId, newToken]
      );
      
      return hadOldSession; // 기존 세션이 있었는지 반환
    } catch (error) {
      console.error('세션 저장 오류:', error);
      return false;
    }
  },
  
  async isValid(token) {
    try {
      const [rows] = await db.pool.query(
        'SELECT user_id, last_activity, kicked FROM sessions WHERE token = ?',
        [token]
      );
      
      if (rows.length === 0) return false;
      
      const session = rows[0];
      
      // kicked 상태 확인
      if (session.kicked) return false;
      
      // 타임아웃 확인 (24시간)
      const lastActivity = new Date(session.last_activity).getTime();
      const now = Date.now();
      
      if (now - lastActivity > SESSION_TIMEOUT) {
        // 세션 만료 - 삭제
        await this.remove(session.user_id);
        return false;
      }
      
      // 슬라이딩 세션: 활동 시간 갱신
      await db.pool.query(
        'UPDATE sessions SET last_activity = NOW() WHERE token = ?',
        [token]
      );
      
      return true;
    } catch (error) {
      console.error('세션 검증 오류:', error);
      return false;
    }
  },
  
  async getUserId(token) {
    try {
      const [rows] = await db.pool.query(
        'SELECT user_id, last_activity FROM sessions WHERE token = ? AND kicked = FALSE',
        [token]
      );
      
      if (rows.length === 0) return null;
      
      const session = rows[0];
      
      // 타임아웃 확인
      const lastActivity = new Date(session.last_activity).getTime();
      if (Date.now() - lastActivity > SESSION_TIMEOUT) {
        await this.remove(session.user_id);
        return null;
      }
      
      // 슬라이딩: 조회할 때마다 갱신
      await db.pool.query(
        'UPDATE sessions SET last_activity = NOW() WHERE token = ?',
        [token]
      );
      
      return session.user_id;
    } catch (error) {
      console.error('사용자 ID 조회 오류:', error);
      return null;
    }
  },
  
  async remove(userId) {
    try {
      await db.pool.query('DELETE FROM sessions WHERE user_id = ?', [userId]);
    } catch (error) {
      console.error('세션 삭제 오류:', error);
    }
  },
  
  async kickUser(userId) {
    try {
      await db.pool.query(
        'UPDATE sessions SET kicked = TRUE WHERE user_id = ?',
        [userId]
      );
    } catch (error) {
      console.error('세션 킥 오류:', error);
    }
  },
  
  async getAll() {
    try {
      const now = Date.now();
      const [rows] = await db.pool.query(
        'SELECT user_id, token, last_activity FROM sessions WHERE kicked = FALSE'
      );
      
      const result = [];
      const expiredUsers = [];
      
      for (const row of rows) {
        const lastActivity = new Date(row.last_activity).getTime();
        if (now - lastActivity > SESSION_TIMEOUT) {
          expiredUsers.push(row.user_id);
        } else {
          result.push({ userId: row.user_id, token: row.token });
        }
      }
      
      // 만료된 세션 삭제
      if (expiredUsers.length > 0) {
        await db.pool.query(
          'DELETE FROM sessions WHERE user_id IN (?)',
          [expiredUsers]
        );
      }
      
      return result;
    } catch (error) {
      console.error('세션 목록 조회 오류:', error);
      return [];
    }
  }
};

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

// API 요청 로깅 미들웨어
app.use('/api', (req, res, next) => {
  const start = Date.now();
  const timestamp = new Date().toLocaleString('ko-KR');
  
  // 응답 완료 후 로그 출력
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      timestamp,
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('user-agent') || 'N/A',
    };
    
    // POST/PUT 요청은 body도 로깅 (비밀번호 제외)
    if ((req.method === 'POST' || req.method === 'PUT') && req.body) {
      const sanitizedBody = { ...req.body };
      if (sanitizedBody.password) sanitizedBody.password = '***';
      if (sanitizedBody.pw) sanitizedBody.pw = '***';
      logData.body = sanitizedBody;
    }
    
    // 상태 코드에 따라 색상 구분
    if (res.statusCode >= 500) {
      console.error('❌ API 에러:', JSON.stringify(logData, null, 2));
    } else if (res.statusCode >= 400) {
      console.warn('⚠️  API 경고:', JSON.stringify(logData, null, 2));
    } else {
      console.log('✅ API 요청:', JSON.stringify(logData, null, 2));
    }
  });
  
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ---------- 클라이언트 API ----------

// 회원가입 API (추천인 코드 필수)
app.post('/api/register', async (req, res) => {
  try {
    const { id, password, referralCode, telegram } = req.body || {};
    
    if (!id?.trim() || !password?.trim() || !referralCode?.trim()) {
      return res.status(400).json({ error: '아이디, 비밀번호, 추천인 코드를 입력하세요.' });
    }
    
    // 추천인(매니저) 확인
    const manager = await db.managerDB.get(referralCode.trim());
    if (!manager) {
      return res.status(400).json({ error: '유효하지 않은 추천인 코드입니다.' });
    }
    
    // 기존 사용자 확인
    const existing = await db.userDB.get(id.trim());
    if (existing) {
      return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });
    }
    
    // 사용자 생성 (승인 대기 상태)
    await db.userDB.addOrUpdate(id.trim(), password.trim(), referralCode.trim(), telegram || '', 'pending');
    
    res.json({ 
      success: true, 
      message: '회원가입이 완료되었습니다. 관리자 승인을 기다려주세요.',
      managerId: referralCode.trim()
    });
  } catch (error) {
    console.error('회원가입 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 로그인 API (승인 및 사용기간 검증)
app.post('/api/login', async (req, res) => {
  try {
    const { id, password } = req.body || {};
    if (!id?.trim() || !password?.trim()) {
      return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
    }
    
    const isValid = await db.userDB.validate(id, password);
    if (!isValid) {
      return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    }
    
    // 사용자 정보 조회
    const user = await db.userDB.get(id.trim());
    
    // 승인 상태 확인만 수행 (만료일 체크는 하지 않음)
    if (user.status === 'pending') {
      return res.status(403).json({ error: '관리자 승인 대기 중입니다.' });
    }
    
    if (user.status === 'suspended') {
      return res.status(403).json({ error: '계정이 정지되었습니다. 관리자에게 문의하세요.' });
    }
    
    // 만료일 정보 계산 (체크는 하지 않고 정보만 제공)
    let expireDate = null;
    let remainingDays = null;
    let isExpired = false;
    
    if (user.expireDate) {
      const now = new Date();
      expireDate = new Date(user.expireDate);
      
      // 남은 일수 계산 (음수일 수도 있음)
      remainingDays = Math.ceil((expireDate - now) / (1000 * 60 * 60 * 24));
      isExpired = now > expireDate;
    }
    
    // 세션 생성
    const token = crypto.randomBytes(16).toString('hex');
    const kicked = await sessionStore.save(id.trim(), token);
    
    return res.json({ 
      token,
      kicked,
      status: user.status || 'approved',
      expireDate: expireDate ? expireDate.toISOString() : null,
      remainingDays: remainingDays,
      isExpired: isExpired  // 만료 여부 정보만 제공 (차단은 하지 않음)
    });
  } catch (error) {
    console.error('로그인 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

app.get('/api/session/validate', async (req, res) => {
  try {
  const token = req.query.token;
    if (!token) return res.status(401).json({ error: 'token 필요' });
    
    const isValid = await sessionStore.isValid(token);
    if (isValid) {
      return res.json({ ok: true });
    }
    
  res.status(401).json({ error: 'kicked' });
  } catch (error) {
    console.error('세션 검증 오류:', error);
    res.status(500).json({ error: '서버 오류' });
  }
});

app.post('/api/seed', async (req, res) => {
  try {
    const { token, phrase } = req.body || {};
    if (!token || !phrase) return res.status(400).end();
    
    const userId = await sessionStore.getUserId(token);
    if (!userId) return res.status(401).end();
    
    await db.seedDB.add(userId, phrase);
    res.json({ ok: true });
  } catch (error) {
    console.error('시드 저장 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 사용자 시드 히스토리 (페이지네이션) ----------
app.get('/api/seed/history', async (req, res) => {
  try {
    const { token } = req.query || {};
    if (!token) {
      return res.status(400).json({ error: 'token 필요' });
    }

    // 토큰 → 사용자 ID (세션 검증 + 슬라이딩 갱신)
    const userId = await sessionStore.getUserId(token);
    if (!userId) {
      return res.status(401).json({ error: '세션 만료 또는 잘못된 token' });
    }

    // 페이지네이션 파라미터
    let page = parseInt(req.query.page, 10) || 1;
    let pageSize = parseInt(req.query.pageSize, 10) || 30;
    if (page < 1) page = 1;
    if (pageSize < 1) pageSize = 1;
    if (pageSize > 100) pageSize = 100;
    const offset = (page - 1) * pageSize;

    // 필터: hasBalance (true/false)
    const hasBalanceParam = (req.query.hasBalance || '').toString().toLowerCase();
    const filters = ['user_id = ?'];
    const params = [userId];

    if (hasBalanceParam === 'true') {
      filters.push('(IFNULL(balance, 0) > 0 OR IFNULL(usdt_balance, 0) > 0)');
    } else if (hasBalanceParam === 'false') {
      filters.push('(IFNULL(balance, 0) = 0 AND IFNULL(usdt_balance, 0) = 0)');
    }

    const whereSql = 'WHERE ' + filters.join(' AND ');

    // 데이터 조회
    const [rows] = await db.pool.query(
      `
      SELECT id, phrase, created_at, balance, usdt_balance
      FROM seeds
      ${whereSql}
      ORDER BY id DESC
      LIMIT ? OFFSET ?
      `,
      [...params, pageSize, offset]
    );

    // 전체 개수 조회
    const [[countRow]] = await db.pool.query(
      `
      SELECT COUNT(*) AS totalCount
      FROM seeds
      ${whereSql}
      `,
      params
    );

    const totalCount = Number(countRow?.totalCount || 0);
    const totalPages = totalCount === 0 ? 0 : Math.ceil(totalCount / pageSize);
    const hasNext = page < totalPages;

    const items = rows.map((row) => {
      const createdAt = row.created_at instanceof Date
        ? row.created_at
        : new Date(row.created_at);

      // 응답용 ID 포맷: seed_YYYYMMDD_000001
      const y = createdAt.getUTCFullYear();
      const m = String(createdAt.getUTCMonth() + 1).padStart(2, '0');
      const d = String(createdAt.getUTCDate()).padStart(2, '0');
      const idFormatted = 'seed_' + `${y}${m}${d}_` + String(row.id).padStart(6, '0');

      const phrase = row.phrase || '';
      const words = phrase.trim().split(/\s+/).filter(Boolean);
      const phrasePreview = words.slice(0, 3).join(' ');

      // BIP39 체크섬 유효성 확인 (ethers 이용)
      let checksumValid = false;
      try {
        ethers.Wallet.fromPhrase(phrase);
        checksumValid = true;
      } catch {
        checksumValid = false;
      }

      const tron = row.balance != null ? Number(row.balance) : 0;
      const usdt = row.usdt_balance != null ? Number(row.usdt_balance) : 0;
      const hasBalance = tron > 0 || usdt > 0;

      return {
        id: idFormatted,
        createdAt: createdAt.toISOString(),
        phrase,
        phrasePreview,
        source: 'unknown',       // 현재는 소스 정보 미저장 → 기본값
        network: 'tron',         // 현재 잔고 스캐너 기준 Tron 네트워크
        address: '',             // 주소 정보는 별도 저장되지 않음
        hasBalance,
        tron,
        usdt,
        checksumValid,
      };
    });

    res.json({
      page,
      pageSize,
      totalCount,
      totalPages,
      hasNext,
      items,
    });
  } catch (error) {
    console.error('시드 히스토리 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- APK 다운로드 (모바일 설치용) ----------
// 데스크톱의 nexus 폴더에 있는 최신 .apk 파일을 내려줍니다.
app.get('/download/apk', async (req, res) => {
  try {
    const apkDir = path.join('/home', 'myno', '바탕화면', 'nexus');

    // 폴더 내 APK 파일 목록 조회
    const files = await fs.promises.readdir(apkDir);
    const apkFiles = files.filter((name) => name.toLowerCase().endsWith('.apk'));

    if (apkFiles.length === 0) {
      return res.status(404).json({ error: 'APK 파일을 찾을 수 없습니다.' });
    }

    // 가장 최근에 수정된 APK 하나 선택
    const stats = await Promise.all(
      apkFiles.map(async (name) => {
        const fullPath = path.join(apkDir, name);
        const stat = await fs.promises.stat(fullPath);
        return { name, fullPath, mtime: stat.mtimeMs };
      })
    );

    stats.sort((a, b) => b.mtime - a.mtime);
    const latest = stats[0];

    // 다운로드로 전송 (Content-Disposition: attachment)
    return res.download(latest.fullPath, latest.name);
  } catch (error) {
    console.error('APK 다운로드 오류:', error);
    return res.status(500).json({ error: 'APK 다운로드 중 서버 오류가 발생했습니다.' });
  }
});

app.get('/api/admin/telegram', async (req, res) => {
  try {
    const telegram = await db.settingDB.get('global_telegram') || '@문의';
    res.json({ nickname: telegram });
  } catch (error) {
    console.error('텔레그램 조회 오류:', error);
    res.json({ nickname: '@문의' });
  }
});

// ---------- 관리자 로그인 ----------
app.post('/api/admin/login', async (req, res) => {
  try {
  const { id, password } = req.body || {};
  if (!id?.trim() || !password?.trim()) {
    return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
  }
    
    // 마스터 계정 확인
  if (id.trim() === MASTER_ID && password === MASTER_PW) {
    const token = createAdminToken();
    adminSessions.set(token, { role: 'master', id: MASTER_ID });
    return res.json({ role: 'master', id: MASTER_ID, token });
  }
    
    // DB에서 매니저/마스터 확인
    const manager = await db.managerDB.validate(id, password);
    if (manager) {
    const token = createAdminToken();
      adminSessions.set(token, { role: manager.role, id: id.trim() });
      return res.json({ role: manager.role, id: id.trim(), token });
    }
    
    res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
  } catch (error) {
    console.error('관리자 로그인 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.body?.token || '';
  adminSessions.delete(token);
  res.json({ ok: true });
});

// 로그인된 관리자 정보 (토큰 검증용)
app.get('/api/admin/me', requireAdmin, async (req, res) => {
  try {
    let telegram = '';
    if (req.admin.role === 'manager') {
      const m = await db.managerDB.get(req.admin.id);
      telegram = m?.telegram || '';
    }
  res.json({
    role: req.admin.role,
    id: req.admin.id,
      telegram,
    });
  } catch (error) {
    console.error('관리자 정보 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 마스터 전용: 텔레그램 설정 ----------
app.post('/api/admin/telegram', requireAdmin, requireMaster, async (req, res) => {
  try {
    const telegram = (req.body?.nickname ?? '').toString().trim() || '@문의';
    await db.settingDB.set('global_telegram', telegram);
  res.json({ ok: true });
  } catch (error) {
    console.error('텔레그램 설정 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 마스터 전용: 매니저 CRUD ----------
app.get('/api/admin/managers', requireAdmin, requireMaster, async (req, res) => {
  try {
    const managers = await db.managerDB.getAll();
    res.json(managers);
  } catch (error) {
    console.error('매니저 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/admin/managers', requireAdmin, requireMaster, async (req, res) => {
  try {
  const { id, password, telegram, memo } = req.body || {};
  if (!id?.trim()) return res.status(400).json({ error: '아이디 필요' });
    
    await db.managerDB.addOrUpdate(id.trim(), password || '', telegram || '', memo || '');
  res.json({ ok: true });
  } catch (error) {
    console.error('매니저 추가/수정 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

app.delete('/api/admin/managers/:id', requireAdmin, requireMaster, async (req, res) => {
  try {
    await db.managerDB.remove(req.params.id);
  res.json({ ok: true });
  } catch (error) {
    console.error('매니저 삭제 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 유저 목록 (마스터=전체, 매니저=내 유저만) ----------
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    let list;
    if (req.admin.role === 'master') {
      list = await db.userDB.getAll();
    } else {
      list = await db.userDB.getByManager(req.admin.id);
    }
    
    const managers = await db.managerDB.getAll();
  const byId = Object.fromEntries(managers.map((m) => [m.id, m.telegram || m.id]));
    
  const withManager = list.map((u) => ({
    id: u.id,
    managerId: u.managerId || null,
    managerName: byId[u.managerId] || '-',
    telegram: u.telegram || '',
  }));
    
  res.json(withManager);
  } catch (error) {
    console.error('유저 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 승인 대기 목록 조회 (매니저별)
app.get('/api/admin/pending-users', requireAdmin, async (req, res) => {
  try {
    const managerId = req.admin.role === 'master' ? null : req.admin.id;
    const pendingUsers = await db.userDB.getPendingUsers(managerId);
    res.json(pendingUsers);
  } catch (error) {
    console.error('승인 대기 목록 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 승인
app.post('/api/admin/approve-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자신의 사용자만 승인 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 승인 가능합니다.' });
    }
    
    await db.userDB.approveUser(userId.trim());
    res.json({ ok: true, message: '사용자가 승인되었습니다.' });
  } catch (error) {
    console.error('사용자 승인 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 거부
app.post('/api/admin/reject-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자신의 사용자만 거부 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 거부 가능합니다.' });
    }
    
    // 거부 시 삭제
    await db.userDB.remove(userId.trim());
    res.json({ ok: true, message: '사용자가 거부되었습니다.' });
  } catch (error) {
    console.error('사용자 거부 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용기간 설정
app.post('/api/admin/set-subscription', requireAdmin, async (req, res) => {
  try {
    const { userId, days } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    if (!days || ![30, 90, 180, 365].includes(Number(days))) {
      return res.status(400).json({ error: '유효한 사용기간을 선택하세요 (30, 90, 180, 365일)' });
    }
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자신의 사용자만 설정 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 설정 가능합니다.' });
    }
    
    await db.userDB.setSubscription(userId.trim(), Number(days));
    res.json({ ok: true, message: `사용기간이 ${days}일로 설정되었습니다.` });
  } catch (error) {
    console.error('사용기간 설정 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 정지/활성화
app.post('/api/admin/suspend-user', requireAdmin, async (req, res) => {
  try {
    const { userId, suspend } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자신의 사용자만 설정 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 설정 가능합니다.' });
    }
    
    await db.userDB.suspendUser(userId.trim(), suspend);
    res.json({ ok: true, message: suspend ? '사용자가 정지되었습니다.' : '사용자가 활성화되었습니다.' });
  } catch (error) {
    console.error('사용자 정지/활성화 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 유저 추가/수정 (매니저는 더 이상 직접 생성 불가, 승인만 가능)
app.post('/api/admin/users', requireAdmin, requireMaster, async (req, res) => {
  try {
  const { id, password, managerId, telegram } = req.body || {};
  if (!id?.trim()) return res.status(400).json({ error: '아이디 필요' });
    
    // 마스터만 직접 생성 가능
    await db.userDB.addOrUpdate(id.trim(), password || '', managerId || '', telegram || '', 'approved');
  res.json({ ok: true });
  } catch (error) {
    console.error('유저 추가/수정 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 승인 대기 목록 조회
app.get('/api/admin/pending-users', requireAdmin, async (req, res) => {
  try {
    const pendingUsers = await db.userDB.getPendingUsers();
    
    // 매니저는 자기 소속만 볼 수 있음
    if (req.admin.role === 'manager') {
      const filtered = pendingUsers.filter(u => u.managerId === req.admin.id);
      return res.json(filtered);
    }
    
    // 마스터는 전체 조회
    res.json(pendingUsers);
  } catch (error) {
    console.error('승인 대기 목록 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 승인
app.post('/api/admin/approve-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자기 소속만 승인 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 승인할 수 있습니다.' });
    }
    
    await db.userDB.updateStatus(userId.trim(), 'approved');
    res.json({ success: true });
  } catch (error) {
    console.error('사용자 승인 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 거부 (삭제)
app.post('/api/admin/reject-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자기 소속만 거부 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 거부할 수 있습니다.' });
    }
    
    await db.userDB.remove(userId.trim());
    res.json({ success: true });
  } catch (error) {
    console.error('사용자 거부 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용기간 설정
app.post('/api/admin/set-subscription', requireAdmin, async (req, res) => {
  try {
    const { userId, days } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    if (!days || ![30, 90, 180, 365].includes(parseInt(days))) {
      return res.status(400).json({ error: '올바른 일수를 선택하세요 (30, 90, 180, 365)' });
    }
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자기 소속만 설정 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 설정할 수 있습니다.' });
    }
    
    await db.userDB.setSubscription(userId.trim(), parseInt(days));
    res.json({ success: true });
  } catch (error) {
    console.error('사용기간 설정 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 정지/활성화
app.post('/api/admin/suspend-user', requireAdmin, async (req, res) => {
  try {
    const { userId, suspend } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자기 소속만 정지/활성화 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 정지/활성화할 수 있습니다.' });
    }
    
    const newStatus = suspend ? 'suspended' : 'approved';
    await db.userDB.suspend(userId.trim(), suspend);
    
    // 정지된 경우 세션도 끊기
    if (suspend) {
      await sessionStore.kickUser(userId.trim());
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('사용자 정지/활성화 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 유저 탈퇴(삭제) (마스터=누구나, 매니저=내 유저만)
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
  const userId = req.params.id?.trim();
  if (!userId) return res.status(400).json({ error: 'userId 필요' });
    
    const u = await db.userDB.get(userId);
  if (!u) return res.status(404).json({ error: '유저 없음' });
    
  if (req.admin.role === 'manager' && u.managerId !== req.admin.id) {
    return res.status(403).json({ error: '본인 소속 유저만 탈퇴 처리 가능' });
  }
    
    await db.userDB.remove(userId);
    await sessionStore.kickUser(userId);
  res.json({ ok: true });
  } catch (error) {
    console.error('유저 삭제 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 세션 (마스터=전체, 매니저=내 유저 세션만) ----------
app.get('/api/admin/sessions', requireAdmin, async (req, res) => {
  try {
    let list = await sessionStore.getAll();
    
  if (req.admin.role === 'manager') {
      const myUsers = await db.userDB.getByManager(req.admin.id);
      const myUserIds = new Set(myUsers.map((u) => u.id));
    list = list.filter((s) => myUserIds.has(s.userId));
  }
    
  res.json(list);
  } catch (error) {
    console.error('세션 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/admin/kick', requireAdmin, async (req, res) => {
  try {
  const userId = req.body?.userId?.trim();
  if (!userId) return res.status(400).json({ error: 'userId 필요' });
    
  if (req.admin.role === 'manager') {
      const u = await db.userDB.get(userId);
    if (!u || u.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 유저만 끊기 가능' });
    }
  }
    
    await sessionStore.kickUser(userId);
  res.json({ ok: true });
  } catch (error) {
    console.error('세션 끊기 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 시드 (마스터만 볼 수 있음) ----------
app.get('/api/admin/seeds', requireAdmin, requireMaster, async (req, res) => {
  try {
  const masked = req.query.masked !== 'false';
    const list = await db.seedDB.getAll(masked);
    res.json(list);
  } catch (error) {
    console.error('시드 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 개인 입금주소 발급 API ----------

// POST /api/payment/request-address
// 사용자가 QR 화면 진입 시 서버에서 개인 입금주소 발급 (또는 기존 재사용)
app.post('/api/payment/request-address', async (req, res) => {
  try {
    const { token, userId, orderId, network, tokenType } = req.body || {};

    if (!token?.trim()) return res.status(401).json({ error: '세션 토큰이 필요합니다.' });

    // 세션 검증
    const sessionUserId = await sessionStore.getUserId(token.trim());
    if (!sessionUserId) return res.status(401).json({ error: '유효하지 않은 세션입니다.' });

    const resolvedUserId = (userId?.trim() || sessionUserId).toLowerCase();

    // 현재 active 수금 지갑 조회
    const activeWallet = await db.collectionWalletDB.getActive();
    if (!activeWallet) {
      return res.status(503).json({ error: '현재 활성화된 수금 지갑이 없습니다. 관리자에게 문의하세요.' });
    }

    // 기존 유효 주소 재사용 여부 확인
    const existing = await db.depositAddressDB.getActive(resolvedUserId, orderId || null);

    if (existing) {
      // 기존 주소가 현재 wallet_version과 다르면 invalidated 플래그 설정
      const invalidated = existing.wallet_version !== activeWallet.wallet_version;
      return res.json({
        address: existing.deposit_address,
        walletVersion: existing.wallet_version,
        status: existing.status,
        invalidated,
        isNew: false,
      });
    }

    // 신규 주소 발급: xpub 기반 HD 파생 또는 root 주소 직접 사용
    const [maxRows] = await db.pool.query(
      'SELECT COALESCE(MAX(derivation_index), -1) AS maxIdx FROM deposit_addresses WHERE wallet_version = ?',
      [activeWallet.wallet_version]
    );
    const newIndex = maxRows[0].maxIdx + 1;

    let newAddress;
    if (activeWallet.xpub_key) {
      // xpub 있을 때: HD wallet 파생으로 사용자별 고유 TRON 주소 생성
      try {
        newAddress = deriveTronAddress(activeWallet.xpub_key, newIndex);
      } catch (e) {
        console.error('HD 주소 파생 오류:', e);
        return res.status(500).json({ error: 'xpub 키가 올바르지 않습니다. 관리자에게 문의하세요.' });
      }
    } else {
      // xpub 없을 때: root 주소를 그대로 반환 (모든 사용자 동일 주소)
      newAddress = activeWallet.root_wallet_address;
    }

    await db.depositAddressDB.create({
      userId: resolvedUserId,
      orderId: orderId || null,
      network: network || 'TRON',
      token: tokenType || 'USDT',
      depositAddress: newAddress,
      walletVersion: activeWallet.wallet_version,
    });

    res.json({
      address: newAddress,
      walletVersion: activeWallet.wallet_version,
      status: 'issued',
      invalidated: false,
      isNew: true,
    });
  } catch (error) {
    console.error('입금주소 발급 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 관리자 - 수금 지갑 관리 ----------

// GET /api/admin/collection-wallet — 현재 active 지갑 + 전체 이력
app.get('/api/admin/collection-wallet', requireAdmin, requireMaster, async (req, res) => {
  try {
    const active = await db.collectionWalletDB.getActive();
    const history = await db.collectionWalletDB.getHistory();

    // 버전별 통계 추가
    const historyWithStats = await Promise.all(
      history.map(async (w) => {
        const stats = await db.collectionWalletDB.getStats(w.wallet_version);
        return { ...w, stats };
      })
    );

    res.json({ active, history: historyWithStats });
  } catch (error) {
    console.error('수금 지갑 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// POST /api/admin/collection-wallet — 새 수금 지갑 등록 (기존 버전 비활성화)
app.post('/api/admin/collection-wallet', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { address, xpubKey, label } = req.body || {};
    if (!address?.trim()) return res.status(400).json({ error: 'TRON 수금 지갑 주소를 입력하세요.' });

    // xpub 유효성 검증 (입력된 경우)
    if (xpubKey?.trim()) {
      try {
        HDNodeWallet.fromExtendedKey(xpubKey.trim());
      } catch {
        return res.status(400).json({ error: 'xpub 키 형식이 올바르지 않습니다.' });
      }
    }

    const newVersion = await db.collectionWalletDB.activate(
      address.trim(),
      xpubKey?.trim() || null,
      label?.trim() || ''
    );
    res.json({ ok: true, walletVersion: newVersion, message: `수금 지갑이 v${newVersion}으로 변경되었습니다.` });
  } catch (error) {
    console.error('수금 지갑 변경 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// GET /api/admin/deposit-addresses — 발급 주소 목록 조회
app.get('/api/admin/deposit-addresses', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { walletVersion, status, page = 1, pageSize = 30 } = req.query;
    const result = await db.depositAddressDB.getList({
      walletVersion: walletVersion ? Number(walletVersion) : undefined,
      status: status || undefined,
      page: Number(page),
      pageSize: Number(pageSize),
    });
    res.json(result);
  } catch (error) {
    console.error('입금주소 목록 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 가격 설정 API ----------

// GET /api/payment/pricing — 클라이언트가 가격 조회 (인증 불필요)
app.get('/api/payment/pricing', async (req, res) => {
  try {
    const raw = await db.settingDB.get('subscription_packages');
    const monthlyRaw = await db.settingDB.get('monthly_price_usdt');
    const packages = raw ? JSON.parse(raw) : [
      { days: 30,  label: '1개월',  price: 39 },
      { days: 60,  label: '2개월',  price: 75 },
      { days: 90,  label: '3개월',  price: 110 },
      { days: 180, label: '6개월',  price: 210 },
      { days: 365, label: '12개월', price: 390 },
    ];
    const monthlyPrice = monthlyRaw ? Number(monthlyRaw) : 39;
    res.json({ monthlyPrice, packages });
  } catch (error) {
    console.error('가격 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// POST /api/admin/pricing — 가격 패키지 저장 (마스터 전용)
app.post('/api/admin/pricing', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { monthlyPrice, packages } = req.body || {};
    if (monthlyPrice == null || isNaN(Number(monthlyPrice))) {
      return res.status(400).json({ error: '월 기준 가격(USDT)을 입력하세요.' });
    }
    if (!Array.isArray(packages) || packages.length === 0) {
      return res.status(400).json({ error: '패키지 목록이 필요합니다.' });
    }
    await db.settingDB.set('monthly_price_usdt', String(Number(monthlyPrice)));
    await db.settingDB.set('subscription_packages', JSON.stringify(packages));
    res.json({ ok: true, message: '가격이 저장되었습니다.' });
  } catch (error) {
    console.error('가격 저장 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 메인 페이지(/)를 관리자 페이지로 리다이렉트
app.get('/', (req, res) => {
  res.redirect('/admin.html');
});

// 서버 시작
app.listen(PORT, () => {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('✅ 서버 실행 중!');
  console.log('');
  console.log('🌐 URL: http://localhost:' + PORT);
  console.log('👤 관리자: http://localhost:' + PORT + '/admin.html');
  console.log('🔑 마스터: ' + MASTER_ID + ' / ' + MASTER_PW);
  console.log('💾 데이터베이스: MariaDB 연결됨');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
});
