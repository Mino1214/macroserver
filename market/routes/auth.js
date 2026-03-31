const express = require('express');
const db = require('../../db');
const { hashPassword, verifyUserStoredPassword } = require('../password');
const { signAccess, signRefresh, verifyRefreshToken } = require('../jwtMarket');
const { saveRefreshToken, consumeRefreshToken, pruneExpiredRefreshTokens } = require('../refreshStore');

const router = express.Router();

const ACCOUNT_ID_REGEX = /^[a-z0-9][a-z0-9_-]{3,19}$/;
const ACCOUNT_PASSWORD_REGEX = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d!@#$%^&*()_\-+=\[\]{};:,.?]{8,24}$/;

function normalizeAccountId(value) {
  return String(value || '').trim().toLowerCase();
}

async function isReservedAdminLikeId(normalized) {
  const MASTER_ID = process.env.MASTER_ID || 'tlarbwjd';
  if (normalized === String(MASTER_ID).trim().toLowerCase()) return true;
  const [[manager]] = await db.pool.query(
    'SELECT id FROM managers WHERE LOWER(id) = LOWER(?) LIMIT 1',
    [normalized],
  );
  return !!manager;
}

async function issueTokensPair(res, payload, subjectType, usersId, muUserId) {
  const access = signAccess(payload);
  const refresh = signRefresh({ sub: payload.sub, role: payload.role, muUserId: payload.muUserId });
  const expMs = 7 * 24 * 60 * 60 * 1000;
  const expiresAt = new Date(Date.now() + expMs);
  await saveRefreshToken({
    rawToken: refresh,
    subjectType,
    usersId,
    muUserId,
    expiresAt,
  });
  res.json({
    accessToken: access,
    refreshToken: refresh,
    role: payload.role,
    muUserId: payload.muUserId ?? null,
    operatorMuUserId: payload.operatorMuUserId ?? null,
  });
}

/** POST /api/market/auth/register */
router.post('/register', async (req, res) => {
  try {
    const { id, password, operator_mu_user_id } = req.body || {};
    const idError =
      !id?.trim()
        ? '아이디를 입력하세요.'
        : !ACCOUNT_ID_REGEX.test(normalizeAccountId(id))
          ? '아이디 형식이 올바르지 않습니다.'
          : null;
    if (idError) return res.status(400).json({ error: idError });
    if (!password?.trim() || !ACCOUNT_PASSWORD_REGEX.test(String(password))) {
      return res.status(400).json({ error: '비밀번호는 8~24자, 영문과 숫자를 포함해야 합니다.' });
    }

    const newId = normalizeAccountId(id);
    if (await isReservedAdminLikeId(newId)) {
      return res.status(400).json({ error: '사용할 수 없는 아이디입니다.' });
    }

    const [[exists]] = await db.pool.query('SELECT id FROM users WHERE id = ? LIMIT 1', [newId]);
    if (exists) return res.status(409).json({ error: '이미 가입된 아이디입니다.' });

    let opId =
      operator_mu_user_id != null && operator_mu_user_id !== ''
        ? parseInt(operator_mu_user_id, 10)
        : null;
    if (opId == null || Number.isNaN(opId)) {
      opId = req.marketTenantOperatorId;
    }
    if (opId != null) {
      const [[op]] = await db.pool.query(
        `SELECT id FROM mu_users WHERE id = ? AND market_role = 'operator' LIMIT 1`,
        [opId],
      );
      if (!op) return res.status(400).json({ error: '유효하지 않은 운영자입니다.' });
    }

    const pwHash = hashPassword(password.trim());
    await db.pool.query(
      `INSERT INTO users (id, pw, manager_id, telegram, status, owner_id, charge_required_until, operator_mu_user_id, market_status)
       VALUES (?, ?, NULL, NULL, 'approved', NULL, NULL, ?, 'active')`,
      [newId, pwHash, opId],
    );

    await db.pool.query(
      `INSERT INTO market_cash_balance (user_id, balance) VALUES (?, 0)
       ON DUPLICATE KEY UPDATE user_id = user_id`,
      [newId],
    );

    const accessPayload = {
      sub: newId,
      role: 'user',
      muUserId: null,
      operatorMuUserId: opId,
    };
    await issueTokensPair(res, accessPayload, 'user', newId, null);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

/** POST /api/market/auth/login */
router.post('/login', async (req, res) => {
  try {
    const { login_id, password } = req.body || {};
    if (!login_id?.trim() || !password?.trim()) {
      return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
    }

    const lid = String(login_id).trim();
    const pw = String(password).trim();
    const MASTER_ID = process.env.MASTER_ID || 'tlarbwjd';
    const MASTER_PW = process.env.MASTER_PW || 'tlarbwjd';

    if (normalizeAccountId(lid) === normalizeAccountId(MASTER_ID) && pw === MASTER_PW) {
      await issueTokensPair(
        res,
        { sub: 'master', role: 'master', muUserId: null, operatorMuUserId: null },
        'master',
        null,
        null,
      );
      return;
    }

    const hash = hashPassword(pw);
    const [[mu]] = await db.pool.query(
      `SELECT id, market_role, status, site_domain FROM mu_users
       WHERE login_id = ? AND password_hash = ? AND market_role = 'operator' LIMIT 1`,
      [lid, hash],
    );
    if (mu) {
      if (mu.status !== 'active') return res.status(403).json({ error: '비활성 계정입니다.' });
      await issueTokensPair(
        res,
        { sub: String(mu.id), role: 'operator', muUserId: mu.id, operatorMuUserId: mu.id },
        'operator',
        null,
        mu.id,
      );
      return;
    }

    const uid = normalizeAccountId(lid);
    const [[user]] = await db.pool.query(
      'SELECT id, pw, operator_mu_user_id, market_status FROM users WHERE id = ? LIMIT 1',
      [uid],
    );
    if (!user) return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    if (user.market_status === 'suspended') return res.status(403).json({ error: '정지된 계정입니다.' });
    if (!verifyUserStoredPassword(user.pw, pw)) {
      return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    }

    await issueTokensPair(
      res,
      {
        sub: user.id,
        role: 'user',
        muUserId: null,
        operatorMuUserId: user.operator_mu_user_id,
      },
      'user',
      user.id,
      null,
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

/** POST /api/market/auth/refresh */
router.post('/refresh', async (req, res) => {
  try {
    await pruneExpiredRefreshTokens();
    const { refreshToken } = req.body || {};
    if (!refreshToken?.trim()) return res.status(400).json({ error: 'refreshToken이 필요합니다.' });

    let decoded;
    try {
      decoded = verifyRefreshToken(refreshToken.trim());
    } catch (_e) {
      return res.status(401).json({ error: '리프레시 토큰이 유효하지 않습니다.' });
    }
    if (decoded.typ !== 'market_rt') return res.status(401).json({ error: '유효하지 않은 토큰입니다.' });

    const consumed = await consumeRefreshToken(refreshToken.trim());
    if (!consumed) return res.status(401).json({ error: '리프레시 토큰이 이미 사용되었거나 없습니다.' });

    const role = decoded.role;
    const sub = decoded.sub;
    const muUserId = decoded.muUserId ?? null;
    const accessPayload = {
      sub: String(sub),
      role,
      muUserId,
      operatorMuUserId: role === 'operator' ? muUserId : null,
    };

    if (role === 'user') {
      const [[u]] = await db.pool.query(
        'SELECT id, operator_mu_user_id, market_status FROM users WHERE id = ? LIMIT 1',
        [sub],
      );
      if (!u || u.market_status === 'suspended') return res.status(403).json({ error: '계정을 사용할 수 없습니다.' });
      accessPayload.operatorMuUserId = u.operator_mu_user_id;
    }

    const refresh = signRefresh({ sub, role, muUserId });
    const expMs = 7 * 24 * 60 * 60 * 1000;
    const expiresAt = new Date(Date.now() + expMs);
    await saveRefreshToken({
      rawToken: refresh,
      subjectType: role,
      usersId: role === 'user' ? sub : null,
      muUserId: role === 'operator' ? muUserId : role === 'master' ? null : null,
      expiresAt,
    });

    res.json({
      accessToken: signAccess(accessPayload),
      refreshToken: refresh,
      role: accessPayload.role,
      muUserId: accessPayload.muUserId,
      operatorMuUserId: accessPayload.operatorMuUserId,
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
