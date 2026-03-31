const express = require('express');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const db = require('../../db');
const { requireMarketRoles } = require('../middleware');
const {
  getPointSum,
  getCashBalance,
  getConvertPolicy,
  getMonthlyConvertedPoints,
  GAME_POINTS,
} = require('../services');
const { tryUploadVideoToS3 } = require('../s3upload');

const router = express.Router();
router.use(requireMarketRoles('user'));

const uploadRoot = path.join(__dirname, '..', '..', 'uploads', 'market-videos');
fs.mkdirSync(uploadRoot, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadRoot),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname || '') || '.bin';
    const base = `${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
    cb(null, base + ext);
  },
});
const upload = multer({ storage, limits: { fileSize: 200 * 1024 * 1024 } });

function userId(req) {
  return req.marketAuth.sub;
}

/** GET /me */
router.get('/me', async (req, res) => {
  try {
    const uid = userId(req);
    const [[u]] = await db.pool.query(
      `SELECT id, telegram, status, operator_mu_user_id, market_status FROM users WHERE id = ? LIMIT 1`,
      [uid],
    );
    if (!u) return res.status(404).json({ error: '유저 없음' });
    const points = await getPointSum(uid);
    const cash = await getCashBalance(uid);
    res.json({
      user: u,
      pointsBalance: points,
      cashBalance: cash,
      operatorMuUserId: u.operator_mu_user_id,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/points', async (req, res) => {
  try {
    const uid = userId(req);
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 50));
    const [rows] = await db.pool.query(
      `SELECT id, amount, type, description, created_at FROM market_points WHERE user_id = ? ORDER BY id DESC LIMIT ?`,
      [uid, limit],
    );
    res.json({ points: rows, balance: await getPointSum(uid) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/cash', async (req, res) => {
  try {
    const uid = userId(req);
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 50));
    const [rows] = await db.pool.query(
      `SELECT id, amount, type, description, created_at FROM market_cash_transactions WHERE user_id = ? ORDER BY id DESC LIMIT ?`,
      [uid, limit],
    );
    res.json({ transactions: rows, balance: await getCashBalance(uid) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** POST /attendance */
router.post('/attendance', async (req, res) => {
  const conn = await db.pool.getConnection();
  try {
    const uid = userId(req);
    await conn.beginTransaction();
    const [[{ todayStr }]] = await conn.query(`SELECT DATE_FORMAT(CURDATE(), '%Y-%m-%d') AS todayStr`);

    const [[exists]] = await conn.query(
      `SELECT id FROM market_attendance WHERE user_id = ? AND checked_date = ? FOR UPDATE`,
      [uid, todayStr],
    );
    if (exists) {
      await conn.rollback();
      return res.status(400).json({ error: '오늘은 이미 출석했습니다.' });
    }

    const [[y]] = await conn.query(
      `SELECT streak_count FROM market_attendance WHERE user_id = ? AND checked_date = DATE_SUB(?, INTERVAL 1 DAY) LIMIT 1`,
      [uid, todayStr],
    );
    let streak = 1;
    if (y && y.streak_count) streak = Number(y.streak_count) + 1;
    const capped = Math.min(streak, 7);
    const bonusSteps = Math.max(0, capped - 1);
    const pointsEarned = 100 + bonusSteps * 50;

    await conn.query(
      `INSERT INTO market_attendance (user_id, checked_date, points_earned, streak_count) VALUES (?, ?, ?, ?)`,
      [uid, todayStr, pointsEarned, streak],
    );
    await conn.query(
      `INSERT INTO market_points (user_id, amount, type, description) VALUES (?, ?, 'attendance', ?)`,
      [uid, pointsEarned, `streak ${streak}`],
    );
    await conn.commit();
    res.json({ ok: true, pointsEarned, streakCount: streak, date: todayStr });
  } catch (e) {
    try {
      await conn.rollback();
    } catch (_r) {
      /* */
    }
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

router.get('/attendance/streak', async (req, res) => {
  try {
    const uid = userId(req);
    const [rows] = await db.pool.query(
      `SELECT checked_date, points_earned, streak_count FROM market_attendance WHERE user_id = ? ORDER BY checked_date DESC LIMIT 30`,
      [uid],
    );
    res.json({ history: rows, streakCurrent: rows[0]?.streak_count || 0 });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/mini-game/play', async (req, res) => {
  try {
    const uid = userId(req);
    const { game_type, score } = req.body || {};
    const gt = String(game_type || 'default').slice(0, 50);
    const sc = parseInt(score, 10) || 0;
    const base = GAME_POINTS[gt] ?? GAME_POINTS.default;
    const pointsEarned = Math.max(50, Math.min(200, base + Math.min(50, Math.floor(sc / 20))));

    await db.pool.query(
      `INSERT INTO market_mini_game_logs (user_id, game_type, score, points_earned) VALUES (?, ?, ?, ?)`,
      [uid, gt, sc, pointsEarned],
    );
    await db.pool.query(
      `INSERT INTO market_points (user_id, amount, type, description) VALUES (?, ?, 'mini_game', ?)`,
      [uid, pointsEarned, `${gt} score=${sc}`],
    );
    res.json({ ok: true, pointsEarned, game_type: gt });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/videos', upload.single('file'), async (req, res) => {
  try {
    const uid = userId(req);
    if (!req.file) return res.status(400).json({ error: 'file 필드에 동영상을 올려주세요.' });
    const title = (req.body?.title || '').trim() || null;
    let relUrl = `/market-static/videos/${req.file.filename}`;
    const s3url = await tryUploadVideoToS3(req.file.path, req.file.originalname);
    if (s3url) relUrl = s3url;
    const [r] = await db.pool.query(
      `INSERT INTO market_videos (user_id, file_url, title, status, review_stage) VALUES (?, ?, ?, 'pending', 'operator')`,
      [uid, relUrl, title],
    );
    res.status(201).json({ ok: true, id: r.insertId, fileUrl: relUrl });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/videos', async (req, res) => {
  try {
    const uid = userId(req);
    const [rows] = await db.pool.query(
      `SELECT * FROM market_videos WHERE user_id = ? ORDER BY id DESC LIMIT 50`,
      [uid],
    );
    res.json({ videos: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/cash/charge', async (req, res) => {
  try {
    const bypass = process.env.MARKET_DEV_CHARGE === '1' || process.env.NODE_ENV !== 'production';
    if (!bypass && process.env.MARKET_PG_BYPASS !== '1') {
      return res.status(501).json({ error: 'PG 연동 전에는 충전을 사용할 수 없습니다. (개발: MARKET_DEV_CHARGE=1)' });
    }
    const uid = userId(req);
    const amount = parseInt(req.body?.amount, 10);
    if (Number.isNaN(amount) || amount <= 0) return res.status(400).json({ error: '충전 금액이 필요합니다.' });

    const conn = await db.pool.getConnection();
    try {
      await conn.beginTransaction();
      await conn.query(
        `INSERT INTO market_cash_balance (user_id, balance) VALUES (?, 0) ON DUPLICATE KEY UPDATE user_id = user_id`,
        [uid],
      );
      await conn.query(`UPDATE market_cash_balance SET balance = balance + ? WHERE user_id = ?`, [amount, uid]);
      await conn.query(
        `INSERT INTO market_cash_transactions (user_id, amount, type, description) VALUES (?, ?, 'charge', ?)`,
        [uid, amount, 'manual or dev charge'],
      );
      await conn.commit();
    } catch (e) {
      await conn.rollback();
      throw e;
    } finally {
      conn.release();
    }
    res.json({ ok: true, balance: await getCashBalance(uid) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/points/convert', async (req, res) => {
  const conn = await db.pool.getConnection();
  try {
    const uid = userId(req);
    const points = parseInt(req.body?.points, 10);
    if (Number.isNaN(points) || points <= 0) return res.status(400).json({ error: '전환할 포인트 양이 필요합니다.' });

    await conn.beginTransaction();
    const [[u]] = await conn.query(`SELECT operator_mu_user_id FROM users WHERE id = ? FOR UPDATE`, [uid]);
    if (!u) {
      await conn.rollback();
      return res.status(404).json({ error: '유저 없음' });
    }

    const [[{ s }]] = await conn.query(
      `SELECT COALESCE(SUM(amount),0) AS s FROM market_points WHERE user_id = ?`,
      [uid],
    );
    const balance = Number(s);
    if (balance < points) {
      await conn.rollback();
      return res.status(400).json({ error: '포인트가 부족합니다.' });
    }

    const policy = await getConvertPolicy(u.operator_mu_user_id);
    const monthlyUsed = await getMonthlyConvertedPoints(uid);
    const monthLimit = Number(policy.monthly_limit);
    if (monthlyUsed + points > monthLimit) {
      await conn.rollback();
      return res.status(400).json({ error: `월 전환 한도를 초과했습니다. (한도: ${monthLimit}, 사용: ${monthlyUsed})` });
    }
    const rate = Number(policy.convert_rate);
    const cashGain = Math.floor(points * rate);
    if (cashGain <= 0) {
      await conn.rollback();
      return res.status(400).json({ error: '전환 결과 캐쉬가 0입니다.' });
    }
    await conn.query(
      `INSERT INTO market_points (user_id, amount, type, description) VALUES (?, ?, 'point_convert', ?)`,
      [uid, -points, `convert to cash ${cashGain}`],
    );
    await conn.query(
      `INSERT INTO market_cash_balance (user_id, balance) VALUES (?, 0) ON DUPLICATE KEY UPDATE user_id = user_id`,
      [uid],
    );
    await conn.query(`UPDATE market_cash_balance SET balance = balance + ? WHERE user_id = ?`, [cashGain, uid]);
    await conn.query(
      `INSERT INTO market_cash_transactions (user_id, amount, type, description) VALUES (?, ?, 'point_convert', ?)`,
      [uid, cashGain, `from ${points} pts`],
    );
    await conn.commit();
    res.json({ ok: true, pointsSpent: points, cashGained: cashGain, cashBalance: await getCashBalance(uid) });
  } catch (e) {
    try {
      await conn.rollback();
    } catch (_r) {
      /* */
    }
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

router.get('/products', async (req, res) => {
  try {
    const opId = req.marketAuth.operatorMuUserId;
    if (!opId) {
      const [rows] = await db.pool.query(
        `SELECT * FROM market_products WHERE is_visible = 1 AND operator_mu_user_id IS NULL ORDER BY id DESC LIMIT 200`,
      );
      return res.json({ products: rows });
    }
    const [rows] = await db.pool.query(
      `SELECT * FROM market_products WHERE is_visible = 1 AND (operator_mu_user_id IS NULL OR operator_mu_user_id = ?) ORDER BY id DESC LIMIT 200`,
      [opId],
    );
    res.json({ products: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/orders', async (req, res) => {
  const conn = await db.pool.getConnection();
  try {
    const uid = userId(req);
    const productId = parseInt(req.body?.product_id, 10);
    const qty = Math.max(1, parseInt(req.body?.quantity, 10) || 1);
    if (Number.isNaN(productId)) return res.status(400).json({ error: 'product_id 필요' });

    const opId = req.marketAuth.operatorMuUserId;

    await conn.beginTransaction();
    const [[p]] = await conn.query(`SELECT * FROM market_products WHERE id = ? FOR UPDATE`, [productId]);
    if (!p || !p.is_visible) {
      await conn.rollback();
      return res.status(404).json({ error: '상품을 찾을 수 없습니다.' });
    }
    if (p.operator_mu_user_id != null && opId != null && p.operator_mu_user_id !== opId) {
      await conn.rollback();
      return res.status(403).json({ error: '이 사이트에서 구매할 수 없는 상품입니다.' });
    }
    const total = Number(p.price_cash) * qty;
    const stock = Number(p.stock);
    if (stock >= 0 && stock < qty) {
      await conn.rollback();
      return res.status(400).json({ error: '재고가 부족합니다.' });
    }

    await conn.query(
      `INSERT INTO market_cash_balance (user_id, balance) VALUES (?, 0) ON DUPLICATE KEY UPDATE user_id = user_id`,
      [uid],
    );
    const [[cb]] = await conn.query(`SELECT balance FROM market_cash_balance WHERE user_id = ? FOR UPDATE`, [uid]);
    const bal = Number(cb?.balance ?? 0);
    if (bal < total) {
      await conn.rollback();
      return res.status(400).json({ error: '캐쉬 잔액이 부족합니다.' });
    }

    await conn.query(`UPDATE market_cash_balance SET balance = balance - ? WHERE user_id = ?`, [total, uid]);
    await conn.query(
      `INSERT INTO market_cash_transactions (user_id, amount, type, description) VALUES (?, ?, 'purchase', ?)`,
      [uid, -total, `product ${productId} x${qty}`],
    );
    const ordOp = p.operator_mu_user_id != null ? p.operator_mu_user_id : opId;
    const [ins] = await conn.query(
      `INSERT INTO market_orders (user_id, product_id, operator_mu_user_id, quantity, total_cash, status)
       VALUES (?, ?, ?, ?, ?, 'confirmed')`,
      [uid, productId, ordOp, qty, total],
    );
    if (stock >= 0) {
      await conn.query(`UPDATE market_products SET stock = stock - ? WHERE id = ?`, [qty, productId]);
    }
    await conn.commit();
    res.status(201).json({ ok: true, orderId: ins.insertId, totalCash: total });
  } catch (e) {
    try {
      await conn.rollback();
    } catch (_r) {
      /* */
    }
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

router.get('/orders', async (req, res) => {
  try {
    const uid = userId(req);
    const [rows] = await db.pool.query(
      `SELECT o.*, p.name AS product_name FROM market_orders o
       LEFT JOIN market_products p ON p.id = o.product_id
       WHERE o.user_id = ? ORDER BY o.id DESC LIMIT 100`,
      [uid],
    );
    res.json({ orders: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
