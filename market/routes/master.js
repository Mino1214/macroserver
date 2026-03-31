const express = require('express');
const db = require('../../db');
const { hashPassword } = require('../password');
const { requireMarketRoles } = require('../middleware');
const masterTotalMarket = require('./masterTotalMarket');

const router = express.Router();
router.use(requireMarketRoles('master'));
router.use(masterTotalMarket);

/** GET /operators */
router.get('/operators', async (_req, res) => {
  try {
    const [rows] = await db.pool.query(
      `SELECT id, name, login_id, role, status, market_role, site_domain, is_site_active, created_at
       FROM mu_users WHERE market_role = 'operator' ORDER BY id DESC`,
    );
    res.json({ operators: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** POST /operators */
router.post('/operators', async (req, res) => {
  try {
    const { name, login_id, password, site_domain } = req.body || {};
    if (!name?.trim() || !login_id?.trim() || !password?.trim()) {
      return res.status(400).json({ error: '이름, 로그인 ID, 비밀번호가 필요합니다.' });
    }
    const domain = site_domain?.trim() || null;
    if (domain) {
      const [[dup]] = await db.pool.query(
        `SELECT id FROM mu_users WHERE site_domain IS NOT NULL AND LOWER(site_domain) = LOWER(?) LIMIT 1`,
        [domain],
      );
      if (dup) return res.status(409).json({ error: '이미 사용 중인 사이트 도메인입니다.' });
    }
    const ph = hashPassword(password.trim());
    const [r] = await db.pool.query(
      `INSERT INTO mu_users (name, login_id, password_hash, role, status, market_role, site_domain, is_site_active)
       VALUES (?, ?, ?, 'USER', 'active', 'operator', ?, 1)`,
      [name.trim(), login_id.trim(), ph, domain],
    );
    res.status(201).json({ ok: true, id: r.insertId });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: '중복된 로그인 ID입니다.' });
    res.status(500).json({ error: e.message });
  }
});

/** PATCH /operators/:id */
router.patch('/operators/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: '잘못된 ID입니다.' });
    const [[op]] = await db.pool.query(
      `SELECT id FROM mu_users WHERE id = ? AND market_role = 'operator' LIMIT 1`,
      [id],
    );
    if (!op) return res.status(404).json({ error: '운영자를 찾을 수 없습니다.' });

    const { name, password, site_domain, is_site_active, status } = req.body || {};
    const fields = [];
    const vals = [];
    if (name?.trim()) {
      fields.push('name = ?');
      vals.push(name.trim());
    }
    if (password?.trim()) {
      fields.push('password_hash = ?');
      vals.push(hashPassword(password.trim()));
    }
    if (site_domain !== undefined) {
      const domain = site_domain?.trim() || null;
      if (domain) {
        const [[dup]] = await db.pool.query(
          `SELECT id FROM mu_users WHERE LOWER(site_domain) = LOWER(?) AND id <> ? LIMIT 1`,
          [domain, id],
        );
        if (dup) return res.status(409).json({ error: '이미 사용 중인 사이트 도메인입니다.' });
      }
      fields.push('site_domain = ?');
      vals.push(domain);
    }
    if (typeof is_site_active === 'boolean' || is_site_active === 0 || is_site_active === 1) {
      fields.push('is_site_active = ?');
      vals.push(is_site_active ? 1 : 0);
    }
    if (['active', 'inactive'].includes(status)) {
      fields.push('status = ?');
      vals.push(status);
    }
    if (!fields.length) return res.status(400).json({ error: '수정할 필드가 없습니다.' });
    vals.push(id);
    await db.pool.query(`UPDATE mu_users SET ${fields.join(', ')} WHERE id = ?`, vals);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** DELETE /operators/:id */
router.delete('/operators/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (Number.isNaN(id)) return res.status(400).json({ error: '잘못된 ID입니다.' });
    const [r] = await db.pool.query(`DELETE FROM mu_users WHERE id = ? AND market_role = 'operator'`, [id]);
    if (r.affectedRows === 0) return res.status(404).json({ error: '운영자를 찾을 수 없습니다.' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** GET /users */
router.get('/users', async (req, res) => {
  try {
    const opFilter = req.query.operator_mu_user_id;
    let where = 'WHERE operator_mu_user_id IS NOT NULL';
    const params = [];
    if (opFilter != null && String(opFilter).trim() !== '') {
      where += ' AND operator_mu_user_id = ?';
      params.push(parseInt(opFilter, 10));
    }
    const [rows] = await db.pool.query(
      `SELECT id, telegram, status, operator_mu_user_id, market_status FROM users ${where} ORDER BY id DESC LIMIT 2000`,
      params,
    );
    res.json({ users: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** GET /stats */
router.get('/stats', async (_req, res) => {
  try {
    const [[{ opCount }]] = await db.pool.query(
      `SELECT COUNT(*) AS opCount FROM mu_users WHERE market_role = 'operator'`,
    );
    const [[{ userCount }]] = await db.pool.query(
      `SELECT COUNT(*) AS userCount FROM users WHERE operator_mu_user_id IS NOT NULL`,
    );
    const [[{ orderSum }]] = await db.pool.query(
      `SELECT COALESCE(SUM(total_cash),0) AS orderSum FROM market_orders WHERE status = 'confirmed'`,
    );
    const [[{ pointSum }]] = await db.pool.query(`SELECT COALESCE(SUM(amount),0) AS pointSum FROM market_points`);
    res.json({
      operatorCount: Number(opCount),
      marketUserCount: Number(userCount),
      totalCashSales: Number(orderSum),
      totalPointsIssued: Number(pointSum),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** --- products --- */
router.get('/products', async (_req, res) => {
  try {
    const [rows] = await db.pool.query(
      `SELECT * FROM market_products ORDER BY id DESC LIMIT 500`,
    );
    res.json({ products: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/products', async (req, res) => {
  try {
    const { name, description, category, operator_mu_user_id, price_cash, stock, is_visible } = req.body || {};
    if (!name?.trim()) return res.status(400).json({ error: '상품명이 필요합니다.' });
    const op = operator_mu_user_id != null ? parseInt(operator_mu_user_id, 10) : null;
    const price = parseInt(price_cash, 10);
    if (Number.isNaN(price) || price < 0) return res.status(400).json({ error: '유효한 캐쉬 가격이 필요합니다.' });
    const st = stock !== undefined ? parseInt(stock, 10) : -1;
    const vis = is_visible !== false && is_visible !== 0 ? 1 : 0;
    const [r] = await db.pool.query(
      `INSERT INTO market_products (name, description, category, operator_mu_user_id, price_cash, stock, is_visible)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [name.trim(), description || null, category || null, Number.isNaN(op) ? null : op, price, st, vis],
    );
    res.status(201).json({ ok: true, id: r.insertId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.patch('/products/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const { name, description, category, operator_mu_user_id, price_cash, stock, is_visible } = req.body || {};
    const fields = [];
    const vals = [];
    if (name?.trim()) {
      fields.push('name = ?');
      vals.push(name.trim());
    }
    if (description !== undefined) {
      fields.push('description = ?');
      vals.push(description);
    }
    if (category !== undefined) {
      fields.push('category = ?');
      vals.push(category);
    }
    if (operator_mu_user_id !== undefined) {
      fields.push('operator_mu_user_id = ?');
      vals.push(operator_mu_user_id === null ? null : parseInt(operator_mu_user_id, 10));
    }
    if (price_cash != null && !Number.isNaN(parseInt(price_cash, 10))) {
      fields.push('price_cash = ?');
      vals.push(parseInt(price_cash, 10));
    }
    if (stock != null && !Number.isNaN(parseInt(stock, 10))) {
      fields.push('stock = ?');
      vals.push(parseInt(stock, 10));
    }
    if (typeof is_visible === 'boolean' || is_visible === 0 || is_visible === 1) {
      fields.push('is_visible = ?');
      vals.push(is_visible ? 1 : 0);
    }
    if (!fields.length) return res.status(400).json({ error: '수정할 필드가 없습니다.' });
    vals.push(id);
    const [u] = await db.pool.query(`UPDATE market_products SET ${fields.join(', ')} WHERE id = ?`, vals);
    if (u.affectedRows === 0) return res.status(404).json({ error: '상품 없음' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.delete('/products/:id', async (req, res) => {
  try {
    const id = parseInt(req.params.id, 10);
    const [r] = await db.pool.query(`DELETE FROM market_products WHERE id = ?`, [id]);
    if (r.affectedRows === 0) return res.status(404).json({ error: '상품 없음' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** --- policy --- */
router.get('/policy', async (_req, res) => {
  try {
    const [rows] = await db.pool.query(`SELECT * FROM market_point_convert_policy ORDER BY operator_mu_user_id IS NULL DESC, id ASC`);
    res.json({ policies: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.patch('/policy', async (req, res) => {
  try {
    const { monthly_limit, convert_rate } = req.body || {};
    const [[g]] = await db.pool.query(
      `SELECT id FROM market_point_convert_policy WHERE operator_mu_user_id IS NULL ORDER BY id ASC LIMIT 1`,
    );
    const fields = [];
    const vals = [];
    if (monthly_limit != null && !Number.isNaN(parseInt(monthly_limit, 10))) {
      fields.push('monthly_limit = ?');
      vals.push(parseInt(monthly_limit, 10));
    }
    if (convert_rate != null && !Number.isNaN(Number(convert_rate))) {
      fields.push('convert_rate = ?');
      vals.push(Number(convert_rate));
    }
    if (!fields.length) return res.status(400).json({ error: '수정할 값이 없습니다.' });
    if (g) {
      vals.push(g.id);
      await db.pool.query(`UPDATE market_point_convert_policy SET ${fields.join(', ')} WHERE id = ?`, vals);
    } else {
      await db.pool.query(
        `INSERT INTO market_point_convert_policy (operator_mu_user_id, monthly_limit, convert_rate)
         VALUES (NULL, ?, ?)`,
        [
          monthly_limit != null ? parseInt(monthly_limit, 10) : 50000,
          convert_rate != null ? Number(convert_rate) : 1.0,
        ],
      );
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.patch('/policy/:operatorId', async (req, res) => {
  try {
    const operatorId = parseInt(req.params.operatorId, 10);
    if (Number.isNaN(operatorId)) return res.status(400).json({ error: '잘못된 운영자 ID' });
    const { monthly_limit, convert_rate } = req.body || {};
    const [[existing]] = await db.pool.query(
      `SELECT id FROM market_point_convert_policy WHERE operator_mu_user_id <=> ? LIMIT 1`,
      [operatorId],
    );
    const ml = monthly_limit != null ? parseInt(monthly_limit, 10) : 50000;
    const cr = convert_rate != null ? Number(convert_rate) : 1.0;
    if (existing) {
      await db.pool.query(
        `UPDATE market_point_convert_policy SET monthly_limit = ?, convert_rate = ? WHERE id = ?`,
        [ml, cr, existing.id],
      );
    } else {
      await db.pool.query(
        `INSERT INTO market_point_convert_policy (operator_mu_user_id, monthly_limit, convert_rate)
         VALUES (?, ?, ?)`,
        [operatorId, ml, cr],
      );
    }
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/** --- videos (master final review) --- */
router.get('/videos', async (_req, res) => {
  try {
    const [rows] = await db.pool.query(
      `SELECT v.*, u.telegram FROM market_videos v
       LEFT JOIN users u ON u.id = v.user_id
       WHERE v.status = 'pending' AND v.review_stage = 'master'
       ORDER BY v.id ASC LIMIT 500`,
    );
    res.json({ videos: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.patch('/videos/:id/review', async (req, res) => {
  const conn = await db.pool.getConnection();
  try {
    const id = parseInt(req.params.id, 10);
    const { action, points } = req.body || {};
    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'action은 approve 또는 reject' });
    }
    await conn.beginTransaction();
    const [[v]] = await conn.query(`SELECT * FROM market_videos WHERE id = ? FOR UPDATE`, [id]);
    if (!v) {
      await conn.rollback();
      return res.status(404).json({ error: '영상 없음' });
    }
    if (v.review_stage !== 'master' || v.status !== 'pending') {
      await conn.rollback();
      return res.status(400).json({ error: '마스터 검수 대기 상태가 아닙니다.' });
    }
    if (action === 'reject') {
      await conn.query(
        `UPDATE market_videos SET status = 'rejected', reviewed_by_mu_user_id = NULL, reviewed_at = NOW() WHERE id = ?`,
        [id],
      );
      await conn.commit();
      return res.json({ ok: true, status: 'rejected' });
    }
    const pts = points != null ? parseInt(points, 10) : 500;
    await conn.query(
      `UPDATE market_videos SET status = 'approved', points_earned = ?, reviewed_by_mu_user_id = NULL, reviewed_at = NOW() WHERE id = ?`,
      [pts, id],
    );
    await conn.query(
      `INSERT INTO market_points (user_id, amount, type, description) VALUES (?, ?, 'video_upload', ?)`,
      [v.user_id, pts, `video ${id} approved`],
    );
    await conn.commit();
    res.json({ ok: true, status: 'approved', pointsGranted: pts });
  } catch (e) {
    try {
      await conn.rollback();
    } catch (_r) {
      /* ignore */
    }
    res.status(500).json({ error: e.message });
  } finally {
    conn.release();
  }
});

/** GET /orders — 전체 주문 */
router.get('/orders', async (_req, res) => {
  try {
    const [rows] = await db.pool.query(
      `SELECT o.*, p.name AS product_name FROM market_orders o
       LEFT JOIN market_products p ON p.id = o.product_id
       ORDER BY o.id DESC LIMIT 1000`,
    );
    res.json({ orders: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
