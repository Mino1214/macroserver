const express = require('express');
const db = require('../../db');
const { requireMarketRoles } = require('../middleware');
const { getPointSum } = require('../services');

const router = express.Router();
router.use(requireMarketRoles('operator'));

function myOpId(req) {
  return req.marketAuth.muUserId;
}

router.get('/dashboard', async (req, res) => {
  try {
    const oid = myOpId(req);
    const [[{ uc }]] = await db.pool.query(
      `SELECT COUNT(*) AS uc FROM users WHERE operator_mu_user_id = ?`,
      [oid],
    );
    const [[{ sales }]] = await db.pool.query(
      `SELECT COALESCE(SUM(total_cash),0) AS sales FROM market_orders WHERE operator_mu_user_id = ? AND status = 'confirmed'`,
      [oid],
    );
    const [users] = await db.pool.query(`SELECT id FROM users WHERE operator_mu_user_id = ? LIMIT 500`, [oid]);
    let pointsTotal = 0;
    for (const u of users) {
      pointsTotal += await getPointSum(u.id);
    }
    res.json({
      userCount: Number(uc),
      confirmedCashSales: Number(sales),
      pointsSumSampledUsers: pointsTotal,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/users', async (req, res) => {
  try {
    const oid = myOpId(req);
    const [rows] = await db.pool.query(
      `SELECT id, telegram, status, market_status FROM users WHERE operator_mu_user_id = ? ORDER BY id DESC LIMIT 1000`,
      [oid],
    );
    res.json({ users: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.patch('/users/:id', async (req, res) => {
  try {
    const oid = myOpId(req);
    const uid = String(req.params.id).trim().toLowerCase();
    const [[u]] = await db.pool.query(
      `SELECT id FROM users WHERE id = ? AND operator_mu_user_id = ? LIMIT 1`,
      [uid, oid],
    );
    if (!u) return res.status(404).json({ error: '유저를 찾을 수 없습니다.' });
    const { market_status } = req.body || {};
    if (!['active', 'suspended'].includes(market_status)) {
      return res.status(400).json({ error: 'market_status는 active 또는 suspended' });
    }
    await db.pool.query(`UPDATE users SET market_status = ? WHERE id = ?`, [market_status, uid]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/products', async (req, res) => {
  try {
    const oid = myOpId(req);
    const [rows] = await db.pool.query(
      `SELECT * FROM market_products WHERE operator_mu_user_id <=> ? ORDER BY id DESC`,
      [oid],
    );
    res.json({ products: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.post('/products', async (req, res) => {
  try {
    const oid = myOpId(req);
    const { name, description, category, price_cash, stock, is_visible } = req.body || {};
    if (!name?.trim()) return res.status(400).json({ error: '상품명 필요' });
    const price = parseInt(price_cash, 10);
    if (Number.isNaN(price) || price < 0) return res.status(400).json({ error: '가격 필요' });
    const st = stock !== undefined ? parseInt(stock, 10) : -1;
    const vis = is_visible !== false && is_visible !== 0 ? 1 : 0;
    const [r] = await db.pool.query(
      `INSERT INTO market_products (name, description, category, operator_mu_user_id, price_cash, stock, is_visible)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [name.trim(), description || null, category || null, oid, price, st, vis],
    );
    res.status(201).json({ ok: true, id: r.insertId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.patch('/products/:id', async (req, res) => {
  try {
    const oid = myOpId(req);
    const id = parseInt(req.params.id, 10);
    const [[p]] = await db.pool.query(
      `SELECT id FROM market_products WHERE id = ? AND operator_mu_user_id <=> ?`,
      [id, oid],
    );
    if (!p) return res.status(404).json({ error: '상품 없음' });
    const { name, description, category, price_cash, stock, is_visible } = req.body || {};
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
    if (!fields.length) return res.status(400).json({ error: '수정 필드 없음' });
    vals.push(id);
    await db.pool.query(`UPDATE market_products SET ${fields.join(', ')} WHERE id = ?`, vals);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/orders', async (req, res) => {
  try {
    const oid = myOpId(req);
    const [rows] = await db.pool.query(
      `SELECT o.*, p.name AS product_name FROM market_orders o
       LEFT JOIN market_products p ON p.id = o.product_id
       WHERE o.operator_mu_user_id = ? ORDER BY o.id DESC LIMIT 500`,
      [oid],
    );
    res.json({ orders: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.get('/videos', async (req, res) => {
  try {
    const oid = myOpId(req);
    const [rows] = await db.pool.query(
      `SELECT v.* FROM market_videos v
       JOIN users u ON u.id = v.user_id
       WHERE u.operator_mu_user_id = ?
       ORDER BY v.id DESC LIMIT 200`,
      [oid],
    );
    res.json({ videos: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

router.patch('/videos/:id/review', async (req, res) => {
  try {
    const oid = myOpId(req);
    const id = parseInt(req.params.id, 10);
    const { action } = req.body || {};
    if (!['approve', 'reject'].includes(action)) return res.status(400).json({ error: 'approve/reject' });

    const [[v]] = await db.pool.query(`SELECT v.* FROM market_videos v JOIN users u ON u.id = v.user_id WHERE v.id = ? AND u.operator_mu_user_id = ?`, [
      id,
      oid,
    ]);
    if (!v) return res.status(404).json({ error: '영상 없음' });
    if (v.review_stage !== 'operator' || v.status !== 'pending') {
      return res.status(400).json({ error: '1차 검수 대기 상태가 아닙니다.' });
    }

    if (action === 'reject') {
      await db.pool.query(
        `UPDATE market_videos SET status = 'rejected', reviewed_by_mu_user_id = ?, reviewed_at = NOW() WHERE id = ?`,
        [oid, id],
      );
      return res.json({ ok: true, status: 'rejected' });
    }
    await db.pool.query(
      `UPDATE market_videos SET review_stage = 'master', reviewed_by_mu_user_id = ?, reviewed_at = NOW() WHERE id = ?`,
      [oid, id],
    );
    res.json({ ok: true, status: 'forwarded_to_master' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
