const db = require('../db');

async function getPointSum(userId) {
  const [[row]] = await db.pool.query(
    'SELECT COALESCE(SUM(amount),0) AS s FROM market_points WHERE user_id = ?',
    [userId],
  );
  return Number(row.s);
}

async function getCashBalance(userId) {
  const [[row]] = await db.pool.query(
    'SELECT balance FROM market_cash_balance WHERE user_id = ? LIMIT 1',
    [userId],
  );
  if (!row) {
    await db.pool.query('INSERT INTO market_cash_balance (user_id, balance) VALUES (?, 0)', [userId]);
    return 0;
  }
  return Number(row.balance);
}

async function getConvertPolicy(operatorMuUserId) {
  const [[custom]] = await db.pool.query(
    `SELECT * FROM market_point_convert_policy
     WHERE operator_mu_user_id <=> ? ORDER BY id DESC LIMIT 1`,
    [operatorMuUserId],
  );
  if (custom) return custom;
  const [[global]] = await db.pool.query(
    `SELECT * FROM market_point_convert_policy WHERE operator_mu_user_id IS NULL ORDER BY id ASC LIMIT 1`,
  );
  return global || { monthly_limit: 50000, convert_rate: 1.0 };
}

function startOfUtcMonth(d = new Date()) {
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1, 0, 0, 0));
}

async function getMonthlyConvertedPoints(userId) {
  const start = startOfUtcMonth();
  const [[row]] = await db.pool.query(
    `SELECT COALESCE(SUM(-amount),0) AS s FROM market_points
     WHERE user_id = ? AND type = 'point_convert' AND amount < 0 AND created_at >= ?`,
    [userId, start],
  );
  return Number(row.s);
}

const GAME_POINTS = {
  default: 100,
  spin: 150,
  quiz: 200,
  flappy: 80,
};

module.exports = {
  getPointSum,
  getCashBalance,
  getConvertPolicy,
  getMonthlyConvertedPoints,
  startOfUtcMonth,
  GAME_POINTS,
};
