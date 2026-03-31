const crypto = require('crypto');
const db = require('../db');

function hashToken(raw) {
  return crypto.createHash('sha256').update(raw, 'utf8').digest('hex');
}

async function saveRefreshToken({ rawToken, subjectType, usersId, muUserId, expiresAt }) {
  const tokenHash = hashToken(rawToken);
  await db.pool.query(
    `INSERT INTO market_refresh_tokens (token_hash, subject_type, users_id, mu_user_id, expires_at)
     VALUES (?, ?, ?, ?, ?)`,
    [tokenHash, subjectType, usersId || null, muUserId || null, expiresAt],
  );
}

async function consumeRefreshToken(rawToken) {
  const tokenHash = hashToken(rawToken);
  const [[row]] = await db.pool.query(
    `SELECT id, subject_type, users_id, mu_user_id, expires_at
     FROM market_refresh_tokens WHERE token_hash = ? LIMIT 1`,
    [tokenHash],
  );
  if (!row) return null;
  await db.pool.query('DELETE FROM market_refresh_tokens WHERE id = ?', [row.id]);
  if (new Date(row.expires_at) < new Date()) return null;
  return row;
}

async function pruneExpiredRefreshTokens() {
  try {
    await db.pool.query('DELETE FROM market_refresh_tokens WHERE expires_at < NOW()');
  } catch (_e) {
    /* ignore */
  }
}

module.exports = {
  saveRefreshToken,
  consumeRefreshToken,
  pruneExpiredRefreshTokens,
  hashToken,
};
