const crypto = require('crypto');

/** macroServer mu_users와 동일한 SHA256 hex */
function hashPassword(pw) {
  return crypto.createHash('sha256').update(String(pw), 'utf8').digest('hex');
}

/** 기존 users.pw 평문 또는 SHA256 호환 검증 */
function verifyUserStoredPassword(stored, input) {
  const s = String(stored || '');
  const i = String(input || '');
  if (!s || !i) return false;
  const h = hashPassword(i);
  if (s === h) return true;
  if (s.length !== 64) return s === i;
  return false;
}

module.exports = { hashPassword, verifyUserStoredPassword };
