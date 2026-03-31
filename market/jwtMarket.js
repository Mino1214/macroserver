const jwt = require('jsonwebtoken');

const ACCESS_SECRET =
  process.env.MARKET_JWT_ACCESS_SECRET ||
  process.env.MARKET_JWT_SECRET ||
  'market-access-dev-only';
const REFRESH_SECRET =
  process.env.MARKET_JWT_REFRESH_SECRET ||
  process.env.MARKET_JWT_SECRET ||
  'market-refresh-dev-only';

const ACCESS_EXPIRES = process.env.MARKET_JWT_ACCESS_EXPIRES || '15m';
const REFRESH_EXPIRES = process.env.MARKET_JWT_REFRESH_EXPIRES || '7d';

function signAccess(payload) {
  return jwt.sign({ typ: 'market', ...payload }, ACCESS_SECRET, { expiresIn: ACCESS_EXPIRES });
}

function signRefresh(payload) {
  return jwt.sign({ typ: 'market_rt', ...payload }, REFRESH_SECRET, { expiresIn: REFRESH_EXPIRES });
}

function verifyAccess(token) {
  return jwt.verify(token, ACCESS_SECRET);
}

function verifyRefreshToken(token) {
  return jwt.verify(token, REFRESH_SECRET);
}

module.exports = {
  signAccess,
  signRefresh,
  verifyAccess,
  verifyRefreshToken,
  ACCESS_SECRET,
  REFRESH_SECRET,
};
