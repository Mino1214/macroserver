const db = require('../db');
const { verifyAccess } = require('./jwtMarket');

/**
 * Host / X-Operator-Id 기반 테넌트 (운영자 mu_users.id)
 */
async function resolveMarketTenant(req, res, next) {
  if (req.method === 'OPTIONS') return next();
  req.marketTenantOperatorId = null;
  const headerOp = req.headers['x-operator-id'];
  if (headerOp !== undefined && headerOp !== null && String(headerOp).trim() !== '') {
    const n = parseInt(String(headerOp), 10);
    if (!Number.isNaN(n)) req.marketTenantOperatorId = n;
    return next();
  }

  const hostRaw =
    (req.headers['x-forwarded-host'] || req.headers.host || '').toString().split(',')[0].trim();
  const host = hostRaw.split(':')[0].toLowerCase();
  if (!host) return next();

  try {
    const [[row]] = await db.pool.query(
      `SELECT id FROM mu_users
       WHERE market_role = 'operator' AND is_site_active = 1
         AND site_domain IS NOT NULL AND LOWER(site_domain) = ? LIMIT 1`,
      [host],
    );
    if (row) req.marketTenantOperatorId = row.id;
  } catch (e) {
    console.warn('[market] resolveMarketTenant:', e.message);
  }
  next();
}

function requireMarketRoles(...allowed) {
  return (req, res, next) => {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7).trim() : '';
    if (!token) return res.status(401).json({ error: '인증이 필요합니다.' });
    try {
      const decoded = verifyAccess(token);
      if (decoded.typ !== 'market') return res.status(401).json({ error: '유효하지 않은 토큰입니다.' });
      const role = decoded.role;
      if (!allowed.includes(role)) return res.status(403).json({ error: '권한이 없습니다.' });
      req.marketAuth = decoded;
      next();
    } catch (_e) {
      return res.status(401).json({ error: '액세스 토큰이 만료되었거나 유효하지 않습니다.' });
    }
  };
}

/** 운영자는 자기 소속 리소스만 (operator_mu_user_id 일치) */
function operatorMustOwnParam(paramName = 'operatorId') {
  return (req, res, next) => {
    const mine = req.marketAuth.muUserId;
    if (mine == null) return res.status(403).json({ error: '운영자 정보가 없습니다.' });
    const fromParam = parseInt(req.params[paramName], 10);
    if (!Number.isNaN(fromParam) && fromParam !== mine) {
      return res.status(403).json({ error: '해당 리소스에 접근할 수 없습니다.' });
    }
    next();
  };
}

module.exports = {
  resolveMarketTenant,
  requireMarketRoles,
  operatorMustOwnParam,
};
