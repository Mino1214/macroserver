/**
 * 선택적 Redis (REDIS_URL). 없으면 동작하지 않음.
 */
let _cached;
let _attempted;

function getRedis() {
  if (_attempted) return _cached;
  _attempted = true;
  const url = process.env.REDIS_URL || process.env.MARKET_REDIS_URL;
  if (!url) {
    _cached = null;
    return null;
  }
  try {
    const Redis = require('ioredis');
    _cached = new Redis(url);
    _cached.on('error', (e) => console.warn('[market redis]', e.message));
    return _cached;
  } catch (e) {
    console.warn('[market redis]', e.message);
    _cached = null;
    return null;
  }
}

module.exports = { getRedis };
