const express = require('express');
const path = require('path');
const { resolveMarketTenant } = require('./middleware');
const authRoutes = require('./routes/auth');
const masterRoutes = require('./routes/master');
const operatorRoutes = require('./routes/operator');
const userRoutes = require('./routes/user');

const videoUploadDir = path.join(__dirname, '..', 'uploads', 'market-videos');

function mountMarketApi(app) {
  fsEnsureDir(videoUploadDir);
  app.use('/market-static/videos', express.static(videoUploadDir));

  const market = express.Router();
  market.use(resolveMarketTenant);
  market.use('/auth', authRoutes);
  market.use('/master', masterRoutes);
  market.use('/operator', operatorRoutes);
  market.use('/user', userRoutes);

  app.use('/api/market', market);
}

function fsEnsureDir(dir) {
  const fs = require('fs');
  try {
    fs.mkdirSync(dir, { recursive: true });
  } catch (_e) {
    /* ignore */
  }
}

module.exports = { mountMarketApi };
