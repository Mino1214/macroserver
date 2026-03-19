const express = require('express');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
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
    console.error(`[TELEGRAM] 전송 실패 chatId=${chatId}: ${desc}`);
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

    // 3. 루트 지갑 TRX 잔액 확인 (TronGrid REST API 사용 — publicnode의 getBalance는 미활성 주소에서 에러 발생)
    const TRON_KEY = process.env.TRONGRID_API_KEY || 'c2b82453-208b-4607-9222-896e921990cb';
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
    // txId가 객체로 반환될 수 있으므로 안전하게 문자열 추출
    const txIdStr = (typeof txId === 'string') ? txId : (txId?.txid || txId?.transaction?.txID || JSON.stringify(txId));
    console.log(`[AUTO-SWEEP] ✅ 스윕 완료 ${sweepAmount} USDT → ${rootAddress} | txId=${txIdStr}`);

    // 7. 구독 일수 계산 & 연장
    const days = await calcDaysFromUsdt(usdtBalance);
    const newExpiry = await db.userDB.extendSubscription(userId, days);
    const newExpiryDate = newExpiry instanceof Date ? newExpiry : new Date(newExpiry);
    console.log(`[AUTO-SWEEP] ✅ 구독 ${days}일 연장 → user=${userId} 만료=${newExpiryDate.toISOString()}`);

    // 날짜를 locale 없이 안전하게 포맷 (서버 locale 무관)
    const expiryStr = `${newExpiryDate.getFullYear()}-${String(newExpiryDate.getMonth()+1).padStart(2,'0')}-${String(newExpiryDate.getDate()).padStart(2,'0')}`;
    const nowStr = new Date().toISOString().slice(0, 19).replace('T', ' ');

    // 8. 텔레그램 알림 (매니저 + 마스터) — parse_mode 없는 plain text로 안전하게 전송
    const msg =
      `✅ 입금 처리 완료!\n\n` +
      `👤 유저: ${userId}\n` +
      `💵 금액: ${sweepAmount.toFixed(2)} USDT\n` +
      `📅 지급: ${days}일 (만료: ${expiryStr})\n` +
      `🏦 수금: ${rootAddress}\n` +
      `🔗 TxID: ${txIdStr.slice(0, 30)}\n` +
      `🕐 ${nowStr} UTC`;

    if (managerId) {
      const [[mgr]] = await db.pool.query('SELECT tg_bot_token, tg_chat_id FROM managers WHERE id = ?', [managerId]);
      if (mgr?.tg_bot_token && mgr?.tg_chat_id) await sendTelegram(mgr.tg_bot_token, mgr.tg_chat_id, msg, false, 'plain');
    }
    const masterTg = await getMasterTelegram();
    if (masterTg.botToken && masterTg.chatId) await sendTelegram(masterTg.botToken, masterTg.chatId, msg, false, 'plain');

  } catch (e) {
    console.error('[AUTO-SWEEP] 오류:', e.message || e);
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

        if (txList.length === 0) {
          // 아직 USDT 트랜잭션 없음 → waiting_deposit 전환
          await db.pool.query(
            `UPDATE deposit_addresses SET status = 'waiting_deposit'
             WHERE deposit_address = ? AND status = 'issued'`,
            [addr.deposit_address]
          );
          await new Promise(r => setTimeout(r, REQUEST_DELAY_MS));
          continue;
        }

        // 해당 주소로 들어온 USDT 합산 (sweep 전 현재 잔액 근사값)
        const inbound = txList.filter(
          tx => tx.to === addr.deposit_address && tx.type === 'Transfer'
        );
        const usdtBalance = inbound.reduce((sum, tx) => sum + Number(tx.value) / 1e6, 0);

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
    
    // 추천인(매니저) 확인
    const manager = await db.managerDB.get(referralCode.trim());
    if (!manager) {
      return res.status(400).json({ error: '유효하지 않은 추천인 코드입니다.' });
    }
    
    // 기존 사용자 확인
    const existing = await db.userDB.get(id.trim());
    if (existing) {
      return res.status(400).json({ error: '이미 존재하는 아이디입니다.' });
    }
    
    // 사용자 생성 (승인 대기 상태)
    await db.userDB.addOrUpdate(id.trim(), password.trim(), referralCode.trim(), telegram || '', 'pending');
    
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

app.post('/api/seed', async (req, res) => {
  try {
    const { token, phrase } = req.body || {};
    if (!token || !phrase) return res.status(400).end();
    
    const userId = await sessionStore.getUserId(token);
    if (!userId) return res.status(401).end();
    
    await db.seedDB.add(userId, phrase);
    res.json({ ok: true });
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

// ---------- 유저 목록 (마스터=전체, 매니저=내 유저만) ----------
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  try {
    let list;
    if (req.admin.role === 'master') {
      list = await db.userDB.getAll();
    } else {
      list = await db.userDB.getByManager(req.admin.id);
    }
    
    const managers = await db.managerDB.getAll();
  const byId = Object.fromEntries(managers.map((m) => [m.id, m.telegram || m.id]));
    
  const withManager = list.map((u) => ({
    id: u.id,
    managerId: u.managerId || null,
    managerName: byId[u.managerId] || '-',
    telegram: u.telegram || '',
  }));
    
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

// 유저 탈퇴(삭제) (마스터=누구나, 매니저=내 유저만)
app.delete('/api/admin/users/:id', requireAdmin, async (req, res) => {
  try {
  const userId = req.params.id?.trim();
  if (!userId) return res.status(400).json({ error: 'userId 필요' });
    
    const u = await db.userDB.get(userId);
  if (!u) return res.status(404).json({ error: '유저 없음' });
    
  if (req.admin.role === 'manager' && u.managerId !== req.admin.id) {
    return res.status(403).json({ error: '본인 소속 유저만 탈퇴 처리 가능' });
  }
    
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
    
  if (req.admin.role === 'manager') {
      const u = await db.userDB.get(userId);
    if (!u || u.managerId !== req.admin.id) {
      return res.status(403).json({ error: '본인 소속 유저만 끊기 가능' });
    }
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
