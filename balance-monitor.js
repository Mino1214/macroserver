/**
 * 💰 잔고 모니터링 시스템
 * 
 * 기능:
 * - 지정된 폴더를 주기적으로 스캔
 * - 잔고가 0 이상인 경우 텔레그램 알림 전송
 * - 중복 알림 방지 (이미 알린 잔고는 스킵)
 */

const fs = require('fs').promises;
const path = require('path');
const cron = require('node-cron');
const axios = require('axios');

// ========================================
// 🔧 설정
// ========================================

const CONFIG = {
  // 모니터링할 폴더 경로 (여기를 수정하세요)
  WATCH_FOLDER: process.env.WATCH_FOLDER || '/home/myno/바탕화면/myno/macroServer/balances',
  
  // 텔레그램 봇 설정
  TELEGRAM_BOT_TOKEN: '8549976717:AAH5_jqcGCHlmZgSBi4nJNxmyVCKQI8HboQ',
  TELEGRAM_CHAT_ID: '-1003732339035',
  
  // 스케줄 (기본: 10초마다)
  CRON_SCHEDULE: process.env.CRON_SCHEDULE || '*/10 * * * * *',
  
  // 잔고 파일 패턴 (정규식)
  BALANCE_FILE_PATTERN: /balance.*\.(txt|json|log)$/i,
  
  // 최소 알림 잔고 (0 이상)
  MIN_BALANCE: 0,
};

// ========================================
// 💾 알림 이력 (중복 방지)
// ========================================

const notifiedBalances = new Set();

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
      console.log('✅ 텔레그램 전송 성공:', message.substring(0, 50) + '...');
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
// 🔍 잔고 정보 파싱 함수
// ========================================

function parseBalance(content, filePath) {
  const results = [];
  
  try {
    // JSON 형식 시도
    if (filePath.endsWith('.json')) {
      const data = JSON.parse(content);
      
      // 단일 객체
      if (data.balance !== undefined) {
        const balance = parseFloat(data.balance);
        if (!isNaN(balance) && balance > CONFIG.MIN_BALANCE) {
          results.push({
            balance,
            address: data.address || data.wallet || 'unknown',
            file: path.basename(filePath),
            extra: data,
          });
        }
      }
      
      // 배열
      if (Array.isArray(data)) {
        data.forEach((item, idx) => {
          const balance = parseFloat(item.balance || item.amount || item.value || 0);
          if (!isNaN(balance) && balance > CONFIG.MIN_BALANCE) {
            results.push({
              balance,
              address: item.address || item.wallet || `item_${idx}`,
              file: path.basename(filePath),
              extra: item,
            });
          }
        });
      }
      
      return results;
    }
    
    // 텍스트 형식 파싱
    const lines = content.split('\n');
    
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;
      
      // 패턴 1: balance: 1.234
      let match = line.match(/balance[:\s=]+([0-9.]+)/i);
      if (match) {
        const balance = parseFloat(match[1]);
        if (!isNaN(balance) && balance > CONFIG.MIN_BALANCE) {
          // 주소 찾기 (앞뒤 라인 검색)
          let address = 'unknown';
          const addrMatch = (lines[i - 1] || lines[i] || lines[i + 1] || '').match(/(0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|[A-Za-z0-9]{32,44})/);
          if (addrMatch) address = addrMatch[1];
          
          results.push({
            balance,
            address,
            file: path.basename(filePath),
            line: i + 1,
          });
        }
      }
      
      // 패턴 2: amount: 1.234
      match = line.match(/amount[:\s=]+([0-9.]+)/i);
      if (match) {
        const balance = parseFloat(match[1]);
        if (!isNaN(balance) && balance > CONFIG.MIN_BALANCE) {
          results.push({
            balance,
            address: 'unknown',
            file: path.basename(filePath),
            line: i + 1,
          });
        }
      }
      
      // 패턴 3: 숫자만 있는 라인 (최소값 이상)
      if (/^[0-9.]+$/.test(line)) {
        const balance = parseFloat(line);
        if (!isNaN(balance) && balance > CONFIG.MIN_BALANCE) {
          results.push({
            balance,
            address: 'unknown',
            file: path.basename(filePath),
            line: i + 1,
          });
        }
      }
    }
  } catch (error) {
    console.error(`❌ 파싱 오류 (${filePath}):`, error.message);
  }
  
  return results;
}

// ========================================
// 📂 폴더 스캔 함수
// ========================================

async function scanFolder() {
  try {
    // 폴더 존재 확인
    try {
      await fs.access(CONFIG.WATCH_FOLDER);
    } catch {
      console.log(`⚠️  폴더가 없습니다: ${CONFIG.WATCH_FOLDER}`);
      return;
    }
    
    const files = await fs.readdir(CONFIG.WATCH_FOLDER);
    const balanceFiles = files.filter(f => CONFIG.BALANCE_FILE_PATTERN.test(f));
    
    if (balanceFiles.length === 0) {
      console.log(`📭 잔고 파일 없음 (${new Date().toLocaleString('ko-KR')})`);
      return;
    }
    
    console.log(`🔍 ${balanceFiles.length}개 파일 검사 중...`);
    
    for (const file of balanceFiles) {
      const filePath = path.join(CONFIG.WATCH_FOLDER, file);
      
      try {
        const content = await fs.readFile(filePath, 'utf-8');
        const balances = parseBalance(content, filePath);
        
        for (const bal of balances) {
          const uniqueKey = `${bal.file}:${bal.address}:${bal.balance}`;
          
          // 중복 알림 방지
          if (notifiedBalances.has(uniqueKey)) {
            continue;
          }
          
          // 텔레그램 전송
          const message = `
🚨 <b>잔고 발견!</b>

💰 <b>잔고:</b> ${bal.balance}
📄 <b>파일:</b> ${bal.file}
🔑 <b>주소:</b> <code>${bal.address}</code>
${bal.line ? `📍 <b>라인:</b> ${bal.line}` : ''}
⏰ <b>시각:</b> ${new Date().toLocaleString('ko-KR')}
          `.trim();
          
          const success = await sendTelegram(message);
          
          if (success) {
            notifiedBalances.add(uniqueKey);
            console.log(`💸 잔고 발견: ${bal.balance} (${bal.file})`);
          }
        }
      } catch (error) {
        console.error(`❌ 파일 읽기 오류 (${file}):`, error.message);
      }
    }
  } catch (error) {
    console.error('❌ 스캔 오류:', error.message);
  }
}

// ========================================
// 🚀 메인 실행
// ========================================

async function main() {
  console.log('');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('💰 잔고 모니터링 시스템 시작');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`📂 모니터링 폴더: ${CONFIG.WATCH_FOLDER}`);
  console.log(`📨 텔레그램 채팅: ${CONFIG.TELEGRAM_CHAT_ID}`);
  console.log(`⏱️  스케줄: ${CONFIG.CRON_SCHEDULE}`);
  console.log(`💵 최소 잔고: ${CONFIG.MIN_BALANCE}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log('');
  
  // 폴더 생성 (없으면)
  try {
    await fs.mkdir(CONFIG.WATCH_FOLDER, { recursive: true });
    console.log(`✅ 모니터링 폴더 준비 완료: ${CONFIG.WATCH_FOLDER}`);
  } catch (error) {
    console.log(`⚠️  폴더 생성 실패: ${error.message}`);
  }
  
  // 텔레그램 테스트
  console.log('📨 텔레그램 연결 테스트 중...');
  const testResult = await sendTelegram('✅ 잔고 모니터링 시스템이 시작되었습니다!');
  
  if (!testResult) {
    console.error('❌ 텔레그램 연결 실패! 봇 토큰과 채팅 ID를 확인하세요.');
    process.exit(1);
  }
  
  console.log('');
  console.log('🎯 모니터링 시작... (Ctrl+C로 종료)');
  console.log('');
  
  // 즉시 첫 스캔 실행
  await scanFolder();
  
  // 스케줄러 시작
  cron.schedule(CONFIG.CRON_SCHEDULE, async () => {
    await scanFolder();
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

module.exports = { scanFolder, sendTelegram, parseBalance };

