# Seed Checker RPC 연결 오류 해결

## 문제점

`seed-checker`가 시작할 때 다음 오류가 반복적으로 발생:
```
JsonRpcProvider failed to detect network and cannot start up; retry in 1s 
(perhaps the URL is wrong or the node is not started)
```

## 원인

1. **RPC URL 문제**: 일부 공개 RPC가 API 키를 요구하거나 네트워크 감지에 실패
   - `eth.llamarpc.com` → 응답 느림
   - `polygon-rpc.com` → API 키 요구 (401 Unauthorized)
   - `rpc.ankr.com/*` → API 키 요구

2. **ethers.js 설정**: `JsonRpcProvider`가 네트워크 자동 감지 시도 → 타임아웃

3. **TronWeb 문제**: `TronWeb is not a constructor` 오류

## 해결 방법

### 1. RPC URL 변경 (무료 공개 RPC)

```javascript
RPC_URLS: {
  ethereum: 'https://rpc.flashbots.net',           // Flashbots 공개 RPC
  bsc: 'https://bsc-dataseed1.binance.org',        // Binance 공식
  polygon: 'https://polygon.drpc.org',             // dRPC 무료
  // tron: 임시 비활성화 (TronWeb 호환성 문제)
},
```

### 2. Provider 설정 개선

```javascript
const provider = new ethers.JsonRpcProvider(CONFIG.RPC_URLS[network], null, {
  staticNetwork: true,  // 네트워크 자동 감지 스킵
  timeout: 10000,       // 10초 타임아웃
});
```

**변경 사항**:
- `staticNetwork: true`: 네트워크 감지를 시도하지 않음
- `timeout: 10000`: 10초 타임아웃 설정

### 3. 에러 로깅 개선

```javascript
catch (error) {
  console.error(`❌ ${network.toUpperCase()} 잔고 확인 오류: ${error.message}`);
  
  if (error.message.includes('network') || error.message.includes('timeout')) {
    console.error(`   RPC URL: ${CONFIG.RPC_URLS[network]}`);
    console.error(`   해결방법: RPC 엔드포인트를 확인하거나 다른 공개 RPC로 변경하세요.`);
  }
  
  return { success: false, network, error: error.message };
}
```

### 4. Tron 임시 비활성화

TronWeb 버전 호환성 문제로 인해 Tron 체인 확인을 임시로 비활성화했습니다.

## 테스트 결과

### 성공한 체인

#### Ethereum (Flashbots)
```
🌐 ETHEREUM   | 주소: 0xa643e61b4AF8C020cbFFB6854c5C516a5574F84E
   💵 ETH   : 0.0                  ⚪
   💵 USDT  : 0                    ⚪
```

#### BSC (Binance)
```
🌐 BSC        | 주소: 0xa643e61b4AF8C020cbFFB6854c5C516a5574F84E
   💵 BNB   : 0.0                  ⚪
   💵 USDT  : 0.0                  ⚪
```

#### Polygon (dRPC)
```
🌐 POLYGON    | 주소: 0xa643e61b4AF8C020cbFFB6854c5C516a5574F84E
   💵 MATIC : 0.0                  ⚪
   💵 USDT  : 0.0                  ⚪
```

### 실행 로그

```
✅ MariaDB 연결 성공!
✅ seeds 테이블 스키마 확인 완료
✅ 텔레그램 전송 성공
🎯 검수 시작...

🔍 1개 시드 검수 시작...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 시드 검수 시작
📋 ID: 213
📝 시드 문구: ...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💰 체인별 잔고 확인 결과:
  ✅ ETHEREUM: 성공
  ✅ BSC: 성공
  ✅ POLYGON: 성공

💾 잔고 저장: ID 213, Balance: 0, USDT: 0
✅ 검수 완료!
```

## 추천 무료 공개 RPC

### Ethereum
- ✅ `https://rpc.flashbots.net` (Flashbots 공식)
- `https://ethereum.publicnode.com`
- `https://eth.drpc.org`

### BSC (Binance Smart Chain)
- ✅ `https://bsc-dataseed1.binance.org` (Binance 공식)
- `https://bsc-dataseed2.binance.org`
- `https://bsc.publicnode.com`

### Polygon
- ✅ `https://polygon.drpc.org`
- `https://polygon.publicnode.com`
- `https://polygon-rpc.com` (API 키 필요)

### 주의사항
- 무료 RPC는 rate limit이 있을 수 있음
- 프로덕션 환경에서는 유료 RPC 서비스 추천 (Infura, Alchemy, QuickNode)
- RPC가 느리거나 응답 없으면 대체 URL로 변경

## Tron 지원 계획

TronWeb 호환성 문제는 추후 해결 예정:
1. TronWeb 최신 버전으로 업데이트
2. TronGrid API 키 발급
3. 또는 다른 Tron 라이브러리로 교체

현재는 Ethereum, BSC, Polygon 3개 체인만 지원합니다.

## 완료!

Seed checker가 정상적으로 작동하며:
- ✅ Ethereum 잔고 확인
- ✅ BSC 잔고 확인  
- ✅ Polygon 잔고 확인
- ✅ USDT 잔고 확인 (각 체인별)
- ✅ DB 저장 및 검수 완료 처리
- ✅ 텔레그램 알림 (잔고 > 0인 경우)

RPC 연결 오류 없이 안정적으로 실행됩니다!

*최종 수정: 2026-02-19 01:50*
*작성: Myno Lab*

