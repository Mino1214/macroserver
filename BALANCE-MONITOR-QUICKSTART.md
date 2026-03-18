# 💰 잔고 모니터링 - 빠른 시작

## 🚀 1분 안에 시작하기

### 1단계: 모니터링 폴더 설정

원하는 폴더 경로를 `balance-monitor.js`에 설정:

```javascript
const CONFIG = {
  WATCH_FOLDER: '/your/balance/folder/path',  // ← 여기 수정!
  // ...
};
```

### 2단계: 서버 시작

```bash
cd /home/myno/바탕화면/myno/macroServer
pm2 start balance-monitor.js --name balance-monitor
pm2 save
```

### 3단계: 완료! 🎉

이제 `WATCH_FOLDER`에 잔고 파일이 생기면 자동으로 텔레그램 알림이 옵니다!

---

## 📱 텔레그램 알림 예시

```
🚨 잔고 발견!

💰 잔고: 1.234
📄 파일: balance_test.json
🔑 주소: 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb
⏰ 시각: 2024-02-18 15:30:45
```

---

## 🔧 자주 사용하는 명령어

```bash
# 상태 확인
pm2 status balance-monitor

# 로그 보기
pm2 logs balance-monitor

# 재시작
pm2 restart balance-monitor

# 중지
pm2 stop balance-monitor

# 삭제
pm2 delete balance-monitor
```

---

## 📂 지원하는 파일 예시

### balance_wallet.json
```json
{
  "address": "0xABC...",
  "balance": 1.234
}
```

### balance_info.txt
```
address: 0xABC...
balance: 1.234
```

### balance.log
```
1.234
```

---

## ⚙️ 스캔 주기 변경

`balance-monitor.js`에서:

```javascript
// 5초마다
CRON_SCHEDULE: "*/5 * * * * *"

// 1분마다
CRON_SCHEDULE: "0 * * * * *"

// 10분마다
CRON_SCHEDULE: "0 */10 * * * *"
```

---

## 🧪 테스트

```bash
# 테스트 파일 생성
cd /home/myno/바탕화면/myno/macroServer/balances
echo '{"address":"TEST","balance":999}' > test.json

# 로그 확인 (10초 이내 알림)
pm2 logs balance-monitor
```

---

## 📖 자세한 내용

전체 가이드: [잔고모니터링-가이드.md](잔고모니터링-가이드.md)

---

## 🎯 핵심 정보

- **모니터링 폴더**: `/home/myno/바탕화면/myno/macroServer/balances`
- **스캔 주기**: 10초마다
- **텔레그램 봇**: @nexus001vip_bot
- **최소 잔고**: 0 이상
- **중복 알림**: 방지됨

---

**잔고가 발견되면 즉시 텔레그램으로 알림이 옵니다!** 🚀

