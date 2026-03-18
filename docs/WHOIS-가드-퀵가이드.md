# 🛡️ WHOIS 가드 퀵 가이드

## 1️⃣ 현재 상태 확인

```bash
cd /home/myno/바탕화면/myno/macroServer
./whois-확인.sh
```

또는 온라인에서:
- **한국 도메인**: https://whois.kisa.or.kr
- **글로벌**: https://www.whois.com/whois/mynolab.kr

---

## 2️⃣ 등록 업체별 설정 방법

### 🔵 가비아
1. https://domain.gabia.com 로그인
2. **My가비아** → **도메인 관리**
3. mynolab.kr 선택
4. **도메인 정보 보호 서비스** 신청
5. 무료/유료 옵션 선택 → 활성화

### 🟢 카페24
1. https://www.cafe24.com 로그인
2. **나의 서비스 관리** → **도메인 관리**
3. mynolab.kr 선택
4. **도메인 정보보호 서비스** 활성화

### 🟡 호스팅케이알
1. https://www.hostingkr.co.kr 로그인
2. **도메인 관리**
3. **WHOIS 보호 서비스** 신청

### 🔴 Cloudflare (추천)
1. https://dash.cloudflare.com 로그인
2. 도메인 추가
3. **자동으로 WHOIS 보호 제공** (무료)

---

## 3️⃣ 한국 도메인 (.kr) 특별 설정

### KISA 개인정보 보호
1. https://whois.kisa.or.kr 접속
2. **등록자 정보 보호 신청**
3. 본인 인증
4. 신청 완료

---

## 4️⃣ 확인 (24시간 후)

```bash
# 터미널에서
whois mynolab.kr | grep -i registrant

# 보호되면 이렇게 보임:
# Registrant Name: REDACTED FOR PRIVACY
# Registrant Email: REDACTED FOR PRIVACY
```

---

## 5️⃣ 추가 보안 (필수!)

### ✅ 도메인 잠금
- 등록업체에서 **Transfer Lock** 활성화
- 무단 이전 방지

### ✅ 2단계 인증
- 계정에 **2FA/OTP** 설정
- 탈취 방지

### ✅ 자동 갱신
- **Auto Renewal** 설정
- 도메인 만료 방지

---

## 🚨 비용

| 업체 | 연간 비용 |
|-----|---------|
| 가비아 | 11,000원 (또는 무료) |
| 카페24 | 10,000원 (또는 무료) |
| Namecheap | 무료 |
| Cloudflare | 무료 |

---

## 📞 고객센터

- **가비아**: ☎️ 1544-4755
- **카페24**: ☎️ 1544-6789
- **호스팅케이알**: ☎️ 1544-2233

---

## ⚡ 즉시 실행할 것

```bash
# 1. 상태 확인
./whois-확인.sh

# 2. 등록업체 로그인 → WHOIS 보호 활성화

# 3. 24시간 후 재확인
./whois-확인.sh
```

---

**개인정보를 지금 바로 보호하세요!** 🔐

자세한 내용: `WHOIS-가드-설정.md` 참고

