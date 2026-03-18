# 🛡️ WHOIS 가드 설정 가이드

## WHOIS란?

WHOIS는 도메인 등록자의 정보를 공개하는 데이터베이스입니다.
보호하지 않으면 다음 정보가 공개됩니다:
- 이름
- 이메일 주소
- 전화번호
- 실제 주소
- 등록 날짜

## ⚠️ 위험성

WHOIS 정보가 공개되면:
- 스팸 메일/전화 증가
- 개인정보 유출
- 피싱 공격 대상이 될 수 있음
- 사생활 침해

---

## 1️⃣ 현재 WHOIS 정보 확인

### 터미널에서 확인:
```bash
whois mynolab.kr
```

### 온라인에서 확인:
- https://whois.kisa.or.kr (한국 도메인)
- https://www.whois.com/whois/mynolab.kr

---

## 2️⃣ WHOIS 가드 설정 방법

### 📌 도메인 등록 업체에서 설정

도메인을 구매한 곳에서 WHOIS 보호 서비스를 활성화하세요:

#### 가비아 (Gabia)
1. 가비아 로그인 → My가비아
2. 도메인 관리
3. **도메인 정보 보호 서비스** 신청
4. 무료 또는 유료 옵션 선택

#### 카페24
1. 카페24 로그인
2. 나의 서비스 관리
3. 도메인 관리 → 도메인 정보보호 서비스
4. 신청/활성화

#### 호스팅케이알 (HostingKR)
1. 로그인 → 도메인 관리
2. WHOIS 보호 서비스 활성화
3. 대리 등록 정보로 변경

#### 닷넷코리아 (DotName Korea)
1. 회원 로그인
2. 도메인 관리
3. 개인정보보호서비스 신청

#### 아임웹 (Imweb)
1. 로그인 → 도메인 설정
2. 개인정보 보호 활성화

---

## 3️⃣ 해외 등록업체

### GoDaddy
1. 로그인 → My Products
2. Domain → 해당 도메인 선택
3. **Domain Privacy & Protection** 구매/활성화

### Namecheap
1. 로그인 → Domain List
2. Manage → 해당 도메인
3. **WhoisGuard** 활성화 (보통 무료 제공)

### Cloudflare
1. Cloudflare에 도메인 등록 시 자동으로 WHOIS 보호 제공
2. 추가 비용 없음

---

## 4️⃣ 한국 도메인 (.kr) 특별 사항

### ⚠️ 중요: .kr 도메인은 일부 정보 공개 필수

한국 도메인(.kr)은 법적으로 일부 정보 공개가 필요합니다:
- 등록자명 (개인의 경우 일부 마스킹 가능)
- 등록 날짜
- 만료 날짜

하지만 다음은 보호 가능:
- 상세 주소
- 전화번호
- 이메일 주소

### KISA (한국인터넷진흥원) 개인정보보호

.kr 도메인은 KISA를 통해 개인정보 보호 신청 가능:
1. https://whois.kisa.or.kr 접속
2. 등록자 정보 보호 신청
3. 본인 인증 후 신청

---

## 5️⃣ 무료 WHOIS 보호 제공 업체

| 업체 | WHOIS 보호 | 비용 |
|-----|-----------|------|
| Namecheap | ✅ WhoisGuard | 무료 (1년) |
| Cloudflare | ✅ 자동 제공 | 무료 |
| Porkbun | ✅ 자동 제공 | 무료 |
| 가비아 | ⚠️ 선택 옵션 | 유료/무료 혼재 |
| GoDaddy | ⚠️ 별도 구매 | 유료 |

---

## 6️⃣ 확인 방법

설정 후 24-48시간 뒤 확인:

```bash
# 터미널에서 확인
whois mynolab.kr

# 또는
nslookup mynolab.kr
```

### 보호가 활성화되면:
```
Registrant Name: REDACTED FOR PRIVACY
Registrant Email: REDACTED FOR PRIVACY
Registrant Phone: REDACTED FOR PRIVACY
```

---

## 7️⃣ 추가 보안 팁

### A. 도메인 잠금 (Domain Lock)
- 무단 이전 방지
- 등록업체에서 설정 가능

### B. 2단계 인증
- 도메인 계정에 2FA 활성화
- 도메인 탈취 방지

### C. 자동 갱신 설정
- 도메인 만료로 인한 손실 방지
- 신용카드/자동이체 설정

### D. 도메인 감시 서비스
- 무단 변경 감지
- 알림 설정

---

## 8️⃣ 비용 예상

### 한국 업체
- **가비아**: 연 11,000원 ~ 무료
- **카페24**: 연 10,000원 ~ 무료
- **호스팅케이알**: 연 15,000원

### 해외 업체
- **Namecheap**: 무료 (WhoisGuard 포함)
- **Cloudflare**: 무료 (자동 포함)
- **GoDaddy**: 연 $9.99

---

## 9️⃣ 현재 mynolab.kr 상태 확인

터미널에서 확인하세요:

```bash
# 현재 WHOIS 정보 확인
whois mynolab.kr

# 네임서버 확인
dig mynolab.kr NS

# 등록 정보 확인
whois mynolab.kr | grep -i "registrant"
```

---

## 🚨 긴급: 이미 정보가 노출되었다면?

### 1. 즉시 WHOIS 보호 활성화
### 2. 노출된 이메일 변경
```bash
# 스팸 방지 임시 이메일 사용
- 10minutemail.com
- temp-mail.org
```
### 3. 전화번호 변경 (가능하다면)
### 4. 스팸 필터 강화

---

## ✅ 체크리스트

- [ ] 도메인 등록업체 로그인
- [ ] WHOIS 보호 서비스 확인
- [ ] WHOIS 보호 활성화
- [ ] 도메인 잠금 설정
- [ ] 2단계 인증 설정
- [ ] 자동 갱신 설정
- [ ] 24시간 후 WHOIS 정보 재확인

---

## 📞 도움이 필요하면?

각 등록업체 고객센터:
- **가비아**: 1544-4755
- **카페24**: 1544-6789
- **호스팅케이알**: 1544-2233

---

## 🎯 권장 사항

### 최선의 선택:
1. **Cloudflare로 도메인 이전** (무료 WHOIS 보호)
2. **현재 업체에서 WHOIS 보호 활성화**
3. **도메인 잠금 + 2FA 설정**

### 즉시 실행:
```bash
# 1. 현재 상태 확인
whois mynolab.kr > whois_before.txt

# 2. WHOIS 보호 활성화 (업체 사이트에서)

# 3. 24시간 후 재확인
whois mynolab.kr > whois_after.txt

# 4. 변경사항 비교
diff whois_before.txt whois_after.txt
```

---

**개인정보 보호는 필수입니다!** 🛡️
**지금 바로 WHOIS 가드를 설정하세요!**

