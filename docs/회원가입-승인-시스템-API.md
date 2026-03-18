# 🎯 회원가입 및 승인 시스템 API 문서

## ✅ 완료된 변경사항

### 1. DB 스키마 수정
```sql
ALTER TABLE users 
ADD COLUMN status ENUM('pending', 'approved', 'suspended') DEFAULT 'pending',
ADD COLUMN expire_date DATETIME DEFAULT NULL,
ADD COLUMN subscription_days INT DEFAULT 0;
```

---

## 📝 새로운 API 목록

### 1️⃣ 회원가입 API

**POST** `/api/register`

**Request Body:**
```json
{
  "id": "사용자아이디",
  "password": "비밀번호",
  "referralCode": "매니저아이디",  // 추천인 코드 (필수)
  "telegram": "@텔레그램"  // 선택
}
```

**Response (성공):**
```json
{
  "success": true,
  "message": "회원가입이 완료되었습니다. 관리자 승인을 기다려주세요.",
  "managerId": "qazwsx"
}
```

**Response (에러):**
```json
{
  "error": "유효하지 않은 추천인 코드입니다."
}
```

---

### 2️⃣ 로그인 API (수정됨)

**POST** `/api/login`

**Request Body:**
```json
{
  "id": "user1",
  "password": "1234"
}
```

**Response (성공 - 승인됨):**
```json
{
  "token": "abc123...",
  "kicked": false,
  "expireDate": "2026-06-18T12:00:00.000Z",
  "remainingDays": 120,
  "status": "approved"
}
```

**Response (승인 대기):**
```json
{
  "error": "관리자 승인 대기 중입니다."
}
```

**Response (사용기간 만료):**
```json
{
  "error": "사용기간이 만료되었습니다. 관리자에게 문의하세요."
}
```

**Response (정지됨):**
```json
{
  "error": "계정이 정지되었습니다. 관리자에게 문의하세요."
}
```

---

## 🔐 관리자 API (새로 추가됨)

### 3️⃣ 승인 대기 목록 조회

**GET** `/api/admin/pending-users`

**Headers:**
```
Authorization: Bearer {adminToken}
```

**Response:**
```json
[
  {
    "id": "user123",
    "managerId": "qazwsx",
    "telegram": "@user123",
    "createdAt": "2026-02-18T12:00:00.000Z"
  }
]
```

---

### 4️⃣ 사용자 승인

**POST** `/api/admin/approve-user`

**Headers:**
```
Authorization: Bearer {adminToken}
```

**Request Body:**
```json
{
  "userId": "user123"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "사용자가 승인되었습니다."
}
```

---

### 5️⃣ 사용자 거부 (삭제)

**POST** `/api/admin/reject-user`

**Headers:**
```
Authorization: Bearer {adminToken}
```

**Request Body:**
```json
{
  "userId": "user123"
}
```

**Response:**
```json
{
  "ok": true,
  "message": "사용자가 거부되었습니다."
}
```

---

### 6️⃣ 사용기간 설정

**POST** `/api/admin/set-subscription`

**Headers:**
```
Authorization: Bearer {adminToken}
```

**Request Body:**
```json
{
  "userId": "user123",
  "days": 30  // 30, 90, 180, 365만 가능
}
```

**Response:**
```json
{
  "ok": true,
  "message": "사용기간이 30일로 설정되었습니다."
}
```

**참고:** 사용기간은 현재 시간부터 계산됩니다.

---

### 7️⃣ 사용자 정지/활성화

**POST** `/api/admin/suspend-user`

**Headers:**
```
Authorization: Bearer {adminToken}
```

**Request Body:**
```json
{
  "userId": "user123",
  "suspend": true  // true: 정지, false: 활성화
}
```

**Response:**
```json
{
  "ok": true,
  "message": "사용자가 정지되었습니다."
}
```

---

### 8️⃣ 사용자 생성 (마스터 전용)

**POST** `/api/admin/users`

**Headers:**
```
Authorization: Bearer {masterToken}
```

**Request Body:**
```json
{
  "id": "user123",
  "password": "1234",
  "managerId": "qazwsx",
  "telegram": "@user123"
}
```

**Response:**
```json
{
  "ok": true
}
```

**참고:** 
- 매니저는 더 이상 직접 생성 불가
- 마스터만 직접 생성 가능 (자동 승인됨)

---

## 📊 사용자 상태 (status)

| 상태 | 설명 |
|------|------|
| `pending` | 승인 대기 중 (로그인 불가) |
| `approved` | 승인됨 (로그인 가능) |
| `suspended` | 정지됨 (로그인 불가) |

---

## 🔄 회원가입 프로세스

```
1. 사용자가 /api/register 호출
   ├─ 추천인 코드(매니저 아이디) 필수
   └─ status = 'pending'으로 저장

2. 매니저가 /api/admin/pending-users에서 확인

3. 매니저가 승인 또는 거부
   ├─ 승인: /api/admin/approve-user
   │   └─ status = 'approved'로 변경
   └─ 거부: /api/admin/reject-user
       └─ DB에서 삭제

4. 매니저가 사용기간 설정
   └─ /api/admin/set-subscription (30/90/180/365일)

5. 사용자 로그인 가능
   ├─ 승인 상태 확인
   ├─ 사용기간 확인
   └─ 로그인 성공 시 남은 일수 반환
```

---

## 🎯 로그인 검증 로직

```javascript
1. 아이디/비밀번호 확인
2. status가 'pending'이면 → 승인 대기 메시지
3. status가 'suspended'이면 → 정지 메시지
4. expire_date 확인
   ├─ 만료되었으면 → 만료 메시지
   └─ 유효하면 → 로그인 성공 + 남은 일수 반환
```

---

## 🧪 테스트

### 회원가입 테스트
```bash
curl -X POST https://nexus001.vip/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "id": "testuser",
    "password": "test1234",
    "referralCode": "qazwsx",
    "telegram": "@testuser"
  }'
```

### 승인 대기 목록 조회
```bash
curl -X GET https://nexus001.vip/api/admin/pending-users \
  -H "Authorization: Bearer {adminToken}"
```

### 사용자 승인
```bash
curl -X POST https://nexus001.vip/api/admin/approve-user \
  -H "Authorization: Bearer {adminToken}" \
  -H "Content-Type: application/json" \
  -d '{"userId": "testuser"}'
```

### 사용기간 설정
```bash
curl -X POST https://nexus001.vip/api/admin/set-subscription \
  -H "Authorization: Bearer {adminToken}" \
  -H "Content-Type: application/json" \
  -d '{"userId": "testuser", "days": 30}'
```

### 로그인 테스트
```bash
curl -X POST https://nexus001.vip/api/login \
  -H "Content-Type: application/json" \
  -d '{"id": "testuser", "password": "test1234"}'
```

---

## 📝 주요 변경사항 요약

### ✅ 변경된 기능
1. **회원가입 시스템 추가** - 추천인 코드 필수
2. **승인 시스템 추가** - 매니저가 승인/거부
3. **사용기간 관리** - 30/90/180/365일 설정
4. **로그인 검증 강화** - 상태 및 만료일 확인
5. **매니저 권한 변경** - 직접 생성 불가, 승인만 가능

### ❌ 제거된 기능
- 매니저의 사용자 직접 생성 (마스터만 가능)

### ➕ 추가된 기능
- 회원가입 API
- 승인 대기 목록 API
- 승인/거부 API
- 사용기간 설정 API
- 사용자 정지/활성화 API

---

## 🎉 완료!

모든 API가 정상 작동합니다. 이제 `admin.html` UI를 수정해야 합니다!

