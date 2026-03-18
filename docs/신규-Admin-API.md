# ✅ 새로 추가된 Admin API 목록

## 📋 개요
관리자 페이지 업데이트에 맞춰 새로운 API 엔드포인트가 추가되었습니다.

---

## 🆕 추가된 API 엔드포인트

### 1. 승인 대기 목록 조회
```http
GET /api/admin/pending-users
```

**인증**: 필요 (관리자 토큰)

**권한**:
- 마스터: 전체 대기 목록 조회
- 매니저: 자기 소속 대기 목록만 조회

**응답**:
```json
[
  {
    "id": "testuser",
    "managerId": "qazwsx",
    "telegram": "@testuser",
    "status": "pending",
    "createdAt": "2024-02-18T10:00:00.000Z"
  }
]
```

---

### 2. 사용자 승인
```http
POST /api/admin/approve-user
```

**인증**: 필요 (관리자 토큰)

**권한**:
- 마스터: 모든 사용자 승인 가능
- 매니저: 자기 소속만 승인 가능

**요청 Body**:
```json
{
  "userId": "testuser"
}
```

**응답**:
```json
{
  "success": true
}
```

**에러**:
- `400`: userId 필요
- `403`: 권한 없음 (다른 매니저 소속)
- `404`: 사용자를 찾을 수 없음
- `500`: 서버 오류

---

### 3. 사용자 거부 (삭제)
```http
POST /api/admin/reject-user
```

**인증**: 필요 (관리자 토큰)

**권한**:
- 마스터: 모든 사용자 거부 가능
- 매니저: 자기 소속만 거부 가능

**요청 Body**:
```json
{
  "userId": "testuser"
}
```

**응답**:
```json
{
  "success": true
}
```

**동작**:
- 사용자를 DB에서 완전히 삭제
- 되돌릴 수 없으므로 주의!

---

### 4. 사용기간 설정
```http
POST /api/admin/set-subscription
```

**인증**: 필요 (관리자 토큰)

**권한**:
- 마스터: 모든 사용자 설정 가능
- 매니저: 자기 소속만 설정 가능

**요청 Body**:
```json
{
  "userId": "testuser",
  "days": 30
}
```

**days 값**: `30`, `90`, `180`, `365` 중 하나

**응답**:
```json
{
  "success": true
}
```

**동작**:
- 현재 시각부터 지정된 일수만큼 사용기간 설정
- `expire_date`와 `subscription_days` 업데이트
- 상태가 자동으로 `approved`로 변경

**에러**:
- `400`: 올바른 일수를 선택하세요 (30, 90, 180, 365)
- `403`: 권한 없음
- `404`: 사용자를 찾을 수 없음

---

### 5. 사용자 정지/활성화
```http
POST /api/admin/suspend-user
```

**인증**: 필요 (관리자 토큰)

**권한**:
- 마스터: 모든 사용자 정지/활성화 가능
- 매니저: 자기 소속만 정지/활성화 가능

**요청 Body**:
```json
{
  "userId": "testuser",
  "suspend": true
}
```

**suspend 값**:
- `true`: 정지 (status → `suspended`)
- `false`: 활성화 (status → `approved`)

**응답**:
```json
{
  "success": true
}
```

**동작**:
- 정지 시: 사용자 상태를 `suspended`로 변경 + 세션 강제 종료
- 활성화 시: 사용자 상태를 `approved`로 변경

---

## 🔐 인증 방법

모든 API는 관리자 인증이 필요합니다.

### Cookie 방식
```http
Cookie: adminToken=YOUR_ADMIN_TOKEN
```

### Header 방식
```http
Authorization: Bearer YOUR_ADMIN_TOKEN
```

---

## 📊 사용 흐름

### 1. 신규 사용자 가입 → 승인
```
1. 사용자가 POST /api/register로 가입 (status: pending)
   ↓
2. 관리자가 GET /api/admin/pending-users로 대기 목록 확인
   ↓
3. 관리자가 POST /api/admin/approve-user로 승인 (status: approved)
   ↓
4. 관리자가 POST /api/admin/set-subscription으로 사용기간 설정
   ↓
5. 사용자 로그인 가능!
```

### 2. 신규 사용자 가입 → 거부
```
1. 사용자가 POST /api/register로 가입 (status: pending)
   ↓
2. 관리자가 GET /api/admin/pending-users로 대기 목록 확인
   ↓
3. 관리자가 POST /api/admin/reject-user로 거부 (삭제됨)
```

### 3. 기존 사용자 정지
```
1. 관리자가 POST /api/admin/suspend-user (suspend: true)
   ↓
2. 사용자 상태가 suspended로 변경
   ↓
3. 기존 세션 강제 종료
   ↓
4. 로그인 시도 시 "계정이 정지되었습니다" 에러
```

---

## 🧪 테스트 예시

### curl 테스트

#### 1. 승인 대기 목록 조회
```bash
curl -X GET http://localhost:3000/api/admin/pending-users \
  -H "Cookie: adminToken=YOUR_TOKEN"
```

#### 2. 사용자 승인
```bash
curl -X POST http://localhost:3000/api/admin/approve-user \
  -H "Content-Type: application/json" \
  -H "Cookie: adminToken=YOUR_TOKEN" \
  -d '{"userId":"testuser"}'
```

#### 3. 사용기간 설정 (30일)
```bash
curl -X POST http://localhost:3000/api/admin/set-subscription \
  -H "Content-Type: application/json" \
  -H "Cookie: adminToken=YOUR_TOKEN" \
  -d '{"userId":"testuser","days":30}'
```

#### 4. 사용자 정지
```bash
curl -X POST http://localhost:3000/api/admin/suspend-user \
  -H "Content-Type: application/json" \
  -H "Cookie: adminToken=YOUR_TOKEN" \
  -d '{"userId":"testuser","suspend":true}'
```

#### 5. 사용자 활성화
```bash
curl -X POST http://localhost:3000/api/admin/suspend-user \
  -H "Content-Type: application/json" \
  -H "Cookie: adminToken=YOUR_TOKEN" \
  -d '{"userId":"testuser","suspend":false}'
```

---

## 📝 DB 변경사항

### users 테이블
```sql
-- status 컬럼
status ENUM('pending', 'approved', 'suspended')

-- pending: 승인 대기
-- approved: 승인됨 (로그인 가능)
-- suspended: 정지됨 (로그인 불가)

-- 사용기간 컬럼
expire_date DATETIME          -- 만료일
subscription_days INT         -- 구독 일수 (30, 90, 180, 365)
```

---

## ✅ 완료!

모든 API가 정상적으로 추가되었습니다! 🚀

이제 관리자 페이지에서:
1. ✅ 승인 대기 목록 조회
2. ✅ 사용자 승인/거부
3. ✅ 사용기간 설정
4. ✅ 사용자 정지/활성화

모든 기능을 사용할 수 있습니다!

---

*최종 업데이트: 2024-02-18*
*작성: Myno Lab*

