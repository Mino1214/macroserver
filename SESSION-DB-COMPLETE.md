# 세션 관리 DB 기반으로 완전 전환 완료

## 문제점

클라이언트가 주기적으로 `/api/session/validate`를 호출하는데, 세션 검증이 제대로 동작하지 않았습니다.

### 원인
- `sessionStore`가 메모리 기반 (Map)으로 구현되어 있었음
- 서버 재시작 시 모든 세션이 소실됨
- DB에는 세션이 저장되어 있지만, 실제 검증은 메모리에서만 수행
- `sessionStore`와 `db.sessionDB`가 혼용되어 일관성 부족

## 해결 방법

### 1. `sessionStore`를 완전히 DB 기반으로 재작성

#### 변경 전 (메모리 기반)
```javascript
const sessionStore = {
  tokenToUser: new Map(),
  userToToken: new Map(),
  
  login(userId, newToken) {
    // Map에 저장
  },
  
  isValid(token) {
    // Map에서 조회
  }
};
```

#### 변경 후 (DB 기반)
```javascript
const sessionStore = {
  async save(userId, newToken) {
    // sessions 테이블에 저장
    await db.pool.query(
      'INSERT INTO sessions (user_id, token, last_activity) VALUES (?, ?, NOW())',
      [userId, newToken]
    );
  },
  
  async isValid(token) {
    // DB에서 조회 및 검증
    const [rows] = await db.pool.query(
      'SELECT user_id, last_activity, kicked FROM sessions WHERE token = ?',
      [token]
    );
    
    // kicked 확인
    if (session.kicked) return false;
    
    // 타임아웃 확인 (24시간)
    if (now - lastActivity > SESSION_TIMEOUT) {
      await this.remove(session.user_id);
      return false;
    }
    
    // 슬라이딩 세션: 활동 시간 갱신
    await db.pool.query(
      'UPDATE sessions SET last_activity = NOW() WHERE token = ?',
      [token]
    );
    
    return true;
  }
};
```

### 2. 주요 메서드

#### `save(userId, token)`
- 기존 세션 삭제 후 새 세션 저장
- `last_activity`를 현재 시각으로 설정
- 중복 로그인 시 이전 세션 제거

#### `isValid(token)`
- DB에서 토큰 조회
- `kicked` 상태 확인
- 24시간 타임아웃 확인
- 유효하면 `last_activity` 갱신 (슬라이딩)
- 만료되면 세션 삭제

#### `getUserId(token)`
- DB에서 토큰으로 사용자 ID 조회
- 타임아웃 확인 및 슬라이딩
- `kicked=FALSE` 조건

#### `kickUser(userId)`
- `kicked=TRUE`로 업데이트
- 강제 로그아웃 처리

#### `getAll()`
- 모든 활성 세션 조회
- 만료된 세션 자동 삭제

### 3. API 업데이트

#### `/api/login`
```javascript
// 변경 전
await db.sessionDB.save(id.trim(), token);

// 변경 후
const kicked = await sessionStore.save(id.trim(), token);
return res.json({ token, kicked, ... });
```

#### `/api/session/validate`
```javascript
// 변경 전
app.get('/api/session/validate', (req, res) => {
  if (sessionStore.isValid(token)) return res.json({ ok: true });
  res.status(401).json({ error: 'kicked' });
});

// 변경 후
app.get('/api/session/validate', async (req, res) => {
  const isValid = await sessionStore.isValid(token);
  if (isValid) return res.json({ ok: true });
  res.status(401).json({ error: 'kicked' });
});
```

#### `/api/admin/kick`
```javascript
// 변경 후
await sessionStore.kickUser(userId);
```

#### `/api/admin/sessions`
```javascript
// 변경 후
let list = await sessionStore.getAll();
```

#### `/api/admin/suspend-user`
```javascript
// 변경 후
if (suspend) {
  await sessionStore.kickUser(userId.trim());
}
```

#### `DELETE /api/admin/users/:id`
```javascript
// 변경 후
await sessionStore.kickUser(userId);
```

## 장점

### 1. 서버 재시작 시에도 세션 유지
- DB에 저장되므로 서버가 재시작되어도 사용자는 계속 로그인 상태 유지

### 2. 슬라이딩 세션
- 검증/조회 시마다 `last_activity` 갱신
- 활동 중인 사용자는 자동으로 세션 연장 (24시간)

### 3. 강제 로그아웃 (kick)
- `kicked=TRUE`로 설정하면 즉시 로그인 불가
- 관리자가 사용자 강제 종료 가능

### 4. 자동 만료 처리
- 24시간 동안 활동 없으면 자동 만료
- `getAll()` 호출 시 만료된 세션 자동 삭제

### 5. 일관성
- 모든 세션 관련 로직이 `sessionStore`로 통일
- `db.sessionDB`와 혼용하지 않음

## DB 스키마

### sessions 테이블
```sql
CREATE TABLE sessions (
  user_id VARCHAR(50) PRIMARY KEY,
  token VARCHAR(64) NOT NULL,
  last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
  kicked BOOLEAN DEFAULT FALSE,
  INDEX (token),
  INDEX (kicked),
  INDEX (last_activity)
);
```

## 클라이언트 동작

### 주기적 검증
```javascript
setInterval(async () => {
  const response = await fetch('/api/session/validate?token=' + myToken);
  
  if (!response.ok) {
    // 세션 만료 또는 kicked
    // 로그아웃 처리
  } else {
    // 세션 유효
    // last_activity 자동 갱신됨 (슬라이딩)
  }
}, 60000); // 1분마다
```

### 로그인 응답
```json
{
  "token": "a1b2c3d4...",
  "kicked": false,
  "status": "approved",
  "expireDate": "2025-03-18T10:00:00.000Z",
  "remainingDays": 30
}
```

- `kicked: true` → 기존 세션이 강제 종료됨
- `kicked: false` → 새로운 로그인 또는 기존 세션 없음

## 테스트 시나리오

### 1. 정상 로그인 및 검증
```bash
# 로그인
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"id":"testuser","password":"testpass"}'

# 응답: { "token": "abc123...", "kicked": false }

# 세션 검증
curl http://localhost:3000/api/session/validate?token=abc123...

# 응답: { "ok": true }
```

### 2. 강제 로그아웃 (kick)
```bash
# 관리자가 kick
curl -X POST http://localhost:3000/api/admin/kick \
  -H "Cookie: adminToken=ADMIN_TOKEN" \
  -d '{"userId":"testuser"}'

# 세션 검증 (kicked=TRUE 상태)
curl http://localhost:3000/api/session/validate?token=abc123...

# 응답: 401 { "error": "kicked" }
```

### 3. 24시간 후 자동 만료
```bash
# 24시간 동안 활동 없음
# 세션 검증
curl http://localhost:3000/api/session/validate?token=abc123...

# 응답: 401 { "error": "kicked" }
# DB에서 세션 자동 삭제됨
```

### 4. 슬라이딩 세션
```bash
# 23시간 50분 후 검증 (만료 10분 전)
curl http://localhost:3000/api/session/validate?token=abc123...

# 응답: { "ok": true }
# last_activity 갱신됨 → 24시간 연장

# 다시 23시간 50분 후 검증 (계속 활동 중)
curl http://localhost:3000/api/session/validate?token=abc123...

# 응답: { "ok": true }
# 계속 연장됨
```

## 완료!

이제 세션 관리가 완전히 DB 기반으로 전환되어:
- ✅ 서버 재시작 시에도 세션 유지
- ✅ 슬라이딩 세션으로 자동 연장
- ✅ 강제 로그아웃 (kick) 지원
- ✅ 24시간 자동 만료
- ✅ 일관성 있는 세션 관리

클라이언트가 주기적으로 검증하면 계속 로그인 상태가 유지됩니다! 🎉

*최종 수정: 2026-02-18 16:50*
*작성: Myno Lab*

