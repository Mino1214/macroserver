## ✅ 로그인 만료 체크 제거 완료

### 변경 사항:

**이전 동작:**
- 로그인 시 만료일 체크
- 만료되면 로그인 차단: `사용기간이 만료되었습니다.`

**현재 동작:**
- 로그인 시 만료일 **체크 안 함**
- 만료되어도 로그인 허용
- 만료 정보만 리턴

### API 응답 구조:

```json
{
  "token": "abc123...",
  "kicked": false,
  "status": "approved",
  "expireDate": "2026-03-10T00:00:00.000Z",
  "remainingDays": 5,           // 양수 = 남음, 음수 = 만료됨
  "isExpired": false            // true = 만료, false = 유효
}
```

### 로그인 체크 항목:

✅ **아이디/비밀번호** - 틀리면 로그인 실패
✅ **승인 상태 (pending)** - 대기 중이면 로그인 차단
✅ **정지 상태 (suspended)** - 정지되면 로그인 차단
❌ **만료일 체크** - 제거됨 (정보만 제공)

### 클라이언트에서 사용 예시:

```javascript
// 로그인 응답 받기
const response = await login(id, password);

// 만료 여부 확인 (차단은 안 됨)
if (response.isExpired) {
  console.warn('사용기간이 만료되었습니다.');
  // 경고 메시지만 표시하고 계속 사용 가능
}

if (response.remainingDays < 0) {
  console.log(`${Math.abs(response.remainingDays)}일 만료됨`);
} else {
  console.log(`${response.remainingDays}일 남음`);
}

// 로그인은 성공적으로 완료됨
const token = response.token;
```

### 테스트:

1. 만료된 계정으로 로그인 시도
2. **로그인 성공** (차단 안 됨)
3. 응답에서 `isExpired: true`, `remainingDays: -X` 확인
4. 클라이언트에서 만료 여부를 자유롭게 처리 가능

---

**Status: ✅ 적용 완료 (서버 재시작됨)**
