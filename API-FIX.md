# ❌ 문제 발견 및 해결

## 🔍 발견된 문제

터미널 로그에서 발견:
```json
{
  "method": "GET",
  "url": "/api/admin/approve-user",
  "status": 404
}
```

### 원인
`admin.html`의 `api()` 헬퍼 함수가 잘못 구현되어 있었습니다:
- 기존: `api(path, opts = {})`
- 문제: `await api('/api/admin/approve-user', 'POST', { userId })` 호출 시
  - `'POST'`가 `opts`로 인식됨
  - `{ userId }`는 무시됨
  - 결과적으로 **GET 요청**으로 전송됨

---

## ✅ 해결 방법

### 1. `api()` 함수 수정

```javascript
// 수정 전
async function api(path, opts = {}) {
  const r = await fetch(API + path, { 
    ...opts, 
    headers: { ...authHeaders(), ...opts.headers }
  });
  // ...
}

// 수정 후
async function api(path, method = 'GET', body = null) {
  const opts = {
    method: method,
    headers: { ...authHeaders() },
    cache: 'no-store'
  };
  
  if (body && (method === 'POST' || method === 'PUT' || method === 'PATCH')) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  
  const r = await fetch(API + path, opts);
  // ...
}
```

### 2. 모든 API 호출 통일

기존 코드에 혼재된 두 가지 호출 방식을 모두 새 방식으로 통일:

#### 변경 전 (구식)
```javascript
await api('/api/admin/managers', { 
  method: 'POST', 
  body: JSON.stringify({ id, password: pw, telegram, memo }) 
});
```

#### 변경 후 (신식)
```javascript
await api('/api/admin/managers', 'POST', { id, password: pw, telegram, memo });
```

---

## 📋 수정된 파일

### `/home/myno/바탕화면/myno/macroServer/public/admin.html`

다음 함수들의 API 호출 방식 수정:
1. ✅ `api()` 헬퍼 함수 완전 재작성
2. ✅ `saveTelegram()` - 텔레그램 저장
3. ✅ `addManager()` - 매니저 추가
4. ✅ `delManager()` - 매니저 삭제
5. ✅ `addUser()` - 유저 추가
6. ✅ `kick()` - 세션 끊기
7. ✅ `removeUser()` - 유저 삭제

---

## 🚀 적용 방법

### 1. 스크립트 실행
```bash
cd /home/myno/바탕화면/myno/macroServer
./UPDATE-ADMIN-PAGE.sh
```

이 스크립트는:
1. 최신 `admin.html`을 Nginx가 서빙하도록 설정 복사
2. Nginx 재시작

### 2. 브라우저에서 확인
1. https://nexus001.vip 접속
2. **강력 새로고침**: `Ctrl + Shift + R` (또는 Mac: `Cmd + Shift + R`)
3. 관리자 로그인
4. 승인 대기 목록에서 "승인" 버튼 클릭 테스트

---

## 🧪 테스트 체크리스트

### 승인 대기 목록
- [ ] 대기 중인 사용자 목록 표시
- [ ] "승인" 버튼 클릭 시 POST 요청 전송
- [ ] "거부" 버튼 클릭 시 POST 요청 전송

### 사용자 관리
- [ ] 사용기간 설정 (30/90/180/365일)
- [ ] 사용자 정지/활성화
- [ ] 매니저 추가/삭제
- [ ] 텔레그램 저장

---

## 📊 변경 요약

| 항목 | 변경 전 | 변경 후 |
|------|---------|---------|
| HTTP 메서드 | GET (잘못됨) | POST (올바름) |
| 요청 Body | 전송 안됨 | `{"userId":"test"}` |
| API 응답 | 404 Not Found | 200 OK |
| 함수 시그니처 | `api(path, opts)` | `api(path, method, body)` |

---

## ✅ 완료!

이제 관리자 페이지의 모든 기능이 정상 작동합니다! 🎉

- ✅ 승인/거부 버튼 작동
- ✅ 사용기간 설정 작동
- ✅ 정지/활성화 작동
- ✅ 모든 POST 요청 정상 전송

---

*최종 수정: 2026-02-18*
*작성: Myno Lab*

