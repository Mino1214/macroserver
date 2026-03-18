# 로그인 문제 해결

## 문제
`master666/master666` 계정으로 로그인이 안 되는 문제

## 원인
`api()` 함수의 에러 처리 로직에 문제가 있었습니다:
```javascript
// 문제가 있던 코드
return r.ok ? r.json() : Promise.reject(await r.text());
```

이 코드는 에러를 단순 문자열로 reject하는데, `login()` 함수에서는 `err.message`를 기대했습니다.

## 해결 방법

### 1. `api()` 함수 개선
```javascript
if (!r.ok) {
  let errorMsg = '요청 실패';
  try {
    const errorText = await r.text();
    const errorJson = JSON.parse(errorText);
    errorMsg = errorJson.error || errorText;
  } catch (e) {
    errorMsg = await r.text() || `서버 오류 (${r.status})`;
  }
  throw new Error(errorMsg);  // Error 객체로 throw
}

return r.json();
```

### 2. `login()` 함수 개선
```javascript
async function login(e) {
  e.preventDefault();
  const id = document.getElementById('loginId').value.trim();
  const password = document.getElementById('loginPw').value.trim();
  const errorEl = document.getElementById('loginError');
  
  errorEl.textContent = '';  // 이전 에러 초기화
  errorEl.className = 'text-muted';
  
  try {
    const data = await api('/api/admin/login', 'POST', { id, password });
    adminToken = data.token;
    localStorage.setItem('adminToken', adminToken);
    me = data;
    showDashboard();
  } catch (err) {
    console.error('Login error:', err);  // 디버깅용 로그
    errorEl.textContent = err.message || '로그인 실패';
    errorEl.className = 'error';  // 빨간색 표시
  }
}
```

## 테스트 방법

### 1. 브라우저에서 테스트
```
https://nexus001.vip/admin.html
```

아이디: `master666`
비밀번호: `master666`

### 2. API 직접 테스트
```bash
curl -X POST http://localhost:3000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"id":"master666","password":"master666"}'
```

### 3. 테스트 페이지 사용
```
https://nexus001.vip/test-login.html
```

"Test Login" 버튼 클릭

## 확인 사항

### API가 정상 작동함
```bash
$ curl -X POST http://localhost:3000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"id":"master666","password":"master666"}'

{"role":"master","id":"master666","token":"ad445aef..."}
```

### 매니저 계정도 확인
```sql
mysql> SELECT id, role FROM managers;
+------------+--------+
| id         | role   |
+------------+--------+
| master666  | master |
| qazwsx     | manager|
+------------+--------+
```

## 캐시 문제 해결

만약 여전히 로그인이 안 된다면:

### 1. 강력 새로고침
```
Windows/Linux: Ctrl + Shift + F5
Mac: Cmd + Shift + R
```

### 2. 캐시 완전 삭제
```
1. 브라우저 설정
2. 개인정보 보호 → 쿠키 및 사이트 데이터
3. nexus001.vip 데이터 삭제
```

### 3. 시크릿 모드 테스트
```
새 시크릿 창에서 https://nexus001.vip/admin.html 접속
```

### 4. 로컬 스토리지 초기화
브라우저 개발자 도구 (F12) → Console:
```javascript
localStorage.clear();
location.reload();
```

## 브라우저 콘솔 확인

F12 → Console 탭에서 에러 확인:
```javascript
// 에러가 있다면 다음과 같이 표시됨
Login error: Error: 아이디 또는 비밀번호가 올바르지 않습니다.
```

## 문제 지속 시 디버깅

### 1. 네트워크 탭 확인
F12 → Network 탭:
- `/api/admin/login` 요청 확인
- Status: 200 OK인지 확인
- Response 내용 확인

### 2. 서버 로그 확인
```bash
pm2 logs mynolab-server --lines 50
```

### 3. 계정 확인
```bash
mysql -u mynolab_user -pmynolab2026 mynolab -e "SELECT * FROM managers WHERE id='master666';"
```

## 완료!

이제 로그인이 정상적으로 작동해야 합니다.

**강력 새로고침** (`Ctrl + Shift + R`)을 하고 다시 시도해보세요!

*수정 시간: 2026-02-19 02:20*

