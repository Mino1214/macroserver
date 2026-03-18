# 로그인 페이지 전환 안되는 문제 디버깅 가이드

## 현재 상황
로그인은 되지만 대시보드 페이지로 전환이 안 되는 문제

## 디버깅을 위해 추가된 로그

### 1. 브라우저 개발자 도구 열기
```
F12 키 누르기
또는
우클릭 → 검사
```

### 2. Console 탭 확인
다음과 같은 로그가 나타나야 합니다:

```
[LOGIN] Starting login... {id: "master666"}
[LOGIN] Calling API...
[LOGIN] API response: {role: "master", id: "master666", token: "..."}
[LOGIN] Token saved, calling showDashboard...
[DASHBOARD] Showing dashboard...
[DASHBOARD] me: {role: "master", id: "master666", token: "..."}
[DASHBOARD] Display changed
[DASHBOARD] Sections toggled
[DASHBOARD] Text content updated
[DASHBOARD] Loading all data...
[LOADALL] Starting to load all data...
[LOADALL] All data loaded successfully
[LOGIN] Login complete!
```

## 가능한 문제들

### 문제 1: API 응답 오류
만약 다음과 같은 에러가 보인다면:
```
[LOGIN] Error: ...
```

**해결방법**:
- 서버가 실행 중인지 확인
- 아이디/비밀번호 확인

### 문제 2: JavaScript 오류
만약 다음과 같은 오류가 보인다면:
```
TypeError: Cannot read property 'style' of null
Uncaught ReferenceError: me is not defined
```

**해결방법**:
- 강력 새로고침 (Ctrl + Shift + R)
- 캐시 완전 삭제

### 문제 3: CSS 문제
대시보드가 보이지만 숨겨져 있을 수 있음

**콘솔에서 확인**:
```javascript
// 로그인 박스 상태
console.log(document.getElementById('loginBox').style.display);
// 대시보드 상태
console.log(document.getElementById('dashboard').style.display);
```

**수동으로 표시**:
```javascript
document.getElementById('loginBox').style.display = 'none';
document.getElementById('dashboard').style.display = 'block';
```

### 문제 4: loadAll() 오류
만약 loadAll에서 멈춘다면:

**콘솔에서 확인**:
```
[LOADALL] Error loading data: ...
```

## 수동 테스트 방법

### 1. 콘솔에서 직접 로그인
```javascript
// F12 → Console에서 실행
async function testLogin() {
  try {
    const response = await fetch('/api/admin/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 'master666', password: 'master666' })
    });
    const data = await response.json();
    console.log('Response:', data);
    
    // 토큰 저장
    localStorage.setItem('adminToken', data.token);
    
    // 페이지 새로고침
    location.reload();
  } catch (error) {
    console.error('Error:', error);
  }
}

testLogin();
```

### 2. 페이지 새로고침
토큰이 저장되어 있으면 자동으로 대시보드가 표시되어야 합니다.

### 3. 로컬 스토리지 확인
```javascript
// 토큰 확인
console.log('Token:', localStorage.getItem('adminToken'));

// 토큰 삭제
localStorage.removeItem('adminToken');

// 모두 삭제
localStorage.clear();
```

## 빠른 해결 방법

### 방법 1: 시크릿 모드
```
1. 시크릿/프라이빗 창 열기
2. https://nexus001.vip/admin.html 접속
3. 로그인 시도
```

### 방법 2: 캐시 삭제
```
1. F12 → Application 탭
2. Storage → Local Storage
3. https://nexus001.vip 우클릭 → Clear
4. 페이지 새로고침
```

### 방법 3: 다른 브라우저
```
Chrome에서 안 되면 Firefox, Edge 등 다른 브라우저 시도
```

## 서버 로그 확인

```bash
# 최근 로그 확인
pm2 logs mynolab-server --lines 50

# 실시간 로그
pm2 logs mynolab-server
```

## 완전한 테스트 페이지

`https://nexus001.vip/test-login.html`에서:
1. "Test Login" 버튼 클릭
2. 응답 확인
3. 성공하면 토큰이 표시됨

## 긴급 수정 (콘솔에서 실행)

만약 로그인 후 페이지가 안 바뀐다면:

```javascript
// 강제로 대시보드 표시
document.getElementById('loginBox').style.display = 'none';
document.getElementById('dashboard').style.display = 'block';
```

## 보고해야 할 정보

문제가 지속되면 다음 정보를 알려주세요:

1. **브라우저 콘솔 로그** (F12 → Console 탭 전체 내용)
2. **네트워크 로그** (F12 → Network 탭 → /api/admin/login 요청 확인)
3. **로컬 스토리지** (F12 → Application → Local Storage)
4. **에러 메시지** (빨간색으로 표시되는 모든 에러)

## 다음 단계

1. **F12 열기**
2. **Console 탭으로 이동**
3. **로그인 시도**
4. **나타나는 모든 로그 확인**
5. **에러가 있다면 캡처 또는 복사**

이 정보를 통해 정확한 문제를 파악할 수 있습니다!

*작성: 2026-02-19 02:30*

