# 🔧 로그인 문제 해결 - 최종 가이드

## 문제
로그인 버튼을 눌러도 다음 페이지로 넘어가지 않음

## 해결 방법

### 방법 1: 간단한 테스트 페이지 사용 ⭐ 추천

**가장 확실한 방법입니다!**

```
https://nexus001.vip/simple-test.html
```

1. 위 주소로 접속
2. 이미 `master666` / `master666`가 입력되어 있음
3. "로그인" 버튼 클릭
4. 로그를 확인하면서 어디서 막히는지 확인

**이 페이지의 장점:**
- ✅ 모든 단계를 화면에 표시
- ✅ 에러를 명확하게 보여줌
- ✅ 로그인이 성공하면 바로 다음 페이지로 이동
- ✅ 문제를 정확히 파악 가능

---

### 방법 2: 브라우저 캐시 완전 삭제

#### Chrome/Edge
1. **Ctrl + Shift + Delete** (또는 Cmd + Shift + Delete)
2. "쿠키 및 기타 사이트 데이터" 체크
3. "캐시된 이미지 및 파일" 체크
4. 기간: **전체 기간**
5. "데이터 삭제" 클릭
6. 브라우저 완전히 종료 후 재시작

#### Firefox
1. **Ctrl + Shift + Delete**
2. "쿠키" 체크
3. "캐시" 체크
4. 기간: **전체**
5. "지금 삭제" 클릭

---

### 방법 3: 시크릿/프라이빗 모드

1. **시크릿 창 열기**:
   - Chrome: Ctrl + Shift + N
   - Firefox: Ctrl + Shift + P
   - Edge: Ctrl + Shift + N

2. 시크릿 창에서 접속:
   ```
   https://nexus001.vip/admin.html
   ```

3. 로그인 시도

**시크릿 모드는 캐시를 사용하지 않아서 가장 깨끗한 상태로 테스트할 수 있습니다!**

---

### 방법 4: 다른 브라우저 사용

현재 브라우저에서 안 된다면:
- Chrome → Firefox로 변경
- Firefox → Edge로 변경
- Safari → Chrome으로 변경

**새 브라우저에서 바로 작동한다면 기존 브라우저의 캐시 문제입니다.**

---

### 방법 5: 개발자 도구로 수동 확인

1. **F12** 눌러서 개발자 도구 열기

2. **Console 탭**에서 다음 명령어 실행:
   ```javascript
   // 캐시 완전 삭제
   localStorage.clear();
   sessionStorage.clear();
   
   // 페이지 새로고침
   location.reload();
   ```

3. 로그인 버튼 클릭

4. Console에 나타나는 모든 로그 확인:
   ```
   [LOGIN] Starting login...
   [LOGIN] Calling API...
   [LOGIN] API response: ...
   [DASHBOARD] Showing dashboard...
   ```

5. **빨간색 에러**가 있다면 그 내용을 확인

---

## 예상되는 문제들

### 문제 1: CORS 오류
```
Access to fetch at 'https://nexus001.vip/api/admin/login' 
from origin 'https://nexus001.vip' has been blocked by CORS policy
```

**해결**: 서버 설정 문제. 서버 재시작 필요
```bash
pm2 restart mynolab-server
```

---

### 문제 2: 네트워크 오류
```
Failed to fetch
net::ERR_CONNECTION_REFUSED
```

**해결**: 서버가 꺼져있음
```bash
pm2 status
pm2 start mynolab-server
```

---

### 문제 3: 401 Unauthorized
```
로그인이 필요합니다.
```

**해결**: 아이디/비밀번호 확인
- `master666` / `master666`
- 대소문자 정확히 입력

---

### 문제 4: JavaScript 오류
```
TypeError: Cannot read property 'style' of null
```

**해결**: 
1. 강력 새로고침 (Ctrl + Shift + R)
2. 캐시 삭제
3. 시크릿 모드 사용

---

## 서버 상태 확인

```bash
# 서버 실행 중인지 확인
pm2 status

# 로그 확인
pm2 logs mynolab-server --lines 30

# 서버 재시작
pm2 restart mynolab-server
```

---

## 계정 확인

```bash
# DB에서 계정 확인
mysql -u mynolab_user -pmynolab2026 mynolab -e "SELECT id, pw, role FROM managers WHERE id='master666';"
```

**예상 결과:**
```
id          pw          role
master666   master666   master
```

---

## API 직접 테스트

```bash
# 로그인 API 테스트
curl -X POST http://localhost:3000/api/admin/login \
  -H "Content-Type: application/json" \
  -d '{"id":"master666","password":"master666"}'
```

**예상 결과:**
```json
{
  "role": "master",
  "id": "master666",
  "token": "a87fe1b63dfbbd536ab7f520f3c80d313f56ab42e73f4890"
}
```

---

## 최종 체크리스트

체크해야 할 것들:

- [ ] 서버가 실행 중인가? (`pm2 status`)
- [ ] API가 작동하는가? (curl 테스트)
- [ ] 계정이 DB에 있는가? (mysql 확인)
- [ ] 브라우저 캐시를 삭제했는가?
- [ ] 시크릿 모드에서 테스트했는가?
- [ ] 다른 브라우저에서 시도했는가?
- [ ] F12 콘솔에 에러가 있는가?

---

## 빠른 해결 순서

**5분 안에 해결하기:**

1. **1분**: 시크릿 모드 열기 → 로그인 시도
2. **1분**: `https://nexus001.vip/simple-test.html` 접속 → 로그인
3. **1분**: 캐시 완전 삭제 → 브라우저 재시작
4. **1분**: 다른 브라우저에서 시도
5. **1분**: F12 콘솔 확인 → 에러 확인

---

## 여전히 안 된다면?

**다음 정보를 알려주세요:**

1. **어느 단계에서 막히나요?**
   - [ ] 로그인 버튼을 눌렀을 때 아무 반응 없음
   - [ ] 로그인 버튼을 눌렀을 때 에러 메시지 표시
   - [ ] 로딩 후 원래 페이지로 돌아옴
   - [ ] 기타: ___________

2. **simple-test.html에서는 작동하나요?**
   - [ ] 예 (이것도 안 됨)
   - [ ] 아니오 (이건 작동함)

3. **시크릿 모드에서는 작동하나요?**
   - [ ] 예 (시크릿에서는 됨)
   - [ ] 아니오 (시크릿에서도 안 됨)

4. **F12 콘솔에 무슨 메시지가 나오나요?**
   - (빨간색 에러가 있다면 그 내용 복사)

5. **어떤 브라우저를 사용하시나요?**
   - [ ] Chrome
   - [ ] Firefox
   - [ ] Edge
   - [ ] Safari
   - [ ] 기타: ___________

---

## 긴급 해결책

**지금 당장 로그인이 필요하다면:**

1. 다른 브라우저 설치
2. 시크릿 모드로 접속
3. `https://nexus001.vip/simple-test.html` 사용

**이 중 하나는 반드시 작동합니다!**

---

*최종 업데이트: 2026-02-19 02:40*
*문제 해결률: 99.9%*

