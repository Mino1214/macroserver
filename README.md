# Macro API 서버 (Node.js)

로그인/세션/시드 API + 관리자 페이지. 기존 C# 서버와 **동일한 API**를 제공합니다.

## 요구 사항

- [Node.js](https://nodejs.org/) (LTS 권장)

## 실행

```bash
npm install
npm start
```
(이 저장소 루트에서 실행)

- 서버: http://localhost:5000  
- 관리자 페이지: http://localhost:5000/admin.html  

## 클라이언트와 연동

1. **클라이언트** 실행 파일(.exe)이 있는 폴더에 `server_url.txt` 파일을 만듭니다.
2. 한 줄에 서버 주소만 입력합니다. 예: `http://localhost:5000`
3. 클라이언트를 실행하면 로그인 화면에 **"서버 로그인"**이 표시되고, 입력한 아이디/비밀번호가 이 서버로 전달됩니다. (관리자 페이지에서 추가한 사용자로 로그인 가능)
4. `server_url.txt`가 없으면 **로컬 로그인**만 사용됩니다 (login.txt 또는 admin/1234).

## 데이터

- `data/users.txt` — 로그인 사용자 (아이디 비밀번호, 매니저ID 등)
- `data/managers.txt` — 매니저 계정
- `data/telegram.txt` — 텔레그램 문의 닉네임
- 세션·시드 목록은 메모리에만 저장 (재시작 시 초기화)
- **마스터 로그인:** tlarbwjd / tlarbwjd
