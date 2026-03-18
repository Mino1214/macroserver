# 시드 문구 페이지네이션 추가 완료

## 구현 내용

### 1. 시드 문구 섹션 UI 개선
- **총 개수 표시**: 헤더에 `(총 N개)` 표시
- **페이지네이션 컨트롤**: 이전/다음 버튼 추가
- **페이지 정보**: `현재페이지 / 총페이지` 표시

### 2. 페이지네이션 로직

#### 설정
```javascript
const SEEDS_PER_PAGE = 10; // 페이지당 10개 표시
```

#### 주요 함수
1. **`loadSeeds()`**: API에서 전체 시드 목록 가져오기
2. **`renderSeeds()`**: 현재 페이지의 10개만 렌더링
3. **`changeSeedPage(direction)`**: 페이지 이동 (-1: 이전, +1: 다음)

### 3. 기능 상세

#### 총 개수 표시
```html
<h2>수신 시드 문구 <span id="seedTotal">(총 123개)</span></h2>
```

#### 페이지네이션 컨트롤
```html
<button onclick="changeSeedPage(-1)">이전</button>
<span>3 / 13 페이지</span>
<button onclick="changeSeedPage(1)">다음</button>
```

#### 버튼 자동 비활성화
- 첫 페이지: "이전" 버튼 비활성화
- 마지막 페이지: "다음" 버튼 비활성화

### 4. 화면 구성

```
┌─────────────────────────────────────┐
│ 수신 시드 문구 (총 123개)            │
│ □ 마스킹  [새로고침]                 │
├─────────────────────────────────────┤
│ No │ 사용자 │ 문구 │ 시각           │
├────┼────────┼──────┼────────────────┤
│ 1  │ user1  │ ... │ 2024-01-01 ... │
│ 2  │ user2  │ ... │ 2024-01-02 ... │
│ ... (10개만 표시)                    │
├─────────────────────────────────────┤
│   [이전]  3 / 13 페이지  [다음]      │
└─────────────────────────────────────┘
```

## 코드 구조

### HTML 변경
```html
<!-- 총 개수 표시 -->
<h2>수신 시드 문구 <span id="seedTotal"></span></h2>

<!-- 페이지네이션 컨트롤 -->
<div id="seedPagination">
  <button onclick="changeSeedPage(-1)" id="seedPrevBtn">이전</button>
  <span id="seedPageInfo"></span>
  <button onclick="changeSeedPage(1)" id="seedNextBtn">다음</button>
</div>
```

### JavaScript 변경
```javascript
let allSeeds = []; // 전체 시드 목록 저장
let currentSeedPage = 1; // 현재 페이지 번호
const SEEDS_PER_PAGE = 10; // 페이지당 개수

async function loadSeeds() {
  // 전체 목록 가져오기
  allSeeds = await api('/api/admin/seeds?masked=' + masked);
  currentSeedPage = 1;
  renderSeeds();
}

function renderSeeds() {
  // 현재 페이지의 10개만 표시
  const startIdx = (currentSeedPage - 1) * SEEDS_PER_PAGE;
  const endIdx = startIdx + SEEDS_PER_PAGE;
  const pageSeeds = allSeeds.slice(startIdx, endIdx);
  
  // 렌더링 + 페이지 정보 업데이트 + 버튼 상태 업데이트
}

function changeSeedPage(direction) {
  // 페이지 이동
  currentSeedPage += direction;
  renderSeeds();
}
```

## 사용 방법

### 기본 사용
1. 시드 문구 섹션에서 총 개수 확인
2. 테이블에 최신 10개만 표시됨
3. "다음" 버튼으로 다음 10개 확인
4. "이전" 버튼으로 이전 10개로 돌아가기

### 새로고침
- "새로고침" 버튼 클릭 시 첫 페이지로 이동
- 마스킹 체크박스 변경 후 "새로고침"

### 자동 비활성화
- 첫 페이지에서는 "이전" 버튼 비활성화
- 마지막 페이지에서는 "다음" 버튼 비활성화

## 적용 방법

```bash
cd /home/myno/바탕화면/myno/macroServer
./UPDATE-ADMIN-PAGE.sh
```

## 테스트 시나리오

### 시나리오 1: 시드 0개
- 표시: "수신 시드 없음"
- 페이지네이션: 숨김

### 시나리오 2: 시드 5개 (1페이지 이하)
- 표시: 5개 모두 표시
- 페이지 정보: "1 / 1 페이지"
- 버튼: 모두 비활성화

### 시나리오 3: 시드 25개 (3페이지)
- 1페이지: 1~10번 시드 표시, "이전" 비활성화
- 2페이지: 11~20번 시드 표시, 모든 버튼 활성화
- 3페이지: 21~25번 시드 표시, "다음" 비활성화

## 장점

1. **성능 개선**: 많은 시드가 있어도 10개만 렌더링
2. **UI 간결**: 화면이 깔끔하게 유지됨
3. **사용성**: 직관적인 이전/다음 버튼
4. **정보 제공**: 총 개수와 현재 페이지 위치 표시
5. **반응형 유지**: 모바일에서도 정상 작동

## 완료!

이제 시드 문구가 10개씩 페이지네이션되어 표시됩니다!

*최종 수정: 2026-02-18 16:45*
*작성: Myno Lab*

