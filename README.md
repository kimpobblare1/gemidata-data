# gemidata-data — 개미데이터 데이터 수집기 (GitHub Actions)

Cloud Run + Cloud Scheduler 대신 **GitHub Actions가 장중 5분마다** 한국투자증권(KIS) API에서 데이터를 받아
이 저장소의 `data` 브랜치에 JSON 파일로 올려요. 사이트(gemidata.co.kr)는 그 파일을 바로 읽어요. **서버 비용 0원**이에요.

## 만들어지는 파일 (`data` 브랜치)
| 파일 | 내용 | 갱신 |
|---|---|---|
| `antdata.json` | 홈 화면 전체 데이터 (지수·수급·공매도·신용·TOP 순위) | 평일 08:00~20:00 5분마다 |
| `flow-archive/YYYYMMDD.json` | 그날 기관·외국인 TOP5 (TOP5 조회 페이지용) | 위와 같음 (거래일만) |
| `credit-trend.json` | 신용잔고·예탁금·미수금 5년 추이 | 매일 18시 이후 첫 실행 |
| `credit-cap-cache.json` | 신용잔고 종목 시가총액 하루 캐시 (내부용) | 하루 1회 |

## 처음 설정 (한 번만)
1. GitHub에서 새 저장소 `gemidata-data`를 **Public**으로 만들기
2. `collect.js`, `package.json`, `README.md`, `.gitignore` 업로드
3. `.github/workflows/collect.yml`은 **Add file → Create new file**에서 파일 이름 칸에 경로를 그대로 입력하고 내용 붙여넣기
4. **Settings → Secrets and variables → Actions → New repository secret** 으로 3개 등록
   - `KIS_APP_KEY`, `KIS_APP_SECRET` : Google Cloud → Secret Manager에 있는 값과 동일
   - `KIS_HTS_ID` : HTS 아이디 (조건검색용)
5. **Settings → Actions → General → Workflow permissions** 에서 *Read and write permissions* 선택 후 Save
6. **Actions 탭 → collect → Run workflow** (credit에 `true`) → 초록 체크 확인
7. `https://raw.githubusercontent.com/<아이디>/gemidata-data/data/antdata.json` 이 열리면 성공

## 알아둘 점
- 예약 실행은 GitHub 사정으로 몇 분 늦을 수 있어요. 사이트는 최대 5분 캐시가 더해져 보통 5~10분 안의 데이터를 보여줘요.
- KIS 접근토큰은 `.cache`에 **암호화**해서 다음 실행으로 넘겨요(24시간 재사용). 저장소에 토큰이 올라가지 않아요.
- `data` 브랜치는 매번 기록 1개로 덮어써서 저장소 용량이 늘지 않아요.
- 공개 저장소에 60일 동안 활동이 없으면 GitHub가 예약 실행을 멈출 수 있어요. 메일이 오면 Actions 탭에서 다시 켜주세요.
- 수동 테스트: Actions 탭 → collect → Run workflow
