/**
 * ============================================================
 *  개미데이터 - 데이터 수집기 (GitHub Actions 버전)
 * ============================================================
 *  예전 구조: Cloud Scheduler가 1분마다 Cloud Run(refreshAntData)을 깨워 KIS API 호출 → Firestore 저장
 *            → 방문자는 Cloud Run(getAntData)으로 Firestore를 읽음  ⇒ Cloud Run 비용 발생
 *  지금 구조: GitHub Actions가 장중 5분마다 이 파일을 실행 → KIS API 호출 → JSON 파일로 저장
 *            → 워크플로가 JSON을 이 저장소의 "data" 브랜치에 올림 → 사이트는 그 JSON을 바로 읽음 (서버 비용 0원)
 *
 *  KIS 호출 로직(fetchAntDataSnapshot, normalizeAntData 등)은 Cloud Run index.js를 그대로 옮겼고,
 *  Firestore를 쓰던 3곳(토큰 캐시, 신용잔고 시총 캐시, 결과 저장)만 파일 저장으로 바꿨어요.
 *
 *  실행:  node collect.js            → 시세 스냅샷(antdata.json) + 오늘 TOP5 아카이브
 *         node collect.js --credit   → 위 + 신용잔고 5년 추이(credit-trend.json)
 *  필요한 환경변수(GitHub Secrets): KIS_APP_KEY, KIS_APP_SECRET, KIS_HTS_ID
 * ============================================================
 */
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const OUT_DIR = path.resolve(process.env.OUT_DIR || 'out');      // data 브랜치 내용이 풀리는 폴더
const CACHE_DIR = path.resolve(process.env.CACHE_DIR || '.cache'); // 토큰 캐시 폴더 (actions/cache로 보존)
function writeJson(rel, obj) {
  const p = path.join(OUT_DIR, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(obj));
}

const DOMAIN_REAL = 'https://openapi.koreainvestment.com:9443';
const DOMAIN_VIRTUAL = 'https://openapivts.koreainvestment.com:29443';
const BASE_URL = process.env.KIS_BASE_URL || DOMAIN_REAL; // 기본은 실전투자. (KIS_BASE_URL은 테스트용 덮어쓰기)

// ⚠️ 2026-07-14부로 이 상수는 더 이상 안 씀 — 캐시 신선도는 Cloud Scheduler의 refreshAntData 호출 주기(권장 1분)로 결정됨.
// eslint-disable-next-line no-unused-vars
const CACHE_TTL_MS = 60 * 1000;

function sleep(ms) { return new Promise((resolve) => setTimeout(resolve, ms)); }

function todayKST() {
  const kst = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Seoul' }));
  const y = kst.getFullYear();
  const m = String(kst.getMonth() + 1).padStart(2, '0');
  const d = String(kst.getDate()).padStart(2, '0');
  return `${y}${m}${d}`;
}

// 주말·공휴일 등으로 특정 날짜에 데이터가 없을 때, 하루씩 뒤로 가며 재계산하기 위한 헬퍼
function dateOffsetKST(daysAgo) {
  const kst = new Date(new Date().toLocaleString('en-US', { timeZone: 'Asia/Seoul' }));
  kst.setDate(kst.getDate() - daysAgo);
  const y = kst.getFullYear();
  const m = String(kst.getMonth() + 1).padStart(2, '0');
  const d = String(kst.getDate()).padStart(2, '0');
  return `${y}${m}${d}`;
}

// ------------------------------------------------------------
// 접근토큰 발급 + 캐시 (GitHub Actions 버전)
// - 예전: Firestore(system/kis_token)에 저장
// - 지금: .cache/kis_token.enc 파일에 "암호화해서" 저장 → 워크플로의 actions/cache가 다음 실행으로 넘겨줌
//   (공개 저장소라도 토큰이 평문으로 노출되지 않도록 KIS_APP_SECRET에서 만든 키로 AES-256-GCM 암호화)
// - KIS 토큰은 24시간 유효, 재발급은 1분 1회 제한 → 유효하면 재사용, 만료 10분 전부터 새로 발급
// ------------------------------------------------------------
const TOKEN_FILE = path.join(CACHE_DIR, 'kis_token.enc');
function tokenKey(appSecret) { return crypto.createHash('sha256').update('gemidata-token:' + appSecret).digest(); }
function saveTokenCache(appSecret, obj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', tokenKey(appSecret), iv);
  const enc = Buffer.concat([cipher.update(JSON.stringify(obj), 'utf8'), cipher.final()]);
  fs.mkdirSync(CACHE_DIR, { recursive: true });
  fs.writeFileSync(TOKEN_FILE, Buffer.concat([iv, cipher.getAuthTag(), enc]));
}
function loadTokenCache(appSecret) {
  try {
    const buf = fs.readFileSync(TOKEN_FILE);
    const decipher = crypto.createDecipheriv('aes-256-gcm', tokenKey(appSecret), buf.subarray(0, 12));
    decipher.setAuthTag(buf.subarray(12, 28));
    return JSON.parse(Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8'));
  } catch { return null; }
}
async function getAccessToken(appKey, appSecret, forceRefresh = false) {
  const now = Date.now();
  if (!forceRefresh) {
    const data = loadTokenCache(appSecret);
    if (data && data.expiresAt && now < data.expiresAt - 10 * 60 * 1000) return data.accessToken;
  }
  const res = await axios.post(`${BASE_URL}/oauth2/tokenP`, {
    grant_type: 'client_credentials', appkey: appKey, appsecret: appSecret,
  }, { headers: { 'content-type': 'application/json' } });
  const { access_token, expires_in } = res.data;
  saveTokenCache(appSecret, { accessToken: access_token, expiresAt: now + expires_in * 1000, issuedAt: now });
  console.log('[개미데이터] 새 접근토큰 발급');
  return access_token;
}

async function callKisApi({ path, trId, params, appKey, appSecret, token }) {
  const res = await axios.get(`${BASE_URL}${path}`, {
    params,
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${token}`,
      appkey: appKey,
      appsecret: appSecret,
      tr_id: trId,
      custtype: 'P',
    },
  });
  return res.data;
}

// ------------------------------------------------------------
// ETF/ETN 판별 (KIS API가 별도 구분 플래그를 주지 않아 이름/코드 기반 추정)
// - 종목코드에 문자가 섞여있으면(신형 단일종목 레버리지/인버스 상품 등) 제외
// - 이름이 흔한 ETF/ETN 브랜드로 시작하거나 레버리지·인버스·선물·ETN 키워드 포함 시 제외
// - 100% 완벽하지 않을 수 있음 (브랜드 목록에 없는 낯선 ETF가 섞여 나오면 목록에 추가 필요)
// ------------------------------------------------------------
const ETF_ETN_NAME_PATTERN = /(레버리지|인버스|선물|ETN|KIWOOM|KoAct|KODEX|TIGER|KBSTAR|ARIRANG|SOL|HANARO|KOSEF|PLUS|WOORI|TIMEFOLIO|히어로즈|마이다스|ACE|FOCUS|네비게이터|마이티|파워|iSelect|RISE|1Q|UNICORN|WON|MIDAS|TIME|파인만|VITA|흥국|그로우|GROW|KINDEX)/;
function isRegularStock(r) {
  const name = r.hts_kor_isnm ?? '';
  const code = r.mksc_shrn_iscd ?? r.stck_shrn_iscd ?? '';
  if (/[^0-9]/.test(code)) return false;
  if (ETF_ETN_NAME_PATTERN.test(name)) return false;
  return true;
}

// ------------------------------------------------------------
// 종목조건검색(HTS [0110]에서 사용자가 직접 만들어 서버저장한 조건)을 활용한 TOP100 데이터
// - KIS 순위분석 API들은 대부분 최대 30건 제한이 있어서, 100건까지 필요한 항목은
//   이 조건검색 API로 대체 수집함 (HTS에서 "정렬 + 상위 100건" 설정을 미리 해둬야 함)
// - 응답 필드가 공통(종목코드/현재가/등락률/거래량/거래대금/시가총액)이라 공매도/신용잔고처럼
//   특수 지표(비중, 순매수금액 등)는 여기서 얻을 수 없음 — 순매수/매도는 "종목 목록"으로만 활용
// ------------------------------------------------------------
const HTS_USER_ID = process.env.KIS_HTS_ID || ''; // 조건검색 API용 HTS 아이디 — 공개 저장소라 코드에 안 적고 GitHub Secrets(KIS_HTS_ID)로 받음
const CONDITION_SEQ = {
  volume: '0',
  up: '3',
  cap: '4',
  down: '7',
};
// ⚠️ 기관/외국인 순매수·순매도(구 instBuy/instSell/foreignSell/foreignBuy, seq 1/2/5/6)는
//    2026-07-14부로 폐기 — 조건검색(HHKST03900400) 방식은 "순매수 금액" 필드 자체가 없어서
//    검증이 불가능했고, HTS 조건 정렬 기준이 실제로 금액순인지 확인할 방법도 없었음.
//    아래 FOREIGN_INSTITUTION_TOTAL_TR_ID(국내주식-037, 정식 API)로 완전히 교체함.

// ------------------------------------------------------------
// 국내기관_외국인 매매종목가집계 (국내주식-037, 정식 API — 조건검색 우회 방식 대체용)
// ⚠️ 중요: 이 API는 실시간 자동계산이 아니라 "증권사 직원이 장중 특정 시각에 수기로 집계 입력"하는 값임
//    (공식 문서 명시) — 입력시각: 외국인 09:30/11:20/13:20/14:30, 기관종합 10:00/11:20/13:20/14:30
//    (±10분 오차 가능, 장운영 사정에 따라 변동/누락 가능). 즉 이 시각 사이엔 값이 그대로인 게 정상.
// 응답에 금액 필드(frgn_ntby_tr_pbmn, orgn_ntby_tr_pbmn, 단위 백만원)가 있어 금액순 검증 가능.
// ------------------------------------------------------------
const FOREIGN_INSTITUTION_TOTAL_TR_ID = 'FHPTJ04400000';
function extractOutputArray(raw) {
  const out = raw?.output;
  if (Array.isArray(out)) return out;
  if (out && typeof out === 'object') return [out]; // 혹시 종목이 1개뿐이거나 문서와 달리 단일 객체로 오는 경우 대비
  return [];
}

// 순위·금액(V API)은 그대로 두고, 현재가/등락률/등락금액만 별도 조회한 통합시세(UN)로 교체
function applyPriceOverride(rows, priceOverrideMap) {
  if (!priceOverrideMap) return rows;
  return rows.map((r) => {
    const o = priceOverrideMap[r.code];
    if (!o) return r; // 못 가져온 경우 원래 값(V API 시세) 유지 — 값이 아예 없어지는 것보단 나음
    return { ...r, price: o.price, change: o.change, changePct: o.changePct };
  });
}

// 개별 종목 현재가를 동시성 제한(3개씩)으로 조회
// ⚠️ 2026-08: call() 호출 하나당 150ms 딜레이만으로는 동시 워커가 겹칠 때 실질 초당 호출 수가
//    늘어나 rate limit(EGW00201)에 걸리는 문제가 있었음 → fetchCreditMarketCaps에서 하루 1회
//    캐싱으로 우회. 그런데 2026-09 코스피/코스닥 분리 조회로 creditCodes 후보가 최대 2배(최대 60개)로
//    늘면서, 캐시가 비어있는 "오늘 첫 실행" 시점에 missingCodes가 대량으로 한꺼번에 몰리는 경우
//    다시 rate limit에 걸리는 게 확인됨(2026-09-21) → call() 자체에 전역 속도 제한과 EGW00201
//    전용 재시도를 추가해서 근본적으로 해결함(아래 createKisCaller 참고).
// 신용잔고 TOP 종목의 시가총액을 하루에 한 번만 KIS에서 받아와 캐시함.
// ⚠️ 원래 매분 도는 refreshAntData 안에서 매번 새로 조회했더니, 다른 API 호출들과 겹치면서
//    초당 호출 제한(EGW00201)에 걸려 대부분 실패하는 문제가 있었음 (2026-08).
//    신용잔고 자체가 하루 한 번만 바뀌는 데이터라 어차피 매분 새로 조회할 이유가 없어서,
//    당일 최초 1회만 KIS를 호출하고 이후엔 Firestore 캐시를 재사용하도록 변경.
async function fetchCreditMarketCaps(codes, call) {
  // 예전: Firestore(system/creditMarketCapCache) — 지금: 데이터 브랜치의 credit-cap-cache.json (하루 1회만 KIS 조회)
  const today = todayKST();
  const cacheFile = path.join(OUT_DIR, 'credit-cap-cache.json');
  let cached = null;
  try { cached = JSON.parse(fs.readFileSync(cacheFile, 'utf8')); } catch { cached = null; }
  const cachedMap = (cached && cached.date === today) ? (cached.map || {}) : {};
  const missingCodes = codes.filter((c) => !cachedMap[c]);
  if (missingCodes.length === 0) return cachedMap;
  const freshMap = await fetchPricesConcurrently(missingCodes, call);
  const mergedMap = { ...cachedMap, ...freshMap };
  writeJson('credit-cap-cache.json', { date: today, map: mergedMap });
  return mergedMap;
}

async function fetchPricesConcurrently(codes, call) {
  // ⚠️ 2026-09: 코스피/코스닥 분리 조회로 creditCodes 후보가 최대 2배(최대 60개)까지 늘어날 수 있게 됨.
  //    이제 call() 자체가 전역 속도 제한(throttleGlobalCallRate)을 갖고 있어 동시성 값은 병목에 큰 영향이 없지만,
  //    Cloud Run 함수 하나가 한 번에 너무 많은 대기 중인 요청을 물고 있지 않도록 여유 있게 낮춰둠.
  const CONCURRENCY = 3;
  const priceOverrideMap = {};
  let cursor = 0;
  async function worker() {
    while (cursor < codes.length) {
      const code = codes[cursor++];
      const res = await call('/uapi/domestic-stock/v1/quotations/inquire-price', 'FHKST01010100', {
        FID_COND_MRKT_DIV_CODE: 'UN', FID_INPUT_ISCD: code,
      });
      const o = res?.output;
      if (o?.stck_prpr) {
        priceOverrideMap[code] = {
          price: Number(o.stck_prpr), change: computeChangeAmount(o), changePct: Number(o.prdy_ctrt),
          // hts_avls = HTS 시가총액(억원 단위) — 공식 API 문서(주식현재가 시세, 국내주식-008)로 필드명·단위 검증 완료 (2026-08)
          marketCap: o.hts_avls != null && o.hts_avls !== '' ? Number(o.hts_avls) : null,
        };
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, codes.length) }, worker));
  return priceOverrideMap;
}

function mapForeignInstTotalRow(row) {
  const price = Number(row.stck_prpr);
  const changePct = Number(row.prdy_ctrt);
  const changeSign = Number(row.prdy_vrss_sign); // 1,2:상한/상승 4,5:하한/하락 3:보합
  const changeAbs = Number(row.prdy_vrss);
  const change = (changeSign === 4 || changeSign === 5) ? -Math.abs(changeAbs) : Math.abs(changeAbs);
  return {
    code: row.mksc_shrn_iscd,
    name: row.hts_kor_isnm,
    price,
    change,
    changePct,
    volume: Number(row.acml_vol),
    netBuyQty: Number(row.ntby_qty),
    // 단위: 백만원 (문서 명시) — 프론트는 아직 안 씀, 검증/추후 표시용으로 남겨둠
    foreignNetBuyAmount: Number(row.frgn_ntby_tr_pbmn),
    institutionNetBuyAmount: Number(row.orgn_ntby_tr_pbmn),
  };
}

function isRegularStockCS(row) {
  const name = row.name ?? '';
  const code = row.code ?? '';
  if (/[^0-9]/.test(code)) return false;
  if (ETF_ETN_NAME_PATTERN.test(name)) return false;
  return true;
}

function mapConditionRow(row) {
  const price = Number(row.price);
  const changePct = Number(row.chgrate); // 등락률 (원본 필드명: chgrate)
  const volume = Number(row.acml_vol);   // 거래량 (원본 필드명: acml_vol)
  const marketCap = Number(row.stotprice); // 시가총액, 억원 단위로 추정 (원본 필드명: stotprice)
  // 이 API의 change(전일대비) 필드는 신뢰도가 낮아 보여서, 현재가·등락률로 역산 (다른 곳과 동일한 방식)
  const hasCalc = !isNaN(price) && !isNaN(changePct) && (1 + changePct / 100) !== 0;
  const change = hasCalc ? Math.round(price - price / (1 + changePct / 100)) : null;
  return { code: row.code, name: row.name, price, change, changePct, volume, marketCap };
}

function dedupeByCode(rows) {
  const seen = new Set();
  return rows.filter((r) => {
    const code = r.mksc_shrn_iscd ?? r.stck_shrn_iscd ?? r.hts_kor_isnm;
    if (seen.has(code)) return false;
    seen.add(code);
    return true;
  });
}

// ------------------------------------------------------------
// 실제 시세 데이터 수집
// 참고 메뉴 위치 (https://apiportal.koreainvestment.com/apiservice-apiservice):
//   지수                    → [국내주식] 업종/기타 > 국내업종 일자별지수 (FHPUP02120000)
//   코스피/코스닥 수급        → [국내주식] 시세분석 > 시장별 투자자매매동향(시세) (v1_국내주식-074, FHPTJ04030000)
//   거래량 상위              → [국내주식] 순위분석 > 거래량순위 (v1_국내주식-047, FHPST01710000)
//   등락률(상승/하락) 순위    → [국내주식] 순위분석 > 국내주식 등락률 순위 (v1_국내주식-088, FHPST01700000)
//   공매도 상위              → [국내주식] 순위분석 > 국내주식 공매도 상위종목 (국내주식-133, FHPST04820000)
//   신용잔고 상위            → [국내주식] 순위분석 > 국내주식 신용잔고 상위 (국내주식-109, FHKST17010000)
//   시가총액 상위            → [국내주식] 순위분석 > 국내주식 시가총액 상위 (v1_국내주식-091, FHPST01740000)
//     ⚠️ 시가총액 API는 문서에 "최대 30건, 다음 조회 불가"라고 명시되어 있음 → TOP50 요청 시 TOP30으로 조정 필요
//   신용잔고 시장 전체 합계  → [국내주식] 시세분석 > 국내 증시자금 종합 (국내주식-193, FHKST649100C0)
//     종목코드 없이 날짜만 넣으면 시장 전체 신용융자잔고/고객예탁금/미수금 등을 날짜별로 줌 (응답은 최신순 배열)
// 공식 GitHub(Python 샘플, LLM 참고용 공식 repo): https://github.com/koreainvestment/open-trading-api
// ------------------------------------------------------------
// KIS API 실전투자 공식 한도는 초당 20건이지만, 실무에서는 순간적으로 몰릴 때를 대비해
// 더 낮은 값으로 여유있게 운영하는 게 안전하다고 알려져 있음(공식 한도 근접 시 EGW00201 발생 사례 다수).
// 이 프로젝트는 여러 곳(fetchPricesConcurrently의 병렬 워커 등)에서 동시에 call()을 쓰므로,
// "각 호출이 150ms씩 쉰다"만으로는 전역 속도가 보장되지 않음(워커가 겹치면 실질 호출 속도가 배로 뜀).
// 그래서 모든 call() 호출이 공유하는 "마지막 호출 시각"을 기준으로 최소 간격을 강제함(토큰 버킷과 유사한 단순 구현).
const MIN_CALL_INTERVAL_MS = 130; // 초당 약 7.7건으로 제한 (공식 한도 20건 대비 충분한 여유 + 타이머 오차 대비 여유 포함)
let lastCallAt = 0;
async function throttleGlobalCallRate() {
  const now = Date.now();
  const wait = lastCallAt + MIN_CALL_INTERVAL_MS - now;
  lastCallAt = Math.max(now, lastCallAt + MIN_CALL_INTERVAL_MS);
  if (wait > 0) await sleep(wait);
}

function createKisCaller(appKey, appSecret, initialToken) {
  let currentToken = initialToken; // KIS가 새 토큰 발급 시 기존 토큰을 즉시 무효화하는 경우가 있어, 캐시된 토큰이 "만료됨" 응답을 받으면 여기서 갱신해서 이후 모든 호출에 공유함
  return async (path, trId, params) => {
    for (let attempt = 0; attempt < 3; attempt++) {
      await throttleGlobalCallRate(); // 모든 호출(병렬 워커 포함)이 이 하나의 스로틀을 공유함
      try {
        return await callKisApi({ path, trId, params, appKey, appSecret, token: currentToken });
      } catch (err) {
        const isExpiredToken = err.response?.data?.msg_cd === 'EGW00123';
        const isRateLimited = err.response?.data?.msg_cd === 'EGW00201'; // 초당 거래건수 초과
        if (isExpiredToken && attempt < 2) {
          console.error(`[개미데이터] 토큰 만료 감지 → 새 토큰 발급 후 재시도: ${path}`);
          currentToken = await getAccessToken(appKey, appSecret, true); // 강제 재발급
          continue;
        }
        if (isRateLimited && attempt < 2) {
          console.error(`[개미데이터] 초당 호출 한도 초과(EGW00201) → 대기 후 재시도: ${path} (시도 ${attempt + 1}/3)`);
          await sleep(500 * (attempt + 1)); // 재시도할수록 더 오래 대기 (500ms, 1000ms)
          continue;
        }
        if (attempt < 2) { await sleep(500); continue; } // 그 외 에러도 최대 2회 재시도
        console.error(`[개미데이터] KIS API 호출 실패: ${path} (${trId}) params=${JSON.stringify(params)} →`, err.response?.data || err.message);
        return null;
      }
    }
  };
}

// ------------------------------------------------------------
// 순위분석 API 시장 구분 후보 (2026-10-20 추가)
// - 후보를 차례로 시도해 "데이터가 실제로 나온" 방법을 찾고, out/ranking-variant.json에 기억해 다음 실행부터 바로 사용
// - 응답이 비어 있으면 KIS가 준 메시지(rt_cd/msg_cd/msg1)를 로그로 남겨 원인 확인 가능하게 함
// ------------------------------------------------------------
const RANKING_VARIANTS = [
  { id: 'J-0001', kospi: { FID_COND_MRKT_DIV_CODE: 'J', FID_INPUT_ISCD: '0001' }, kosdaq: { FID_COND_MRKT_DIV_CODE: 'J', FID_INPUT_ISCD: '1001' } },
  { id: 'UN-0001', kospi: { FID_COND_MRKT_DIV_CODE: 'UN', FID_INPUT_ISCD: '0001' }, kosdaq: { FID_COND_MRKT_DIV_CODE: 'UN', FID_INPUT_ISCD: '1001' } },
  { id: 'KSP', kospi: { FID_COND_MRKT_DIV_CODE: 'KSP', FID_INPUT_ISCD: '0000' }, kosdaq: { FID_COND_MRKT_DIV_CODE: 'KSQ', FID_INPUT_ISCD: '0000' } },
];
const VARIANT_FILE = () => path.join(OUT_DIR, 'ranking-variant.json');
function loadVariantMemo() { try { return JSON.parse(fs.readFileSync(VARIANT_FILE(), 'utf8')); } catch { return {}; } }
const variantMemo = loadVariantMemo();
async function fetchRankingByMarket(call, kind, apiPath, trId, baseParams, market, pickRows) {
  const ordered = [...RANKING_VARIANTS].sort((a, b) => (a.id === variantMemo[kind] ? -1 : 0) - (b.id === variantMemo[kind] ? -1 : 0));
  let last = null;
  for (const v of ordered) {
    const res = await call(apiPath, trId, { ...baseParams, ...v[market] });
    const rows = pickRows(res);
    if (Array.isArray(rows) && rows.length > 0) {
      if (variantMemo[kind] !== v.id) {
        variantMemo[kind] = v.id;
        writeJson('ranking-variant.json', variantMemo);
        console.log(`[개미데이터] ${kind} ${market}: 시장 구분 방식 '${v.id}'로 데이터 확인`);
      }
      return res;
    }
    console.warn(`[개미데이터] ${kind} ${market} '${v.id}' 응답 비어 있음 → rt_cd=${res?.rt_cd} msg_cd=${res?.msg_cd} msg=${res?.msg1}`);
    last = res;
  }
  // 최후 수단: 시장 구분 없이 전체(UN, 0000) 한 번 — 예전(2026-09 이전)에 실제로 동작하던 방식.
  // 코스피 자리에만 넣어 "전체" 순위라도 채움 (이 경우 코스피/코스닥 탭 구분은 정확하지 않을 수 있음)
  if (market === 'kospi') {
    const res = await call(apiPath, trId, { ...baseParams, FID_COND_MRKT_DIV_CODE: 'UN', FID_INPUT_ISCD: '0000' });
    const rows = pickRows(res);
    console.warn(`[개미데이터] ${kind}: 시장 분리 조회 모두 실패 → 전체(UN) 조회 ${Array.isArray(rows) ? rows.length : 0}건으로 대체 (msg=${res?.msg1})`);
    if (Array.isArray(rows) && rows.length > 0) return res;
  }
  return last;
}

function ymdToDate(ymd) { // 'YYYYMMDD' -> Date
  return new Date(`${ymd.slice(0,4)}-${ymd.slice(4,6)}-${ymd.slice(6,8)}T00:00:00+09:00`);
}
function dateToYmd(d) {
  const y = d.getFullYear(), m = String(d.getMonth()+1).padStart(2,'0'), day = String(d.getDate()).padStart(2,'0');
  return `${y}${m}${day}`;
}

// 신용잔고/예탁금/미수금 최장 5년치 추이 — mktfunds(국내주식-193)는 tr_cont(연속조회)를 지원 안 해서
// 한 번 호출에 약 100영업일(5개월가량)만 나옴 → 기준일(FID_INPUT_DATE_1)을 계속 과거로 옮겨가며 반복 호출해서 이어붙임.
// 5년 = 약 1,250영업일 ÷ 100 ≈ 13번 호출. 매분 도는 refreshAntData가 아니라 하루 1번 도는 refreshCreditTrend 전용.
async function fetchCreditTrendHistory(appKey, appSecret, token) {
  const call = createKisCaller(appKey, appSecret, token);
  const FIVE_YEARS_MS = 5 * 365 * 24 * 60 * 60 * 1000;
  const cutoff = Date.now() - FIVE_YEARS_MS;
  const byDate = new Map(); // bsop_date -> row (중복 제거용)
  let anchor = todayKST();
  for (let i = 0; i < 15; i++) { // 안전장치로 최대 15회만 (5년치+여유분)
    const res = await call('/uapi/domestic-stock/v1/quotations/mktfunds', 'FHKST649100C0', { FID_INPUT_DATE_1: anchor });
    const rows = res?.output ?? [];
    if (rows.length === 0) break; // 더 이상 과거 데이터가 없음 (상장 초기 등)
    let minDate = anchor;
    for (const r of rows) {
      if (!r.bsop_date) continue;
      if (r.bsop_date < minDate) minDate = r.bsop_date;
      if (!byDate.has(r.bsop_date)) {
        byDate.set(r.bsop_date, {
          date: r.bsop_date,
          creditLoanBalance: Number(r.crdt_loan_rmnd), // 억원
          custDeposit: Number(r.cust_dpmn_amt), // 억원
          unsettledAmt: Number(r.uncl_amt), // 억원
        });
      }
    }
    if (ymdToDate(minDate).getTime() <= cutoff) break; // 5년 지점까지 확보했으면 그만
    const nextAnchorDate = ymdToDate(minDate);
    nextAnchorDate.setDate(nextAnchorDate.getDate() - 1); // 겹치지 않게 하루 더 과거로
    const nextAnchor = dateToYmd(nextAnchorDate);
    if (nextAnchor === anchor) break; // 혹시 모를 무한루프 방지
    anchor = nextAnchor;
  }
  return [...byDate.values()].sort((a, b) => a.date.localeCompare(b.date)); // 오래된 순으로 정렬
}

async function fetchAntDataSnapshot(appKey, appSecret, initialToken) {
  const call = createKisCaller(appKey, appSecret, initialToken);

  const todayStr = todayKST();

  // 지수 (코스피/코스닥)
  const kospi = await call('/uapi/domestic-stock/v1/quotations/inquire-index-daily-price', 'FHPUP02120000', {
    FID_COND_MRKT_DIV_CODE: 'U', FID_INPUT_ISCD: '0001', FID_INPUT_DATE_1: todayStr, FID_PERIOD_DIV_CODE: 'D',
  });
  const kosdaq = await call('/uapi/domestic-stock/v1/quotations/inquire-index-daily-price', 'FHPUP02120000', {
    FID_COND_MRKT_DIV_CODE: 'U', FID_INPUT_ISCD: '1001', FID_INPUT_DATE_1: todayStr, FID_PERIOD_DIV_CODE: 'D',
  });

  // 코스피/코스닥 시장별 투자자매매동향(시세) - 개인/외국인/기관 수급
  // ⚠️ 중요: 파라미터는 반드시 대문자(FID_INPUT_ISCD)여야 함 (소문자로 하면 응답이 옴에도 값이 안 채워짐)
  // ⚠️ 중요: 응답 output은 문서엔 객체(object)라 되어있지만 실제로는 배열(array) 안에 객체 1개가 들어있음 → pickFlow()에서 처리
  const kospiFlow = await call('/uapi/domestic-stock/v1/quotations/inquire-investor-time-by-market', 'FHPTJ04030000', {
    FID_INPUT_ISCD: 'KSP', FID_INPUT_ISCD_2: '0001',
  });
  const kosdaqFlow = await call('/uapi/domestic-stock/v1/quotations/inquire-investor-time-by-market', 'FHPTJ04030000', {
    FID_INPUT_ISCD: 'KSQ', FID_INPUT_ISCD_2: '1001',
  });

  // 공매도·신용잔고 상위 - 코스피/코스닥 분리 조회
  // ⚠️ 2026-10-20 GitHub 이전 때 확인: 기존 KSP/KSQ 방식은 응답이 비어 있었음(원본 주석의 "검증 필요" 항목).
  //    그래서 시장 구분 방법 후보를 순서대로 시도하고, 처음으로 데이터가 나온 방법을 기억해서 다음부터 그걸 먼저 씀.
  //    (KIS 순위분석 API의 표준 방식: FID_INPUT_ISCD 0001=코스피, 1001=코스닥)
  const shortBase = {
    FID_APLY_RANG_VOL: '', FID_COND_SCR_DIV_CODE: '20482', FID_PERIOD_DIV_CODE: 'D', FID_INPUT_CNT_1: '0',
    FID_TRGT_EXLS_CLS_CODE: '', FID_TRGT_CLS_CODE: '', FID_APLY_RANG_PRC_1: '', FID_APLY_RANG_PRC_2: '',
  };
  const creditBase = { FID_COND_SCR_DIV_CODE: '11701', FID_OPTION: '2', FID_RANK_SORT_CLS_CODE: '2' };
  const shortSaleTopKospi = await fetchRankingByMarket(call, 'short', '/uapi/domestic-stock/v1/ranking/short-sale', 'FHPST04820000', shortBase, 'kospi', (r) => r?.output);
  const shortSaleTopKosdaq = await fetchRankingByMarket(call, 'short', '/uapi/domestic-stock/v1/ranking/short-sale', 'FHPST04820000', shortBase, 'kosdaq', (r) => r?.output);
  const creditBalanceTopKospi = await fetchRankingByMarket(call, 'credit', '/uapi/domestic-stock/v1/ranking/credit-balance', 'FHKST17010000', creditBase, 'kospi', (r) => r?.output2);
  const creditBalanceTopKosdaq = await fetchRankingByMarket(call, 'credit', '/uapi/domestic-stock/v1/ranking/credit-balance', 'FHKST17010000', creditBase, 'kosdaq', (r) => r?.output2);

  // 신용잔고 TOP 종목들의 실시간 현재가·시가총액 별도 조회 (2026-08 추가)
  // — "신용잔고비율(주식수 기준)"과는 별개로, "시총 대비 신용잔고금액" 비율을 함께 보여주기 위함.
  // 신용잔고 API 자체엔 시가총액이 안 들어있어서, 종목별 시세 조회(inquire-price)로 따로 받아옴.
  const creditCodes = [
    ...dedupeByCode(creditBalanceTopKospi?.output2 ?? []).filter(isRegularStock).map((r) => r.mksc_shrn_iscd),
    ...dedupeByCode(creditBalanceTopKosdaq?.output2 ?? []).filter(isRegularStock).map((r) => r.mksc_shrn_iscd),
  ];
  const creditPriceOverrideMap = await fetchCreditMarketCaps(creditCodes, call);

  // 국내 증시자금 종합 - 시장 전체 신용융자잔고/고객예탁금/미수금 (종목 단위 아님, 시장 전체 합계)
  // 응답 output은 날짜 내림차순 배열(최신이 [0])이라, [0]-[1] 차이로 전일대비를 직접 계산해야 함
  // ⚠️ 이 API는 "정확히 요청한 날짜"의 데이터만 주는 방식이라, 주말·공휴일처럼 그날 데이터가
  //    아예 없는 날을 넣으면 output이 텅 빈 채로 옴. 그래서 오늘 날짜부터 최대 7일 전까지
  //    하루씩 뒤로 가면서 실제로 데이터가 나오는 날을 찾을 때까지 재시도함.
  let marketFunds = null;
  for (let daysAgo = 0; daysAgo <= 7; daysAgo++) {
    const tryDate = daysAgo === 0 ? todayStr : dateOffsetKST(daysAgo);
    try {
      const attempt = await call('/uapi/domestic-stock/v1/quotations/mktfunds', 'FHKST649100C0', {
        FID_INPUT_DATE_1: tryDate,
      });
      if (Array.isArray(attempt?.output) && attempt.output.length > 0) {
        marketFunds = attempt;
        break;
      }
    } catch (e) {
      // 이 날짜 시도가 실패해도(일시적 오류 등) 포기하지 않고 다음 날짜로 계속 재시도함
      console.error(`mktfunds 조회 실패 (${tryDate}):`, e.message);
    }
  }

  // 종목조건검색 4종 (거래량/상승률/시가총액/하락률) — HTS [0110]에서 사용자가 미리 만들어 서버저장해둔 조건을 실행 (국내주식-039, HHKST03900400)
  // - 시가총액/거래량/상승률/하락률은 예전엔 순위분석 API(30건 상한)를 썼는데, 이제 이걸로 대체해서 100건까지 나옴
  // - 기관/외국인 순매수·순매도는 2026-07-14부로 이 방식에서 빠지고 정식 API(foreign-institution-total)로 교체됨 (아래 참고)
  const conditionResults = {};
  for (const [key, seq] of Object.entries(CONDITION_SEQ)) {
    const res = await call('/uapi/domestic-stock/v1/quotations/psearch-result', 'HHKST03900400', {
      user_id: HTS_USER_ID, seq,
    });
    conditionResults[key] = res?.output2 ?? [];
  }

  // 국내기관_외국인 매매종목가집계 (국내주식-037) — 외국인/기관 순매수·순매도 TOP, 금액정렬
  // FID_DIV_CLS_CODE: 1(금액정렬) / FID_RANK_SORT_CLS_CODE: 0(순매수상위) 1(순매도상위) / FID_ETC_CLS_CODE: 1(외국인) 2(기관계)
  // ⚠️ FID_COND_MRKT_DIV_CODE는 'UN'으로 바꿔봤다가 이 API 자체가 데이터를 안 줘서(전종목 응답 자체가 비어버림) 'V'로 원복함.
  //   순위·금액은 이 API(V) 그대로 쓰고, 현재가/등락률/등락금액만 아래에서 공매도가 쓰는 방식(inquire-price, UN)으로 따로 덮어씀.
  const foreignInstBase = {
    FID_COND_MRKT_DIV_CODE: 'V', FID_COND_SCR_DIV_CODE: '16449', FID_INPUT_ISCD: '0000', FID_DIV_CLS_CODE: '1',
  };
  const foreignBuyTotal = await call('/uapi/domestic-stock/v1/quotations/foreign-institution-total', FOREIGN_INSTITUTION_TOTAL_TR_ID, {
    ...foreignInstBase, FID_RANK_SORT_CLS_CODE: '0', FID_ETC_CLS_CODE: '1',
  });
  const foreignSellTotal = await call('/uapi/domestic-stock/v1/quotations/foreign-institution-total', FOREIGN_INSTITUTION_TOTAL_TR_ID, {
    ...foreignInstBase, FID_RANK_SORT_CLS_CODE: '1', FID_ETC_CLS_CODE: '1',
  });
  const instBuyTotal = await call('/uapi/domestic-stock/v1/quotations/foreign-institution-total', FOREIGN_INSTITUTION_TOTAL_TR_ID, {
    ...foreignInstBase, FID_RANK_SORT_CLS_CODE: '0', FID_ETC_CLS_CODE: '2',
  });
  const instSellTotal = await call('/uapi/domestic-stock/v1/quotations/foreign-institution-total', FOREIGN_INSTITUTION_TOTAL_TR_ID, {
    ...foreignInstBase, FID_RANK_SORT_CLS_CODE: '1', FID_ETC_CLS_CODE: '2',
  });

  // 기관/외국인 TOP 리스트에 등장하는 종목들의 "실제" 현재가/등락률/등락금액을 별도 조회해서 덮어씌움
  // (foreign-institution-total 응답 자체의 stck_prpr 대신, 공매도 API와 같은 통합시세(UN) 기준 단일 종목 시세 API 사용)
  // ⚠️ 종목 수만큼 개별 호출이 늘어남 (call()에 150ms 딜레이 내장) — 응답 시간 길어지면 다음 세션에서 최적화 필요
  const matchedFlowCodes = new Set();
  for (const raw of [foreignBuyTotal, foreignSellTotal, instBuyTotal, instSellTotal]) {
    for (const row of extractOutputArray(raw)) {
      if (row?.mksc_shrn_iscd) matchedFlowCodes.add(row.mksc_shrn_iscd);
    }
  }
  const priceOverrideMap = await fetchPricesConcurrently([...matchedFlowCodes], call);

  return {
    kospi, kosdaq, kospiFlow, kosdaqFlow,
    shortSaleTopKospi, shortSaleTopKosdaq, creditBalanceTopKospi, creditBalanceTopKosdaq,
    marketFunds, conditionResults,
    foreignBuyTotal, foreignSellTotal, instBuyTotal, instSellTotal, priceOverrideMap, creditPriceOverrideMap,
  };
}

function pickFlow(flowRaw) {
  // 문서에는 output이 객체(object)라고 되어있었지만, 실제 응답은 배열(array) 안에 객체 1개가 들어있는 구조였다.
  const raw = flowRaw?.output;
  const o = Array.isArray(raw) ? raw[0] : raw;
  if (!o || typeof o.frgn_ntby_qty === 'undefined') return null;
  return {
    foreign: { qty: o.frgn_ntby_qty ?? null, amount: o.frgn_ntby_tr_pbmn ?? null },
    individual: { qty: o.prsn_ntby_qty ?? null, amount: o.prsn_ntby_tr_pbmn ?? null },
    institution: { qty: o.orgn_ntby_qty ?? null, amount: o.orgn_ntby_tr_pbmn ?? null },
  };
}

// ------------------------------------------------------------
// 변동금액(전일대비 금액) 계산
// - KIS 응답에 prdy_vrss(전일대비, 보통 부호 없는 절대값) + prdy_vrss_sign(1상한/2상승/3보합/4하한/5하락)이
//   있으면 그걸로 부호를 정확히 결정
// - 혹시 필드명이 다르거나 없는 경우를 대비해, 현재가·등락률로 역산하는 fallback도 넣어둠
//   (역산은 반올림 특성상 실제 값과 1원 정도 오차가 날 수 있음 — 화면 표시용으로는 무방)
// ------------------------------------------------------------
function computeChangeAmount(r) {
  const raw = r.prdy_vrss;
  if (raw !== undefined && raw !== null && raw !== '') {
    const magnitude = Math.abs(Number(raw));
    if (!isNaN(magnitude)) {
      const sign = r.prdy_vrss_sign;
      if (sign === '4' || sign === '5') return -magnitude;
      if (sign === '1' || sign === '2') return magnitude;
      // 부호 필드가 없거나 예상 밖 값이면 등락률 부호를 따라감
      const pct = Number(r.prdy_ctrt);
      if (!isNaN(pct)) return pct < 0 ? -magnitude : magnitude;
      return magnitude;
    }
  }
  // prdy_vrss 필드 자체가 없을 때의 fallback: 현재가/등락률로 역산
  const price = Number(r.stck_prpr);
  const pct = Number(r.prdy_ctrt);
  if (isNaN(price) || isNaN(pct)) return null;
  const prevClose = price / (1 + pct / 100);
  return Math.round(price - prevClose);
}

function mapMarketCredit(marketFundsRaw) {
  const rows = marketFundsRaw?.output;
  if (!Array.isArray(rows) || rows.length === 0) return null;
  const latest = rows[0]; // 응답이 날짜 내림차순이라 [0]이 최신
  const prevRow = rows[1];
  const latestVal = Number(latest.crdt_loan_rmnd); // 억원
  const prevVal = prevRow ? Number(prevRow.crdt_loan_rmnd) : NaN;
  const hasChange = !isNaN(latestVal) && !isNaN(prevVal) && prevVal !== 0;
  return {
    date: latest.bsop_date,
    creditLoanBalance: isNaN(latestVal) ? null : latestVal, // 억원
    change: hasChange ? Math.round(latestVal - prevVal) : null, // 억원
    changePct: hasChange ? ((latestVal - prevVal) / prevVal) * 100 : null,
    custDeposit: Number(latest.cust_dpmn_amt) || null, // 억원, 고객예탁금
    unsettledAmt: Number(latest.uncl_amt) || null, // 억원, 미수금
  };
}

// ------------------------------------------------------------
// 공매도 상위 / 신용잔고 상위 API 응답의 "기준일자" 추출
// - 공매도 상위(국내주식-133): 각 row에 stnd_date1/2가 있는데, 예시상 첫 row만 값이 차있고
//   나머지는 "0"으로 오는 경우가 있어 방어적으로 0이 아닌 첫 값을 찾음
// - 신용잔고 상위(국내주식-109): output1이라는 별도 요약 object에 stnd_date1(매매기준일),
//   stnd_date2(공표/집계기준일)가 있고, 실제로 2일 차이가 나는 경우가 있음(T+2 정산 구조로 추정)
// ------------------------------------------------------------
function extractShortSaleAsOf(shortSaleRaw) {
  const rows = shortSaleRaw?.output ?? [];
  const found = rows.find((r) => r.stnd_date1 && r.stnd_date1 !== '0');
  return found ? found.stnd_date1 : null;
}
function extractCreditAsOf(creditRaw) {
  const summary = creditRaw?.output1?.[0];
  if (!summary) return null;
  return {
    tradeDate: summary.stnd_date1 || null,   // 기준 일자1 (매매기준일로 추정)
    publishDate: summary.stnd_date2 || null, // 기준 일자2 (공표/집계기준일로 추정, 매매기준일보다 며칠 뒤인 경우 있음)
  };
}

function normalizeAntData(raw) {
  const mapVolumeRow = (r) => ({
    name: r.hts_kor_isnm, code: r.mksc_shrn_iscd, price: r.stck_prpr, change: computeChangeAmount(r), changePct: r.prdy_ctrt, volume: r.acml_vol,
  });
  const mapFluctRow = (r) => ({
    name: r.hts_kor_isnm, code: r.stck_shrn_iscd, price: r.stck_prpr, change: computeChangeAmount(r), changePct: r.prdy_ctrt, volume: r.acml_vol,
  });
  const mapShortSaleRow = (r) => ({
    name: r.hts_kor_isnm, code: r.mksc_shrn_iscd, price: r.stck_prpr, change: computeChangeAmount(r), changePct: r.prdy_ctrt,
    shortVolumeRatio: r.ssts_vol_rlim, // 당일 거래량 대비 공매도 비중(%)
    shortValue: r.ssts_tr_pbmn,        // 공매도 거래대금 (원 단위 — 검증 완료, 그대로 사용)
  });
  const creditPriceMap = raw.creditPriceOverrideMap || {};
  const mapCreditRow = (r) => {
    const override = creditPriceMap[r.mksc_shrn_iscd];
    const loanBalanceAmtWon = Number(r.whol_loan_rmnd_amt) * 10000; // 만원 → 원
    let marketCapBasedRate = null;
    if (override?.marketCap) {
      const marketCapWon = override.marketCap * 100000000; // 억원 → 원
      if (marketCapWon > 0) marketCapBasedRate = (loanBalanceAmtWon / marketCapWon) * 100;
    }
    return {
      name: r.hts_kor_isnm, code: r.mksc_shrn_iscd, price: r.stck_prpr, change: computeChangeAmount(r), changePct: r.prdy_ctrt,
      loanBalanceAmt: r.whol_loan_rmnd_amt, // ⚠️ 만원(10,000원) 단위! 원 단위 아님 (검증 완료) — 프론트에서 /10000 해서 억원 변환
      loanBalanceRate: r.whol_loan_rmnd_rate, // 신용잔고 비율(%) — 상장주식수 대비 (KRX 공식 정의)
      marketCapBasedRate, // 신용잔고금액 ÷ 실시간 시가총액 비율(%) — 참고용 보조 지표 (2026-08 추가), 시총 실시간 조회 실패 시 null
    };
  };
  const mapMarketCapRow = (r) => ({
    name: r.hts_kor_isnm, code: r.mksc_shrn_iscd, price: r.stck_prpr, change: computeChangeAmount(r), changePct: r.prdy_ctrt,
    marketCap: r.stck_avls, // 이미 억원 단위로 옴 (추가 변환 불필요, 검증 완료)
    weightPct: r.mrkt_whol_avls_rlim,
  });

  return {
    updatedAt: Date.now(),
    indices: {
      kospi: raw.kospi?.output1 ? {
        value: raw.kospi.output1.bstp_nmix_prpr, change: raw.kospi.output1.bstp_nmix_prdy_vrss,
        changePct: raw.kospi.output1.bstp_nmix_prdy_ctrt,
      } : null,
      kosdaq: raw.kosdaq?.output1 ? {
        value: raw.kosdaq.output1.bstp_nmix_prpr, change: raw.kosdaq.output1.bstp_nmix_prdy_vrss,
        changePct: raw.kosdaq.output1.bstp_nmix_prdy_ctrt,
      } : null,
    },
    flowByMarket: {
      kospi: pickFlow(raw.kospiFlow),
      kosdaq: pickFlow(raw.kosdaqFlow),
    },
    marketCredit: mapMarketCredit(raw.marketFunds), // 시장 전체 신용잔고 합계 (종목 순위 아님)
    dataAsOf: {
      // ⚠️ 코스피/코스닥 중 하나가 비어있을 수 있어(휴장 등) 둘 다 확인해서 값이 있는 쪽 사용
      shortSale: extractShortSaleAsOf(raw.shortSaleTopKospi) || extractShortSaleAsOf(raw.shortSaleTopKosdaq),
      creditBalance: extractCreditAsOf(raw.creditBalanceTopKospi) || extractCreditAsOf(raw.creditBalanceTopKosdaq),
    },
    // 공매도/신용잔고는 여전히 KIS 순위분석 API(다음조회 불가, 최대 30건)를 써서 시장당 TOP30이 상한
    // (2026-09 변경) 코스피·코스닥 분리 호출로 바뀜: FID_COND_MRKT_DIV_CODE를 KSP/KSQ로 나눠서 각각 호출.
    //   ⚠️ 이 시장구분 값이 이 API에서 실제로 통하는지는 배포 후 응답을 직접 봐야 확실함(검증 전 상태).
    //   안 통하면(코스피/코스닥 응답이 똑같거나 하나가 텅 비면) FID_COND_MRKT_DIV_CODE: 'UN' 통합 방식으로 롤백할 것.
    //
    // 기존 프론트엔드 호환을 위해 shortSaleTop/creditBalanceTop은 코스피+코스닥을 합쳐 재정렬한
    // "통합 TOP30"을 그대로 유지하고, 시장별로 나눠 보고 싶을 때 쓸 수 있게
    // shortSaleTopByMarket / creditBalanceTopByMarket을 새로 추가함 (각 시장 TOP30, 최대 60건).
    shortSaleTop: [
      ...(raw.shortSaleTopKospi?.output ?? []),
      ...(raw.shortSaleTopKosdaq?.output ?? []),
    ]
      .filter(isRegularStock)
      .sort((a, b) => Number(b.ssts_vol_rlim) - Number(a.ssts_vol_rlim)) // 공매도 비중 기준 직접 정렬 (API 자체 순서를 신뢰하지 않음)
      .slice(0, 30).map(mapShortSaleRow),
    shortSaleTopByMarket: {
      kospi: [...(raw.shortSaleTopKospi?.output ?? [])]
        .filter(isRegularStock)
        .sort((a, b) => Number(b.ssts_vol_rlim) - Number(a.ssts_vol_rlim))
        .slice(0, 30).map(mapShortSaleRow),
      kosdaq: [...(raw.shortSaleTopKosdaq?.output ?? [])]
        .filter(isRegularStock)
        .sort((a, b) => Number(b.ssts_vol_rlim) - Number(a.ssts_vol_rlim))
        .slice(0, 30).map(mapShortSaleRow),
    },
    creditBalanceTop: dedupeByCode([
      ...(raw.creditBalanceTopKospi?.output2 ?? []),
      ...(raw.creditBalanceTopKosdaq?.output2 ?? []),
    ]) // API가 종목을 중복으로 주는 경우가 있어 중복 제거 필수
      .filter(isRegularStock)
      .sort((a, b) => Number(b.whol_loan_rmnd_rate) - Number(a.whol_loan_rmnd_rate))
      .slice(0, 30).map(mapCreditRow),
    creditBalanceTopByMarket: {
      kospi: dedupeByCode(raw.creditBalanceTopKospi?.output2 ?? [])
        .filter(isRegularStock)
        .sort((a, b) => Number(b.whol_loan_rmnd_rate) - Number(a.whol_loan_rmnd_rate))
        .slice(0, 30).map(mapCreditRow),
      kosdaq: dedupeByCode(raw.creditBalanceTopKosdaq?.output2 ?? [])
        .filter(isRegularStock)
        .sort((a, b) => Number(b.whol_loan_rmnd_rate) - Number(a.whol_loan_rmnd_rate))
        .slice(0, 30).map(mapCreditRow),
    },
    // 아래는 종목조건검색(HTS에서 미리 만든 조건) 기반 TOP100 — 시가총액/거래량/등락률은 여기로 교체됨
    marketCapTop: (raw.conditionResults?.cap ?? []).filter(isRegularStockCS).slice(0, 50).map(mapConditionRow),
    volumeTop: (raw.conditionResults?.volume ?? []).filter(isRegularStockCS).slice(0, 50).map(mapConditionRow),
    fluctuationUpTop: (raw.conditionResults?.up ?? []).filter(isRegularStockCS).slice(0, 50).map(mapConditionRow),
    fluctuationDownTop: (raw.conditionResults?.down ?? []).filter(isRegularStockCS).slice(0, 50).map(mapConditionRow),
    // 신규(2026-07-14): 기관/외국인 순매수·순매도 — 정식 API(국내주식-037, foreign-institution-total)로 교체
    // (구 조건검색 방식은 금액 필드가 없어 검증 불가 + 정렬 기준 오류 있었음, 위 HANDOFF 참고)
    // ⚠️ 이 API는 실시간이 아니라 하루 4번(외국인 09:30/11:20/13:20/14:30, 기관 10:00/11:20/13:20/14:30)
    //    수기 집계 입력값 — 그 시각 사이엔 값이 그대로인 게 정상 동작임
    institutionBuyTop: applyPriceOverride(extractOutputArray(raw.instBuyTotal).map(mapForeignInstTotalRow).filter(isRegularStockCS).slice(0, 30), raw.priceOverrideMap),
    institutionSellTop: applyPriceOverride(extractOutputArray(raw.instSellTotal).map(mapForeignInstTotalRow).filter(isRegularStockCS).slice(0, 30), raw.priceOverrideMap),
    foreignBuyTop: applyPriceOverride(extractOutputArray(raw.foreignBuyTotal).map(mapForeignInstTotalRow).filter(isRegularStockCS).slice(0, 30), raw.priceOverrideMap),
    foreignSellTop: applyPriceOverride(extractOutputArray(raw.foreignSellTotal).map(mapForeignInstTotalRow).filter(isRegularStockCS).slice(0, 30), raw.priceOverrideMap),
  };
}

// 기관·외국인 "동시" 순매수/순매도 종목 — 두 리스트 모두에 있는 종목만 교집합으로 추출
// 정렬 기준: 기관금액+외국인금액 합산 절대값 큰 순 (얼마나 강하게 같은 방향으로 쏠렸는지)
function buildMatchedFlow(instList, foreignList) {
  const foreignByCode = new Map(foreignList.map((r) => [r.code, r]));
  const matched = [];
  for (const instRow of instList) {
    const foreignRow = foreignByCode.get(instRow.code);
    if (!foreignRow) continue;
    matched.push({
      code: instRow.code, name: instRow.name, price: instRow.price, change: instRow.change, changePct: instRow.changePct,
      institutionAmount: instRow.institutionNetBuyAmount, // 백만원
      foreignAmount: foreignRow.foreignNetBuyAmount,       // 백만원
    });
  }
  matched.sort((a, b) => (Math.abs(b.institutionAmount) + Math.abs(b.foreignAmount)) - (Math.abs(a.institutionAmount) + Math.abs(a.foreignAmount)));
  return matched;
}

function attachMatchedFlow(data) {
  data.matchedBuyTop = buildMatchedFlow(data.institutionBuyTop, data.foreignBuyTop);
  data.matchedSellTop = buildMatchedFlow(data.institutionSellTop, data.foreignSellTop);
  return data;
}

// ------------------------------------------------------------
// 실행부
// ------------------------------------------------------------
async function main() {
  const appKey = process.env.KIS_APP_KEY;
  const appSecret = process.env.KIS_APP_SECRET;
  if (!appKey || !appSecret) throw new Error('KIS_APP_KEY / KIS_APP_SECRET 환경변수가 없어요 (GitHub Secrets 확인)');
  if (!HTS_USER_ID) console.warn('[개미데이터] KIS_HTS_ID가 없어 시가총액·거래량·등락률(조건검색) 목록이 비어 있을 수 있어요');
  const withCredit = process.argv.includes('--credit');
  const t0 = Date.now();

  const token = await getAccessToken(appKey, appSecret);
  const raw = await fetchAntDataSnapshot(appKey, appSecret, token);
  const data = attachMatchedFlow(normalizeAntData(raw));

  // 지수 응답이 비면(점검·장애) 기존 파일을 덮어쓰지 않음 — 빈 화면 방지
  if (!data.indices?.kospi && !data.indices?.kosdaq) throw new Error('지수 데이터가 비어 있어 저장을 건너뜀');
  writeJson('antdata.json', { ok: true, cached: true, data });

  // 기관/외국인 TOP5 날짜별 아카이브 (TOP5 조회 페이지용) — 오늘이 실제 거래일일 때만 저장
  const todayStr = todayKST();
  const lastTradeDate = raw.kospi?.output2?.[0]?.stck_bsop_date;
  if (!lastTradeDate || lastTradeDate === todayStr) {
    writeJson(`flow-archive/${todayStr}.json`, { ok: true, data: {
      date: todayStr, updatedAt: data.updatedAt,
      institutionBuyTop5: (data.institutionBuyTop ?? []).slice(0, 5),
      institutionSellTop5: (data.institutionSellTop ?? []).slice(0, 5),
      foreignBuyTop5: (data.foreignBuyTop ?? []).slice(0, 5),
      foreignSellTop5: (data.foreignSellTop ?? []).slice(0, 5),
    } });
  } else {
    console.log(`[개미데이터] 오늘(${todayStr})은 거래일이 아니라 TOP5 아카이브 저장 생략 (최근 거래일 ${lastTradeDate})`);
  }

  if (withCredit) {
    const series = await fetchCreditTrendHistory(appKey, appSecret, await getAccessToken(appKey, appSecret));
    if (series.length > 0) writeJson('credit-trend.json', { ok: true, cached: true, data: { updatedAt: Date.now(), series } });
    console.log(`[개미데이터] 신용잔고 추이 ${series.length}일치 저장`);
  }
  console.log(`[개미데이터] 수집 완료 (${((Date.now() - t0) / 1000).toFixed(1)}초)`);
}

main().catch((err) => { console.error('[개미데이터] 수집 실패:', err.message); process.exit(1); });
