# domain_monitoring_v3


---

# 도메인 모니터링 대시보드

사내 도메인 자산을 **가시화**하고, **SSL 이슈** 및 **방치/미사용** 도메인을 조기에 식별하는 웹 기반 대시보드입니다.
PRD(2025-08) 기준으로 설계되었으며, **밝은 테마**, **클라이언트 단독 실행(정적 호스팅)** 을 기본으로 합니다.

## TL;DR (빠른 시작)

```bash
# 1) 저장소 클론 후, 프로젝트 루트에서 간단 서버 실행
python3 -m http.server 8000

# 2) 브라우저 접속
# http://<서버IP>:8000/Domain_Monitoring_v3.html?date=YYYYMMDD
# (또는 data/dates.json 제공 시 드롭다운에서 선택)
```

---

## 1. 주요 기능 (PRD 매핑)

* **KPI 카드 7종**: 총 도메인 / 인증서 만료(만료·7일·30일) / CN·SAN 불일치 / 점검 필요 / 캡처 실패(CSV 다운로드) / 서비스 중지 검토(TLS 핸드셰이크 실패) / 정상(비율)
* **필터**: 점검 날짜, 도메인 멀티선택, CNAME 포함/깊이, 상태(정상/경고/위험/점검필요/중지검토), 스크린샷 응답코드(2xx/3xx/4xx/5xx/텍스트만/오류)
* **도메인 탭**: 표 + 액션(🔍 RAW 보기, 🖼 스크린샷 모달, 🚫/✅ Ignore 토글)
* **스크린샷 탭**: 그리드 + 확대 모달, HTTP 코드 필터, 이미지/RAW/Ignore 액션, (비교 기능 hook 포함)
* **SSL 뷰어 탭**: 발급자/유효기간/CN·SAN/알고리즘/체인/불일치 표 + 상세 모달 hook
* **Ignore 관리**: `output/ignore.json` 로드/저장(UI에서 불러오기/다운로드)

---

## 2. 폴더 구조

```
css/
data/
  <YYYYMMDD>/
    lge.com.csv
    lge.co.kr.csv
    lgthinq.com.csv
    CNAME_lge.com.csv
    CNAME_lge.co.kr.csv
    CNAME_lgthinq.com.csv
    ssl_audit_lge.com.csv
    ssl_audit_lge.co.kr.csv
    ssl_audit_lgthinq.com.csv
    ssl_audit_CNAME_lge.com.csv
    ssl_audit_CNAME_lge.co.kr.csv
    ssl_audit_CNAME_lgthinq.com.csv
  dates.json            # (선택) 최근 스냅샷 목록
images/
  img.lge.com/<YYYYMMDD>/*.png
  img.lge.co.kr/<YYYYMMDD>/*.png
  img.lgthinq.com/<YYYYMMDD>/*.png
  # 실패 목록
  img.<domain>/<YYYYMMDD>/failures.csv
js/
  images/               # 스크린샷 경로/비교 로직
  table/                # 정렬/페이지/CSV Export
  ui/                   # 앱/필터/KPI/그리드/모달
output/
  ignore.json           # Ignore 목록(뷰어에서 토글/저장)
tool/                   # (예) audit_domain_ssl_certs.py 등
Domain_Monitoring_v3.html
```

**스크린샷 파일명 규칙**
`<inputHost>_to_<finalHost>_YYYYMMDD_HHMMSS.png`
예) `ehtls.lge.co.kr_to_ehtls.lge.co.kr_20250828_134705.png`

---

## 3. 데이터 컨트랙트

대시보드는 서로 다른 CSV를 읽어 **단일 내부 스키마**로 맵핑합니다.

### 3.1 입력 CSV 파일

* **도메인 리스트**: `data/<DATE>/<domain>.csv`
* **CNAME 리스트**: `data/<DATE>/CNAME_<domain>.csv`
* **SSL 감사(메인)**: `data/<DATE>/ssl_audit_<domain>.csv`
* **SSL 감사(CNAME)**: `data/<DATE>/ssl_audit_CNAME_<domain>.csv`
* **캡처 실패 목록**: `images/img.<domain>/<DATE>/failures.csv`

> 실제 컬럼명은 환경에 따라 다를 수 있습니다. 아래 표는 **권장 헤더** 예시이며, 로더는 흔한 별칭도 휴리스틱으로 인식합니다.

#### (A) 도메인/ CNAME CSV 권장 헤더

| column         | 예시                       | 비고                                        |              |
| -------------- | ------------------------ | ----------------------------------------- | ------------ |
| `domain`       | `sub.a.lge.com`          | 없으면 `host`/`hostname`/`final_url_host` 사용 |              |
| `ip`           | `1.2.3.4`                | 복수 IP면 콤마                                 |              |
| `http_status`  | `200`                    | 또는 `http_status_final`                    |              |
| `response_ms`  | `1234`                   | 또는 `latency_ms`,`response_time`           |              |
| `last_checked` | `2025-08-29T12:34:56Z`   | ISO8601 권장                                |              |
| `cname_chain`  | `a.lge.com -> b.cdn.net` | `>`, \`                                   | \`, 공백 구분 허용 |

#### (B) SSL 감사 CSV 권장 헤더

| column             | 예시                     | 비고                                      |
| ------------------ | ---------------------- | --------------------------------------- |
| `host`             | `sub.a.lge.com`        | 또는 `domain`,`hostname`,`final_url_host` |
| `tls_handshake_ok` | `true/false`           | 문자열 `ok/true/1` 지원                      |
| `issuer_cn`        | `R3`                   | 또는 `cert_issuer`                        |
| `cert_subject_cn`  | `*.lge.com`            | 또는 `cert_cn`                            |
| `cert_san_list`    | `a.lge.com, *.lge.com` | 공백/콤마/세미콜론 분리                           |
| `not_before_utc`   | `2025-06-01T00:00:00Z` | 또는 `valid_from_utc`                     |
| `not_after_utc`    | `2026-06-01T00:00:00Z` | 또는 `valid_to_utc`                       |
| `days_to_expiry`   | `274`                  | 없으면 UI에서 계산                             |
| `signature_algo`   | `RSA-SHA256`           | 또는 `cert_algo`                          |
| `chain_ok`         | `true/false`           |                                         |

#### (C) failures.csv 권장 헤더

| column      | 예시                        | 비고 |
| ----------- | ------------------------- | -- |
| `url`       | `https://foo.lge.com`     |    |
| `reason`    | `timeout/network/tls/...` |    |
| `message`   | 에러 원문                     |    |
| `timestamp` | `2025-08-29T03:21:00Z`    |    |

### 3.2 내부 통합 스키마(요약)

```json
{
  "domain": "sub.a.lge.com",
  "is_cname": true,
  "cname_chain": ["a.lge.com", "b.cdn.net"],
  "ip": "1.2.3.4",
  "last_checked": "2025-08-29T12:34:56Z",
  "http_status": 200,
  "response_ms": 1234,

  "tls_handshake_ok": true,
  "cert_issuer": "R3",
  "cert_cn": "*.lge.com",
  "cert_san": ["a.lge.com","*.lge.com"],
  "valid_from_utc": "2025-06-01T00:00:00Z",
  "valid_to_utc": "2026-06-01T00:00:00Z",
  "days_to_expiry": 274,
  "cert_algo": "RSA-SHA256",
  "chain_ok": true,
  "cn_san_mismatch": false,

  "has_screenshot": true,
  "screenshot_type": "normal",
  "screenshot_path": "images/img.lge.com/20250829/....png",

  "status": "정상",
  "ignored": false
}
```

---

## 4. 상태 정의(표시 로직)

* **중지검토**: `tls_handshake_ok === false`
* **위험**: 만료(`days_to_expiry < 0`) 또는 `chain_ok === false`
* **경고**: 만료 임박(`days_to_expiry ≤ 30`) 또는 `cn_san_mismatch === true`
* **점검필요**: 스크린샷 없음/핵심지표 결측/텍스트만(후속 감지 로직 연동)
* **정상**: 위 조건 미해당 + 스크린샷 존재

---

## 5. 실행 방법

### 5.1 로컬 서버

```bash
python3 -m http.server 8000   # 루트에서 실행
# Windows PC에서 접속: http://<우분투IP>:8000/Domain_Monitoring_v3.html?date=YYYYMMDD
```

* `data/dates.json` 제공 시 날짜 드롭다운 활성화. (예: `["20250814","20250825","20250829"]`)

### 5.2 n8n/크론 파이프라인(선택)

* SSL 스캔 예시:

```bash
python3 tool/audit_domain_ssl_certs.py --date YYYYMMDD --tls-timeout 5 --http-timeout 6
# 결과물은 data/<DATE> 및 images/... 구조에 저장
```

* **n8n 컨테이너에서 python3 미존재 시**:

  * `Dockerfile` 예시:

    ```dockerfile
    FROM n8nio/n8n:latest
    USER root
    RUN apt-get update && apt-get install -y python3 python3-pip && rm -rf /var/lib/apt/lists/*
    USER node
    ```
  * 또는 별도 사이드카 컨테이너로 실행 후 볼륨 공유.

---

## 6. UI 규범(Style Guide)

* 테마: **밝은 배경(카드 흰색, 소프트 섀도우)**
* `.badge { font-weight: 500; }` (**bold 금지**)
* 레이블 통일: “인증서 재발급 검토” → **“인증서 재발급”**
* 버튼 순서 합의: **‘불일치’** 버튼은 **‘Manual’** 앞에 배치
* 스크린샷 탭: 도메인 필터 대신 **HTTP 응답코드 필터** 사용

---

## 7. 설정 상수 (경로)

```js
export const PATHS = {
  dataRoot: (date) => `data/${date}/`,
  csv:  (date, domain) => `data/${date}/${domain}.csv`,
  cnameCsv: (date, domain) => `data/${date}/CNAME_${domain}.csv`,
  sslCsv: (date, domain) => `data/${date}/ssl_audit_${domain}.csv`,
  sslCnameCsv: (date, domain) => `data/${date}/ssl_audit_CNAME_${domain}.csv`,
  shotsRoot: (domain) => `images/img.${domain}/`,
  shots: (domain, date) => `images/img.${domain}/${date}/`,
  failsCsv: (domain, date) => `images/img.${domain}/${date}/failures.csv`,
  ignoreJson: `output/ignore.json`,
};
export const SHOT_NAME_RE =
/^(?<input>.+)_to_(?<final>.+)_(?<date>\d{8})_(?<time>\d{6})\.png$/;
```

---

## 8. Ignore 사용법

* **표시**: 도메인/스크린샷 그리드에 `Ignored` 배지
* **토글**: 각 행/타일의 🚫/✅ 버튼
* **저장**: 우상단 **“ignore.json 다운로드”** 버튼 → `output/ignore.json` 교체
* **불러오기**: **“ignore.json 불러오기”** 버튼으로 로컬 파일 업로드

`ignore.json` 포맷:

```json
{ "domains": ["foo.lge.com", "bar.lgthinq.com"] }
```

---

## 9. 자주 묻는 질문(FAQ)

**Q. 스크린샷이 안 보입니다.**
A. `images/img.<domain>/<date>/` 경로가 맞는지, 파일명이 규칙에 부합하는지 확인하세요. `python3 -m http.server`의 디렉터리 인덱스에서 PNG 링크가 노출되어야 합니다.

**Q. n8n에서 `python3: not found` 오류가 발생합니다.**
A. n8n 공식 이미지에는 Python이 없습니다. 위 **Dockerfile 예시**처럼 설치하거나 사이드카 컨테이너로 파이프라인을 분리하세요.

**Q. 날짜가 드롭다운에 안 보입니다.**
A. `data/dates.json`을 제공하거나, URL에 `?date=YYYYMMDD`를 명시하세요.

**Q. CNAME 포함/깊이는 어떻게 동작하나요?**
A. `CNAME_<domain>.csv` 및 `ssl_audit_CNAME_<domain>.csv`를 로드하여 CNAME 행을 추가하고, 토글과 깊이값으로 뷰어에 표시/제외합니다.

---

## 10. 로드맵

* [ ] **텍스트만 스크린샷** 자동 식별(OCR/히ュー리스틱)
* [ ] **연속 실패 기간** 계산(스냅샷 비교)
* [ ] **이전 스냅샷 비교 뷰**(그리드 좌우 비교)
* [ ] **알림/구독**: 만료 임박/체인 오류 Webhook
* [ ] **Export**: 도메인/SSL 테이블 내보내기 버튼
* [ ] **성능 최적화**: 가상 스크롤, CSV 스트리밍 파서

---

