# MVP 개발 스펙 — AI Agent 보안·컴플라이언스 데이터 플레인 (Phase 0)

> 목적: 이 문서는 **코딩 에이전트가 그대로 구현할 수 있도록** 작성된 MVP 명세다.
> 모든 결정은 구체적이며, 모호한 부분은 "결정 필요(CONFIRM)"로 표시했다.

---

## 0. 한 줄 정의

어떤 AI 에이전트든(노코드 포함) **모델 API 호출 경로 앞단에 드롭인**으로 끼워, 입출력 위협을 차단하고 모든 호출을 **OWASP ASI 항목으로 태깅한 감사 로그**로 남기는, **단독 실행 가능한 데이터 플레인**.

포지셔닝 원칙: "보안은 쉽다"가 아니라 **"보안을 쉽게 만들어준다"**. 깊이(다층 방어)는 제거하지 않고 좋은 기본값 뒤로 숨긴다.

---

## 1. MVP 범위

### 1.1 In scope (이번에 만든다)

- **G — Gateway**: OpenAI / Anthropic 호환 리버스 프록시 (`base_url` 교체로 드롭인)
- **I — Input guardrails**: 프롬프트 인젝션/탈옥 탐지, 입력 PII·시크릿 탐지
- **O — Output guardrails (DLP)**: 출력 PII 마스킹, 시크릿 누출 차단
- **A — Audit log**: 모든 요청/응답을 ASI 태깅하여 영구 저장 + JSON/CSV export
- **P — Policy engine**: 선언적 YAML 정책 (scanner on/off, threshold, action)
- **D — Dashboard**: 로컬 단일 페이지 — 라이브 이벤트, ASI 분포, 로그 검색/내보내기
- **X — Demo attack injector**: 첫 aha를 강제하는 샘플 공격 주입기
- **배포**: 단일 `docker run` 한 줄로 기동

### 1.2 Out of scope (Phase 1 이후, 만들지 않는다)

- 에이전트 방화벽 / MCP·네트워크 egress 통제 (Phase 1)
- SaaS 컨트롤 플레인, 멀티테넌시, 원격 정책 배포 (관리형 티어)
- 국가별 컴플라이언스 모듈, 규제 자동 매핑 자산 (Phase 3)
- RBAC / SSO / 사용자 관리
- 프레임워크별 SDK 어댑터 (Phase 1.5)
- 자동 정책 튜닝, 위협 인텔 피드

---

## 2. 핵심 기술 결정 (코딩 에이전트는 이 스택을 사용)

| 항목         | 결정                                               | 비고                                                 |
| ---------- | ------------------------------------------------ | -------------------------------------------------- |
| 언어/런타임     | Python 3.11+                                     | guardrail OSS 생태계 직접 사용                            |
| 웹 프레임워크    | FastAPI + Uvicorn                                | async 프록시                                          |
| 배포         | Docker 이미지 (`docker run` 단일 컨테이너)                | "단일 바이너리"의 MVP 형태. 진짜 Go 정적 바이너리는 post-MVP         |
| 저장소        | SQLite (WAL 모드, 임베디드)                            | 외부 의존성 0 — self-host 철학                            |
| PII 탐지/마스킹 | Microsoft Presidio (analyzer + anonymizer)       |                                                    |
| 프롬프트 인젝션   | LLM Guard `PromptInjection` 스캐너 (로컬 HF 모델)       | 예: `protectai/deberta-v3-base-prompt-injection-v2` |
| 시크릿 탐지     | LLM Guard `Secrets` 스캐너                          | 자격증명 누출                                            |
| 대시보드       | 서버 렌더 HTML + HTMX (또는 vanilla JS) + SSE 라이브 tail | 무거운 SPA 금지                                         |
| 설정         | `config.yaml` + 환경변수(업스트림 키)                     |                                                    |

**CONFIRM-1**: 언어를 Go(진짜 단일 정적 바이너리)로 갈지, MVP 속도를 위해 Python+Docker로 갈지. 본 스펙은 **Python+Docker**를 가정. (Go 전환은 데이터 플레인 안정화 후 별도 과제)

**CONFIRM-2**: 모델 기반 인젝션 스캐너는 CPU에서 100~200ms 지연이 발생할 수 있음. MVP 기본값은 ON. 지연이 문제면 룰베이스 1차 + 모델 2차의 2단계 캐스케이드로 전환(스펙 §7.3).

---

## 3. 아키텍처 개요

### 3.1 배포 토폴로지

- 데이터 플레인 전체가 **고객 환경 안**(로컬/VPC/온프레)에서 단일 컨테이너로 동작.
- 민감 데이터(프롬프트·PII·자격증명)는 **컨테이너 경계를 벗어나지 않는다** (업스트림 모델 API 호출 제외).
- 외부 네트워크 의존: **업스트림 모델 API 1곳뿐**. 그 외 어떤 외부 전송도 없음(개인정보 보호 기본).

### 3.2 요청 처리 플로우

```
[Agent / no-code platform]
   │  (base_url = http://gateway:8080/v1)
   ▼
┌─────────────────────────────────────────────┐
│  GATEWAY (FastAPI proxy)                     │
│   1. 요청 파싱 (OpenAI/Anthropic schema)     │
│   2. INPUT guardrails  → policy decision     │  ── block/flag/redact ──┐
│   3. (통과 시) 업스트림 모델 API 호출        │                         │
│   4. OUTPUT guardrails → policy decision     │  ── redact/flag ──┐     │
│   5. AUDIT log 기록 (ASI 태깅)               │                   │     │
│   6. 응답 반환                               │                   ▼     ▼
└─────────────────────────────────────────────┘            [Audit store / Dashboard]
```

- 차단(block) 시: 업스트림 호출 없이 표준 오류 응답 반환 + 감사 기록.
- 마스킹(redact) 시: 변형된 페이로드로 진행 + 원본/변형 모두 감사 기록(원본 스니펫은 마스킹 저장).

---

## 4. 컴포넌트 명세

### 4.1 Gateway (G)

- 엔드포인트(업스트림 호환, 드롭인 목적):
  - `POST /v1/chat/completions` (OpenAI 호환) — **우선순위 1**
  - `POST /v1/messages` (Anthropic 호환) — **우선순위 2**
- 업스트림 라우팅: `config.yaml`의 `upstreams`에서 모델→provider 매핑. API 키는 환경변수.
- 스트리밍(SSE): passthrough 지원.
  - 입력 가드레일: 스트리밍 여부와 무관하게 **항상** 적용.
  - 출력 가드레일: 비스트리밍은 완전 적용. **스트리밍은 buffer-then-scan-then-emit**(전체 버퍼링 후 스캔)을 목표로 하되, MVP 1차에서는 스트리밍 출력 DLP를 "best-effort + 감사기록"으로 두고 §11 M0.7에서 강화. (스펙에 명시적 한계로 표기할 것)
- 헤더/메타: 클라이언트 식별용 `X-Request-Id` 부여(없으면 생성). **PII는 URL/쿼리스트링에 절대 넣지 않는다.**

### 4.2 Guardrail engine (I / O)

- 입력 스캐너: `prompt_injection`, `pii`, `secrets`.

- 출력 스캐너: `pii`, `secrets`.

- 각 스캐너는 공통 인터페이스 구현:
  
  ```python
  class Scanner(Protocol):
      name: str
      def scan(self, text: str, ctx: ScanContext) -> ScanResult: ...
  # ScanResult: { detected: bool, score: float, asi_id: str,
  #               severity: "low|medium|high", spans: list[Span] }
  ```

- 스캐너는 플러그형(레지스트리 등록). **OSS 엔진 교체 가능하도록 추상화**할 것(인수·아카이브 리스크 흡수가 제품 가치).

### 4.3 Policy engine (P)

- 정책은 `config.yaml`에서 로드(§6.2).
- 각 스캐너별 `action`: `block` | `redact` | `flag` | `off`, 그리고 `threshold`(score 컷).
- 에러 동작(`on_error`): `fail_open`(트래픽 유지) | `fail_closed`(차단). **기본값 = `fail_open`**(MVP에서 고객 트래픽을 끊지 않음). 단, 대시보드에 에러 명확히 표시.
- 탐지 액션과 에러 동작은 **별개 개념**으로 분리 구현.

### 4.4 Audit store (A)

- SQLite, WAL. 테이블 스키마 §6.1.
- 모든 요청/응답 1건 = 이벤트 N개(입력 결정 + 출력 결정).
- export: `GET /audit/export?format=json|csv&from=&to=` — ASI 태그 포함.

### 4.5 Dashboard (D)

- 로컬 `GET /` 단일 페이지.
- 구성: (a) 라이브 이벤트 tail(SSE), (b) ASI 항목별 카운트, (c) 차단/마스킹 이벤트 리스트, (d) 로그 검색 + export 버튼.
- 무인증(로컬 전용 가정). 외부 노출 시 경고 배너.

### 4.6 Demo attack injector (X)

- `POST /demo/inject` 또는 CLI `python -m app.demo` 로 샘플 공격(인젝션 문자열, 합성 SSN/이메일 포함 응답 유도)을 흘려 **첫 차단/마스킹 이벤트를 즉시 생성**.
- quickstart의 마지막 단계로 호출되어 "5분 안의 첫 aha"를 보장(§12 AT-5).

---

## 5. ASI ↔ 스캐너 매핑 (감사 태깅 기준)

| 탐지            | 매핑 ASI / LLM                              | severity 기본 |
| ------------- | ----------------------------------------- | ----------- |
| 프롬프트 인젝션 / 탈옥 | ASI01 (Goal Hijack) + LLM01               | high        |
| 출력 PII 누출     | LLM02 (Sensitive Info Disclosure) / ASI09 | medium      |
| 입출력 시크릿/자격증명  | ASI03 (Identity & Privilege Abuse)        | high        |

> MVP는 위 3종만 정직하게 태깅한다. ASI02/04/05/06/07/08/10은 Phase 1+에서 추가(표에 "planned"로만 노출).

---

## 6. 데이터 모델

### 6.1 Audit event 스키마 (SQLite `audit_events`)

| 컬럼             | 타입              | 설명                                                             |
| -------------- | --------------- | -------------------------------------------------------------- |
| id             | TEXT (uuid)     | PK                                                             |
| ts             | TEXT (ISO8601)  | 발생 시각                                                          |
| request_id     | TEXT            | 동일 호출 묶음 키                                                     |
| direction      | TEXT            | `input` \| `output`                                            |
| upstream_model | TEXT            | 대상 모델                                                          |
| scanners_run   | TEXT (json)     | 실행된 스캐너 목록                                                     |
| detections     | TEXT (json)     | `[{scanner, asi_id, severity, score, action, snippet_masked}]` |
| decision       | TEXT            | `allow` \| `block` \| `redact` \| `flag`                       |
| latency_ms     | INTEGER         | 가드레일 처리 지연                                                     |
| error          | TEXT (nullable) | 스캐너 에러 + on_error 동작                                           |
| client_meta    | TEXT (json)     | **PII 금지** (ip 해시, user-agent 등만)                              |

원문 저장 금지. 스니펫은 마스킹된 형태로만 저장.

### 6.2 `config.yaml` 예시

```yaml
server:
  port: 8080
  dashboard: true

upstreams:
  - match: "gpt-*"
    provider: openai
    base_url: "https://api.openai.com"
  - match: "claude-*"
    provider: anthropic
    base_url: "https://api.anthropic.com"

policy:
  on_error: fail_open        # fail_open | fail_closed
  input:
    prompt_injection: { action: block,  threshold: 0.8 }
    pii:              { action: flag,   threshold: 0.5 }
    secrets:          { action: block,  threshold: 0.5 }
  output:
    pii:              { action: redact, threshold: 0.5 }
    secrets:          { action: block,  threshold: 0.5 }

audit:
  store: "/data/audit.db"
  retention_days: 90
```

업스트림 API 키는 `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` 환경변수.

---

## 7. 비기능 요구 (Non-functional)

1. **지연(latency)**: 게이트웨이 자체 오버헤드(모델 기반 스캐너 제외) p95 < 20ms. 인젝션 모델 스캐너 포함 추가 지연 목표 CPU < 200ms / GPU < 50ms. 대시보드에 실측 노출.
2. **오탐(false-positive)**: 양성(benign) 100문장 코퍼스에서 FP < 2% (KPI, §12 AT-6). *오탐 높은 가드는 일주일 안에 꺼진다 — 이 지표가 리텐션의 생명줄.*
3. **프라이버시**: 업스트림 모델 API 외 외부 전송 0. 원문 비저장. PII 비-URL.
4. **배포 용이성**: `docker run -e OPENAI_API_KEY=... -p 8080:8080 <image>` 한 줄로 기동. 외부 DB·서비스 의존 0.
5. **가용성(fail mode)**: 스캐너 크래시가 고객 트래픽을 끊지 않음(기본 fail_open + 명시 로깅).
6. **이식성**: OSS 스캐너는 레지스트리 추상화 뒤 — 교체 가능.

---

## 8. API 명세 (요약)

| 메서드  | 경로                     | 용도               |
| ---- | ---------------------- | ---------------- |
| POST | `/v1/chat/completions` | OpenAI 호환 프록시    |
| POST | `/v1/messages`         | Anthropic 호환 프록시 |
| GET  | `/healthz`             | 헬스체크             |
| GET  | `/audit/events`        | 감사 조회(필터·페이지네이션) |
| GET  | `/audit/export`        | JSON/CSV 내보내기    |
| GET  | `/stats/asi`           | ASI 항목별 집계       |
| GET  | `/events/stream`       | SSE 라이브 tail     |
| POST | `/demo/inject`         | 샘플 공격 주입         |
| GET  | `/`                    | 대시보드             |

차단 응답은 업스트림 스키마와 호환되는 오류 형태(예: HTTP 200 + `choices`에 차단 메시지, 또는 4xx + 구조화된 `error`)로 — **CONFIRM-3**: 클라이언트 호환성을 위해 "200 + 안내 메시지" vs "4xx 차단" 중 선택. 기본값은 `403` + JSON error body, 헤더 `X-Guardrail-Decision: block`.

---

## 9. 권장 디렉터리 구조

```
app/
  main.py            # FastAPI 엔트리, 라우팅
  proxy/             # 업스트림 프록시 (openai.py, anthropic.py, stream.py)
  guardrails/        # scanner registry + presidio_pii.py, llmguard_injection.py, secrets.py
  policy/            # policy.py (action/threshold/on_error)
  audit/             # store.py (sqlite), schema.sql, export.py
  asi/               # mapping.py (scanner→ASI)
  dashboard/         # templates/, static/, sse.py
  demo/              # injector
config.yaml
Dockerfile
docker-compose.yml   # 로컬 개발용
tests/
README.md            # quickstart (5분 설치 → demo → 첫 이벤트)
```

---

## 10. 빌드 순서 (코딩 에이전트용 마일스톤 — 증분 검증 가능하게)

| 마일스톤 | 산출물                                                                            | 완료 증명                                   |
| ---- | ------------------------------------------------------------------------------ | --------------------------------------- |
| M0.1 | 프록시 골격: OpenAI/Anthropic passthrough, config 로드, 업스트림 포워딩, raw 요청/응답 SQLite 기록 | 에이전트가 프록시를 통해 정상 응답 수신 (AT-1)           |
| M0.2 | 감사 스키마 + 구조화 로깅 + `/audit/events`·`/audit/export`                              | export에 이벤트가 ASI 필드 포함 출력 (AT-4)        |
| M0.3 | 입력 가드레일: 인젝션 + PII + secrets, policy engine, ASI 태깅                            | 인젝션 문자열 차단·태깅 (AT-2)                    |
| M0.4 | 출력 가드레일/DLP: PII redact, secrets block                                         | 합성 SSN/이메일 응답 마스킹 (AT-3)                |
| M0.5 | 대시보드: 라이브 tail(SSE), ASI 분포, 검색/export UI                                      | 이벤트가 실시간 표시                             |
| M0.6 | demo injector + quickstart + Docker 패키징 + README                               | `docker run` → demo → 첫 이벤트 < 5분 (AT-5) |
| M0.7 | 하드닝: fail mode, 지연 튜닝, FP 코퍼스 테스트, config 검증, 스트리밍 출력 DLP 강화                   | AT-6, AT-7 통과                           |

---

## 11. 수용 기준 / 인수 테스트

- **AT-1 (passthrough)**: `base_url`을 프록시로 설정한 OpenAI SDK 호출이 정상 completion 반환.
- **AT-2 (injection)**: 알려진 인젝션 문자열 입력 시 `block`(또는 정책상 `flag`)되고, 대시보드에 수초 내 ASI01 태깅 이벤트 표시.
- **AT-3 (output DLP)**: 합성 SSN/이메일이 포함된 응답이 출력에서 마스킹되고 LLM02/ASI09로 기록.
- **AT-4 (audit export)**: JSON/CSV export가 ASI 태그 포함하여 생성.
- **AT-5 (time-to-first-aha)**: 새 `docker run` 후 번들 demo injector 실행 → 첫 이벤트 가시화까지 < 5분.
- **AT-6 (false-positive)**: benign 100문장에서 FP < 2%.
- **AT-7 (fail mode)**: 스캐너 강제 에러 주입 시 트래픽 미차단(fail_open) + 에러 로깅.
- **AT-8 (privacy)**: 네트워크 캡처에서 업스트림 모델 API 외 외부 송신 0건; 감사 DB에 원문 미저장 확인.

---

## 12. 열린 결정 (피드 전에 확인)

- **CONFIRM-1**: 런타임 Python+Docker(가정) vs Go 단일 바이너리.
- **CONFIRM-2**: 인젝션 스캐너 항상 ON vs 룰→모델 2단계 캐스케이드.
- **CONFIRM-3**: 차단 응답 형태(403 JSON vs 200+안내).
- **CONFIRM-4**: 인젝션 모델 라이선스/가중치 — `protectai/deberta-v3-base-prompt-injection-v2` 사용 가능 여부 및 상업적 라이선스 확인. (불가 시 대체 모델 또는 룰베이스 1차)

---

## 13. 이 MVP가 의도적으로 증명하려는 것

1. **드롭인 = 진짜 5분** (base_url 교체로 any-agent·노코드 커버)
2. **첫 5분 내 aha** (첫 차단/마스킹 이벤트가 보인다)
3. **compliance by design의 씨앗** (모든 호출이 ASI 태깅 감사 로그로 남고 export된다)
4. **낮은 오탐** (리텐션 KPI)

이 네 가지가 PLG 쐐기(개발자·SMB)와 비콘 고객(금융 VPC 데이터 플레인) 양쪽의 착지점을 동시에 만족시킨다.
