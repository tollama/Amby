# MVP 개발 스펙 — AI Agent 보안·컴플라이언스 데이터 플레인 (Phase 0~2.1)

> 목적: 이 문서는 **코딩 에이전트가 그대로 구현할 수 있도록** 작성된 MVP 명세다.
> 모든 결정은 구체적이며, 모호한 부분은 "결정 필요(CONFIRM)"로 표시했다.

---

## 0. 한 줄 정의

어떤 AI 에이전트든(노코드 포함) **모델 API 호출 경로, 도구 실행 직전, framework memory/RAG context 경계**에 드롭인으로 끼워, 입출력 위협과 과도한 도구 권한 및 컨텍스트 오염을 통제하고 모든 호출을 **OWASP ASI 항목으로 태깅한 감사 로그**로 남기는, **단독 실행 가능한 데이터 플레인**.

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
- **E — Evidence package**: report, manifest, audit export, hash chain, config snapshot, Mythos-ready matrix 생성/검증
- **M — Mythos-ready matrix**: CSA Mythos-ready priority action을 implemented / partial / planned 상태로 표시
- **F — Agent firewall**: 도구/API/MCP식 function call을 dispatch 전에 평가, egress/권한/승인/회로차단 증거 기록
- **H — Framework hooks**: LangGraph/CrewAI/LlamaIndex-style memory/RAG context hook 평가와 local MCP/plugin/skill discovery
- **R — Predeploy governance**: Garak/PyRIT/Promptfoo adapter, CI gate, AIBOM, predeploy evidence chain
- **S — Pre-production hardening**: deployment mode, dashboard/API token auth, production diagnostics, local evidence ledger
- **T — Pilot release pack**: production profile, policy/config hash evidence, JSONL/SIEM export, release gate, reviewer bundle
- **배포**: 단일 `docker run` 한 줄로 기동

### 1.2 Out of scope (Phase 1.5 이후, 만들지 않는다)

- Native framework package에 대한 deep monkey-patch/middleware 배포와 JavaScript SDK (Phase 2+)
- LLM-assisted PR/source code review runner와 vulnerability SLA/VulnOps workflow (Phase 2+)
- Signed inventory provenance, authoritative owner/RBAC registry (Phase 2.5)
- 관리형 team RBAC, SSO, virtual key 발급, 원격 정책 배포 (Phase 2.5)
- WORM/remote notarization, asymmetric signing, remote policy push, formal change workflow (Phase 2.5+)
- SaaS 컨트롤 플레인, 멀티테넌시, 원격 정책 배포 (관리형 티어)
- 국가별 컴플라이언스 모듈, 규제 자동 매핑 자산 (Phase 3)
- CSA Mythos-ready 전체 보안 프로그램 완성 주장. MVP는 evidence and model-boundary control seed까지만 주장한다.
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
- 외부 네트워크 의존: **업스트림 모델 API 1곳뿐**. 도구/API egress는 에이전트가 실행하기 전에 Amby가 정책 평가한다.

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

도구 실행 플로우:

```
[Agent runtime] ── tool call proposal ──▶ [Amby Agent Firewall]
     │                                      │
     │                                      ├─ inventory / owner / allowed_agents
     │                                      ├─ method/action risk
     │                                      ├─ egress allowlist
     │                                      ├─ circuit breaker
     │                                      └─ human approval status
     ◀──────── allow | block | approval_required ────────
```

Framework context hook 플로우:

```
[LangGraph/CrewAI/LlamaIndex runtime]
   ├─ memory write proposal ───────▶ [Amby Context Hook]
   └─ retrieved context handoff ───▶ [Amby Context Hook]
                                      ├─ input scanner reuse
                                      ├─ memory/RAG context mapping
                                      ├─ raw context 비저장 audit
                                      └─ evidence hash chain
   ◀──────── allow | block | redact | flag ───────────────
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
  - 출력 가드레일: 비스트리밍은 완전 적용. 스트리밍은 Phase 0.5에서 **buffer-then-scan-then-emit**으로 적용한다. 토큰 단위 실시간 DLP는 후속 hardening 과제로 둔다.
- 헤더/메타: 클라이언트 식별용 `X-Request-Id` 부여(없으면 생성). **PII는 URL/쿼리스트링에 절대 넣지 않는다.**

### 4.2 Guardrail engine (I / O)

- 입력 스캐너: `prompt_injection`, `pii`, `secrets`.

- 출력 스캐너: `pii`, `secrets`, `system_prompt_leakage`, `improper_output`.

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
- 각 스캐너별 `action`: `block` | `redact` | `flag` | `off`, `threshold`(score 컷), `engine`, `timeout_ms`, `cascade`.
- `engine`은 `auto`, `regex`, `presidio`, `llm_guard`를 지원한다. optional dependency가 없으면 deterministic fallback으로 계속 동작한다.
- 에러 동작(`on_error`): `fail_open`(트래픽 유지) | `fail_closed`(차단). **기본값 = `fail_open`**(MVP에서 고객 트래픽을 끊지 않음). 단, 대시보드에 에러 명확히 표시.
- 탐지 액션과 에러 동작은 **별개 개념**으로 분리 구현.

### 4.4 Audit store (A)

- SQLite, WAL. 테이블 스키마 §6.1.
- 모든 요청/응답 1건 = 이벤트 N개(입력 결정 + 출력 결정).
- export: `GET /audit/export?format=json|csv&scope=guardrails|tool_calls|context|all&from=&to=` — ASI 태그 포함.

### 4.5 Dashboard (D)

- 로컬 `GET /` 단일 페이지.
- 구성: (a) 라이브 이벤트 tail(SSE), (b) ASI 항목별 카운트, (c) 차단/마스킹 이벤트 리스트, (d) 로그 검색 + export 버튼, (e) action lineage, (f) agent/tool inventory.
- Phase 1.5 구성에 `Context Hooks`, `Framework Adapters`, `Discovered Inventory` 패널을 포함한다.
- Phase 0 구성에 `Mythos Readiness` 패널을 포함한다. 이 패널은 `/stats/mythos`의 implemented/partial/planned 상태와 evidence_present 값을 그대로 보여준다.
- **표준 커버리지 매트릭스**(Phase 0.7): OWASP LLM Top 10 / OWASP ASI / NIST AI RMF 함수별로 각 항목을 implemented / observed / planned / out-of-scope 배지로 표기. 과장 없는 정직한 커버리지 표시가 목적이며 규제 PoC의 핵심 자료.
- 기본값은 무인증(로컬 전용 가정). 외부 노출이나 production mode에서는 `security.dashboard_auth`와 `security.api_auth`를 켜고 `/diagnostics` production readiness check를 통과해야 한다.

### 4.6 Demo attack injector (X)

- `POST /demo/inject` 또는 CLI `python -m app.demo` 로 샘플 공격(인젝션 문자열, 합성 SSN/이메일 포함 응답 유도)을 흘려 **첫 차단/마스킹 이벤트를 즉시 생성**.
- quickstart의 마지막 단계로 호출되어 "5분 안의 첫 aha"를 보장(§12 AT-5).

### 4.7 Evidence package and Mythos-ready matrix (E / M)

- CLI:
  - `python -m app.evidence generate --out evidence`
  - `python -m app.evidence verify evidence/<timestamp>`
- API:
  - `POST /audit/evidence`: 서버 로컬 evidence package 생성
  - `GET /stats/mythos`: CSA Mythos-ready coverage matrix 조회
- evidence package 파일:
  - `report.md`: 사람이 읽는 MVP/CISO evidence report
  - `manifest.json`: package metadata, file hash, manifest hash
  - `audit_events.jsonl`, `audit_events.csv`: canonical audit export
  - `audit_chain.jsonl`: event-level hash chain
  - `tool_call_events.jsonl`, `tool_call_events.csv`, `tool_call_chain.jsonl`: agent firewall export와 hash chain
  - `context_events.jsonl`, `context_events.csv`, `context_chain.jsonl`: framework memory/RAG hook export와 hash chain
  - `predeploy_runs.jsonl`, `predeploy_findings.jsonl`, `predeploy_findings.csv`, `predeploy_chain.jsonl`: predeploy governance export와 hash chain
  - `aibom.json`: model, prompt, tool, MCP, framework, scanner, dependency metadata
  - `tool_outputs/`: sanitized scanner output summaries
  - `discovered_inventory.json`: local MCP/plugin/skill discovery snapshot
  - `config_snapshot.yaml`: 정책/config snapshot
  - `mythos_ready.json`: CSA Mythos-ready control coverage and evidence matrix
  - `hashes.sha256`: file-level SHA-256 checksums
  - external `ledger.jsonl`: `evidence.ledger.path`에 기록되는 local continuity ledger. manifest hash, event/tool/context/predeploy chain head, file count, previous ledger hash를 저장한다.
- `mythos_ready.json` 상태값:
  - `implemented`: MVP가 현재 enforce 또는 evidence 생성까지 수행
  - `partial`: 모델 경계에서는 수행하지만 agent/tool/egress/조직 워크플로는 미완성
  - `planned`: roadmap에 있으나 현재 증거 없음
  - `external`: Amby가 직접 구현하기보다 고객 보안 통제와 integration으로 증명할 항목
- MVP의 현재 구현 항목은 자동 감사 수집, AI-speed risk reporting, prompt/output harness defense, tool-call firewall, memory/RAG framework hook, agent/tool inventory와 local MCP/plugin/skill discovery, predeploy red-team/AIBOM evidence, pre-production diagnostics/auth/local ledger다. LLM PR/code review, VulnOps, deception, automated response, WORM/notarization은 후속 phase다.
- Pilot release pack은 production profile, `policy_hash`/`config_hash`, JSONL/SIEM export, release gate, reviewer bundle을 제공한다. 이는 pilot handoff를 위한 운영 증거이며 image signing, signed policy bundle, WORM/notarization을 대체하지 않는다.

### 4.8 Agent firewall (F)

- API:
  - `POST /v1/agent/tool-calls/evaluate`: tool/function/API call dispatch 전 정책 평가
  - `POST /v1/agent/approvals/{approval_id}/approve`: pending approval 승인
  - `POST /v1/agent/approvals/{approval_id}/deny`: pending approval 거부
  - `GET /agent/tool-calls/events`: action lineage 조회
  - `GET /agent/inventory`: owner, permission, data access, egress scope 포함 inventory 조회
- 판정값: `allow` | `block` | `approval_required`.
- 통제:
  - unknown/unmanaged tool은 `default_decision` 적용
  - `allowed_agents` scope 위반은 block
  - global/tool egress allowlist 위반은 block
  - high-risk action 또는 high/critical risk tool은 approval_required
  - kill switch와 per-agent calls/minute circuit breaker는 LLM10으로 block
- 개인정보 기본값:
  - tool arguments 원문은 저장하지 않는다.
  - 저장 항목은 argument key 목록, key fingerprint, target host/path, approval status, policy snapshot이다.

### 4.9 Framework hooks and discovery (H)

- API:
  - `GET /frameworks/adapters`: LangGraph/CrewAI/LlamaIndex adapter contract와 hook support 조회
  - `GET /frameworks/inventory/discover`: workspace 내 MCP/plugin/skill discovery snapshot 조회
  - `GET /frameworks/context/events`: context hook audit lineage 조회
  - `POST /v1/frameworks/context/evaluate`: generic memory/RAG context hook 평가
  - `POST /v1/frameworks/memory/evaluate`: memory write hook shortcut
  - `POST /v1/frameworks/retrieval/evaluate`: retrieval/RAG context hook shortcut
- hook 타입:
  - `memory_write`: agent memory/checkpoint 저장 직전 평가. LLM04/ASI06 evidence를 생성한다.
  - `retrieval_context`: RAG/retriever 결과가 모델 context로 들어가기 직전 평가. LLM08/ASI06 evidence를 생성한다.
- adapter:
  - Python SDK wrapper는 `app.framework_adapters.sdk`에 둔다.
  - LangGraph, CrewAI, LlamaIndex는 optional dependency 없이 HTTP contract로 연동한다.
- discovery:
  - configured workspace root만 scan한다.
  - `SKILL.md`, `plugin.json`, `.codex-plugin/manifest.json`, `mcp.json`, `.mcp.json`을 발견한다.
  - secret value는 저장하지 않고 command basename, URL host, env key name, source path 등 metadata만 저장한다.
  - local manifest가 없을 때도 common MCP server와 agent skill recommended catalog를 제공한다.
  - catalog entry는 `available` 상태로 표시하며 자동 설치하거나 discovered runtime exposure로 계산하지 않는다.

### 4.10 Predeploy governance and AIBOM (R)

- CLI:
  - `python -m app.predeploy run --suite default --out evidence/predeploy`
  - `python -m app.predeploy run --suite default --out evidence/predeploy --use-fixtures`
- API:
  - `POST /predeploy/run`: configured predeploy suite 실행
  - `GET /predeploy/runs`: predeploy run evidence 조회
  - `GET /predeploy/findings`: normalized finding 조회
- SQLite:
  - `predeploy_runs`: suite, decision, adapter status, thresholds, target metadata, output dir
  - `predeploy_findings`: adapter, target, severity, decision, control, ASI/LLM/NIST mapping, sanitized evidence
- 판정값:
  - run/finding decision은 `pass | fail | warn | error`
  - default CI gate는 `fail` 또는 `error`에서 nonzero exit code
- adapters:
  - Garak: `python -m garak`
  - PyRIT: `pyrit_scan`
  - Promptfoo: `npx promptfoo eval -c promptfooconfig.yaml --no-table --output .amby-predeploy/promptfoo/results.json`
  - adapter 실패도 `error` finding으로 저장
- AIBOM:
  - `aibom.json`은 models, prompt file hashes, tools, MCP inventory/catalog, framework hooks, scanner engines, dependency summaries를 저장한다.
  - raw prompt response, raw scanner output, raw secret value는 저장하지 않는다.
  - authoritative owner, RBAC, signed provenance는 Phase 2/2.5 항목으로 둔다.

### 4.11 Pre-production hardening (S)

- Config:
  - `deployment.mode`: `development | pilot | production`
  - `security.dashboard_auth`: dashboard token auth. token 값은 env var에만 둔다.
  - `security.api_auth`: sensitive management API token auth. token 값은 env var에만 둔다.
  - `security.protect_sensitive_apis`: `/audit/*`, `/agent/*`, `/frameworks/*`, `/predeploy/*`, `/control/*`, `/stats/*`, `/events/*`, `/demo/*`, `/diagnostics` 보호 여부.
  - `evidence.ledger`: local ledger enable/path.
- Auth:
  - dashboard는 `Authorization: Bearer`, `x-amby-dashboard-token`, cookie, 또는 `?token=`으로 열 수 있다.
  - API는 `Authorization: Bearer`, `x-amby-api-key`, cookie, 또는 `?token=`으로 호출할 수 있다.
  - browser dashboard에서는 동일 token을 dashboard/API token으로 사용하면 첫 `/?token=<token>` 접근 시 same-origin HttpOnly cookie가 설정된다.
- Diagnostics:
  - `GET /diagnostics`는 token value를 노출하지 않고 `token_env`와 `token_present`만 반환한다.
  - production mode에서 dashboard/API auth, persistent audit store, evidence ledger, predeploy CI gate, control-plane signing key가 누락되면 `status=blocked`.
- Evidence ledger:
  - package 내부 hash와 별도로 output root의 `ledger.jsonl`에 package manifest hash를 append한다.
  - ledger row 자체도 previous hash와 ledger hash로 연결한다.
  - verify는 manifest/file/chain 검증과 ledger chain 및 해당 manifest entry 존재를 함께 확인한다.

### 4.12 Pilot release pack (T)

- `config.production.yaml`:
  - `deployment.mode=production`
  - dashboard/API token auth enabled
  - persistent audit store
  - predeploy CI gate enabled
  - evidence ledger enabled
- Policy/config hash:
  - `policy_hash`와 `config_hash`는 diagnostics, audit events, tool-call events, context events, predeploy runs, evidence manifest/report에 포함한다.
  - hash input은 secret value를 포함하지 않는다.
- JSONL/SIEM export:
  - `GET /audit/export?format=jsonl&scope=guardrails|tool_calls|context|all`
  - 각 line은 `schema_version`, `event_type`, `policy_hash`, `config_hash`를 포함한다.
- Scripts:
  - `scripts/release_gate.sh`: tests, fixture predeploy, signed policy bundle create/activate, heartbeat, drift check, evidence generate/verify, production diagnostics.
  - `scripts/pilot_bundle.sh`: diagnostics, test output, predeploy result, control policy bundle, control heartbeat, control drift, evidence verify output, merged `audit-all.jsonl`, ledger entry, config snapshot, reviewer README.

### 4.13 Local managed control-plane foundation (T)

- Config:
  - `control_plane.enabled`
  - `control_plane.node_id`: explicit id 또는 `auto`
  - `control_plane.policy_signing.enabled`
  - `control_plane.policy_signing.key_env`: default `AMBY_POLICY_SIGNING_KEY`
  - `control_plane.heartbeat.enabled`
- Signed policy bundle:
  - 기본 signing은 dependency 없는 HMAC-SHA256.
  - bundle payload는 `config_hash`, `policy_hash`, `node_id`, Amby version, sanitized config snapshot을 포함한다.
  - signing key value, API token value, raw prompt/response/model output/raw scanner output은 저장하지 않는다.
  - activation은 runtime config를 hot-reload하지 않는다. active bundle은 expected state이며 실제 적용은 재시작/배포 후 drift hash match로 증명한다.
- SQLite:
  - `policy_bundles`: bundle id, config hash, policy hash, signature, status, created/activated timestamps, sanitized bundle payload.
  - `fleet_heartbeats`: node id, version, config/policy hash, diagnostics status, counts summary.
  - `policy_drift_events`: active bundle expected hash vs running hash, severity, evidence.
- API:
  - `POST /control/policy-bundles`
  - `GET /control/policy-bundles`
  - `POST /control/policy-bundles/{id}/activate`
  - `GET /control/drift`
  - `POST /control/fleet/heartbeat`
  - `GET /control/fleet/nodes`
  - `GET /control/summary`
- Evidence:
  - `policy_bundles.jsonl`
  - `fleet_heartbeats.jsonl`
  - `policy_drift_events.jsonl`
  - `control_plane_chain.jsonl`
  - `control_plane.json`
  - `report.md`에 `Control Plane Governance` 섹션.

---

## 5. 표준 프레임워크 ↔ 스캐너 매핑 (감사 태깅 기준)

모든 감사 이벤트는 **하나의 탐지를 여러 표준에 동시 태깅**한다. 고객이 OWASP(LLM/에이전트) 관점이든 NIST(AI RMF) 관점이든 같은 런타임 증거를 재사용할 수 있게 하는 것이 핵심 자산이다(ROADMAP §3.5).

| 탐지            | OWASP ASI                          | OWASP LLM Top 10 (2025)              | NIST AI RMF | severity 기본 |
| ------------- | ---------------------------------- | ----------------------------------- | ----------- | ----------- |
| 프롬프트 인젝션 / 탈옥 | ASI01 (Goal Hijack)                | LLM01 (Prompt Injection)            | MEASURE / MANAGE | high   |
| 출력 PII 누출     | ASI09                              | LLM02 (Sensitive Info Disclosure)   | MAP / MANAGE     | medium |
| 입출력 시크릿/자격증명  | ASI03 (Identity & Privilege Abuse) | LLM02 / LLM07                       | MAP / MANAGE     | high   |
| 시스템 프롬프트 누출 | ASI09 | LLM07 (System Prompt Leakage) | MAP / MANAGE | high |
| 위험한 출력 처리 | ASI08 | LLM05 (Improper Output Handling) | MEASURE / MANAGE | medium |
| 고위험 tool/action | ASI02 | LLM06 (Excessive Agency) | GOVERN / MANAGE | high |
| agent 권한 위반 | ASI03 | LLM06 | GOVERN / MANAGE | high |
| egress/tool 통신 위반 | ASI07 | LLM06 | MAP / MANAGE | high |
| 호출량/kill switch 회로차단 | ASI08 | LLM10 (Unbounded Consumption) | MEASURE / MANAGE | high |
| memory write 오염 | ASI06 | LLM04 (Data and Model Poisoning) | MAP / MEASURE / MANAGE | high |
| RAG/retrieval context 오염 | ASI06 | LLM08 (Vector and Embedding Weaknesses) | MAP / MEASURE / MANAGE | high |

> MVP는 구현된 항목만 정직하게 enforce·태깅한다. Phase 1.5 기준 runtime enforce 대상은 prompt/PII/secrets/system prompt/improper output, tool-call firewall, memory/RAG context hook이다. 매핑 카탈로그는 코드에서 단일 소스로 관리한다(`app/asi/mapping.py`).

### 5.1 확장 매핑 상태

| 표준 항목 | 위협 | 도입 단계 |
| --- | --- | --- |
| LLM05 / ASI | Improper Output Handling | Phase 0.7 implemented |
| LLM07 | System Prompt Leakage | Phase 0.7 implemented |
| LLM06 / ASI02 | Excessive Agency / Tool Misuse | Phase 1 implemented |
| LLM10 | Unbounded Consumption (호출량 회로차단) | Phase 1 implemented |
| LLM04 / ASI06 | Data·Model Poisoning, Memory Poisoning | Phase 1.5 partial implemented |
| LLM08 | Vector & Embedding Weaknesses (RAG) | Phase 1.5 partial implemented |
| LLM03 / ASI04 | Supply Chain (AIBOM) | Phase 2 |
| LLM09 | Misinformation / Confabulation | Phase 2/3 |
| ASI05/10 | Code exec, rogue agent | Phase 2~3 |
| NIST GenAI Profile (AI 600-1) | 정보 무결성·정보 보안·인간-AI 구성 등 권고 액션 | Phase 2/3 |

거짓 "전 항목 커버" 주장은 금지한다. 각 항목은 대시보드 커버리지 매트릭스에 **implemented / observed / planned / out-of-scope** 중 하나로만 표기한다(§4.5).

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
| detections     | TEXT (json)     | `[{scanner, asi_id, owasp_llm, nist_rmf, nist_genai, severity, score, action, snippet_masked}]` |
| decision       | TEXT            | `allow` \| `block` \| `redact` \| `flag`                       |
| latency_ms     | INTEGER         | 가드레일 처리 지연                                                     |
| error          | TEXT (nullable) | 스캐너 에러 + on_error 동작                                           |
| client_meta    | TEXT (json)     | **PII 금지** (ip 해시, user-agent 등만)                              |

원문 저장 금지. 스니펫은 마스킹된 형태로만 저장.

`detections`의 프레임워크 태그(`asi_id`/`owasp_llm`/`nist_rmf`/`nist_genai`)는 스캐너명으로부터 매핑 카탈로그(§5)를 통해 채운다. export(`/audit/export`)는 guardrail, tool-call, context hook 범위를 분리해서 내보낼 수 있어야 한다.

### 6.1.1 Tool-call event 스키마 (SQLite `tool_call_events`)

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | TEXT (uuid) | PK |
| ts | TEXT (ISO8601) | 발생 시각 |
| request_id | TEXT | 동일 호출 묶음 키 |
| agent_id | TEXT | agent/runtime identity |
| session_id | TEXT nullable | agent session |
| tool_name | TEXT | function/API/MCP tool 이름 |
| action | TEXT | create/update/delete/send/lookup 등 정책 action |
| method | TEXT | HTTP 또는 logical method |
| target_host | TEXT nullable | egress host |
| target | TEXT nullable | query 제거된 target |
| decision | TEXT | `allow` \| `block` \| `approval_required` |
| risk_level | TEXT | `low` \| `medium` \| `high` \| `critical` |
| approval_id | TEXT nullable | pending/approved human approval |
| detections | TEXT (json) | ASI/OWASP/NIST 태그가 포함된 firewall finding |
| reasons | TEXT (json) | 정책 판정 이유 |
| policy_snapshot | TEXT (json) | inventory, argument key fingerprint, approval status |
| client_meta | TEXT (json) | PII 금지 |

### 6.1.2 Approval 스키마 (SQLite `tool_approvals`)

`tool_approvals`는 pending/approved/denied/expired 상태, approver, comment, created_at/decided_at/expires_at을 저장한다. 이 테이블이 금융권 "AI 제안과 인간 최종 승인 분리" 증거의 원천이다.

### 6.1.3 Context event 스키마 (SQLite `context_events`)

| 컬럼 | 타입 | 설명 |
| --- | --- | --- |
| id | TEXT (uuid) | PK |
| ts | TEXT (ISO8601) | 발생 시각 |
| request_id | TEXT | 동일 hook 호출 묶음 키 |
| framework | TEXT | `langgraph` / `crewai` / `llamaindex` / `generic` |
| hook_type | TEXT | `memory_write` 또는 `retrieval_context` |
| agent_id | TEXT | agent/runtime identity |
| session_id | TEXT nullable | agent session |
| source_ref | TEXT nullable | memory/retrieval source reference. 원문이 아니라 참조 ID |
| decision | TEXT | `allow` \| `block` \| `redact` \| `flag` |
| latency_ms | INTEGER | hook scanner 지연 |
| scanners_run | TEXT (json) | 실행된 scanner 목록 |
| detections | TEXT (json) | ASI/OWASP/NIST 태그가 포함된 memory/RAG finding |
| policy_snapshot | TEXT (json) | text count/length, metadata keys, source ref |
| client_meta | TEXT (json) | PII 금지 |
| error | TEXT nullable | scanner error + on_error 동작 |

### 6.2 `config.yaml` 예시

```yaml
server:
  port: 8080
  dashboard: true

deployment:
  mode: development

security:
  dashboard_auth:
    enabled: false
    token_env: AMBY_DASHBOARD_TOKEN
  api_auth:
    enabled: false
    token_env: AMBY_API_TOKEN
  protect_sensitive_apis: true

evidence:
  ledger:
    enabled: true
    path: ledger.jsonl

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
    prompt_injection: { action: block,  threshold: 0.8, engine: auto, timeout_ms: 250, cascade: [regex, llm_guard] }
    pii:              { action: flag,   threshold: 0.5, engine: auto, timeout_ms: 250 }
    secrets:          { action: block,  threshold: 0.5, engine: auto, timeout_ms: 250, cascade: [regex, llm_guard] }
  output:
    pii:              { action: redact, threshold: 0.5, engine: auto, timeout_ms: 250 }
    secrets:          { action: block,  threshold: 0.5, engine: auto, timeout_ms: 250 }
    system_prompt_leakage: { action: block, threshold: 0.8, engine: regex, timeout_ms: 100 }
    improper_output:       { action: flag,  threshold: 0.8, engine: regex, timeout_ms: 100 }

audit:
  store: "/data/audit.db"
  retention_days: 90

agent_firewall:
  enabled: true
  default_decision: approval_required
  egress_allowlist: [api.stripe.com, api.sendgrid.com, "*.company.internal"]
  blocked_egress: ["169.254.169.254", localhost, "127.0.0.1", "::1"]
  high_risk_actions: ["create_*", "update_*", "delete_*", "send_*", "transfer_*", "purchase*"]
  approval:
    required_for_risk: [high, critical]
    ttl_seconds: 3600
  circuit_breaker:
    enabled: true
    kill_switch: false
    max_tool_calls_per_minute: 60
    max_blocked_calls_per_minute: 10
  inventory:
    - name: stripe.create_payment
      owner: finance-platform
      category: api
      risk: high
      permissions: [payments:create]
      data_access: [customer_id, amount, currency]
      egress: [api.stripe.com]
      allowed_agents: [finance-assistant]
      approval_required: true

framework_adapters:
  enabled: true
  adapters: [langgraph, crewai, llamaindex]
  context_hooks:
    memory_write: { enabled: true, source_direction: input, add_context_mapping: true }
    retrieval_context: { enabled: true, source_direction: input, add_context_mapping: true }
  discovery:
    enabled: true
    roots: [".", ".agents", ".codex"]
    max_depth: 5
    max_files: 5000
  catalog:
    enabled: true
    include_builtin: true

predeploy:
  enabled: true
  suite: default
  ci_gate: true
  output_root: "evidence/predeploy"
  thresholds:
    max_fail_findings: 0
    max_error_findings: 0
    max_warn_findings: 999
    fail_on_adapter_error: true
  targets:
    model: "gpt-*"
    promptfooconfig: "promptfooconfig.yaml"
    checks: [prompt_injection, leakage, unsafe_tool_use, rag_poisoning, supply_chain_metadata]
  adapters:
    garak: { enabled: true, command: [python, -m, garak], timeout_seconds: 300, output_format: jsonl }
    pyrit: { enabled: true, command: [pyrit_scan], timeout_seconds: 300, output_format: json }
    promptfoo: { enabled: true, command: [npx, promptfoo, eval, -c, promptfooconfig.yaml, --no-table, --output, .amby-predeploy/promptfoo/results.json], timeout_seconds: 300, output_format: json }
```

업스트림 API 키는 `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` 환경변수.

---

## 7. 비기능 요구 (Non-functional)

1. **지연(latency)**: 게이트웨이 자체 오버헤드(모델 기반 스캐너 제외) p95 < 20ms. 인젝션 모델 스캐너 포함 추가 지연 목표 CPU < 200ms / GPU < 50ms. 대시보드에 실측 노출.
2. **오탐(false-positive)**: 양성(benign) 100문장 코퍼스에서 FP < 2% (KPI, §12 AT-6). *오탐 높은 가드는 일주일 안에 꺼진다 — 이 지표가 리텐션의 생명줄.*
3. **프라이버시**: runtime은 업스트림 모델 API 외 외부 전송 0. 원문 비저장. PII 비-URL. Predeploy scanner는 설정된 scanner command의 외부 호출을 허용할 수 있지만 Amby evidence에는 raw output/secret을 저장하지 않는다.
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
| GET  | `/diagnostics`         | startup config/readiness diagnostics + production readiness |
| GET  | `/audit/events`        | 감사 조회(필터·페이지네이션) |
| GET  | `/audit/export`        | JSON/CSV/JSONL 내보내기 (`scope=guardrails|tool_calls|context|all`) |
| GET  | `/agent/inventory`     | agent/tool inventory와 egress scope |
| GET  | `/agent/tool-calls/events` | action lineage 조회 |
| GET  | `/agent/approvals/{approval_id}` | approval 상태 조회 |
| POST | `/v1/agent/tool-calls/evaluate` | tool dispatch 전 firewall 평가 |
| POST | `/v1/agent/approvals/{approval_id}/approve` | high-risk tool call 승인 |
| POST | `/v1/agent/approvals/{approval_id}/deny` | high-risk tool call 거부 |
| GET  | `/frameworks/adapters` | framework adapter contract 조회 |
| GET  | `/frameworks/inventory/discover` | MCP/plugin/skill discovery snapshot |
| GET  | `/frameworks/context/events` | framework context hook audit 조회 |
| POST | `/v1/frameworks/context/evaluate` | framework context hook 평가 |
| POST | `/v1/frameworks/memory/evaluate` | memory write hook 평가 |
| POST | `/v1/frameworks/retrieval/evaluate` | retrieval/RAG hook 평가 |
| POST | `/predeploy/run`      | predeploy governance suite 실행 |
| GET  | `/predeploy/runs`     | predeploy run evidence 조회 |
| GET  | `/predeploy/findings` | normalized predeploy finding 조회 |
| POST | `/audit/evidence`      | 로컬 evidence package 생성 |
| GET  | `/stats/asi`           | ASI 항목별 집계       |
| GET  | `/stats/mythos`        | CSA Mythos-ready coverage matrix |
| GET  | `/stats/runtime`       | latency/error/scanner runtime stats |
| GET  | `/stats/coverage`      | OWASP/NIST 커버리지 매트릭스 |
| GET  | `/events/stream`       | SSE 라이브 tail     |
| POST | `/demo/inject`         | 샘플 공격 주입         |
| POST | `/demo/tool-call`      | 샘플 high-risk tool-call 이벤트 생성 |
| POST | `/demo/context`        | 샘플 framework context 이벤트 생성 |
| GET  | `/`                    | 대시보드             |

차단 응답은 업스트림 스키마와 호환되는 오류 형태(예: HTTP 200 + `choices`에 차단 메시지, 또는 4xx + 구조화된 `error`)로 — **CONFIRM-3**: 클라이언트 호환성을 위해 "200 + 안내 메시지" vs "4xx 차단" 중 선택. 기본값은 `403` + JSON error body, 헤더 `X-Guardrail-Decision: block`.

---

## 9. 권장 디렉터리 구조

```
app/
  main.py            # FastAPI 엔트리, 라우팅
  agent_firewall/    # tool-call pre-dispatch policy engine
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
| M0.65 | evidence package + verify CLI + dashboard/API button + Mythos-ready matrix      | demo → evidence generate → verify 통과 (AT-10) |
| M0.7 | Phase 0.5 hardening: mock E2E, fail mode, privacy invariant, runtime stats, config diagnostics, streaming output DLP | AT-7, AT-8, AT-11, AT-12 통과 |
| M0.8 | Phase 0.7 scanner upgrade: optional adapters, cascade/timeout, Korean corpus, multi-framework 태깅, 커버리지 매트릭스, LLM05/LLM07 스캐너 | AT-9, AT-13 통과        |
| M1.0 | Phase 1 agent firewall: tool-call audit, inventory, egress/method/action policy, approval, circuit breaker, dashboard lineage, evidence export | AT-14~AT-17 통과 |
| M1.5 | Framework adapters: memory/RAG hook, context audit/export, MCP/plugin/skill discovery, recommended catalog | AT-18~AT-19 통과 |
| M2.0 | Predeploy governance: Garak/PyRIT/Promptfoo adapters, CI gate, AIBOM, predeploy evidence chain, dashboard panel | AT-20~AT-23 통과 |
| M2.1 | Pre-production hardening: deployment mode, dashboard/API auth, production diagnostics, local evidence ledger | AT-24~AT-25 통과 |
| M2.2 | Pilot release pack: production profile, policy/config hash, JSONL export, release gate, reviewer bundle | AT-26~AT-28 통과 |

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
- **AT-9 (multi-framework tagging)**: 인젝션/PII/시크릿 이벤트가 각각 OWASP ASI, OWASP LLM Top 10, NIST AI RMF 함수 태그를 동시에 포함하고, `/stats/coverage`와 export에서 framework별로 조회·필터된다.
- **AT-10 (evidence proof)**: demo injector 실행 후 `python -m app.evidence generate --out evidence`와 `python -m app.evidence verify evidence/<timestamp>`가 통과하고, `mythos_ready.json`과 `report.md`에 implemented/partial/planned coverage가 포함된다.
- **AT-11 (streaming DLP)**: `stream: true` upstream SSE 응답이 buffer-then-scan 방식으로 검사되고, split chunk에 걸친 PII도 redaction된 SSE로 반환된다.
- **AT-12 (pilot smoke)**: 실행 중인 gateway에 대해 `scripts/pilot_smoke.sh`가 health, demo inject, runtime stats, Mythos stats, evidence generate, verify, report section check를 모두 통과한다.
- **AT-13 (scanner quality)**: `python -m app.guardrails.benchmark`가 seed corpus에서 false negative 0, false positive 0을 보고하고, audit export detection에 `owasp_llm`/`owasp_asi`/`nist_rmf`/`nist_genai` 태그가 포함된다.
- **AT-14 (agent firewall approval)**: high-risk tool call은 `approval_required`가 되고, human approval 전에는 `allow`가 되지 않는다. 승인 후 같은 approval id로 재평가하면 `allow`된다.
- **AT-15 (egress and scope)**: tool inventory의 `allowed_agents` 또는 egress allowlist를 위반하면 `block`되고 ASI03/ASI07 및 LLM06 태그가 기록된다.
- **AT-16 (unbounded consumption)**: per-agent tool-call rate limit 또는 kill switch가 작동하면 `block`되고 LLM10/ASI08로 기록된다.
- **AT-17 (tool-call evidence)**: `/audit/export?scope=tool_calls`, `tool_call_events.jsonl`, `tool_call_chain.jsonl`, dashboard Action Lineage에서 approval status, policy snapshot, owner/permission/egress evidence를 확인할 수 있다.
- **AT-18 (framework context evidence)**: memory/RAG hook 평가가 `context_events`, `/frameworks/context/events`, `context_chain.jsonl`에 기록되고 LLM04/LLM08/ASI06 mapping을 포함한다.
- **AT-19 (inventory discovery privacy)**: MCP/plugin/skill discovery가 env secret value를 저장하지 않고 env key name과 manifest metadata만 저장한다.
- **AT-20 (predeploy CI gate)**: predeploy finding 중 `fail` 또는 `error`가 threshold를 초과하면 `python -m app.predeploy run`이 nonzero exit code를 반환한다.
- **AT-21 (AIBOM evidence)**: `aibom.json`에 model/prompt/tool/MCP/framework/scanner/dependency metadata가 포함되고 raw prompt response, raw scanner output, raw secret은 저장하지 않는다.
- **AT-22 (predeploy evidence proof)**: `scripts/predeploy_smoke.sh`가 predeploy run, evidence generate, evidence verify, predeploy chain validation을 모두 통과한다.
- **AT-23 (dashboard separation)**: dashboard는 runtime audit events와 predeploy findings를 별도 panel/table로 표시한다.
- **AT-24 (production readiness)**: `deployment.mode=production`에서 dashboard/API auth, persistent audit store, evidence ledger, predeploy CI gate 누락 시 `/diagnostics`가 `status=blocked`를 반환하고 dashboard Production Readiness panel에 open check가 표시된다.
- **AT-25 (ledger proof)**: evidence generate 후 local ledger에 manifest hash와 chain heads가 append되고, `python -m app.evidence verify`가 package 내부 hash chain과 ledger entry를 모두 검증한다.
- **AT-26 (policy/config traceability)**: runtime audit, tool-call, context, predeploy run, diagnostics, evidence manifest/report에 동일한 `policy_hash`와 `config_hash`가 포함된다.
- **AT-27 (SIEM JSONL export)**: `/audit/export?format=jsonl&scope=all`이 event type별 newline-delimited JSON을 반환하고 각 line에 schema/version/hash metadata가 포함된다.
- **AT-28 (pilot release bundle)**: `scripts/release_gate.sh`와 `scripts/pilot_bundle.sh`가 production profile 기준으로 evidence verify와 diagnostics production readiness를 통과시키고 reviewer bundle을 생성한다.

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
3. **compliance by design의 씨앗** (모든 호출이 OWASP ASI/LLM Top 10·NIST AI RMF로 동시 태깅된 감사 로그로 남고 framework별로 export된다)
4. **Mythos-ready evidence seed** (자동 audit collection, risk reporting, hash-chain integrity, current/planned control matrix를 한 package로 증명한다)
5. **낮은 오탐** (리텐션 KPI)

이 다섯 가지가 PLG 쐐기(개발자·SMB)와 비콘 고객(금융 VPC 데이터 플레인) 양쪽의 착지점을 동시에 만족시킨다.
