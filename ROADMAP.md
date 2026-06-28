# Amby 개발 로드맵 및 전략

Status: v0.7, 2026-06-28

반영 소스:

- `MVP_SPEC.md`
- 현재 repository의 Phase 0 구현 상태
- 첨부 문서: `AI 에이전트 보안의 핵심_ 거버넌스 구축 및 글로벌 규제 매핑 전략.md`
- CSA Labs: [The AI Vulnerability Storm: Building a Mythos-ready Security Program](https://labs.cloudsecurityalliance.org/mythos-ciso/) (original release 2026-04-12, last updated 2026-05-01)
- 표준 프레임워크: OWASP Top 10 for LLM Applications (2025), OWASP Agentic Security Initiative(ASI), OWASP GenAI Security Project, NIST AI RMF 1.0(AI 100-1), NIST Generative AI Profile(AI 600-1), CSA Mythos-ready guidance
- 확장 후보 표준: ISO/IEC 42001, ISO/IEC 23894, MITRE ATLAS, MCP security profile, CycloneDX ML-BOM/AIBOM, SLSA/OpenSSF, EU AI Act, UK AI Cyber Security Code of Practice, 한국 AI 기본법/PIPA/ISMS-P/KISA/FSC, 중국 GenAI 규제, Singapore AI Verify, Japan AI Guidelines
- 표준 claim source of truth: `SECURITY_STANDARDS.md`, `SECURITY_STANDARDS_CHECKLIST.md`

## 1. 제품 정의

### 한 줄 포지셔닝

Amby는 어떤 AI 에이전트든 모델 API, 도구 호출, 네트워크 egress 앞단에 끼워 보안 통제와 규제 감사 증거를 자동 생성하는 AI agent security and compliance data plane이다. CSA Mythos 관점에서는 AI-speed threat에 대응하는 agent governance and evidence layer로 포지셔닝한다.

핵심 문장은 "보안은 쉽다"가 아니라 "보안을 쉽게 만들어준다"이다. 깊은 다층 방어를 제거하지 않고, 좋은 기본값과 관리형 운영 뒤로 숨긴다.

### 제품 원칙

1. Any-agent first: CrewAI, LangGraph, SDK, 노코드 플랫폼을 가리지 않고 공통 초크포인트에 붙는다.
2. Data plane local-first: 프롬프트, PII, 자격증명, 도구 호출은 고객 환경 안에서 처리한다.
3. Compliance by design: 모든 런타임 이벤트는 OWASP ASI 태그와 정책 결정 근거를 남긴다.
4. OSS replaceability: LLM Guard, Presidio, NeMo, Garak 같은 OSS는 계층 인터페이스 뒤에 둬서 인수, 아카이브, 라이선스 리스크를 흡수한다.
5. False-positive discipline: 차단 건수보다 낮은 오탐률과 무중단 통과율이 리텐션의 핵심 KPI다.

### 제품 구조

| 계층 | 역할 | MVP 포함 여부 |
| --- | --- | --- |
| 범용 데이터 플레인 | 모델 API 프록시, 입출력 가드레일, 감사 로그, 로컬 대시보드 | 포함 |
| Agent firewall | MCP/도구/API 호출, 네트워크 egress, 권한 분리, 휴먼 승인 | Phase 1 |
| Framework adapters | LangGraph, CrewAI, LlamaIndex 등 추론/메모리 레벨 훅 | Phase 1.5 |
| Pre-deploy governance | Garak/PyRIT/Promptfoo 기반 레드티밍, AIBOM, CI 게이트 | Phase 2 |
| Mythos-ready evidence | CSA Mythos priority action별 implemented/partial/planned 매트릭스, CISO report, hash-chain evidence | Phase 0~3 (점진) |
| Standards mapping engine | OWASP(LLM Top 10/ASI/GenAI) ↔ NIST(AI RMF/GenAI Profile) ↔ CSA Mythos ↔ ISO/MITRE/MCP/supply-chain profile ↔ 국가 규제 통합 태깅·증거 변환 | Phase 0.7~3 (점진) |
| Control plane | 정책 배포, fleet 관리, 규제/위협 업데이트, 메타데이터 집계 | Phase 2.5 |
| Compliance modules | 한국 금융, EU AI Act, 중국, 미국 주별 규제 매핑과 증거 생성 | Phase 3 |

표준 매핑 엔진은 별도 제품이 아니라 데이터 플레인 전 계층을 가로지르는 횡단 자산이다. 모든 런타임/배포 전 이벤트를 OWASP·NIST 프레임워크 항목으로 동시에 태깅하고, 이를 국가 규제 증거로 변환하는 경로의 시작점이다(§3.5).

### CSA Mythos-ready 적용 요약

CSA Mythos-ready 문서는 공격자가 AI로 취약점 탐색, exploit 작성, patch-diffing, 자동화 공격을 빠르게 수행하는 환경을 전제로 한다. Amby에 적용되는 핵심은 "모델 가드레일" 하나가 아니라 **AI 에이전트 운영 증거, agent harness 통제, CI/CD 보안 자동화, VulnOps, 빠른 거버넌스**를 하나의 증거 모델로 묶는 것이다.

| CSA Mythos 초점 | Amby 제품 해석 | 현재 상태 |
| --- | --- | --- |
| 자동 audit data collection | 모든 AI 호출과 정책 결정을 증거 패키지로 생성 | Phase 0 구현 |
| AI-speed risk reporting | ASI/decision/latency/hash-chain 기반 CISO report | Phase 0 구현 |
| Defend your agents | prompt/output에서 tool/MCP/memory/RAG까지 agent harness 보호 확장 | Phase 0 partial, Phase 1~1.5 |
| Unmanaged AI agent attack surface | MCP server, tool, plugin, skill, extension inventory | Phase 1.5 partial 구현 + default catalog |
| Point agents at code and pipelines | PR/CI에서 LLM security review, red-team, AIBOM 증거 생성 | Phase 2 우선순위 상승 |
| Continuous patching / VulnOps | dependency, exploitability, patch SLA를 evidence model에 연결 | Phase 2 |
| Harden environment | egress allowlist, virtual key, scoped credential, MFA/segmentation attestation | Phase 1~3 |
| Deception / automated response | canary secret, honeytoken, circuit breaker, SOAR hook | Phase 3 |

따라서 Amby의 단기 전략은 "Mythos-ready 전체 프로그램"이라고 주장하지 않고, **Mythos-ready evidence and model-boundary control seed**라고 정직하게 포지셔닝한다. 구현 상태는 `implemented`, `partial`, `planned`, `external`로 나누어 dashboard와 evidence package에서 같은 방식으로 표시한다.

## 2. 전략 방향

### 시장 진입 전략

Amby는 두 개의 시장 진입 동선을 동시에 가져가되, 제품 코어는 하나로 유지한다.

| 동선 | 대상 | 구매 논리 | 제품 형태 |
| --- | --- | --- | --- |
| PLG / 오픈코어 | 개발자, 셀프호스트 팀, SMB | 5분 설치, 첫 차단 이벤트, 즉시 감사 로그 | 단독 실행 데이터 플레인 |
| Sales-assist / 비콘 고객 | 국내 금융, 핀테크, 헬스케어, 공공 | 감사가능성, 책임소재, 망분리/데이터 잔류, 규제 증거 | VPC/온프레 데이터 플레인 + 관리형/셀프호스트 컨트롤 플레인 |

국내 금융을 초기 비콘 고객으로 둔다. 금융권은 AI 에이전트가 상품 추천, 가입, 결제 같은 쓰기 액션으로 넘어갈 때 보조수단성, 인간 감독, 접근통제, 보안성, 신뢰성 증거가 필요하다. 이 지점이 Phase 0에서 Phase 1로 확장되는 가장 강한 상업적 트리거다.

### 쉬움과 깊이의 역할 분담

| 세그먼트 | 쉽게 보여야 하는 것 | 깊게 구현해야 하는 것 | 구매를 닫는 논리 |
| --- | --- | --- | --- |
| 개발자/SMB | `base_url` 교체, Docker 한 줄 실행, demo injector, export | 계층 분리, ASI 태깅, 원문 비저장, scanner abstraction | 채택 속도 |
| 미드마켓 | 정책 토글, 낮은 오탐, 팀 대시보드, SLA | agent firewall, 권한 분리, 회로차단, 관리형 튜닝 | 운영 부담 제거 |
| 규제 엔터프라이즈 | 빠른 PoC, 자동 감사 증거, 규제 변경 반영 | 한국 7대 원칙, EU/중국/미국 모듈, 책임소재, 에어갭 운영 | 감사가능성/책임소재 |

쉬움은 land motion이고, 깊이와 컴플라이언스는 expand/close motion이다. 엔터프라이즈에서도 쉬움을 빼면 PoC 착지 속도를 잃기 때문에, 모든 티어에서 쉬움은 유지하고 닫는 논리만 다르게 설계한다.

### 배포 전략

SaaS 단독도, 설치형 단독도 맞지 않는다. 하나의 코드베이스를 데이터 플레인과 컨트롤 플레인으로 분리한다.

| 티어 | 배포 토폴로지 | 데이터 플레인 | 컨트롤 플레인 |
| --- | --- | --- | --- |
| 오픈코어 | 순수 설치형 | 고객 로컬/VPC | 없음 또는 로컬 대시보드 |
| 관리형 | BYOC / VPC | 고객 VPC | Amby SaaS |
| 컴플라이언스 | VPC/온프레/전용망 | 고객 경계 안 | SaaS 또는 에어갭 셀프호스트 |

원칙:

- 민감 데이터는 고객 경계 밖으로 보내지 않는다.
- 컨트롤 플레인에는 정책, 버전, 집계 메타데이터, 규제 매핑, 증거 패키지만 흐른다.
- 컨트롤 플레인이 끊겨도 데이터 플레인은 마지막으로 검증된 정책으로 계속 동작한다.
- 설치형과 SaaS를 제품 두 개로 포크하지 않는다. 같은 데이터 플레인이 토폴로지만 다르게 동작해야 한다.

### 방어 가능한 해자

Scanner 엔진 자체는 교체 가능해야 한다. 장기 해자는 다음 자산이다.

- OWASP LLM Top 10, OWASP ASI, OWASP GenAI 위협 항목과 런타임 이벤트의 정확한 매핑
- OWASP(LLM Top 10/ASI) ↔ NIST AI RMF(GOVERN/MAP/MEASURE/MANAGE) ↔ NIST GenAI Profile(AI 600-1) ↔ EU AI Act ↔ 한국 AI 기본법/금융 가이드라인 ↔ 미국 주별 규제로 이어지는 단일 매핑 카탈로그
- 낮은 오탐을 위한 운영 데이터와 튜닝 플레이북
- OSS 벤더 변경/아카이브를 흡수하는 계층 인터페이스
- 감사 증거 패키지 생성 포맷과 고객별 정책 이력

## 3. 규제 및 거버넌스 전략

### 공통 거버넌스 코어 + 국가 모듈

국가별 규제는 방향이 다르다. 따라서 "가장 엄격한 기준 하나"로 모든 시장을 덮지 않고, 공통 거버넌스 코어 위에 국가 모듈을 얹는다.

| 관할권 | 전략적 의미 | 제품 요구 |
| --- | --- | --- |
| 한국 | 국내 금융 비콘 고객, AI 기본법과 금융 7대 원칙 | 투명성, 보조수단성, 신뢰성, 금융안정성, 신의성실, 보안성 증거 |
| EU | 벌금과 고위험 AI 의무가 강함 | 위험 분류, 기술문서, 적합성 평가, 인간 감독 증거 |
| 중국 | 데이터 반출, 알고리즘 등록, 콘텐츠 라벨링 등 별도 설계 필요 | 인-컨트리/에어갭 모듈, 별도 정책 번들 |
| 미국 | 연방보다 주별 규제가 중요 | 콜로라도, 뉴욕 등 사용 사례별 영향평가/고지/편향 감사 |

### ASI 기반 제품 커버리지

| ASI | 위협 | 주 제품 계층 | 로드맵 단계 |
| --- | --- | --- | --- |
| ASI01 | 목표 탈취, 프롬프트 인젝션 | 입력 가드레일 | Phase 0 |
| ASI02 | 도구 오용/악용 | Agent firewall, 승인 플로우 | Phase 1 |
| ASI03 | 신원/권한 남용 | 권한 분리, RBAC, virtual key | Phase 1 |
| ASI04 | 공급망 침해 | AIBOM, 배포 전 검증 | Phase 2 |
| ASI05 | 예기치 않은 코드 실행 | 샌드박스, CI 레드티밍 | Phase 2 |
| ASI06 | 메모리/컨텍스트 오염 | 입력 검증, framework adapter | Phase 1.5/2 |
| ASI07 | 안전하지 않은 에이전트 간 통신 | MCP/agent 통신 정책 | Phase 1 |
| ASI08 | 연쇄적 에이전트 실패 | 관측, 회로차단, kill switch | Phase 1/3 |
| ASI09 | 인간-에이전트 신뢰 악용, 민감정보 노출 | 출력 DLP, 고지, 감사 | Phase 0/3 |
| ASI10 | 악성/불량 에이전트 | 행위 감사, 격리, 거버넌스 | Phase 3 |

### 표준 프레임워크 커버리지 (OWASP & NIST)

Amby의 차별점은 단일 위협 분류가 아니라 **하나의 이벤트를 여러 표준에 동시 태깅**한다는 점이다. 고객은 LLM·GenAI·에이전트 어느 관점에서 감사를 받아도 같은 런타임 증거를 재사용할 수 있다. 데이터 플레인은 모든 감사 이벤트에 `owasp_llm`, `owasp_asi`, `nist_rmf`, `nist_genai` 태그를 함께 부여한다(MVP_SPEC §5/§6.1).

#### OWASP Top 10 for LLM Applications (2025)

| 항목 | 위협 | 주 제품 계층 | 로드맵 단계 |
| --- | --- | --- | --- |
| LLM01 | Prompt Injection | 입력 가드레일 | Phase 0 (구현) |
| LLM02 | Sensitive Information Disclosure | 출력 DLP, PII 마스킹 | Phase 0 (구현) |
| LLM03 | Supply Chain | AIBOM, 배포 전 검증 | Phase 2 |
| LLM04 | Data and Model Poisoning | 메모리/컨텍스트 검증, red-team CI | Phase 1.5/2 |
| LLM05 | Improper Output Handling | 출력 가드레일, 구조화 응답 검증 | Phase 0.7/1 |
| LLM06 | Excessive Agency | Agent firewall, 권한 scope, 승인 | Phase 1 |
| LLM07 | System Prompt Leakage | 출력 DLP system-prompt 탐지 | Phase 0.7 |
| LLM08 | Vector and Embedding Weaknesses | RAG/임베딩 가드레일, framework adapter | Phase 1.5/2 |
| LLM09 | Misinformation | 출력 검증, 고지, 근거 추적 | Phase 2/3 |
| LLM10 | Unbounded Consumption | 레이트리밋, 비용/토큰 회로차단 | Phase 1 |

> MVP(Phase 0)는 LLM01/LLM02만 정직하게 enforce한다. 나머지는 대시보드 커버리지 매트릭스에 implemented/observed/planned/out-of-scope로 정직하게 표기한다(가짜 "전 항목 커버" 주장 금지).

#### NIST AI RMF 1.0 (AI 100-1) 함수 매핑

| 함수 | 의미 | Amby가 생성하는 증거 | 로드맵 단계 |
| --- | --- | --- | --- |
| GOVERN | 정책·역할·책임 | 정책 스냅샷, 정책 이력, RBAC/권한 분리 기록 | Phase 1/2.5 |
| MAP | 컨텍스트·위험 식별 | ASI/LLM 태깅, 위협 모델 템플릿, AIBOM | Phase 0~2 |
| MEASURE | 위험 측정·테스트 | 탐지율/오탐률, latency, red-team 결과 | Phase 0.5~2 |
| MANAGE | 위험 대응·모니터링 | 차단/마스킹/승인 이벤트, 회로차단, 드리프트 탐지 | Phase 1~4 |

#### NIST Generative AI Profile (AI 600-1)

GenAI 고유/심화 위험(컨퍼뷸레이션, 정보 무결성, 데이터 프라이버시, 정보 보안, 위험 콘텐츠, 인간-AI 구성, 가치사슬/컴포넌트 통합 등)에 대해 Amby는 런타임 통제 가능한 항목(정보 보안, 데이터 프라이버시, 정보 무결성, 인간-AI 구성, 가치사슬)을 우선 매핑하고, 나머지는 정책/고지/배포 전 테스트로 다룬다. AI 600-1의 권고 액션을 RMF 함수별 증거 항목으로 환원한다(Phase 2/3).

#### Standards coverage expansion

Public release claim은 `SECURITY_STANDARDS.md`와 `SECURITY_STANDARDS_CHECKLIST.md`를 기준으로 한다. 현재 claim 가능한 핵심은 OWASP LLM/ASI, NIST AI RMF, NIST GenAI Profile tag, CSA Mythos-ready evidence, Korea finance pilot sample이다. ISO/IEC 42001, ISO/IEC 23894, MITRE ATLAS, MCP security profile, CycloneDX ML-BOM/AIBOM, SLSA/OpenSSF, EU/UK/Korea/China/Singapore/Japan jurisdiction profile은 후속 mapping 후보로 둔다.

| 확장 표준 | 제품 의미 | 우선순위 |
| --- | --- | --- |
| ISO/IEC 42001, ISO/IEC 23894 | AI management system과 AI risk management profile | P0 |
| MITRE ATLAS | red-team finding과 incident technique taxonomy | P0 |
| MCP security profile | MCP/tool/skill authorization, no token passthrough, egress, approval-required controls | P0 |
| CycloneDX ML-BOM/AIBOM, SLSA/OpenSSF | model/tool/dependency supply-chain provenance and release assurance | P0 |
| EU AI Act, UK AI Cyber Security Code of Practice | European risk, documentation, human oversight, robustness, cybersecurity evidence | P1 |
| Korea AI Basic Act/PIPA/ISMS-P/KISA/FSC | Korea general AI and finance compliance evidence profile | P1 |
| China GenAI rules, Singapore AI Verify, Japan AI Guidelines | jurisdiction-specific evidence packages | P1/P2 |

## 4. 개발 로드맵

### Phase 0: Local Data Plane MVP

목표: 모델 API 프록시를 보편 초크포인트로 삼아 5분 안에 첫 차단/마스킹 이벤트와 감사 로그를 보여준다.

현재 구현 상태:

- FastAPI 기반 OpenAI/Anthropic 호환 프록시
- YAML 정책 엔진
- 로컬 prompt injection/PII/secrets scanner
- SQLite 감사 로그와 JSON/CSV export
- ASI 태깅
- 로컬 dashboard와 SSE live tail
- demo injector
- Docker 이미지
- evidence package 생성/검증 CLI: `report.md`, `manifest.json`, `audit_chain.jsonl`, `hashes.sha256`
- CSA Mythos-ready coverage matrix: `mythos_ready.json`, `/stats/mythos`, dashboard panel

완료 게이트:

- Clean machine에서 README만 따라 AT-1~AT-5 통과
- audit DB에 원문 prompt/response, raw PII, raw secret 미저장
- `docker run` 한 줄로 시작 가능
- streaming output DLP 제한이 명시적으로 표시됨
- demo 실행 후 evidence package를 생성하고 verify CLI가 통과
- CISO가 report에서 implemented/partial/planned Mythos coverage를 구분 가능

핵심 KPI:

- Time-to-first-aha: 5분 이하
- 첫 차단/마스킹 이벤트 도달률
- audit export 성공률
- evidence package 검증 성공률
- Mythos-ready report 생성 성공률
- 무중단 통과율

### Phase 0.5: Pilot Hardening

목표: 비콘 고객 PoC에서 첫 1시간 안에 신뢰를 잃게 만드는 구멍을 제거한다.

Status: completed in current repo. Larger multilingual and domain-specific corpus expansion continues in Phase 0.7 scanner quality work.

개발 항목:

- [done] Mock OpenAI/Anthropic upstream 기반 E2E 테스트
- [done] streaming output buffer-then-scan-then-emit
- [done] config validation과 startup diagnostics
- [done] scanner error injection 테스트
- [done] audit privacy invariant 테스트
- [done] latency/error runtime stats
- [done] benign corpus false-positive harness
- [done] README를 pilot script 수준으로 정리
- evidence package WORM 저장 또는 외부 notarization 연동 설계
- [done] Mythos-ready matrix의 false claim 방지 리뷰: 각 항목을 implemented/partial/planned/external로 유지

완료 게이트:

- AT-6 false-positive, AT-7 fail mode, AT-8 privacy, AT-11 streaming DLP, AT-12 pilot smoke 기준 통과
- gateway overhead p95 측정 가능
- output streaming DLP가 더 이상 핵심 제한이 아님
- 국내 금융 PoC 기준의 증거 export 샘플 생성

### Phase 0.7: Scanner Quality Upgrade

목표: MVP scanner를 production-grade adapter 구조로 올리되, deterministic fallback을 유지한다.

Status: completed in current repo at adapter/fallback level. Commercial license and offline model-weight policy remain an open product decision.

개발 항목:

- [done] Presidio analyzer/anonymizer adapter
- [done] LLM Guard PromptInjection adapter
- [done] LLM Guard Secrets 또는 동급 secret scanner adapter
- [done] scanner registry 설정: `engine`, `threshold`, `timeout_ms`, `cascade`
- [done] rule-first, model-second cascade
- [done] per-scanner timeout/error accounting
- [done] scanner benchmark: latency, recall, false positive
- [done] 한국어 injection/PII seed corpus
- [done] multi-framework 태깅 도입: 감사 이벤트에 `owasp_llm`/`owasp_asi`/`nist_rmf`/`nist_genai` 필드 추가
- [done] 표준 매핑 카탈로그 v1 (LLM01/02/05/07, ASI01/03/08/09, RMF MAP/MEASURE/MANAGE) 코드화
- [done] system prompt leakage(LLM07), improper output handling(LLM05) 탐지 스캐너 추가
- [done] 대시보드 OWASP/NIST 커버리지 매트릭스 (implemented/planned)

완료 게이트:

- heavy scanner를 켜도 proxy/policy/audit/dashboard 코드는 그대로 유지
- 모델 기반 scanner를 끄고도 로컬 fallback 보호 가능
- scanner benchmark와 한국어 seed corpus 테스트 통과
- export된 감사 이벤트가 OWASP LLM Top 10과 NIST AI RMF 함수로 동시 조회 가능

### Phase 1: Agent Firewall, 권한 분리, Human-in-the-loop

목표: 에이전트가 읽기에서 쓰기, 즉 가입/결제/DB수정/API호출로 넘어가는 순간의 위험을 통제한다.

상태: **MVP implemented**. 현재 구현은 pre-dispatch tool-call evaluation API, tool inventory, egress policy, approval record, circuit breaker, dashboard lineage, evidence export까지다. MCP/plugin/skill 자동 발견은 Phase 1.5에서 local discovery로 구현되었고, team RBAC와 virtual key 발급은 다음 확장으로 둔다.

개발 항목:

- [done] tool-call audit schema (`tool_call_events`)
- [done] agent/tool inventory schema: owner, permission, data access, egress, risk, allowed agents
- [done] function/API call pre-dispatch evaluation endpoint (`POST /v1/agent/tool-calls/evaluate`)
- [done] MCP/plugin/skill/extension inventory 자동 발견: local workspace discovery, secret value 비저장, evidence export
- [done] egress allowlist와 method/action policy
- [done] dispatch 이전 정책 평가
- [done] high-risk action human approval record
- [partial] virtual key/RBAC/권한 scope: allowed_agents scope는 구현, managed RBAC/virtual key는 Phase 2
- [done] circuit breaker와 kill switch
- [done] 호출량 회로차단 (LLM10 Unbounded Consumption)
- [done] dashboard의 action lineage view
- [done] dashboard의 agent attack surface inventory view
- [done] excessive agency(LLM06/ASI02) 통제: tool scope 제한과 승인 강제
- [done] agent firewall 이벤트를 RMF GOVERN/MANAGE 증거로 태깅
- [done] CSA Mythos `Defend your agents` evidence: tool definition ref, retrieval context ref, escalation logic, human override 상태 기록

완료 게이트:

- [done] 미승인 위험 action 0건: `approval_required` 없이는 high-risk tool이 allow 되지 않음
- [done] 승인 지연 시간 측정 가능: `tool_approvals.created_at/decided_at`
- [done] ASI02/03/07, LLM06/LLM10 이벤트가 감사 로그와 export에 포함
- [done] 금융 "보조수단성" 증거: AI tool-call 제안과 인간 최종 승인 분리 기록
- [partial] 관리 대상 agent/tool/MCP 서버가 owner, permission, data access, egress policy와 함께 inventory에 등록: tool/API inventory와 MCP/plugin/skill discovery는 구현, owner/RBAC authoritative registry는 후속

### Phase 1.5: Framework Adapters and Integration Layer

목표: core만으로 any-agent를 덮되, 인기 프레임워크에는 더 깊은 추론/메모리 레벨 보호를 제공한다.

상태: **MVP implemented**. 현재 구현은 LangGraph/CrewAI/LlamaIndex-style adapter contract, Python SDK wrapper, memory/RAG context hook evaluation, context audit schema/export, dashboard context lineage, local MCP/plugin/skill discovery, recommended MCP/skill default catalog, Mythos/evidence package 반영까지다. JavaScript SDK, framework별 deep native middleware, signed inventory provenance는 Phase 2+로 넘긴다.

개발 항목:

- [done] Python minimal SDK (`app.framework_adapters.sdk`)
- [planned] JavaScript minimal SDK
- [done] LangGraph, CrewAI, LlamaIndex adapter contract
- [done] memory/context scanner hook (`memory_write`, `retrieval_context`)
- [done] framework context audit schema (`context_events`)
- [done] `/v1/frameworks/context|memory|retrieval/evaluate` API
- [done] `/frameworks/adapters`, `/frameworks/context/events`, `/frameworks/inventory/discover` API
- [done] dashboard Context Hooks, Framework Adapters, Discovered Inventory panels
- [done] evidence export: `context_events.*`, `context_chain.jsonl`, `discovered_inventory.json`
- [done] OSS/well-known MCP/skill default catalog: discovered runtime exposure와 installed 전 후보를 분리 표시
- [done] Mythos matrix update for memory/RAG hook and agent exposure inventory
- framework별 threat model template
- no-code base URL/proxy recipe
- Docker Compose와 VPC reference deployment

완료 게이트:

- [done] adapter가 core enforcement를 대체하지 않고 보완: HTTP hook은 기존 guardrail scanner를 재사용
- [done] memory write 탐지 시 LLM04/ASI06 evidence 생성
- [done] RAG retrieval context 탐지 시 LLM08/ASI06 evidence 생성
- [done] raw memory/retrieved context 비저장: 길이, metadata key, masked snippet, policy reason만 audit 저장
- [done] local discovery가 MCP env secret value를 저장하지 않고 env key name만 저장
- [done] local manifest가 없어도 dashboard/evidence에서 recommended catalog를 보여주되 installed/discovered로 오인하지 않음
- [done] 신규 사용자가 내부 아키텍처 문서 없이 연결 가능: README API/SDK 예시 포함
- [planned] adapter 사용 시 오탐 감소 또는 탐지율 향상 수치 확인: Phase 2 corpus/benchmark에서 측정

### Phase 2: Pre-deploy Governance, Red Teaming CI, AIBOM

목표: runtime guardrail이 배포 전 검증의 대체재가 되지 않도록 CI 단계에서 ASI04/05/06 위험을 잡는다.

상태: **MVP implemented / program partial**. 현재 구현은 predeploy CLI/API, Garak/PyRIT/Promptfoo command adapter, fixture smoke mode, `predeploy_runs`/`predeploy_findings` SQLite evidence, AIBOM 생성, evidence package 통합, dashboard Pre-deploy Governance panel, GitHub Actions workflow까지다. LLM-driven PR/code review, vulnerability SLA/VulnOps, signed provenance는 후속이다.

개발 항목:

- [done] Garak/PyRIT/Promptfoo 연동 runner: command adapter와 normalized finding 변환
- [planned] LLM-driven code security review runner: PR/merge 전 agent-generated code와 human code 모두 검사
- [partial] prompt/model/tool regression corpus: Promptfoo repo-local config와 fixture corpus 구현, 대규모 real-provider corpus는 후속
- [done] AIBOM 생성과 export: `aibom.json`
- [done] model/prompt/tool/MCP/framework/scanner/dependency supply-chain metadata
- [done] CI gate: release 전 red-team threshold (`scripts/predeploy_smoke.sh`, `.github/workflows/predeploy.yml`)
- [partial] CI gate: prompt regression과 AIBOM은 같은 evidence package로 합쳐짐; code review와 dependency vulnerability scan은 후속
- [partial] test result → OWASP(LLM Top 10/ASI) / NIST(AI RMF/GenAI Profile) evidence mapping
- 표준 매핑 카탈로그 v2: LLM03/04/08/09, NIST GenAI Profile(AI 600-1) 권고 액션 포함
- NIST AI RMF GOVERN/MAP/MEASURE/MANAGE 함수별 증거 패키지 생성기
- [done] supply chain(LLM03/ASI04) 매핑을 AIBOM과 결합
- [partial] data·model poisoning(LLM04/LLM08) 매핑을 predeploy findings와 runtime context hook evidence에 결합

완료 게이트:

- [done] 배포 전 차단 취약점 수와 회귀 테스트 커버리지 추적: finding decision counts와 adapter status 기록
- [done] runtime audit와 pre-deploy test가 같은 evidence package로 합쳐짐. 단, DB table/file stream은 분리
- [done] 고객이 "배포 전 무엇을 검증했는가"를 `report.md`, `predeploy_findings.jsonl`, `aibom.json`에서 확인 가능
- [partial] OWASP LLM Top 10 전 항목과 NIST AI RMF 4개 함수에 대해 implemented/observed/planned 상태 export 가능: v1 mapping은 구현, v2 catalog 확장은 후속
- [done] CSA Mythos `Point agents at code and pipelines` 항목에 대해 pass/fail/error evidence를 생성

### Phase 2.1: Pre-production Hardening

목표: MVP가 PoC/demo 수준을 넘어 pilot 운영에서 필요한 최소 보안 운영 기준을 스스로 진단하고, 증거 패키지의 연속성을 로컬에서 검증 가능하게 만든다.

상태: **implemented / regulated-production partial**. 현재 구현은 deployment mode, dashboard/API token auth, sensitive management API 보호, production diagnostics, dashboard Production Readiness panel, local evidence ledger, ledger-aware evidence verification까지다. Signed expected-policy bundle은 Phase 2.5A에서 구현되었고, SSO/RBAC, asymmetric signing, remote WORM/notarization, formal change workflow는 Phase 2.5B+다.

개발 항목:

- [done] `deployment.mode`: `development | pilot | production`
- [done] dashboard token auth와 sensitive management API token auth
- [done] `/diagnostics` production readiness checklist: auth, persistent audit store, evidence ledger, predeploy CI gate, control-plane signing key
- [done] dashboard `Production Readiness` panel
- [done] evidence local ledger: package manifest hash, runtime/tool/context/predeploy chain heads, file count, ledger hash chain
- [done] evidence verify가 package 내부 hash chain과 외부 local ledger entry를 함께 검증
- [done] README에 production-mode config, auth header, dashboard cookie bootstrap, ledger 의미 명시

완료 게이트:

- [done] production mode에서 auth/token/gate/ledger 누락 시 diagnostics `status=blocked`
- [done] API auth enabled 상태에서 `/audit/*`, `/agent/*`, `/frameworks/*`, `/predeploy/*`, `/control/*`, `/stats/*`, `/events/*`, `/demo/*`, `/diagnostics` 보호
- [done] dashboard auth enabled 상태에서 `/` 보호
- [done] evidence package 생성 시 `ledger.jsonl`에 manifest hash와 chain heads 추가
- [done] verify CLI가 ledger tamper 또는 entry 누락을 실패로 처리

### Phase 2.2: Pilot Release Pack

목표: pilot 고객에게 넘길 수 있는 반복 가능한 release gate와 reviewer evidence bundle을 만든다.

상태: **implemented / production-release partial**. 현재 구현은 production config profile, policy/config hash evidence, JSONL/SIEM export, release gate script, pilot bundle script까지다. Release-candidate bundle, Docker production smoke, offline SBOM/security metadata는 Phase 2.6에서 보강되며, Docker image signing과 external WORM/notarization은 Phase 2.5B+다.

개발 항목:

- [done] `config.production.yaml`: production mode, auth required, persistent audit DB, predeploy CI gate, evidence ledger
- [done] `policy_hash` / `config_hash`: runtime audit events, tool-call events, context events, predeploy runs, diagnostics, evidence manifest/report
- [done] JSONL/SIEM export: `GET /audit/export?format=jsonl&scope=guardrails|tool_calls|context|all`
- [done] `scripts/release_gate.sh`: tests, fixture predeploy, evidence generate/verify, production diagnostics
- [done] `scripts/pilot_bundle.sh`: diagnostics, test output, predeploy result, evidence verify output, merged `audit-all.jsonl`, ledger entry, reviewer README

완료 게이트:

- [done] release gate가 production profile 기준 diagnostics `status=ok`와 `production_ready=true`를 확인
- [done] evidence report와 manifest가 같은 policy/config hash를 표시
- [done] SIEM JSONL export가 event type과 policy/config hash를 포함
- [done] pilot reviewer bundle이 단일 디렉터리로 생성 가능

### Phase 2.5A: Local Managed Control Plane Foundation

목표: SaaS control plane으로 바로 가지 않고 self-hosted Amby 안에 control-plane contract를 먼저 넣는다.

상태: **implemented / managed-control-plane foundation**. 현재 구현은 HMAC-SHA256 signed policy bundle, active expected policy 지정, metadata-only fleet heartbeat, active bundle 대비 running config/policy drift detection, `/control/*` API, dashboard Control Plane panel, evidence package 통합, release gate/pilot bundle 통합까지다. Activation은 runtime policy hot-reload가 아니며, 재시작/배포 후 hash 일치로 적용을 증명한다.

구현 항목:

- [done] `control_plane` config: enabled, node_id, policy_signing key env, heartbeat enabled
- [done] SQLite tables: `policy_bundles`, `fleet_heartbeats`, `policy_drift_events`
- [done] API: create/list/activate bundle, drift check, heartbeat, fleet nodes
- [done] `/control/*` sensitive API auth 보호
- [done] HMAC-SHA256 signature with `AMBY_POLICY_SIGNING_KEY`
- [done] production diagnostics: control plane enabled + signing enabled이면 signing key 필요
- [done] evidence files: `policy_bundles.jsonl`, `fleet_heartbeats.jsonl`, `policy_drift_events.jsonl`, `control_plane_chain.jsonl`, `control_plane.json`
- [done] `report.md` Control Plane Governance 섹션
- [done] `scripts/release_gate.sh`와 `scripts/pilot_bundle.sh`에 bundle/heartbeat/drift 출력 포함

남은 한계:

- [planned] asymmetric signing and key rotation
- [planned] remote policy push/apply workflow
- [planned] managed RBAC/SSO/org/project boundary
- [planned] external WORM/notarization
- [planned] signed inventory provenance and formal change approval workflow

### Phase 2.5B: Managed Control Plane

목표: self-hosted 데이터 플레인을 유지하면서 운영 편의성과 반복 매출 구조를 만든다.

개발 항목:

- signed policy bundle distribution beyond local HMAC
- fleet health/version inventory across nodes
- metadata-only event summary upload to managed control plane
- policy drift detection across fleet and environments
- innovation governance workflow: fast-track security tooling review, exception approval, expiry, owner 기록
- SaaS dashboard for fleet and compliance state
- RBAC/SSO/org/project boundary
- airgap bundle export/import path

완료 게이트:

- control plane 장애 시 데이터 플레인은 마지막 검증 정책으로 동작
- control plane에 raw prompt/response/PII/secret 미전송 보장
- 여러 배포의 정책 drift와 버전을 중앙에서 확인 가능

### Phase 2.6: Release Candidate Hardening

목표: Phase 2.5A self-hosted pilot build를 release-candidate 수준으로 포장한다.

상태: **implemented / pilot release-candidate partial**. 현재 구현은 hardened Dockerfile, release candidate script, release manifest, offline SBOM metadata, release security metadata, optional Docker production smoke, release checklist, changelog, operator runbook, security model까지다. Online vulnerability scanner enforcement, image signing, WORM/notarization은 후속이다.

구현 항목:

- [done] `scripts/release_candidate.sh`: tests, fixture predeploy, signed bundle, heartbeat, drift, evidence verify, diagnostics, release metadata
- [done] Dockerfile: production config 포함, non-root user, `/data` writable, healthcheck, OCI labels
- [done] `release_manifest.json`: git/config/policy/image/artifact/check metadata
- [done] `release_sbom.json`: offline Python/Node/Docker/lockfile metadata
- [done] `release_security.json`: lockfile, Docker hardening, optional scanner/smoke status
- [done] docs: release checklist, changelog, operator runbook, security model

완료 게이트:

- [done] `RUN_DOCKER=0 scripts/release_candidate.sh`가 deterministic bundle을 생성
- [planned] `RUN_DOCKER=1 scripts/release_candidate.sh`는 Docker 가용 환경에서 production smoke까지 통과
- [partial] online vulnerability scan은 pilot RC에서 warn, high/critical scanner output이 제공되면 fail 처리로 확장 예정

### Phase 3: Country Compliance Modules

목표: ASI-tagged runtime/pre-deploy evidence를 관할권별 감사 문서로 변환한다.

우선순위:

1. 한국 금융: AI 기본법 + 금융분야 AI 가이드라인 7대 원칙
2. EU AI Act: high-risk obligations, technical documentation, human oversight
3. 미국: Colorado AI Act, NYC Local Law 144 등 사용 사례별 모듈
4. 중국: 별도 인-컨트리/에어갭 모듈

개발 항목:

- regulation mapping catalog (베이스라인: OWASP LLM Top 10/ASI + NIST AI RMF/GenAI Profile → 국가 규제로 cross-walk)
- evidence package generator
- Mythos-ready CISO/board report generator: priority action별 current evidence, gaps, next step
- policy snapshot, exception list, event sample, retention config, export hash
- quarterly regulation update feed (OWASP/NIST 버전 갱신 포함)
- "implemented vs planned" control mapping UI
- NIST AI RMF / OWASP 기반의 범용 거버넌스 리포트 (국가 모듈 미구매 고객도 사용 가능한 land 자산)

완료 게이트:

- 감사/보안 담당자가 Amby가 enforce하는 것, observe만 하는 것, out-of-scope를 구분 가능
- 규제 변경 반영 리드타임 측정
- compliance module ARR 추적 가능

### Phase 4: Adaptive Policy and Threat Intelligence

목표: 정책 개선을 자동 추천하되, 집행은 명시적 승인과 감사 가능성을 유지한다.

개발 항목:

- local aggregate 기반 policy recommendation
- threat intelligence feed ingestion
- prompt injection/tool misuse/sensitive leak drift detection
- human review workflow
- automatic policy change safety rail

완료 게이트:

- 고객이 승인한 정책 변경만 production에 반영
- 추천 사유, 근거 이벤트, 영향 범위가 감사 로그에 남음

## 5. PLG 퍼널과 전환 전략

| 단계 | 사용자 상태 | 제품 경험 | KPI |
| --- | --- | --- | --- |
| 획득 | 어떤 에이전트든 5분에 붙는다고 들음 | GitHub, README, Docker quickstart | 설치 수, quickstart 완료율 |
| 활성화 | 첫 위협이 보이고 막힘 | demo injector, 첫 audit event, dashboard | 첫 이벤트 도달률, time-to-value |
| 리텐션 | 끄지 않고 계속 켜둠 | 낮은 오탐, 주간 리포트, 무중단 통과 | weekly retention, false-positive rate |
| 전환 | 무료 한계에 도달 | action firewall, team/RBAC, compliance export | free-to-paid, PQL-to-sales |
| 확장 | 더 넓은 규제/조직으로 확대 | compliance modules, adapters, control plane | NRR, module ARR |

PQL 트리거:

| 제품 신호 | 왜 유료가 필요한가 | 도착 티어 |
| --- | --- | --- |
| 에이전트가 읽기에서 쓰기 액션으로 전환 | dispatch 이전 정책과 인간 승인 필요 | 관리형 agent firewall |
| 처리량/트래픽 임계 초과 | scale, SLA, uptime 필요 | 관리형 |
| 다중 팀/에이전트 협업 | RBAC, SSO, 권한 분리 필요 | team/managed |
| 감사/고객 실사/규제 요구 발생 | 증거 자동 생성과 규제 매핑 필요 | compliance module |
| 오탐 튜닝/운영 신뢰 요구 | 관리형 튜닝과 운영 책임 필요 | managed |

운영 주의점:

- 활성화 병목은 첫 차단/마스킹 이벤트다. demo injector는 제품 핵심 기능이다.
- 리텐션의 적은 오탐이다. 오탐이 높으면 가드레일은 꺼지고, 꺼진 제품은 유료 전환으로 가지 않는다.
- action 전환/처리량/team 트리거는 self-serve로 닫고, 감사/운영 신뢰 트리거는 sales-assist로 닫는다.

## 6. 국내 금융 레퍼런스 패키지

시나리오: 은행/카드/핀테크의 대고객 AI 에이전트가 상품 추천에서 가입/결제까지 수행한다.

| 계층 | 금융 특화 구성 | 대응 포인트 |
| --- | --- | --- |
| 배포 | VPC/전용망 데이터 플레인 | 망분리 완화 시 대체통제 |
| 모델 게이트웨이 | virtual key, RBAC, 전 호출 로깅 | 접근통제, 보안성 |
| 입력 가드레일 | 한국어 injection/탈옥/PII 탐지 | 신뢰성 |
| 출력 DLP | 개인신용정보 마스킹, 고지 문구 | 투명성, 신의성실 |
| Agent firewall | 가입/결제 API dispatch 이전 정책 | 책임/권한 규율 |
| Human approval | 고위험 action 명시 승인 | 보조수단성 |
| 관측/감사 | ASI ↔ 금융 7대 원칙 evidence export | 거버넌스, AI 전용 감독 |
| 배포 전 | red-team CI + AIBOM | 샌드박스/검증 |

초기 유료 패키지는 구축 1회성 + VPC 운영 구독 + action 기반 과금 + compliance module 구독으로 나눈다.

## 7. Near-Term Backlog

### P0: 지금 바로

- [done] Mock upstream E2E 테스트 추가: OpenAI/Anthropic mock upstream, input block, output redact, audit 기록 검증
- [done] MVP evidence package 생성기 추가: `report.md`, `manifest.json`, `audit_events.jsonl`, `audit_chain.jsonl`, `hashes.sha256`
- [done] Evidence package 검증 CLI 추가: 파일 hash와 event hash chain 검증
- [done] Dashboard/API evidence package 생성 버튼 추가
- [done] CSA Mythos-ready matrix 추가: `mythos_ready.json`, `/stats/mythos`, dashboard panel, report section
- [done] Streaming output DLP 구현: SSE buffer-then-scan-then-emit, OpenAI/Anthropic stream redaction 테스트
- [done] Config validation/startup diagnostics: invalid provider/URL/port 검증, `/diagnostics`
- [done] Audit privacy invariant 테스트: DB/export/evidence raw PII·secret 미저장 검증
- [done] Scanner error injection 테스트: `fail_open` allow/error audit, `fail_closed` block/error audit
- [done] Runtime latency/error stats: `/stats/runtime`, dashboard Runtime Health panel
- [done] README quickstart를 pilot script로 정리
- [done] 한국 금융 evidence export 샘플 추가: `docs/korea_finance_evidence_sample.md`
- [done] Mythos report smoke script 추가: demo inject → evidence generate → verify → report snippet 확인

### P1: Pilot 전

- [done] Evidence package local ledger. WORM 저장 또는 외부 notarization 연동은 Phase 2.5+.
- agent/tool/MCP/plugin/skill/extension inventory v0
- agent owner, permission, data access, egress policy metadata schema
- [done] Presidio analyzer/anonymizer adapter
- [done] LLM Guard prompt injection adapter
- [done] Scanner timeout/cascade 설정
- [done] Benign corpus false-positive harness
- Dashboard latency/error/privacy panels
- [done] Dashboard production readiness panel
- [done] Dashboard/API token auth for pilot exposure
- Policy version을 audit event에 저장
- [done] 감사 이벤트 multi-framework 태깅 필드(`owasp_llm`/`owasp_asi`/`nist_rmf`/`nist_genai`)
- [done] 표준 매핑 카탈로그 v1 (OWASP LLM Top 10 ↔ ASI ↔ NIST AI RMF)
- [done] ASI/LLM/NIST implemented/observed/planned taxonomy view
- Mythos readiness score는 숫자 하나로 과장하지 않고 status/evidence matrix로 유지

### P2: Pilot 중/후

- [done] Tool-call audit schema 설계
- [done] MCP/function call interception prototype
- [done] Human approval API와 dashboard flow
- [partial] CI/CD LLM security review runner prototype: predeploy red-team/AIBOM gate 구현, LLM PR review는 후속
- [partial] PR security evidence export: prompt regression과 AIBOM은 구현, code review/dependency vulnerability scan은 후속
- [done] JSONL/SIEM export
- [done] Local evidence ledger and ledger-aware verification
- [done] Production profile, release gate, pilot reviewer bundle
- [done] Release candidate hardening: Docker production smoke path, release manifest, SBOM/security metadata
- Docker image signing workflow
- BYOC/control-plane 연결 프로토콜 초안

## 8. Open Decisions

- Dashboard/API auth default는 로컬 MVP 편의를 위해 off로 유지한다. production profile에서 token auth를 mandatory로 둘지, 첫 managed tier에서 SSO/RBAC로 바로 대체할지
- 차단 응답을 `403` JSON으로 고정할지, provider-shaped `200` 응답 옵션을 둘지
- LLM Guard/Presidio/대체 scanner의 상업 라이선스와 offline 배포 정책
- Go single-binary rewrite를 언제 시작할지: Phase 0.7 이후인지, pilot 이후인지
- 한국 금융 module을 첫 compliance module로 제품화할지, 범용 NIST/EU mapping을 먼저 낼지
- OWASP ASI 위협 번호 체계: 현재 repo의 ASI01~10 자체 번호를 유지할지, OWASP ASI 공식 T-코드(예: T1 Memory Poisoning) 발표본에 맞춰 재정렬할지
- 표준 매핑 카탈로그를 코드 내 dict로 둘지, 버전관리되는 YAML/JSON 데이터 자산으로 분리해 control plane에서 배포할지
- NIST GenAI Profile 12개 위험 중 런타임 enforce 불가 항목을 "observe only"로만 노출할지, 정책 고지 문구로 보강할지
- Control plane metadata schema에서 어떤 필드까지 SaaS로 보낼지
- 중국 모듈을 초기 roadmap에 research only로 둘지, 실제 에어갭 product requirement로 둘지
- CSA Mythos coverage 상태값을 `implemented/partial/planned/external` 네 가지로 고정할지, `observed`를 별도 상태로 추가할지
- Mythos-ready report를 standalone package로 둘지, 국가별 compliance module report 안의 공통 섹션으로 둘지
