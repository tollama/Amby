# Amby Security Standards Checklist

Use this checklist before public releases, pilot reviews, or roadmap planning. It tracks whether a standard is mapped, produces Amby evidence, has runtime or predeploy enforcement, and participates in release gates.

Legend:

- `[x]` implemented for the current OSS release candidate.
- `[~]` partial coverage or native Amby evidence exists, but the external standard is not fully implemented.
- `[ ]` not implemented.

## AI, LLM, And Agent Security

| Standard | Mapped? | Evidence artifact? | Runtime control? | Predeploy gate? | Release gate? | Owner / next phase |
| --- | --- | --- | --- | --- | --- | --- |
| OWASP Top 10 for LLM Applications 2025 | [x] | [x] | [x] | [~] | [x] | Maintain in Phase 2.x; complete LLM03 and LLM09 coverage later. |
| OWASP Agentic Security Initiative | [x] | [x] | [x] | [~] | [x] | Keep internal ASI mapping stable; realign if OWASP taxonomy changes. |
| MITRE ATLAS | [ ] | [ ] | [ ] | [ ] | [ ] | Candidate for Phase 3 red-team and incident technique mapping. |
| CSA Mythos-ready guidance | [x] | [x] | [~] | [~] | [x] | Maintain implemented/partial/planned evidence without claiming full program coverage. |

## Governance And Risk

| Standard | Mapped? | Evidence artifact? | Runtime control? | Predeploy gate? | Release gate? | Owner / next phase |
| --- | --- | --- | --- | --- | --- | --- |
| NIST AI RMF 1.0 | [x] | [x] | [x] | [x] | [x] | Add per-function evidence summaries to reports and dashboard. |
| NIST Generative AI Profile, AI 600-1 | [~] | [x] | [~] | [~] | [~] | Promote tag-level mapping into a profile checklist. |
| ISO/IEC 42001 | [ ] | [ ] | [ ] | [ ] | [ ] | Candidate for Phase 3 governance profile. |
| ISO/IEC 23894 | [ ] | [ ] | [ ] | [ ] | [ ] | Candidate for Phase 3 AI risk-management profile. |

## MCP, Skill, Plugin, And Supply Chain

| Standard or profile | Mapped? | Evidence artifact? | Runtime control? | Predeploy gate? | Release gate? | Owner / next phase |
| --- | --- | --- | --- | --- | --- | --- |
| MCP security and authorization profile | [~] | [x] | [~] | [~] | [~] | Define explicit MCP auth, token audience, no token passthrough, egress, and approval checks. |
| Agent skill governance profile | [~] | [x] | [~] | [~] | [~] | Extend local `SKILL.md` discovery with owner, provenance, and allowed tool-surface review. |
| CycloneDX ML-BOM / AI-BOM | [~] | [x] | [ ] | [~] | [~] | Export CycloneDX-compatible ML-BOM in addition to native `aibom.json`. |
| SLSA provenance | [ ] | [~] | [ ] | [ ] | [~] | Add build provenance and attestations before broad public release. |
| OpenSSF Scorecard / Sigstore | [ ] | [ ] | [ ] | [ ] | [ ] | Add repo health review and optional signing after RC. |

## Jurisdiction Modules

| Jurisdiction or framework | Mapped? | Evidence artifact? | Runtime control? | Predeploy gate? | Release gate? | Owner / next phase |
| --- | --- | --- | --- | --- | --- | --- |
| Korea finance pilot review | [~] | [x] | [~] | [~] | [~] | Productize as `kr-finance` profile. |
| Korea AI Basic Act / PIPA / ISMS-P / KISA / FSC-FSS | [ ] | [~] | [~] | [ ] | [ ] | Planned Korea profile; current PII and finance evidence are not full compliance. |
| EU AI Act / GPAI governance | [ ] | [ ] | [ ] | [ ] | [ ] | Planned Phase 3 jurisdiction module. |
| UK AI Cyber Security Code of Practice | [ ] | [ ] | [ ] | [ ] | [ ] | Candidate profile for secure-by-design AI system review. |
| US NIST CSF / SSDF / Zero Trust / state AI rules | [ ] | [~] | [~] | [~] | [~] | Candidate profile; current NIST AI RMF coverage does not equal US compliance. |
| China generative AI rules / TC260 | [ ] | [ ] | [ ] | [ ] | [ ] | Candidate only if China deployment scope is selected. |
| Singapore AI Verify / Model AI Governance Framework | [ ] | [ ] | [ ] | [ ] | [ ] | Candidate after ISO/NIST/EU/Korea baselines. |
| Japan AI Guidelines for Business | [ ] | [ ] | [ ] | [ ] | [ ] | Candidate reference profile. |

## Release Review Procedure

Before an OSS release:

- [ ] Review [SECURITY_STANDARDS.md](SECURITY_STANDARDS.md) and confirm public claims match implemented evidence.
- [ ] Run the canonical QA sequence in [QA_CHECKLIST.md](QA_CHECKLIST.md).
- [ ] Generate the release candidate bundle with `RUN_TESTS=1 RUN_DOCKER=1 bash scripts/release_candidate.sh` when Docker is available.
- [ ] Confirm `release_manifest.json`, `release_sbom.json`, `release_security.json`, `aibom.json`, `mythos_ready.json`, and `report.md` do not contain raw tokens, signing keys, prompts, responses, or scanner output.
- [ ] Confirm any `candidate` or `planned` standard is described as future coverage, not current compliance.
- [ ] Confirm GitHub release notes link to this checklist and summarize known limitations.
