# Amby Security Standards Coverage

This document is the public coverage map for Amby security standards. It separates what Amby currently implements from standards that are planned or candidate expansions.

Important limitation: this is a coverage and evidence mapping document. It is not a certification, legal opinion, or guarantee of compliance with any law, regulation, or audit framework. Amby generates reproducible evidence that reviewers can inspect.

## Status Legend

| Status | Meaning |
| --- | --- |
| `implemented` | Code, API, or evidence package can export this coverage today. |
| `partial` | Some evidence, scanner, or mapping exists, but the full control catalog is not implemented. |
| `planned` | The standard is already in the roadmap and has a clear implementation path. |
| `candidate` | Recommended for future coverage, but not yet implemented or fully roadmapped. |
| `reference-only` | Useful for comparison or terminology, but not claimed as product coverage. |
| `out-of-scope` | Explicitly not claimed for the current OSS release candidate. |

## Current Coverage

| Standard or framework | Status | Amby evidence | Gap | Recommended next step |
| --- | --- | --- | --- | --- |
| OWASP Top 10 for LLM Applications 2025 | `implemented` / `partial` / `planned` by item | `/stats/coverage`, `audit_events.jsonl`, `tool_call_events.jsonl`, `context_events.jsonl`, `predeploy_findings.jsonl`, `report.md` | Current coverage is strongest for LLM01, LLM02, LLM05, LLM06, LLM07, and LLM10. LLM04 and LLM08 are partial. LLM03 and LLM09 remain planned. | Keep `app/asi/mapping.py` as the code source of truth and add tests whenever a status changes. |
| OWASP Agentic Security Initiative, ASI | `implemented` / `partial` / `planned` by item | ASI-tagged detections in runtime, tool-call, context, and predeploy evidence | Current Amby ASI IDs are an internal ASI01-ASI10 mapping and may need realignment if OWASP publishes a different stable taxonomy. | Add a mapping compatibility layer before making hard external compliance claims. |
| NIST AI RMF 1.0 | `implemented` | GOVERN, MAP, MEASURE, and MANAGE tags in findings and coverage matrix | Function-level mapping exists, but Amby does not claim a full organizational NIST AI RMF assessment. | Add per-function evidence summaries to release reports and dashboard filters. |
| NIST Generative AI Profile, AI 600-1 | `partial` | `nist_genai` tags for privacy, information security, information integrity, human-AI configuration, cybersecurity, harmful content, and resilience | Tag-level mapping exists, but the full AI 600-1 profile is not implemented as a control checklist. | Promote from tag mapping to a profile checklist in the standards mapping engine. |
| CSA Mythos-ready program guidance | `implemented` / `partial` / `planned` by control | `/stats/mythos`, `mythos_ready.json`, `report.md`, release candidate evidence | Amby is a Mythos-ready evidence and model-boundary control seed, not a complete Mythos-ready security program. | Keep implemented, partial, and planned states visible in reports and dashboard. |
| Korea finance pilot evidence sample | `partial` | `docs/korea_finance_evidence_sample.md`, release bundle artifacts, control-plane drift evidence, QA outputs | This is a pilot review checklist, not legal compliance with Korean financial regulation. | Productize a Korea profile that cross-walks PIPA, ISMS-P, KISA guidance, FSC/FSS guidance, and the Korea AI Basic Act. |

## Candidate Expansion List

| Priority | Standard or framework | Status | Amby evidence | Gap | Recommended next step |
| --- | --- | --- | --- | --- | --- |
| P0 | ISO/IEC 42001 AI management system | `candidate` | Policy bundle, diagnostics, release manifest, governance reports can support a future control map | No ISO 42001 control catalog or assessment workflow exists. | Add an ISO 42001 profile focused on policy, accountability, evidence review, risk treatment, and management review. |
| P0 | ISO/IEC 23894 AI risk management | `candidate` | Runtime findings, predeploy findings, policy drift, and release security metadata | No explicit ISO 23894 risk process mapping exists. | Map risk identification, analysis, evaluation, and treatment steps to Amby evidence artifacts. |
| P0 | MITRE ATLAS | `candidate` | Prompt injection, data leakage, tool misuse, memory/RAG poisoning, and supply-chain findings can be technique-mapped | No ATLAS tactic/technique catalog is implemented. | Add `mitre_atlas` tags next to OWASP/NIST mappings for red-team and incident review. |
| P0 | MCP security and authorization profile | `planned` | Runtime `/v1/*` auth, tool firewall, MCP/plugin/skill inventory, env-key-only discovery, AIBOM metadata | No formal MCP auth/security checklist exists, and managed OAuth/OIDC/RBAC remains post-RC work. | Define an MCP profile for OAuth/OIDC boundaries, token audience, no token passthrough, least privilege, egress, and approval-required tools. |
| P0 | CycloneDX ML-BOM / AI-BOM | `planned` | Native `aibom.json`, `release_sbom.json`, dependency summaries | Amby does not yet emit a CycloneDX ML-BOM-compatible document. | Add CycloneDX export alongside native AIBOM without storing prompts, responses, or secrets. |
| P0 | SLSA and OpenSSF supply-chain controls | `planned` | `release_manifest.json`, `release_sbom.json`, `release_security.json`, git revision, dirty-tree status | No SLSA provenance, build attestation, Sigstore signing, or OpenSSF Scorecard gate is enforced. | Add provenance generation, Scorecard review, and optional Sigstore signing before broad public release. |
| P1 | EU AI Act and GPAI governance | `planned` | Risk, logging, human oversight, diagnostics, predeploy, and release evidence can support a future EU profile | No EU AI Act obligation matrix or high-risk workflow exists. | Add an EU module for risk classification, technical documentation, logging, human oversight, robustness, and cybersecurity evidence. |
| P1 | UK AI Cyber Security Code of Practice | `candidate` | Control-plane policy, secure configuration diagnostics, supply-chain metadata, QA gates | No UK code-of-practice mapping exists. | Add a UK baseline profile for AI system cyber security and secure-by-design claims. |
| P1 | Korea AI Basic Act, PIPA, ISMS-P, KISA, FSC/FSS guidance | `planned` | Korea finance evidence sample, PII scanner, no-secret evidence invariant, release and drift artifacts | KISA, ISMS-P, PIPA, FSC/FSS, and AI Basic Act are not yet normalized into one Korea profile. | Build `kr-finance` and `kr-general-ai` profiles with explicit control IDs and reviewer evidence. |
| P1 | China generative AI rules and TC260 security requirements | `candidate` | Content safety findings, AIBOM, release metadata, policy bundles may support a future profile | No China jurisdiction module exists. | Add a China-specific module only if deployment scope requires in-country data, filing, labeling, and content governance controls. |
| P1 | US AI and cyber governance | `candidate` | NIST mappings, release metadata, supply-chain evidence, QA gates | No US state-level AI law or federal agency control module exists. | Start with NIST CSF 2.0, SSDF, Zero Trust, and use-case modules such as Colorado AI Act or NYC Local Law 144 when needed. |
| P2 | Singapore AI Verify and Model AI Governance Framework | `candidate` | Evidence reports and QA outputs can support model testing and governance review | No AI Verify export or Singapore profile exists. | Add a Singapore profile after ISO/NIST/EU/Korea baselines are stable. |
| P2 | Japan AI Guidelines for Business and Hiroshima Process Code of Conduct | `candidate` | Governance reports, release notes, and risk summaries can support future mapping | No Japan jurisdiction profile exists. | Add a reference profile for enterprise governance and cross-border AI assurance. |

## MCP, Plugin, And Skill Security Profile

MCP servers, plugins, and skills should be treated as an agent supply-chain and runtime-permission boundary, not just configuration files.

| Profile area | Current Amby state | Needed before stronger claims |
| --- | --- | --- |
| Inventory | Local MCP/plugin/skill discovery and recommended default catalog are implemented. | Add signed inventory provenance and owner registry. |
| Secrets | Discovery stores env key names and metadata, not raw secret values. | Add recurring secret-retention tests for every new adapter. |
| Authorization | Runtime `/v1/*` auth, tool firewall, and approval-required decisions exist for tool calls. | Add MCP-specific token audience, no token passthrough, OAuth/OIDC, and PKCE checks where applicable. |
| Egress | Tool egress policy and violations are recorded. | Add per-MCP-server egress attestations and release-gate checks. |
| Supply chain | AIBOM includes model, prompt, tool, MCP, framework, scanner, and dependency metadata. | Add CycloneDX ML-BOM export, SLSA provenance, and optional signature verification. |

## Public Claim Guidance

Allowed public claims for the current OSS release candidate:

- Amby maps runtime and predeploy evidence to OWASP LLM Top 10, OWASP ASI, NIST AI RMF, NIST GenAI Profile tags, and CSA Mythos-ready coverage states.
- Amby generates local evidence packages with audit chains, AIBOM metadata, predeploy findings, policy bundle records, heartbeat summaries, and drift evidence.
- Amby includes a Korea finance pilot evidence sample for review discussions.

Claims to avoid:

- Do not claim ISO, KISA, ISMS-P, EU AI Act, China, Singapore, Japan, SOC 2, FedRAMP, or other regulatory compliance.
- Do not claim full Mythos-ready program coverage.
- Do not claim MCP authorization hardening beyond the current tool firewall, inventory, egress, and evidence behavior.
- Do not claim WORM/notarized evidence, SSO/RBAC, SaaS control plane, or remote policy push for the OSS release candidate.
