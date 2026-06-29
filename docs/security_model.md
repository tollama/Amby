# Amby Security Model

## Data Retained

Amby stores security decision metadata:

- scanner/control names
- ASI/LLM/NIST tags
- decisions and latency
- masked snippets
- tool/action metadata and approval state
- framework hook metadata
- predeploy findings and adapter status
- config and policy hashes
- signed policy bundle metadata
- metadata-only fleet heartbeat counts

## Data Not Retained

Amby is designed not to store:

- raw prompts
- raw model responses
- raw tool arguments
- raw memory or retrieved context
- raw scanner output
- dashboard/API token values
- policy signing key values

The release-candidate artifacts inherit the same privacy boundary.

## Auth Model

Local MVP defaults are open for developer use. The production profile enables:

- dashboard token auth through `AMBY_DASHBOARD_TOKEN`
- sensitive management API auth through `AMBY_API_TOKEN`
- runtime `/v1/*` API auth through scoped keys such as `AMBY_RUNTIME_KEY`
- sensitive API protection for audit, agent, framework, predeploy, control-plane, stats, demo, event, and diagnostics endpoints

The release candidate includes local static runtime keys. It does not include SSO/RBAC, managed virtual key issuance, or billing plans.

## Model Proxy Boundary

The OpenAI-compatible `/v1/chat/completions` endpoint, Anthropic-compatible `/v1/messages` endpoint, agent firewall evaluation endpoints, and framework hook endpoints are runtime `/v1/*` endpoints. Production runtime auth protects them separately from management API auth.

For OSS pilot use, run Amby on localhost or behind trusted TLS/network controls. For exposed deployments, enable runtime auth, configure scoped runtime keys, and avoid treating the RC as a full public multi-tenant gateway. SSO/RBAC, managed key issuance, distributed rate limits, and billing plans remain post-RC work.

## Evidence Integrity

Evidence packages include file hashes and hash chains for audit, tool-call, context, predeploy, and control-plane streams. The local ledger appends manifest hashes and chain heads outside the package directory.

The local ledger proves continuity on the host where it is retained. It is not WORM storage and is not external notarization.

## Policy Signing

Phase 2.6 signs policy bundles with HMAC-SHA256 using `AMBY_POLICY_SIGNING_KEY`.

This proves that the expected policy bundle was created with the configured local signing key. It does not provide asymmetric signer identity, external timestamping, key rotation history, or remote policy push. Those controls remain Phase 2.5B+.

## OSS Release Limits

The GitHub-only `v0.1.0-rc1` release includes source, docs, QA gates, offline SBOM/security metadata generation, and release-candidate evidence packaging. It does not publish PyPI packages or Docker registry images, and it does not enforce online vulnerability scanning as a blocking public-release gate.
