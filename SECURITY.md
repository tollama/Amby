# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| `main` | Security fixes accepted |
| `v0.1.0-rc1` | Pilot RC security fixes accepted |

Amby is a pilot release candidate, not a regulated-production security product.

## Reporting A Vulnerability

Use GitHub Security Advisories for private vulnerability reports when available. If advisories are unavailable, open a GitHub issue with a minimal description and do not include exploit payloads, credentials, API keys, raw prompts, model responses, customer data, or scanner output.

For suspected secret exposure, rotate the secret before reporting and include only the affected file path or artifact name.

## Expected Response

- Initial triage target: 3 business days.
- Fix or mitigation target for confirmed high/critical issues: 14 business days when feasible.
- Public disclosure timing is coordinated after a fix, mitigation, or documented non-impact determination.

## Current Security Boundaries

- Production profile protects management and governance endpoints with token auth.
- The model proxy endpoints under `/v1/*` are not protected by management API auth in `v0.1.0-rc1`; bind the gateway to localhost or place it behind trusted network controls.
- Local evidence ledger is not WORM storage or external notarization.
- Policy bundle signing uses local HMAC-SHA256, not asymmetric identity signing.
- SSO/RBAC, virtual keys, remote policy push, image signing, and enforced online vulnerability scanning are post-RC work.
