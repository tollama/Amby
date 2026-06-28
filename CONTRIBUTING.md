# Contributing To Amby

Thanks for helping improve Amby. This project is currently a pilot release candidate, so contributions should preserve the security and evidence boundaries documented in `README.md`, `QA_CHECKLIST.md`, and `docs/security_model.md`.

## Development Setup

```bash
uv sync --extra dev --extra predeploy
npm install
```

Run the standard checks before opening a pull request:

```bash
uv run --extra dev python -m pytest
bash scripts/predeploy_smoke.sh
```

If your change affects release evidence, control-plane behavior, Docker packaging, or public docs, also run the relevant gates from `QA_CHECKLIST.md`.

## Pull Request Guidelines

- Keep changes scoped and explain the user-visible behavior or evidence impact.
- Add or update tests when changing runtime behavior, config parsing, storage, evidence output, or release metadata.
- Do not commit generated evidence packages, local databases, API keys, model responses, raw prompts, raw scanner output, or customer data.
- Security-sensitive changes should mention how they affect retained data, auth, evidence integrity, and release gates.

## Security Reports

Do not report vulnerabilities with exploit payloads or secrets in public issues. Follow `SECURITY.md`.

## License

Unless explicitly stated otherwise, contributions are submitted under the Apache License, Version 2.0.
