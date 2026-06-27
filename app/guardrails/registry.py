from __future__ import annotations

from app.guardrails.scanners import (
    PresidioPiiScanner,
    PromptInjectionScanner,
    RegexPiiScanner,
    SecretsScanner,
)
from app.guardrails.types import Scanner


def build_default_registry(use_presidio: bool = True) -> dict[str, Scanner]:
    pii_scanner: Scanner
    if use_presidio:
        try:
            pii_scanner = PresidioPiiScanner()
        except Exception:
            pii_scanner = RegexPiiScanner()
    else:
        pii_scanner = RegexPiiScanner()

    scanners: list[Scanner] = [
        PromptInjectionScanner(),
        pii_scanner,
        SecretsScanner(),
    ]
    return {scanner.name: scanner for scanner in scanners}
