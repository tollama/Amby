from __future__ import annotations

from app.config import PolicyConfig, ScannerRule

DECISION_PRECEDENCE = {"allow": 0, "flag": 1, "redact": 2, "block": 3}


class PolicyEngine:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def rule_for(self, direction: str, scanner_name: str) -> ScannerRule:
        direction_policy = self.config.input if direction == "input" else self.config.output
        return direction_policy.get(scanner_name, ScannerRule(action="off", threshold=1.0))

    @property
    def on_error(self) -> str:
        return self.config.on_error


def stronger_decision(current: str, candidate: str) -> str:
    if DECISION_PRECEDENCE[candidate] > DECISION_PRECEDENCE[current]:
        return candidate
    return current
