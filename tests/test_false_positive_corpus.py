from app.config import PolicyConfig, ScannerRule
from app.guardrails.engine import GuardrailEngine
from app.guardrails.registry import build_default_registry


BENIGN_PROMPTS = [
    f"Please summarize the quarterly product update for team {index}."
    for index in range(1, 41)
] + [
    f"Draft a polite customer support response about billing question {index}."
    for index in range(1, 31)
] + [
    f"Create a project checklist for onboarding workflow {index}."
    for index in range(1, 31)
]


def test_benign_corpus_false_positive_rate_under_two_percent() -> None:
    policy = PolicyConfig(
        on_error="fail_open",
        input={
            "prompt_injection": ScannerRule(action="block", threshold=0.8),
            "pii": ScannerRule(action="flag", threshold=0.5),
            "secrets": ScannerRule(action="block", threshold=0.5),
        },
        output={},
    )
    engine = GuardrailEngine(policy, build_default_registry(use_presidio=False))

    false_positives = 0
    for index, prompt in enumerate(BENIGN_PROMPTS):
        decision = engine.scan_texts(
            [prompt],
            direction="input",
            model="gpt-test",
            request_id=f"benign-{index}",
        )
        if decision.decision != "allow" or decision.detections:
            false_positives += 1

    assert len(BENIGN_PROMPTS) == 100
    assert false_positives / len(BENIGN_PROMPTS) < 0.02
