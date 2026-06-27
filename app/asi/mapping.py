from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AsiMapping:
    scanner: str
    asi_id: str
    llm_id: str | None
    severity: str
    label: str


MAPPINGS: dict[str, AsiMapping] = {
    "prompt_injection": AsiMapping(
        scanner="prompt_injection",
        asi_id="ASI01",
        llm_id="LLM01",
        severity="high",
        label="Goal Hijack / Prompt Injection",
    ),
    "pii": AsiMapping(
        scanner="pii",
        asi_id="ASI09",
        llm_id="LLM02",
        severity="medium",
        label="Sensitive Information Disclosure",
    ),
    "secrets": AsiMapping(
        scanner="secrets",
        asi_id="ASI03",
        llm_id=None,
        severity="high",
        label="Identity & Privilege Abuse",
    ),
}

PLANNED_ASI = ["ASI02", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI10"]


def mapping_for(scanner_name: str) -> AsiMapping:
    return MAPPINGS.get(
        scanner_name,
        AsiMapping(
            scanner=scanner_name,
            asi_id="ASI_UNMAPPED",
            llm_id=None,
            severity="low",
            label="Unmapped scanner finding",
        ),
    )
