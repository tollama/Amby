from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AsiMapping:
    scanner: str
    asi_id: str
    llm_id: str | None
    severity: str
    label: str
    owasp_llm: tuple[str, ...] = ()
    owasp_asi: tuple[str, ...] = ()
    nist_rmf: tuple[str, ...] = ()
    nist_genai: tuple[str, ...] = ()
    status: str = "implemented"


MAPPINGS: dict[str, AsiMapping] = {
    "prompt_injection": AsiMapping(
        scanner="prompt_injection",
        asi_id="ASI01",
        llm_id="LLM01",
        severity="high",
        label="Goal Hijack / Prompt Injection",
        owasp_llm=("LLM01",),
        owasp_asi=("ASI01",),
        nist_rmf=("MAP", "MEASURE", "MANAGE"),
        nist_genai=("information-security", "human-ai-configuration"),
    ),
    "pii": AsiMapping(
        scanner="pii",
        asi_id="ASI09",
        llm_id="LLM02",
        severity="medium",
        label="Sensitive Information Disclosure",
        owasp_llm=("LLM02",),
        owasp_asi=("ASI09",),
        nist_rmf=("MAP", "MANAGE"),
        nist_genai=("data-privacy", "information-security"),
    ),
    "secrets": AsiMapping(
        scanner="secrets",
        asi_id="ASI03",
        llm_id="LLM02",
        severity="high",
        label="Identity & Privilege Abuse",
        owasp_llm=("LLM02", "LLM07"),
        owasp_asi=("ASI03",),
        nist_rmf=("MAP", "MANAGE"),
        nist_genai=("data-privacy", "information-security"),
    ),
    "system_prompt_leakage": AsiMapping(
        scanner="system_prompt_leakage",
        asi_id="ASI09",
        llm_id="LLM07",
        severity="high",
        label="System Prompt Leakage",
        owasp_llm=("LLM07",),
        owasp_asi=("ASI09",),
        nist_rmf=("MAP", "MANAGE"),
        nist_genai=("data-privacy", "information-security"),
    ),
    "improper_output": AsiMapping(
        scanner="improper_output",
        asi_id="ASI08",
        llm_id="LLM05",
        severity="medium",
        label="Improper Output Handling",
        owasp_llm=("LLM05",),
        owasp_asi=("ASI08",),
        nist_rmf=("MEASURE", "MANAGE"),
        nist_genai=("information-integrity", "harmful-content"),
    ),
}

PLANNED_ASI = ["ASI02", "ASI04", "ASI05", "ASI06", "ASI07", "ASI08", "ASI10"]

STANDARD_COVERAGE: list[dict[str, object]] = [
    {"framework": "OWASP LLM Top 10 2025", "id": "LLM01", "title": "Prompt Injection", "status": "implemented"},
    {"framework": "OWASP LLM Top 10 2025", "id": "LLM02", "title": "Sensitive Information Disclosure", "status": "implemented"},
    {"framework": "OWASP LLM Top 10 2025", "id": "LLM03", "title": "Supply Chain", "status": "planned"},
    {"framework": "OWASP LLM Top 10 2025", "id": "LLM04", "title": "Data and Model Poisoning", "status": "planned"},
    {"framework": "OWASP LLM Top 10 2025", "id": "LLM05", "title": "Improper Output Handling", "status": "implemented"},
    {"framework": "OWASP LLM Top 10 2025", "id": "LLM06", "title": "Excessive Agency", "status": "planned"},
    {"framework": "OWASP LLM Top 10 2025", "id": "LLM07", "title": "System Prompt Leakage", "status": "implemented"},
    {"framework": "OWASP LLM Top 10 2025", "id": "LLM08", "title": "Vector and Embedding Weaknesses", "status": "planned"},
    {"framework": "OWASP LLM Top 10 2025", "id": "LLM09", "title": "Misinformation", "status": "planned"},
    {"framework": "OWASP LLM Top 10 2025", "id": "LLM10", "title": "Unbounded Consumption", "status": "planned"},
    {"framework": "NIST AI RMF", "id": "GOVERN", "title": "Governance and accountability", "status": "planned"},
    {"framework": "NIST AI RMF", "id": "MAP", "title": "Context and risk identification", "status": "implemented"},
    {"framework": "NIST AI RMF", "id": "MEASURE", "title": "Risk measurement and testing", "status": "implemented"},
    {"framework": "NIST AI RMF", "id": "MANAGE", "title": "Risk response and monitoring", "status": "implemented"},
]


def mapping_for(scanner_name: str) -> AsiMapping:
    return MAPPINGS.get(
        scanner_name,
        AsiMapping(
            scanner=scanner_name,
            asi_id="ASI_UNMAPPED",
            llm_id=None,
            severity="low",
            label="Unmapped scanner finding",
            owasp_llm=(),
            owasp_asi=("ASI_UNMAPPED",),
            nist_rmf=("MEASURE",),
            nist_genai=(),
            status="observed",
        ),
    )


def coverage_matrix() -> dict[str, object]:
    status_counts: dict[str, int] = {}
    for item in STANDARD_COVERAGE:
        status = str(item["status"])
        status_counts[status] = status_counts.get(status, 0) + 1
    return {
        "schema_version": "amby.coverage.v1",
        "status_counts": dict(sorted(status_counts.items())),
        "items": STANDARD_COVERAGE,
    }
