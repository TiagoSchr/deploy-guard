"""Data models for Deploy Guard."""

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Issue:
    file: str
    line: int
    type: str
    risk_level: str       # low | medium | high | critical
    confidence: str       # low | medium | high
    impact: str
    decision: str         # ALLOW | WARN | BLOCK | REQUIRE_OVERRIDE
    message: str
    suggestion: str
    rule_id: str = ""
    revoke_required: bool = False
    notify_dpo: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
DECISION_ORDER = {"ALLOW": 0, "WARN": 1, "REQUIRE_OVERRIDE": 2, "BLOCK": 3}


def final_decision(issues: list[Issue]) -> str:
    if not issues:
        return "allow"
    max_decision = max(DECISION_ORDER.get(i.decision, 0) for i in issues)
    return ["allow", "warn", "require_override", "block"][max_decision]


def deduplicate(issues: list[Issue]) -> list[Issue]:
    """Remove duplicatas exatas (mesmo arquivo + linha + rule_id)."""
    seen: set[tuple] = set()
    result = []
    for issue in issues:
        key = (issue.file, issue.line, issue.rule_id, issue.type)
        if key not in seen:
            seen.add(key)
            result.append(issue)
    return result
