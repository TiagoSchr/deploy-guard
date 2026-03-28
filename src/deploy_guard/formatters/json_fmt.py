"""JSON output formatter."""

import json
from ..models import Issue, final_decision, deduplicate


def json_report(issues: list[Issue], path: str) -> str:
    """Generate a JSON report string."""
    issues = deduplicate(issues)
    decision = final_decision(issues)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for i in issues:
        counts[i.risk_level] = counts.get(i.risk_level, 0) + 1

    output = {
        "tool": "deploy-guard",
        "version": "1.0.0",
        "target": path,
        "summary": {
            "total_issues": len(issues),
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
            "low": counts["low"],
            "decision": decision,
            "revoke_required": any(i.revoke_required for i in issues),
            "notify_dpo": any(i.notify_dpo for i in issues),
        },
        "issues": [i.to_dict() for i in issues],
    }
    return json.dumps(output, ensure_ascii=False, indent=2)
