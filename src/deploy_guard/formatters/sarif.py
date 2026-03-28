"""SARIF (Static Analysis Results Interchange Format) output.

SARIF v2.1.0 — integrates with GitHub Security tab, VS Code SARIF Viewer,
Azure DevOps, and other tools.
"""

import json
from ..models import Issue, deduplicate

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

RISK_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def sarif_report(issues: list[Issue], path: str) -> str:
    """Generate a SARIF v2.1.0 report."""
    issues = deduplicate(issues)

    # Collect unique rule IDs
    rules_map: dict[str, dict] = {}
    for issue in issues:
        rid = issue.rule_id or "unknown"
        if rid not in rules_map:
            rules_map[rid] = {
                "id": rid,
                "name": issue.type,
                "shortDescription": {"text": issue.type},
                "helpUri": "https://github.com/TiagoSchr/deploy-guard#rules",
                "properties": {
                    "tags": ["security", "lgpd"] if "lgpd" in rid.lower() else ["security"],
                },
            }

    rules = list(rules_map.values())
    rule_index = {r["id"]: idx for idx, r in enumerate(rules)}

    results = []
    for issue in issues:
        rid = issue.rule_id or "unknown"
        result = {
            "ruleId": rid,
            "ruleIndex": rule_index.get(rid, 0),
            "level": RISK_TO_SARIF_LEVEL.get(issue.risk_level, "warning"),
            "message": {
                "text": f"{issue.message}\n\n**Fix:** {issue.suggestion}",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": issue.file.replace("\\", "/"),
                        },
                        "region": {
                            "startLine": max(issue.line, 1),
                        },
                    }
                }
            ],
            "properties": {
                "risk_level": issue.risk_level,
                "confidence": issue.confidence,
                "decision": issue.decision,
                "revoke_required": issue.revoke_required,
                "notify_dpo": issue.notify_dpo,
            },
        }
        results.append(result)

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Deploy Guard",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/TiagoSchr/deploy-guard",
                        "rules": rules,
                    }
                },
                "results": results,
                "columnKind": "utf16CodeUnits",
            }
        ],
    }

    return json.dumps(sarif, ensure_ascii=False, indent=2)
