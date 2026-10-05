"""SARIF 2.1.0 export, so `warden audit --format sarif` plugs into GitHub code scanning and other CI."""
from __future__ import annotations

from . import __version__

_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
_SCORE = {"high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.0"}


def to_sarif(report, target: str) -> dict:
    rules, index = [], {}
    for f in report.findings:
        if f.rule not in index:
            index[f.rule] = len(rules)
            rules.append({
                "id": f.rule,
                "shortDescription": {"text": f.message[:200]},
                "defaultConfiguration": {"level": _LEVEL[f.severity]},
                "properties": {"security-severity": _SCORE[f.severity]},
            })
    results = []
    for f in report.findings:
        results.append({
            "ruleId": f.rule,
            "ruleIndex": index[f.rule],
            "level": _LEVEL[f.severity],
            "message": {"text": f.message + ("" if f.installed else " (outside data/assets, not installed)")},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {"startLine": max(f.line, 1)},
                },
            }],
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "wardenpack", "version": __version__,
                                "informationUri": "https://github.com/IronCrest-sudo/wardenpack",
                                "rules": rules}},
            "invocations": [{"executionSuccessful": True}],
            "properties": {"target": target, "truncated": report.truncated},
            "results": results,
        }],
    }
