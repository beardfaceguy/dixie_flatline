"""JSON report generator for engagement reports.

Produces a structured JSON document suitable for machine consumption,
integration with vulnerability management platforms, or further processing.
"""

from __future__ import annotations

import json
from datetime import datetime

from dixie.core.schema import Finding
from dixie.reporting.mitre import get_technique, tactics_for_technique, technique_url
from dixie.reporting.models import EngagementReport


def render(report: EngagementReport) -> str:
    return json.dumps(_serialize_report(report), indent=2, default=_json_default)


def _json_default(obj: object) -> str:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


def _serialize_report(report: EngagementReport) -> dict:
    return {
        "metadata": {
            "title": report.title,
            "engagement_id": report.engagement_id,
            "prepared_by": report.prepared_by,
            "prepared_for": report.prepared_for,
            "report_date": report.report_date,
            "version": report.version,
            "generator": "dixie-flatline",
        },
        "scope": {
            "targets": report.scope.targets,
            "out_of_scope": report.scope.out_of_scope,
            "rules_of_engagement": report.scope.rules_of_engagement,
            "methodology": report.scope.methodology,
        },
        "executive_summary": report.executive_summary,
        "risk_summary": {
            "overall_risk": report.risk_summary.overall_risk,
            "total_findings": report.risk_summary.total_findings,
            "by_severity": {
                "critical": report.risk_summary.critical,
                "high": report.risk_summary.high,
                "medium": report.risk_summary.medium,
                "low": report.risk_summary.low,
                "info": report.risk_summary.info,
            },
            "max_cvss": report.risk_summary.max_cvss,
            "unique_cves": report.risk_summary.unique_cves,
            "mitre_attack": {
                "techniques": report.risk_summary.unique_techniques,
                "tactics": report.risk_summary.unique_tactics,
            },
        },
        "findings": [_serialize_finding(i, f) for i, f in enumerate(report.findings, 1)],
        "mitre_attack_coverage": _serialize_mitre_coverage(report),
        "timeline": [
            {
                "timestamp": e.timestamp,
                "phase": e.phase,
                "action": e.action,
                "tool": e.tool,
                "technique_id": e.technique_id,
                "result_summary": e.result_summary,
                "success": e.success,
            }
            for e in report.timeline
        ],
        "methodology": {
            "framework": report.scope.methodology,
            "tools_used": report.tools_used,
            "notes": report.methodology_notes,
            "duration_seconds": report.duration_seconds,
        },
    }


def _serialize_finding(index: int, finding: Finding) -> dict:
    mitre = []
    for tid in finding.attack_techniques:
        tech = get_technique(tid)
        tactics = tactics_for_technique(tid)
        mitre.append({
            "technique_id": tid,
            "technique_name": tech.name if tech else None,
            "url": technique_url(tid),
            "tactics": [{"id": t.id, "name": t.name} for t in tactics],
        })

    result: dict = {
        "index": index,
        "title": finding.title,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "description": finding.description,
        "remediation": finding.remediation,
        "affected_assets": finding.affected_assets,
        "evidence": finding.evidence,
        "found_at": finding.found_at,
    }

    if finding.cvss_score is not None:
        result["cvss"] = {"score": finding.cvss_score, "vector": finding.cvss_vector}
    if finding.cve_ids:
        result["cve_ids"] = finding.cve_ids
    if finding.cwe_ids:
        result["cwe_ids"] = finding.cwe_ids
    if mitre:
        result["mitre_attack"] = mitre
    if finding.tool_results:
        result["tool_results"] = [
            {
                "tool": tr.tool,
                "command": tr.command,
                "success": tr.success,
                "duration_ms": tr.duration_ms,
                "timestamp": tr.timestamp,
            }
            for tr in finding.tool_results
        ]

    return result


def _serialize_mitre_coverage(report: EngagementReport) -> dict:
    all_techniques: set[str] = set()
    for f in report.findings:
        all_techniques.update(f.attack_techniques)

    tactic_map: dict[str, list[dict]] = {}
    for tid in sorted(all_techniques):
        tech = get_technique(tid)
        if not tech:
            continue
        finding_count = sum(1 for f in report.findings if tid in f.attack_techniques)
        for tactic_id in tech.tactic_ids:
            tactic_map.setdefault(tactic_id, []).append({
                "technique_id": tid,
                "technique_name": tech.name,
                "url": technique_url(tid),
                "finding_count": finding_count,
            })

    from dixie.reporting.mitre import TACTICS
    return {
        tactic_id: {
            "tactic_name": TACTICS[tactic_id].name if tactic_id in TACTICS else tactic_id,
            "techniques": techs,
        }
        for tactic_id, techs in tactic_map.items()
    }
