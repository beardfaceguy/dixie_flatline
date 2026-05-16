"""Tests for structured reporting with MITRE ATT&CK mapping."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from dixie.core.schema import (
    Confidence,
    EngagementState,
    Finding,
    Severity,
    ToolResult,
)
from dixie.reporting import markdown as md_renderer
from dixie.reporting import json_report
from dixie.reporting.mitre import (
    TACTICS,
    TECHNIQUES,
    get_tactic,
    get_technique,
    resolve_technique_chain,
    tactics_for_technique,
    technique_url,
    techniques_for_tactic,
)
from dixie.reporting.models import (
    EngagementReport,
    RiskSummary,
    ScopeDefinition,
    TimelineEntry,
)


def _sample_findings() -> list[Finding]:
    return [
        Finding(
            title="SQL Injection in Login Form",
            description="The /admin/login endpoint is vulnerable to SQL injection via the username parameter.",
            severity=Severity.CRITICAL,
            confidence=Confidence.CONFIRMED,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cve_ids=["CVE-2024-12345"],
            cwe_ids=["CWE-89"],
            affected_assets=["192.168.1.10:443/admin/login"],
            evidence=[
                "Parameter: username\nPayload: ' OR 1=1--\nResponse: HTTP 200 with admin dashboard",
            ],
            remediation="Use parameterized queries. Implement input validation.",
            attack_techniques=["T1190"],
        ),
        Finding(
            title="SSH Weak Key Exchange Algorithms",
            description="The SSH server supports deprecated key exchange algorithms.",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            cvss_score=5.3,
            affected_assets=["192.168.1.10:22"],
            evidence=["diffie-hellman-group1-sha1 supported"],
            remediation="Disable weak key exchange algorithms in sshd_config.",
            attack_techniques=["T1595.002", "T1040"],
        ),
        Finding(
            title="Directory Listing Enabled",
            description="Web server exposes directory listings on /static/.",
            severity=Severity.LOW,
            confidence=Confidence.FIRM,
            affected_assets=["192.168.1.10:443/static/"],
            attack_techniques=["T1083"],
        ),
        Finding(
            title="Server Banner Disclosure",
            description="Web server reveals version in HTTP headers.",
            severity=Severity.INFO,
        ),
    ]


def _sample_engagement() -> EngagementState:
    ts = datetime(2026, 4, 30, 10, 0, 0, tzinfo=timezone.utc)
    state = EngagementState(target="192.168.1.10", started_at=ts)

    state.add_result(ToolResult(
        tool="nmap_scan", command="nmap -sV 192.168.1.10",
        raw_output="22/tcp open ssh OpenSSH 8.2\n443/tcp open https nginx 1.18",
        timestamp=datetime(2026, 4, 30, 10, 1, 0, tzinfo=timezone.utc),
        duration_ms=5000,
    ))
    state.add_result(ToolResult(
        tool="gobuster", command="gobuster dir -u https://192.168.1.10 -w common.txt",
        raw_output="/admin (Status: 200)\n/static (Status: 200)",
        timestamp=datetime(2026, 4, 30, 10, 3, 0, tzinfo=timezone.utc),
        duration_ms=12000,
    ))
    state.add_result(ToolResult(
        tool="nikto", command="nikto -h 192.168.1.10",
        raw_output="+ Server: nginx/1.18.0\n+ /admin/login: SQL Injection possible",
        timestamp=datetime(2026, 4, 30, 10, 5, 0, tzinfo=timezone.utc),
        duration_ms=30000,
    ))

    for f in _sample_findings():
        state.add_finding(f)

    return state


class TestMitreCatalog:
    def test_get_technique_exists(self):
        tech = get_technique("T1190")
        assert tech is not None
        assert tech.name == "Exploit Public-Facing Application"
        assert "TA0001" in tech.tactic_ids

    def test_get_technique_missing(self):
        assert get_technique("T9999") is None

    def test_get_tactic(self):
        tactic = get_tactic("TA0001")
        assert tactic is not None
        assert tactic.name == "Initial Access"

    def test_tactics_for_technique(self):
        tactics = tactics_for_technique("T1078")
        tactic_ids = {t.id for t in tactics}
        assert "TA0001" in tactic_ids
        assert "TA0003" in tactic_ids
        assert "TA0004" in tactic_ids

    def test_techniques_for_tactic(self):
        recon = techniques_for_tactic("TA0043")
        ids = {t.id for t in recon}
        assert "T1595" in ids
        assert "T1592" in ids

    def test_technique_url_explicit(self):
        assert technique_url("T1190") == "https://attack.mitre.org/techniques/T1190/"

    def test_technique_url_subtechnique(self):
        url = technique_url("T1059.001")
        assert url == "https://attack.mitre.org/techniques/T1059/001/"

    def test_resolve_technique_chain(self):
        chain = resolve_technique_chain(["T1190", "T1068", "T9999"])
        assert len(chain) == 2
        tech_ids = [t.id for t, _ in chain]
        assert "T1190" in tech_ids
        assert "T1068" in tech_ids

    def test_catalog_consistency(self):
        for tid, tech in TECHNIQUES.items():
            assert tid == tech.id
            for tac_id in tech.tactic_ids:
                assert tac_id in TACTICS, f"{tid} references unknown tactic {tac_id}"


class TestRiskSummary:
    def test_from_findings(self):
        findings = _sample_findings()
        risk = RiskSummary.from_findings(findings)
        assert risk.total_findings == 4
        assert risk.critical == 1
        assert risk.medium == 1
        assert risk.low == 1
        assert risk.info == 1
        assert risk.max_cvss == 9.8
        assert "CVE-2024-12345" in risk.unique_cves
        assert "T1190" in risk.unique_techniques

    def test_overall_risk_critical(self):
        risk = RiskSummary.from_findings(_sample_findings())
        assert risk.overall_risk == "Critical"

    def test_overall_risk_empty(self):
        risk = RiskSummary.from_findings([])
        assert risk.overall_risk == "Informational"
        assert risk.total_findings == 0

    def test_overall_risk_medium_only(self):
        findings = [Finding(
            title="Test", description="Test", severity=Severity.MEDIUM,
        )]
        risk = RiskSummary.from_findings(findings)
        assert risk.overall_risk == "Medium"

    def test_tactics_resolved(self):
        findings = _sample_findings()
        risk = RiskSummary.from_findings(findings)
        assert len(risk.unique_tactics) > 0
        assert "TA0001" in risk.unique_tactics  # T1190 maps to Initial Access


class TestEngagementReport:
    def test_from_engagement(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(
            state, title="Test Report", prepared_for="ACME Corp",
        )
        assert report.title == "Test Report"
        assert report.prepared_for == "ACME Corp"
        assert len(report.findings) == 4
        assert report.findings[0].severity == Severity.CRITICAL
        assert len(report.timeline) == 3
        assert "nmap_scan" in report.tools_used
        assert report.risk_summary.critical == 1

    def test_from_engagement_empty(self):
        state = EngagementState(target="10.0.0.1")
        report = EngagementReport.from_engagement(state)
        assert report.risk_summary.total_findings == 0
        assert report.executive_summary != ""

    def test_findings_sorted_by_severity(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        severities = [f.severity for f in report.findings]
        expected_order = [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        assert severities == expected_order

    def test_executive_summary_content(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        assert "192.168.1.10" in report.executive_summary
        assert "4 findings" in report.executive_summary
        assert "Critical" in report.executive_summary

    def test_duration_calculated(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        assert report.duration_seconds == 300  # 10:00 to 10:05


class TestMarkdownRenderer:
    def test_render_full_report(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state, title="MD Test")
        md = md_renderer.render(report)

        assert "# MD Test" in md
        assert "## Executive Summary" in md
        assert "## Findings" in md
        assert "SQL Injection in Login Form" in md
        assert "MITRE ATT&CK" in md
        assert "T1190" in md
        assert "## Attack Timeline" in md
        assert "nmap_scan" in md

    def test_render_empty_findings(self):
        state = EngagementState(target="10.0.0.1")
        report = EngagementReport.from_engagement(state)
        md = md_renderer.render(report)
        assert "No findings identified" in md

    def test_finding_has_cvss(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        md = md_renderer.render(report)
        assert "9.8" in md
        assert "CVSS:3.1" in md

    def test_finding_has_cve_links(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        md = md_renderer.render(report)
        assert "nvd.nist.gov/vuln/detail/CVE-2024-12345" in md

    def test_finding_has_cwe_links(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        md = md_renderer.render(report)
        assert "cwe.mitre.org" in md

    def test_mitre_matrix_section(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        md = md_renderer.render(report)
        assert "## MITRE ATT&CK Coverage" in md
        assert "Initial Access" in md

    def test_risk_summary_table(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        md = md_renderer.render(report)
        assert "Overall risk rating: Critical" in md


class TestJsonRenderer:
    def test_render_valid_json(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        output = json_report.render(report)
        data = json.loads(output)
        assert isinstance(data, dict)

    def test_json_structure(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        data = json.loads(json_report.render(report))

        assert "metadata" in data
        assert "scope" in data
        assert "executive_summary" in data
        assert "risk_summary" in data
        assert "findings" in data
        assert "mitre_attack_coverage" in data
        assert "timeline" in data
        assert "methodology" in data

    def test_json_metadata(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state, prepared_for="TestCo")
        data = json.loads(json_report.render(report))
        assert data["metadata"]["prepared_for"] == "TestCo"
        assert data["metadata"]["generator"] == "dixie-flatline"

    def test_json_findings(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        data = json.loads(json_report.render(report))
        findings = data["findings"]
        assert len(findings) == 4
        assert findings[0]["severity"] == "critical"
        assert findings[0]["cvss"]["score"] == 9.8

    def test_json_mitre_attack(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        data = json.loads(json_report.render(report))
        first_finding = data["findings"][0]
        assert "mitre_attack" in first_finding
        assert first_finding["mitre_attack"][0]["technique_id"] == "T1190"
        assert first_finding["mitre_attack"][0]["technique_name"] == "Exploit Public-Facing Application"

    def test_json_risk_summary(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        data = json.loads(json_report.render(report))
        risk = data["risk_summary"]
        assert risk["overall_risk"] == "Critical"
        assert risk["by_severity"]["critical"] == 1
        assert "T1190" in risk["mitre_attack"]["techniques"]

    def test_json_timeline(self):
        state = _sample_engagement()
        report = EngagementReport.from_engagement(state)
        data = json.loads(json_report.render(report))
        assert len(data["timeline"]) == 3
        assert data["timeline"][0]["tool"] == "nmap_scan"

    def test_json_empty_engagement(self):
        state = EngagementState(target="10.0.0.1")
        report = EngagementReport.from_engagement(state)
        data = json.loads(json_report.render(report))
        assert data["risk_summary"]["total_findings"] == 0
        assert data["findings"] == []
