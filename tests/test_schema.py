"""Tests for engagement state and data models."""

from dixie.core.schema import Confidence, EngagementState, Finding, Severity, ToolResult


class TestToolResult:
    def test_create_success(self):
        result = ToolResult(
            tool="nmap_scan",
            command="nmap -sS 192.168.1.1",
            raw_output="22/tcp open ssh",
            success=True,
        )
        assert result.success
        assert result.error is None

    def test_create_failure(self):
        result = ToolResult(
            tool="nmap_scan",
            command="nmap -sS 10.0.0.1",
            raw_output="",
            success=False,
            error="Timeout after 300s",
        )
        assert not result.success
        assert "Timeout" in result.error


class TestFinding:
    def test_create_finding(self):
        finding = Finding(
            title="SSH Weak Key Exchange",
            description="Server supports weak key exchange algorithms",
            severity=Severity.MEDIUM,
            confidence=Confidence.CONFIRMED,
            evidence=["diffie-hellman-group1-sha1 supported"],
            remediation="Disable weak key exchange algorithms in sshd_config",
            affected_assets=["192.168.1.1:22"],
            attack_techniques=["T1595"],
        )
        assert finding.severity == Severity.MEDIUM
        assert finding.attack_techniques == ["T1595"]
        assert finding.attack_technique == "T1595"  # backward compat property

    def test_finding_defaults(self):
        finding = Finding(
            title="Test", description="Test", severity=Severity.INFO
        )
        assert finding.confidence == Confidence.TENTATIVE
        assert finding.attack_techniques == []
        assert finding.attack_technique is None
        assert finding.affected_assets == []


class TestEngagementState:
    def test_initial_state(self):
        state = EngagementState(target="192.168.1.1")
        assert state.target == "192.168.1.1"
        assert state.phase == "reconnaissance"
        assert state.iteration == 0
        assert len(state.findings) == 0

    def test_add_result(self):
        state = EngagementState(target="192.168.1.1")
        result = ToolResult(
            tool="nmap_scan",
            command="nmap -sS 192.168.1.1",
            raw_output="22/tcp open ssh",
        )
        state.add_result(result)
        assert len(state.tool_history) == 1

    def test_add_finding(self):
        state = EngagementState(target="192.168.1.1")
        finding = Finding(
            title="Open SSH",
            description="SSH is open",
            severity=Severity.INFO,
        )
        state.add_finding(finding)
        assert len(state.findings) == 1

    def test_summary(self):
        state = EngagementState(target="192.168.1.1")
        state.add_finding(Finding(
            title="Critical vuln", description="Bad", severity=Severity.CRITICAL
        ))
        state.add_finding(Finding(
            title="Info finding", description="FYI", severity=Severity.INFO
        ))
        summary = state.summary()
        assert summary["findings_count"] == 2
        assert summary["severity_breakdown"]["critical"] == 1
        assert summary["severity_breakdown"]["info"] == 1
