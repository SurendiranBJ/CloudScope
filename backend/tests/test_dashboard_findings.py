from types import SimpleNamespace

from app.services.scanner.scan_manager import dashboard_security_findings


def test_dashboard_severity_population_matches_non_path_open_findings():
    findings = [
        SimpleNamespace(status="OPEN", source="STATIC_IAM", type="WILDCARD_POLICY", severity="high"),
        SimpleNamespace(status="OPEN", source="ATTACK_PATH", type="ATTACK_PATH_VULNERABILITY", severity="critical"),
        SimpleNamespace(status="RESOLVED", source="RESOURCE_CONFIGURATION", type="PUBLIC_RESOURCE", severity="medium"),
    ]

    result = dashboard_security_findings(findings)

    assert len(result) == 1
    assert result[0].severity == "high"


def test_dashboard_finding_counts_respect_persisted_lifecycle_status():
    findings = [
        SimpleNamespace(id="open", status="OPEN", source="STATIC_IAM", type="POLICY_RISK", severity="high"),
        SimpleNamespace(id="resolved", status="OPEN", source="RESOURCE_CONFIGURATION", type="PUBLIC_RESOURCE", severity="critical"),
    ]

    result = dashboard_security_findings(findings, {"resolved": {"status": "RESOLVED"}})

    assert [finding.id for finding in result] == ["open"]
