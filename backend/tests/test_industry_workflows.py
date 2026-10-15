"""Regression coverage for durable lifecycle state and scoped cache clearing."""

from unittest.mock import MagicMock

import pytest
import networkx as nx
import json

from app.cache import CacheManager
from app.persistence.repository import get_finding_state, get_finding_state_history, record_finding_state
from app.persistence import DatabasePersistenceError
from app.schemas import SecurityFinding
from app.routers import findings as findings_router
from app.security.models import AuthenticatedUser, Role
from app.services.findings.finding_service import FindingService
from app.services.simulation.simulation_state import SimulationStateManager
from app.services.attack.blast_radius import calculate_blast_radius


def test_finding_status_history_is_append_only_and_deduplicated():
    record_finding_state("finding-history-test", "OPEN", snapshot_id="scan-1")
    record_finding_state("finding-history-test", "OPEN", snapshot_id="scan-2")
    record_finding_state(
        "finding-history-test",
        "ACKNOWLEDGED",
        snapshot_id="scan-2",
        changed_by="analyst-1",
        change_reason="Assigned for investigation",
    )

    history = get_finding_state_history("finding-history-test")
    state = get_finding_state("finding-history-test")
    assert len(history) == 2
    assert history[0]["from_status"] == "OPEN"
    assert history[0]["to_status"] == "ACKNOWLEDGED"
    assert history[0]["actor_id"] == "analyst-1"
    assert history[0]["reason"] == "Assigned for investigation"
    assert state["status"] == "ACKNOWLEDGED"


def test_findings_list_overlays_durable_lifecycle_status(monkeypatch):
    finding = SecurityFinding(
        id="finding-status-overlay",
        type="TEST",
        category="IAM",
        title="Test finding",
        description="Test",
        severity="high",
        riskScore=80,
        source="STATIC_IAM",
        status="OPEN",
    )
    monkeypatch.setattr(findings_router, "get_current_findings", lambda: [finding.model_dump()])
    monkeypatch.setattr(findings_router, "get_all_finding_states", lambda: {
        finding.id: {
            "status": "ACKNOWLEDGED",
            "first_seen": "2026-10-01T00:00:00Z",
            "last_seen": "2026-10-02T00:00:00Z",
            "updated_at": "2026-10-03T00:00:00Z",
            "resolved_at": None,
            "assigned_to": "analyst-1",
            "due_date": "2026-10-10",
            "analyst_notes": "Investigating",
        }
    })

    response = findings_router.get_security_findings(
        severity=None,
        category=None,
        status=None,
        resourceType=None,
        region=None,
        principal=None,
        source=None,
        search=None,
        limit=None,
        offset=None,
        current_user=AuthenticatedUser(subject="viewer-1", roles=[Role.VIEWER]),
    )

    assert response.data[0].status == "ACKNOWLEDGED"
    assert response.data[0].assignedTo == "analyst-1"
    assert response.data[0].analystNotes == "Investigating"


def test_failed_durable_finding_transition_does_not_change_memory(monkeypatch):
    service = FindingService()
    finding = SecurityFinding(
        id="finding-durable-test",
        type="TEST",
        category="IAM",
        title="Test finding",
        description="Test",
        severity="high",
        riskScore=80,
        source="STATIC_IAM",
        status="OPEN",
    )
    service._memory_store = {finding.id: finding}
    monkeypatch.setattr(
        "app.persistence.repository.record_finding_state",
        MagicMock(side_effect=DatabasePersistenceError("database unavailable")),
    )
    monkeypatch.setattr(service, "_save_findings", MagicMock())

    with pytest.raises(DatabasePersistenceError):
        service.acknowledge_finding(finding.id, changed_by="officer-1")

    assert finding.status == "OPEN"
    assert service._save_findings.call_count == 0


def test_cache_clear_only_deletes_cloudscope_redis_keys():
    manager = CacheManager()
    redis_client = MagicMock()
    redis_client.scan_iter.return_value = iter(["v1:findings", "v1:graph"])
    manager.redis_client = redis_client
    manager.local_cache = {"v1:local": {}, "other-app:key": {}}

    manager.clear()

    redis_client.delete.assert_called_once_with("v1:findings", "v1:graph")
    redis_client.flushdb.assert_not_called()
    assert manager.local_cache == {}


def test_simulation_drafts_are_isolated_by_authenticated_owner():
    manager = SimulationStateManager()
    alice = manager.attach_policy("USER", "alice", "arn:aws:iam::aws:policy/ReadOnlyAccess", owner_id="issuer:alice")
    bob = manager.attach_policy("USER", "bob", "arn:aws:iam::aws:policy/ReadOnlyAccess", owner_id="issuer:bob")

    assert [item["change_id"] for item in manager.get_changes("issuer:alice")] == [alice.change_id]
    assert manager.remove_change(bob.change_id, owner_id="issuer:alice") is False
    assert manager.change_count("issuer:alice") == 1
    assert manager.change_count("issuer:bob") == 1

    manager.reset(owner_id="issuer:alice")
    assert manager.get_changes("issuer:alice") == []
    assert [item["change_id"] for item in manager.get_changes("issuer:bob")] == [bob.change_id]


def test_blast_radius_failure_is_reported_as_unknown_not_low_risk(monkeypatch):
    graph = nx.DiGraph()
    graph.add_node("user-1", type="User")
    monkeypatch.setattr(nx, "single_source_shortest_path_length", MagicMock(side_effect=RuntimeError("graph error")))

    result = calculate_blast_radius(graph, "user-1")

    assert result["status"] == "ERROR"
    assert result["is_complete"] is False
    assert result["blast_score"] is None
    assert result["severity"] == "unknown"


@pytest.mark.parametrize("trust_policy", [
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringLike": {"aws:SourceArn": "*"}},
        }],
    },
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
            "Action": "sts:AssumeRole",
            "Resource": "*",
        }],
    },
])
def test_trust_finding_requires_a_structural_wildcard_principal(trust_policy):
    from app.services.scanner.inventory import AWSInventory

    inventory = AWSInventory()
    inventory.roles = [{
        "name": "ScopedRole",
        "arn": "arn:aws:iam::123456789012:role/ScopedRole",
        "trustPolicy": json.dumps(trust_policy),
        "riskScore": 0,
    }]
    findings = FindingService().extract_findings_from_scan(inventory)

    assert not any(finding.type == "ASSUMEROLE_RISK" for finding in findings)


def test_structural_wildcard_assume_role_principal_creates_evidence_backed_finding():
    from app.services.scanner.inventory import AWSInventory

    inventory = AWSInventory()
    inventory.roles = [{
        "name": "OpenRole",
        "arn": "arn:aws:iam::123456789012:role/OpenRole",
        "trustPolicy": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            }],
        }),
        "riskScore": 0,
    }]

    finding = next(
        finding for finding in FindingService().extract_findings_from_scan(inventory)
        if finding.type == "ASSUMEROLE_RISK"
    )
    assert finding.riskFactors[0]["code"] == "WILDCARD_TRUST_PRINCIPAL"
    assert finding.evidence["trust_risk_factors"] == finding.riskFactors
