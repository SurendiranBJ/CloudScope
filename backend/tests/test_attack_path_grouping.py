"""
Unit tests validating Attack Path Deduplication and Shared-Node Grouping Logic
Matching cases 1-5 defined in CloudScope specification.
"""
from typing import List, Dict, Any

def group_attack_paths(raw_paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Groups attack paths by identical intermediate privilege chains.
    Preserves distinct security paths while consolidating common prefixes and targets.
    """
    group_map: Dict[str, Dict[str, Any]] = {}

    for path in raw_paths:
        nodes = path.get("nodes", [])
        if not nodes:
            continue

        source_node = nodes[0]
        target_node = nodes[-1] if len(nodes) > 1 else None

        # Intermediate nodes between source and target
        intermediate_nodes = nodes[1:-1] if len(nodes) > 2 else ([nodes[1]] if len(nodes) == 2 else [])
        
        is_direct_role = len(nodes) == 2 and nodes[1].get("type") == "Role"
        effective_chain = [nodes[1]] if is_direct_role else intermediate_nodes
        effective_target = None if is_direct_role else target_node

        # Grouping signature key
        if effective_chain:
            chain_key = "->".join(f"{n.get('type')}:{n.get('id') or n.get('name')}" for n in effective_chain)
        elif effective_target:
            chain_key = f"target:{effective_target.get('type')}:{effective_target.get('id') or effective_target.get('name')}"
        else:
            chain_key = f"source:{source_node.get('name')}"

        if chain_key not in group_map:
            group_map[chain_key] = {
                "groupId": f"group:{chain_key}",
                "sources": [source_node],
                "sharedChain": effective_chain,
                "targets": [effective_target] if effective_target else [],
                "originalPaths": [path]
            }
        else:
            group = group_map[chain_key]
            group["originalPaths"].append(path)

            # Deduplicate source
            if not any((s.get("id") or s.get("name")) == (source_node.get("id") or source_node.get("name")) for s in group["sources"]):
                group["sources"].append(source_node)

            # Deduplicate target
            if effective_target and not any((t.get("id") or t.get("name")) == (effective_target.get("id") or effective_target.get("name")) for t in group["targets"]):
                group["targets"].append(effective_target)

    return list(group_map.values())


def test_case_1_multiple_users_same_role():
    """CASE 1: Alice -> RoleA, Bob -> RoleA, Carol -> RoleA => 1 grouped path with 3 sources"""
    paths = [
        {"id": "p1", "nodes": [{"name": "Alice", "type": "User"}, {"name": "RoleA", "type": "Role"}]},
        {"id": "p2", "nodes": [{"name": "Bob", "type": "User"}, {"name": "RoleA", "type": "Role"}]},
        {"id": "p3", "nodes": [{"name": "Carol", "type": "User"}, {"name": "RoleA", "type": "Role"}]},
    ]
    groups = group_attack_paths(paths)
    assert len(groups) == 1
    assert len(groups[0]["sources"]) == 3
    source_names = [s["name"] for s in groups[0]["sources"]]
    assert "Alice" in source_names and "Bob" in source_names and "Carol" in source_names


def test_case_2_single_user_multiple_targets():
    """CASE 2: Alice -> RoleA -> S3-A, Alice -> RoleA -> S3-B, Alice -> RoleA -> S3-C => 1 grouped path with 3 targets"""
    paths = [
        {"id": "p1", "nodes": [{"name": "Alice", "type": "User"}, {"name": "RoleA", "type": "Role"}, {"name": "S3-A", "type": "S3"}]},
        {"id": "p2", "nodes": [{"name": "Alice", "type": "User"}, {"name": "RoleA", "type": "Role"}, {"name": "S3-B", "type": "S3"}]},
        {"id": "p3", "nodes": [{"name": "Alice", "type": "User"}, {"name": "RoleA", "type": "Role"}, {"name": "S3-C", "type": "S3"}]},
    ]
    groups = group_attack_paths(paths)
    assert len(groups) == 1
    assert len(groups[0]["sources"]) == 1
    assert len(groups[0]["targets"]) == 3
    target_names = [t["name"] for t in groups[0]["targets"]]
    assert "S3-A" in target_names and "S3-B" in target_names and "S3-C" in target_names


def test_case_3_different_roles_remain_separate():
    """CASE 3: Alice -> RoleA -> S3-A vs Alice -> RoleB -> S3-A => 2 different groups"""
    paths = [
        {"id": "p1", "nodes": [{"name": "Alice", "type": "User"}, {"name": "RoleA", "type": "Role"}, {"name": "S3-A", "type": "S3"}]},
        {"id": "p2", "nodes": [{"name": "Alice", "type": "User"}, {"name": "RoleB", "type": "Role"}, {"name": "S3-A", "type": "S3"}]},
    ]
    groups = group_attack_paths(paths)
    assert len(groups) == 2


def test_case_4_different_policies_remain_separate():
    """CASE 4: Alice -> RoleA -> PolicyA -> S3-A vs Alice -> RoleA -> PolicyB -> S3-A => 2 different groups"""
    paths = [
        {"id": "p1", "nodes": [{"name": "Alice", "type": "User"}, {"name": "RoleA", "type": "Role"}, {"name": "PolicyA", "type": "Policy"}, {"name": "S3-A", "type": "S3"}]},
        {"id": "p2", "nodes": [{"name": "Alice", "type": "User"}, {"name": "RoleA", "type": "Role"}, {"name": "PolicyB", "type": "Policy"}, {"name": "S3-A", "type": "S3"}]},
    ]
    groups = group_attack_paths(paths)
    assert len(groups) == 2


def test_case_5_multi_source_multi_target_dag():
    """CASE 5: Multiple users + common role + common policy + multiple targets => 1 combined branching group"""
    paths = [
        {"id": "p1", "nodes": [{"name": "carol-no-mfa", "type": "User"}, {"name": "OverlyTrustingAdminRole", "type": "Role"}, {"name": "AdministratorAccess", "type": "Policy"}, {"name": "S3-A", "type": "S3"}]},
        {"id": "p2", "nodes": [{"name": "Surendiran", "type": "User"}, {"name": "OverlyTrustingAdminRole", "type": "Role"}, {"name": "AdministratorAccess", "type": "Policy"}, {"name": "S3-B", "type": "S3"}]},
        {"id": "p3", "nodes": [{"name": "alice", "type": "User"}, {"name": "OverlyTrustingAdminRole", "type": "Role"}, {"name": "AdministratorAccess", "type": "Policy"}, {"name": "S3-C", "type": "S3"}]},
        {"id": "p4", "nodes": [{"name": "bob", "type": "User"}, {"name": "OverlyTrustingAdminRole", "type": "Role"}, {"name": "AdministratorAccess", "type": "Policy"}, {"name": "Secret-1", "type": "Secrets"}]},
    ]
    groups = group_attack_paths(paths)
    assert len(groups) == 1
    assert len(groups[0]["sources"]) == 4
    assert len(groups[0]["sharedChain"]) == 2
    assert len(groups[0]["targets"]) == 4
