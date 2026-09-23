import pytest
from app.services.scanner.inventory import AWSInventory
from app.services.graph import graph_loader
from app.services.scanner.scan_manager import ScanManager

def test_canonical_node_deduplication():
    inv = AWSInventory()
    inv.users = [
        {"name": "alice", "arn": "arn:aws:iam::123456789012:user/alice", "groups": ["Developers", "SecurityAuditors"], "policies": ["ReadOnlyAccess"]},
        {"name": "bob", "arn": "arn:aws:iam::123456789012:user/bob", "groups": ["Developers"], "policies": []}
    ]
    inv.groups = [
        {"name": "Developers", "arn": "arn:aws:iam::123456789012:group/Developers", "policies": []},
        {"name": "SecurityAuditors", "arn": "arn:aws:iam::123456789012:group/SecurityAuditors", "policies": []}
    ]
    inv.roles = [
        {"name": "DevRole", "arn": "arn:aws:iam::123456789012:role/DevRole", "attachedPolicies": ["S3Access"], "trustPolicy": {}}
    ]
    inv.policies = [
        {"name": "ReadOnlyAccess", "arn": "arn:aws:iam::123456789012:policy/ReadOnlyAccess", "document": {}},
        {"name": "S3Access", "arn": "arn:aws:iam::123456789012:policy/S3Access", "document": {}}
    ]
    inv.s3 = [
        {"name": "prod-data", "arn": "arn:aws:s3:::prod-data", "region": "us-east-1"}
    ]

    G = graph_loader.build_local_graph(inv)
    assert G.number_of_nodes() > 0

    sm = ScanManager()
    sm.inventory = inv

    # Construct cytoscape elements using scan_manager's logic
    attack_path_node_ids = set()
    relevant_node_ids = set()
    for nid, attr in G.nodes(data=True):
        ntype = attr.get('type', 'Resource')
        if ntype in ('User', 'Group', 'Role', 'Policy'):
            relevant_node_ids.add(nid)
        elif G.in_degree(nid) > 0 or G.out_degree(nid) > 0:
            relevant_node_ids.add(nid)

    canonical_emitted_node_ids = set()
    canonical_emitted_arns = set()
    nid_to_canonical = {}

    for nid, attr in G.nodes(data=True):
        canon = attr.get('canonical_id') or nid
        nid_to_canonical[nid] = canon

    cytoscape_elements = []
    for nid in relevant_node_ids:
        attr = G.nodes[nid]
        if attr.get('is_canonical') is False:
            continue

        canonical_id = attr.get('canonical_id') or nid
        arn = attr.get('arn', '')

        if canonical_id in canonical_emitted_node_ids:
            continue
        if arn and arn in canonical_emitted_arns:
            continue

        canonical_emitted_node_ids.add(canonical_id)
        if arn:
            canonical_emitted_arns.add(arn)

        cytoscape_elements.append({
            "data": {
                "id": canonical_id,
                "label": attr.get('label', canonical_id),
                "type": attr.get('type', 'Resource'),
                "arn": arn
            }
        })

    node_elements = [e for e in cytoscape_elements if 'source' not in e['data']]
    node_ids = [n['data']['id'] for n in node_elements]
    assert len(node_ids) == len(set(node_ids)), f"Duplicate node IDs found: {node_ids}"

    # Verify canonical identity counts: exactly 1 for alice, Developers, SecurityAuditors
    alice_nodes = [n for n in node_elements if n['data']['label'] == 'alice']
    dev_nodes = [n for n in node_elements if n['data']['label'] == 'Developers']
    audit_nodes = [n for n in node_elements if n['data']['label'] == 'SecurityAuditors']

    assert len(alice_nodes) == 1, f"Expected 1 alice node, got {len(alice_nodes)}"
    assert len(dev_nodes) == 1, f"Expected 1 Developers node, got {len(dev_nodes)}"
    assert len(audit_nodes) == 1, f"Expected 1 SecurityAuditors node, got {len(audit_nodes)}"
