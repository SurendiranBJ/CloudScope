"""
CloudScope Centralized Semantic Edge Validation Layer.

Enforces valid AWS IAM and cloud infrastructure semantic relationships:
source node type + relationship type + target node type = valid semantic relationship.

Rejects and logs invalid relationships with meaningful diagnostics without
silently repairing invalid edges.
"""

import logging
from typing import Tuple, Optional, Set

logger = logging.getLogger("scanner")

# Resource types that policies can ALLOW
ALLOWED_POLICY_RESOURCE_TYPES: Set[str] = {
    "S3", "EC2", "Lambda", "Secrets", "Secret", "RDS", "DynamoDB"
}

# Explicit set of valid (source_type, relationship_type, target_type) tuples
VALID_SEMANTIC_EDGES: Set[Tuple[str, str, str]] = {
    # Identity & Group memberships
    ("User", "MEMBER_OF", "Group"),
    
    # Policy attachments
    ("User", "HAS_POLICY", "Policy"),
    ("Group", "HAS_POLICY", "Policy"),
    ("Role", "HAS_POLICY", "Policy"),
    
    # Role assumption (static trust & observed CloudTrail activity)
    ("User", "CAN_ASSUME", "Role"),
    ("User", "ASSUMED_ROLE", "Role"),
    ("Role", "CAN_ASSUME", "Role"),
    ("Role", "ASSUMED_ROLE", "Role"),
    
    # Compute to Role associations
    ("EC2", "ATTACHED_TO", "Role"),
    ("EC2", "EXECUTES_WITH", "Role"),
    ("Lambda", "EXECUTES_WITH", "Role"),
    
    # IAM Database Authentication
    ("Policy", "DB_CONNECT", "AuroraDBUser"),
    ("Policy", "DB_CONNECT", "RDS"),
    ("User", "DB_CONNECT", "RDS"),
    ("Role", "DB_CONNECT", "RDS"),
    ("AuroraDBUser", "BELONGS_TO", "RDS"),
    
    # CloudTrail Activity
    ("User", "OBSERVED_ACTIVITY", "ActivityEvent"),
    ("Role", "OBSERVED_ACTIVITY", "ActivityEvent"),
    ("ActivityEvent", "TARGETS", "Role"),
    ("ActivityEvent", "TARGETS", "Policy"),
    ("ActivityEvent", "TARGETS", "S3"),
    ("ActivityEvent", "TARGETS", "EC2"),
    ("ActivityEvent", "TARGETS", "User"),
    ("ActivityEvent", "TARGETS", "Secrets"),
    ("ActivityEvent", "TARGETS", "Secret"),
    ("ActivityEvent", "TARGETS", "RDS"),
    ("ActivityEvent", "TARGETS", "DynamoDB"),
}

# Add Policy/Identity -> ALLOWS -> Resource for each cloud resource type
for _res in ALLOWED_POLICY_RESOURCE_TYPES:
    VALID_SEMANTIC_EDGES.add(("Policy", "ALLOWS", _res))
    VALID_SEMANTIC_EDGES.add(("User", "ALLOWS", _res))
    VALID_SEMANTIC_EDGES.add(("Role", "ALLOWS", _res))
    VALID_SEMANTIC_EDGES.add(("User", "CAN_ACCESS", _res))
    VALID_SEMANTIC_EDGES.add(("Role", "CAN_ACCESS", _res))


def validate_edge(source_type: str, rel_type: str, target_type: str) -> Tuple[bool, Optional[str]]:
    """Validate that (source_type, rel_type, target_type) constitutes a valid semantic relationship.
    
    Returns:
        (True, None) if valid.
        (False, diagnostic_message) if invalid.
    """
    # Normalize resource variations
    src = "Secrets" if source_type == "Secret" else source_type
    tgt = "Secrets" if target_type == "Secret" else target_type

    candidate = (src, rel_type, tgt)
    if candidate in VALID_SEMANTIC_EDGES:
        return True, None

    msg = f"Disallowed relationship: ({source_type}) -[{rel_type}]-> ({target_type}) is not a permitted AWS authorization relationship."
    logger.warning(msg)
    return False, msg
