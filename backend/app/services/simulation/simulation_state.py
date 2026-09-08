"""
CloudScope Simulation State Manager.

Stores pending IAM policy simulation changes in application memory.
Changes are NEVER applied to AWS or written to Neo4j.

The desired inventory is derived by applying simulation changes on top
of the current AWS inventory (a deep-copy). All security analysis
(risk, attack paths, blast radius) is then run against the desired
inventory using the SAME engines used for the current state.
"""

import copy
import logging
import uuid
from datetime import datetime, timezone
from threading import Lock
from typing import Dict, List, Optional, Any

logger = logging.getLogger("scanner")

# Actions supported by the simulation engine
SUPPORTED_ACTIONS = {"ATTACH_POLICY", "DETACH_POLICY"}

# Principal types supported
SUPPORTED_PRINCIPAL_TYPES = {"USER", "GROUP", "ROLE"}


class SimulationChange:
    """Represents a single pending IAM policy simulation change."""

    def __init__(
        self,
        action: str,
        principal_type: str,
        principal_id: str,
        policy_arn: str,
        policy_name: Optional[str] = None,
    ):
        if action not in SUPPORTED_ACTIONS:
            raise ValueError(f"Unsupported simulation action: {action}. Must be one of {SUPPORTED_ACTIONS}")
        if principal_type.upper() not in SUPPORTED_PRINCIPAL_TYPES:
            raise ValueError(f"Unsupported principal type: {principal_type}")

        self.change_id = str(uuid.uuid4())
        self.action = action
        self.principal_type = principal_type.upper()
        self.principal_id = principal_id
        self.policy_arn = policy_arn
        self.policy_name = policy_name or _name_from_arn(policy_arn)
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "change_id": self.change_id,
            "action": self.action,
            "principal_type": self.principal_type,
            "principal_id": self.principal_id,
            "policy_arn": self.policy_arn,
            "policy_name": self.policy_name,
            "timestamp": self.timestamp,
        }


def _name_from_arn(arn: str) -> str:
    """Extract policy name from ARN (e.g. arn:aws:iam::aws:policy/ReadOnlyAccess → ReadOnlyAccess)."""
    if arn and "/" in arn:
        return arn.split("/")[-1]
    return arn


class SimulationStateManager:
    """Thread-safe in-memory store for pending simulation changes.

    SAFETY GUARANTEES:
    - Never calls any AWS IAM mutation API.
    - Never writes to Neo4j.
    - Desired inventory is a deep-copy of current inventory + local mutations.
    """

    def __init__(self):
        self._changes: Dict[str, SimulationChange] = {}
        self._lock = Lock()

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def attach_policy(
        self,
        principal_type: str,
        principal_id: str,
        policy_arn: str,
        policy_name: Optional[str] = None,
    ) -> SimulationChange:
        """Record an ATTACH_POLICY simulation change."""
        change = SimulationChange(
            action="ATTACH_POLICY",
            principal_type=principal_type,
            principal_id=principal_id,
            policy_arn=policy_arn,
            policy_name=policy_name,
        )
        with self._lock:
            self._changes[change.change_id] = change
        logger.info(
            f"[SIMULATION] ATTACH_POLICY queued: {principal_type} '{principal_id}' "
            f"← {change.policy_name} ({policy_arn}) [change_id={change.change_id}]"
        )
        return change

    def detach_policy(
        self,
        principal_type: str,
        principal_id: str,
        policy_arn: str,
        policy_name: Optional[str] = None,
    ) -> SimulationChange:
        """Record a DETACH_POLICY simulation change."""
        change = SimulationChange(
            action="DETACH_POLICY",
            principal_type=principal_type,
            principal_id=principal_id,
            policy_arn=policy_arn,
            policy_name=policy_name,
        )
        with self._lock:
            self._changes[change.change_id] = change
        logger.info(
            f"[SIMULATION] DETACH_POLICY queued: {principal_type} '{principal_id}' "
            f"× {change.policy_name} ({policy_arn}) [change_id={change.change_id}]"
        )
        return change

    def remove_change(self, change_id: str) -> bool:
        """Remove a pending simulation change by ID. Returns True if found."""
        with self._lock:
            if change_id in self._changes:
                removed = self._changes.pop(change_id)
                logger.info(f"[SIMULATION] Change removed: {change_id} ({removed.action} {removed.policy_name})")
                return True
        logger.warning(f"[SIMULATION] Change not found for removal: {change_id}")
        return False

    def reset(self):
        """Clear all pending simulation changes."""
        with self._lock:
            count = len(self._changes)
            self._changes.clear()
        logger.info(f"[SIMULATION] Simulation state reset: {count} changes cleared")

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def get_changes(self) -> List[dict]:
        """Return a snapshot of all pending changes as dicts."""
        with self._lock:
            return [c.to_dict() for c in self._changes.values()]

    def has_changes(self) -> bool:
        with self._lock:
            return len(self._changes) > 0

    def change_count(self) -> int:
        with self._lock:
            return len(self._changes)

    # ------------------------------------------------------------------
    # Desired inventory derivation
    # ------------------------------------------------------------------

    def get_desired_inventory(self, current_inventory: Any) -> Any:
        """Derive the desired inventory by applying pending simulation changes
        to a deep-copy of the current AWS inventory.

        IMPORTANT: This never modifies the original inventory object.
        IMPORTANT: This never calls any AWS API.

        Args:
            current_inventory: AWSInventory instance from the last scan.

        Returns:
            A new AWSInventory-like object with simulation changes applied.
        """
        from app.services.scanner.inventory import AWSInventory

        with self._lock:
            changes_snapshot = list(self._changes.values())

        # Deep-copy all lists so we never mutate the real scan data
        desired = AWSInventory()
        desired.users = copy.deepcopy(current_inventory.users)
        desired.groups = copy.deepcopy(current_inventory.groups)
        desired.roles = copy.deepcopy(current_inventory.roles)
        desired.policies = copy.deepcopy(current_inventory.policies)
        desired.ec2 = copy.deepcopy(current_inventory.ec2)
        desired.s3 = copy.deepcopy(current_inventory.s3)
        desired.lambdas = copy.deepcopy(current_inventory.lambdas)
        desired.secrets = copy.deepcopy(current_inventory.secrets)
        desired.rds = copy.deepcopy(current_inventory.rds)
        desired.dynamodb = copy.deepcopy(current_inventory.dynamodb)
        desired.findings = copy.deepcopy(current_inventory.findings)
        desired.alerts = copy.deepcopy(current_inventory.alerts)

        # Build lookup maps for fast access
        user_map: Dict[str, dict] = {u["name"]: u for u in desired.users}
        group_map: Dict[str, dict] = {g["name"]: g for g in desired.groups}
        role_map: Dict[str, dict] = {r["name"]: r for r in desired.roles}

        for change in changes_snapshot:
            ptype = change.principal_type
            pid = change.principal_id
            arn = change.policy_arn
            pname = change.policy_name or _name_from_arn(arn)
            action = change.action

            if ptype == "USER":
                entity = user_map.get(pid)
                if entity is None:
                    logger.warning(f"[SIMULATION] User '{pid}' not found in inventory; skipping change.")
                    continue
                _apply_policy_change(entity, action, arn, pname, "policies", "attachedPolicyArns")

            elif ptype == "GROUP":
                entity = group_map.get(pid)
                if entity is None:
                    logger.warning(f"[SIMULATION] Group '{pid}' not found in inventory; skipping change.")
                    continue
                _apply_policy_change(entity, action, arn, pname, "attachedPolicies", "attachedPolicyArns")

            elif ptype == "ROLE":
                entity = role_map.get(pid)
                if entity is None:
                    logger.warning(f"[SIMULATION] Role '{pid}' not found in inventory; skipping change.")
                    continue
                _apply_policy_change(entity, action, arn, pname, "attachedPolicies", "attachedPolicyArns")

            else:
                logger.warning(f"[SIMULATION] Unknown principal type '{ptype}'; skipping change.")

        logger.info(f"[SIMULATION] Desired inventory derived: {len(changes_snapshot)} changes applied")
        return desired


def _apply_policy_change(
    entity: dict,
    action: str,
    policy_arn: str,
    policy_name: str,
    policy_list_key: str,
    policy_arns_key: str,
) -> None:
    """Apply an ATTACH or DETACH action to a single entity dict in place.

    This is purely a local data mutation. No AWS calls are made.
    """
    policies_list: List[str] = entity.setdefault(policy_list_key, [])
    arns_map: Dict[str, str] = entity.setdefault(policy_arns_key, {})

    if action == "ATTACH_POLICY":
        if policy_name not in policies_list:
            policies_list.append(policy_name)
        arns_map[policy_name] = policy_arn
        logger.debug(f"[SIMULATION] Attached '{policy_name}' to {entity.get('name', '?')}")

    elif action == "DETACH_POLICY":
        if policy_name in policies_list:
            policies_list.remove(policy_name)
        arns_map.pop(policy_name, None)
        logger.debug(f"[SIMULATION] Detached '{policy_name}' from {entity.get('name', '?')}")


# Module-level singleton — shared across all API routes
simulation_state = SimulationStateManager()
