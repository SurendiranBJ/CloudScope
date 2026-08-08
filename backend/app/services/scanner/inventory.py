from typing import List, Dict, Any

class AWSInventory:
    def __init__(self):
        self.users: List[Dict[str, Any]] = []
        self.groups: List[Dict[str, Any]] = []
        self.roles: List[Dict[str, Any]] = []
        self.policies: List[Dict[str, Any]] = []
        self.ec2: List[Dict[str, Any]] = []
        self.s3: List[Dict[str, Any]] = []
        self.lambdas: List[Dict[str, Any]] = []
        self.secrets: List[Dict[str, Any]] = []
        self.rds: List[Dict[str, Any]] = []
        self.dynamodb: List[Dict[str, Any]] = []
        self.findings: List[Dict[str, Any]] = []
        self.alerts: List[Dict[str, Any]] = []

    def clear(self):
        self.users.clear()
        self.groups.clear()
        self.roles.clear()
        self.policies.clear()
        self.ec2.clear()
        self.s3.clear()
        self.lambdas.clear()
        self.secrets.clear()
        self.rds.clear()
        self.dynamodb.clear()
        self.findings.clear()
        self.alerts.clear()
