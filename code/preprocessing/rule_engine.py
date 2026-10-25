"""
Deletion policy rules engine.
"""

import csv
from typing import Dict, List, Optional
from code.config import DELETION_RULES_CSV


class RuleEngine:
    def __init__(self):
        self.rules: Dict[str, Dict[str, str]] = {}
        self._load()

    def _load(self):
        with open(DELETION_RULES_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.rules[row["rule_id"]] = row

    def get_action_for_category(self, category: str) -> str:
        for r in self.rules.values():
            if r["data_category"] == category:
                return r["required_action"]
        return "DELETE"

    def get_action_for_resource(self, system_id: str, resource_id: str) -> str:
        res_prefix = resource_id.split("_")[0] if "_" in resource_id else ""
        
        if res_prefix == "account":
            return "DELETE"
        elif res_prefix == "search":
            return "DELETE"
        elif res_prefix == "analytics":
            return "ANONYMIZE"
        elif res_prefix == "support":
            # If support message -> REDACT; if attachment -> DELETE
            return "REDACT"
        elif res_prefix == "export":
            return "DELETE"
        elif res_prefix == "data_flow" or res_prefix == "connector":
            return "DISABLE"
        elif res_prefix == "backup":
            return "BLOCK_RESTORE"
        elif res_prefix == "audit_record":
            return "RETAIN"
        elif res_prefix == "tombstone":
            return "REDACT"
        elif res_prefix == "marketing":
            return "DELETE"
        elif res_prefix == "cache":
            return "DELETE"
        return "DELETE"
