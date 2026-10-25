"""
System activity index indexing all deletion, sync, export, backup, and restore events.
"""

import csv
from typing import Dict, List, Optional
from code.config import SYSTEM_ACTIVITY_CSV


class SystemActivity:
    def __init__(self, activity_id: str, event_time: str, event_type: str,
                 source_system: str, target_system: str, resource_id: str,
                 reported_result: str, details: str):
        self.activity_id = activity_id
        self.event_time = event_time
        self.event_type = event_type
        self.source_system = source_system
        self.target_system = target_system
        self.resource_id = resource_id
        self.reported_result = reported_result
        self.details = details


class ActivityIndex:
    def __init__(self):
        self.activities: List[SystemActivity] = []
        self.by_resource_id: Dict[str, List[SystemActivity]] = {}
        self._load()

    def _load(self):
        with open(SYSTEM_ACTIVITY_CSV, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                act = SystemActivity(
                    activity_id=row["activity_id"],
                    event_time=row["event_time"],
                    event_type=row["event_type"],
                    source_system=row["source_system"],
                    target_system=row["target_system"],
                    resource_id=row["resource_id"],
                    reported_result=row["reported_result"],
                    details=row["details"],
                )
                self.activities.append(act)
                self.by_resource_id.setdefault(act.resource_id, []).append(act)

    def get_activities_for_resource(self, resource_id: str, before_time: Optional[str] = None) -> List[SystemActivity]:
        acts = self.by_resource_id.get(resource_id, [])
        if before_time:
            return [a for a in acts if a.event_time <= before_time]
        return acts

    def get_activities_in_window(self, start_time: str, end_time: str) -> List[SystemActivity]:
        return [a for a in self.activities if start_time <= a.event_time <= end_time]
