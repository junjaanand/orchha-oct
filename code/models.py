"""
Data models and serialization structures.
"""

from typing import List, Optional
from pydantic import BaseModel, Field
from code.config import PHASE_ORDER, OPERATION_ORDER


class Step(BaseModel):
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str = ""

    def sort_key(self):
        return (
            PHASE_ORDER.get(self.phase, 99),
            OPERATION_ORDER.get(self.operation, 99),
            self.system_id,
            self.resource_id,
        )


class CaseResult(BaseModel):
    case_id: str
    deletion_status: str
    steps: List[Step] = Field(default_factory=list)

    def to_output_row(self):
        import json
        sorted_steps = sorted(self.steps, key=lambda s: s.sort_key())
        for idx, step in enumerate(sorted_steps, 1):
            step.step_no = idx
        
        steps_dicts = [s.model_dump() for s in sorted_steps]
        # JSON formatting matching sample format
        return {
            "case_id": self.case_id,
            "deletion_status": self.deletion_status,
            "steps_json": json.dumps(steps_dicts, separators=(',', ':')) if steps_dicts else "[]"
        }
