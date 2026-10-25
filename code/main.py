"""
HackerRank Orchestrate - October 2026
Ghost Data Still Exists
Main entry point for the AI-powered deletion-audit agent.
"""

import os
import sys
import csv
import json
import time
from pathlib import Path

# Ensure repo root is on Python path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from code.config import (
    DATASET_DIR,
    DELETION_REQUESTS_CSV,
    SAMPLE_REQUESTS_CSV,
    SAMPLE_OUTPUT_CSV,
    OUTPUT_CSV,
    STATUS_COMPLETE,
    STATUS_INCOMPLETE,
    STATUS_NOT_APPLICABLE,
)
from code.preprocessing.identity_index import IdentityIndex
from code.preprocessing.activity_index import ActivityIndex
from code.preprocessing.evidence_indexer import EvidenceIndexer
from code.preprocessing.rule_engine import RuleEngine
from code.pipeline.batch_linker import BatchLinker
from code.pipeline.audit_engine import AuditEngine


def run_sample_evaluation(engine: AuditEngine, id_idx: IdentityIndex, act_idx: ActivityIndex, ev_idx: EvidenceIndexer):
    """Run verification against 32 ground-truth sample cases."""
    print("=" * 60)
    print("Running Verification on 32 Public Sample Cases...")
    print("=" * 60)

    with open(SAMPLE_REQUESTS_CSV, newline="", encoding="utf-8") as f:
        sample_reqs = list(csv.DictReader(f))

    with open(SAMPLE_OUTPUT_CSV, newline="", encoding="utf-8") as f:
        sample_outs = {row["case_id"]: row for row in csv.DictReader(f)}

    # Link sample cases
    sample_linker = BatchLinker(act_idx, id_idx, ev_idx)
    sample_linker.link_cases(sample_reqs)
    engine.set_batch_linker(sample_linker)

    correct_status = 0
    correct_steps = 0
    total = len(sample_reqs)

    total_exp_steps = 0
    total_act_steps = 0
    total_matched_steps = 0

    for req in sample_reqs:
        cid = req["case_id"]
        exp_row = sample_outs[cid]
        exp_status = exp_row["deletion_status"]
        exp_steps = json.loads(exp_row["steps_json"])

        res = engine.audit_case(
            cid, req["email"], req["requested_at"], req["reported_status"],
            req["reported_at"], req["audit_at"], req["request_text"]
        )
        out_row = res.to_output_row()
        act_status = out_row["deletion_status"]
        act_steps = json.loads(out_row["steps_json"])

        if act_status == exp_status:
            correct_status += 1
        if act_steps == exp_steps:
            correct_steps += 1

        exp_keys = {(s["phase"], s["operation"], s["resource_id"], s.get("evidence_id", "")) for s in exp_steps}
        act_keys = {(s["phase"], s["operation"], s["resource_id"], s.get("evidence_id", "")) for s in act_steps}
        total_exp_steps += len(exp_keys)
        total_act_steps += len(act_keys)
        total_matched_steps += len(exp_keys.intersection(act_keys))

    precision = total_matched_steps / total_act_steps if total_act_steps > 0 else 0.0
    recall = total_matched_steps / total_exp_steps if total_exp_steps > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    print(f"Sample Status Accuracy:  {correct_status}/{total} ({correct_status/total*100:.1f}%)")
    print(f"Exact Sequence Accuracy: {correct_steps}/{total} ({correct_steps/total*100:.1f}%)")
    print(f"Step Precision:          {precision*100:.1f}%")
    print(f"Step Recall:             {recall*100:.1f}%")
    print(f"Step F1 Score:           {f1*100:.1f}%")
    print("=" * 60)
    return correct_status, correct_steps, total, f1


def run_evaluation_dataset(engine: AuditEngine, id_idx: IdentityIndex, act_idx: ActivityIndex, ev_idx: EvidenceIndexer):
    """Run full audit across all 518 evaluation requests and produce output.csv."""
    print(f"Reading evaluation requests from {DELETION_REQUESTS_CSV}...")
    with open(DELETION_REQUESTS_CSV, newline="", encoding="utf-8") as f:
        requests = list(csv.DictReader(f))

    print(f"Processing global activity linking for {len(requests)} evaluation cases...")
    eval_linker = BatchLinker(act_idx, id_idx, ev_idx)
    eval_linker.link_cases(requests)
    engine.set_batch_linker(eval_linker)

    print(f"Processing {len(requests)} evaluation cases...")
    start_time = time.time()
    results = []

    status_counts = {
        STATUS_COMPLETE: 0,
        STATUS_INCOMPLETE: 0,
        STATUS_NOT_APPLICABLE: 0,
    }

    for idx, req in enumerate(requests, 1):
        cid = req["case_id"]
        res = engine.audit_case(
            cid, req["email"], req["requested_at"], req["reported_status"],
            req["reported_at"], req["audit_at"], req["request_text"]
        )
        out_row = res.to_output_row()
        results.append(out_row)
        status_counts[out_row["deletion_status"]] = status_counts.get(out_row["deletion_status"], 0) + 1

        if idx % 100 == 0 or idx == len(requests):
            elapsed = time.time() - start_time
            print(f"  Processed {idx}/{len(requests)} cases in {elapsed:.1f}s...")

    # Sort strictly by case_id
    results.sort(key=lambda r: r["case_id"])

    # Write output.csv at root
    fieldnames = ["case_id", "deletion_status", "steps_json"]
    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    elapsed_total = time.time() - start_time
    print(f"\nSuccessfully wrote {len(results)} rows to {OUTPUT_CSV}")
    print(f"Total time: {elapsed_total:.2f}s ({elapsed_total/len(requests)*1000:.1f}ms/case)")
    print("\nPredicted Status Distribution:")
    for status, count in sorted(status_counts.items()):
        print(f"  {status:18s}: {count:4d} ({count/len(requests)*100:.1f}%)")


def main():
    print("Initializing Ghost Data Still Exists deletion audit agent...")
    init_start = time.time()

    id_idx = IdentityIndex()
    act_idx = ActivityIndex()
    ev_idx = EvidenceIndexer(DATASET_DIR)
    rule_engine = RuleEngine()
    engine = AuditEngine(id_idx, act_idx, ev_idx, rule_engine)

    print(f"Indexes built in {time.time() - init_start:.2f}s.\n")

    # Run verification against sample dataset
    run_sample_evaluation(engine, id_idx, act_idx, ev_idx)

    # Run evaluation dataset and produce final output.csv
    run_evaluation_dataset(engine, id_idx, act_idx, ev_idx)


if __name__ == "__main__":
    main()
