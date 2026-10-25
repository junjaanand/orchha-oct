# Ghost Data Still Exists: Autonomous Deletion Audit Agent

**HackerRank Orchestrate (October 2026)**  
**Challenge:** Ghost Data Still Exists  
**Team / Participant:** Autonomous Deletion Audit Engine  
**Live Benchmark:** 100.0% Sample Status Accuracy | 100.0% Sequence Accuracy | 100.0% Step F1 Score  

---

## 1. Executive Summary & Approach Overview

In modern distributed commerce platforms, a deletion workflow may report **Complete** while personal data remains across secondary databases, read-replicas, syslog streams, support attachments, exports, search indexes, or disaster recovery backups. Furthermore, active data synchronization pipelines (e.g., ETL bridges, connector subscriptions) can continuously resurrect deleted data from out-of-sync replicas.

This solution implements a production-grade, deterministic AI deletion audit agent that independently reconstructs the true state of personal data at each case's `audit_at` timestamp. Rather than accepting reported claims, the engine grounds all decisions in empirical evidence across multi-modal formats (SQL snapshots, structured JSON, syslog streams, PDF documents, and system consoles).

### Core Pipeline Architecture (7 Stages)

1. **Multi-Lingual Intent Classification (`code/pipeline/intent_classifier.py`):**
   Evaluates natural language `request_text` across multiple languages. Non-deletion requests (data access, portability, spelling updates, marketing-only unsubscribes) are identified as `NOT_APPLICABLE` with `steps_json = []`.

2. **Full Identity Graph Resolution (`code/preprocessing/identity_index.py`):**
   Reconstructs the subject's complete identity graph across current and historical emails, email hashes, phone numbers, names, and internal `user_id` references using `user_identities.csv` and `user_audit_log.csv`.

3. **Multi-Modal Evidence Indexing & Strict Temporal Cutoffs (`code/preprocessing/evidence_indexer.py`):**
   Parses SQL relational tables, JSON snapshot bundles, syslog archives, and PDF documents. Enforces strict temporal boundary filtering: **only evidence captured at or before `audit_at` (`captured_at <= audit_at`) is evaluated or cited.**

4. **Optimal Batch Activity Linker (`code/pipeline/batch_linker.py`):**
   Solves the ambiguous assignment of identity-free deletion worker activities (`account_service DELETE_RECORD`) via the **Kuhn-Munkres (Hungarian) algorithm** (`scipy.optimize.linear_sum_assignment`). Formulates a global minimum-cost matching matrix incorporating wave clustering, temporal proximity to `reported_at`, and downstream activity correlation, achieving a globally optimal 1-to-1 bijection with **zero collisions**.

5. **Policy Matrix Compliance Engine (`code/preprocessing/rule_engine.py`):**
   Applies the 15 organizational deletion rules from `deletion_rules.csv`:
   - Purges direct account records and search documents (`DELETE_RECORD`).
   - Redacts direct identifiers while preserving stable `user_id` for Account Tombstones (Rule 15).
   - Anonymizes analytics profiles (`ANONYMIZE_RECORD`).
   - Strictly preserves legal hold records within retention windows (`VERIFY_RECORD_PRESENT`, Rule 12).

6. **Remediation Dependency Sequencing:**
   Enforces safe operational ordering to prevent data resurrection race conditions:
   - **Infrastructure first:** Stop data flows (`DISABLE_DATA_FLOW`) and block restore paths (`BLOCK_RESTORE`).
   - **Downstream next:** Remediate search indices, analytics, and support attachments before primary records.
   - **Source last:** Delete or redact primary accounts.

7. **Deterministic Evidence-Backed Verification:**
   - For `COMPLETE` cases, emits only evidence-backed verification steps proving the compliant state at `audit_at`.
   - For `INCOMPLETE` cases, emits findings citing evidence, ordered future remediations (`evidence_id=""`), and post-remediation verification checks (`evidence_id=""`).

---

## 2. Setup & Execution Instructions

### Prerequisites

- Python 3.10+ (tested on Python 3.11)
- Standard scientific libraries: `numpy`, `scipy`

### Installation

Install required dependencies:

```bash
pip install numpy scipy
```

*(Note: The solution is completely offline and self-contained. No external LLM API keys or internet access are required for inference).*

### Running the Complete Pipeline

Run the full audit from the repository root:

```bash
python code/main.py
```

This single command:
1. Builds the in-memory multi-modal identity and evidence indexes (~0.4s).
2. Runs verification against all 32 public reference cases in `dataset/sample_deletion_requests.csv` and displays accuracy metrics.
3. Audits all 518 evaluation cases in `dataset/deletion_requests.csv`.
4. Writes the final validated `output.csv` directly at the repository root in **~0.36 seconds** (< 1 ms / case).

### Validating the Output

To verify that `output.csv` strictly adheres to all 12 platform structural and temporal constraints:

```bash
python scratch_validate_output.py
python scratch_verify_temporal.py
```

---

## 3. Quantitative Evaluation & Benchmark Results

### Public Reference Benchmark (32 Sample Cases)

```text
============================================================
Running Verification on 32 Public Sample Cases...
============================================================
Sample Status Accuracy:  32/32 (100.0%)
Exact Sequence Accuracy: 32/32 (100.0%)
Step Precision:          100.0%
Step Recall:             100.0%
Step F1 Score:           100.0%
============================================================
```

### Full Evaluation Dataset (518 Cases)

- **Total cases processed:** 518
- **Temporal violations:** Exactly **0** (verified across all cited evidence IDs)
- **Structural invariant pass rate:** **100.0%** (12 / 12 checks passed)
- **Predicted Status Distribution:**
  - `INCOMPLETE`: 325 cases (62.7%) &mdash; Data residues, active flows, or restore risks detected.
  - `COMPLETE`: 183 cases (35.3%) &mdash; Deletion verified complete with evidence-backed post-audit checks.
  - `NOT_APPLICABLE`: 10 cases (1.9%) &mdash; Non-deletion requests (access, portability, opt-outs).

---

## 4. Repository & Package Structure

```text
.
├── README.md                           # This setup and approach overview
├── INTERVIEW_PREP.md                   # Complete AI Judge Interview cheatsheet & Q&A briefing
├── AGENTS.md                           # Challenge guidelines & turn logging contract
├── problem_statement.md                # Official challenge problem statement
├── output.csv                          # Audited predictions for all 518 evaluation requests
├── log.txt                             # Complete AGENTS.md §5.1 & §5.2 compliant audit log
├── code.zip                            # Clean runnable submission package (38–41 KB)
├── code/
│   ├── main.py                         # High-performance pipeline orchestrator
│   ├── config.py                       # Paths, status constants, and operation enums
│   ├── models.py                       # Step, CaseResult, and serialization models
│   ├── pipeline/
│   │   ├── audit_engine.py             # Core deletion audit and policy reasoning engine
│   │   ├── batch_linker.py             # Kuhn-Munkres global bipartite activity matcher
│   │   └── intent_classifier.py        # Multi-lingual non-deletion intent filter
│   ├── preprocessing/
│   │   ├── activity_index.py           # System activity stream index
│   │   ├── evidence_indexer.py         # Multi-modal SQL, JSON, log, and PDF parser
│   │   ├── identity_index.py           # Historical identity graph resolution
│   │   └── rule_engine.py              # Policy rule definitions and operation mapping
│   └── evaluation/
│       ├── evaluation_report.md        # Detailed quantitative metrics & 3 custom test cases
│       └── usage_report.md             # Token consumption breakdown & cost analysis
└── evaluation/
    ├── evaluation_report.md            # Top-level duplicate for automated grading compatibility
    └── usage_report.md                 # Top-level duplicate for automated grading compatibility
```

---

## 5. Submission Deliverables Summary

| Item | File Path | Description |
|---|---|---|
| **Code Zip** | `code.zip` | Runnable source code, README, evaluation reports, zero dataset/caches |
| **Output CSV** | `output.csv` | 518 audited rows, sorted by `case_id`, 100% schema invariant pass |
| **Chat Transcript** | `log.txt` | Complete per-turn development audit log adhering to `AGENTS.md` §5 |
| **AI Interview Guide** | `INTERVIEW_PREP.md` | Model answers for the post-submission conversational evaluation |
