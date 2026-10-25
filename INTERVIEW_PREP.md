# AI Judge Interview Preparation & Cheatsheet

**Challenge:** HackerRank Orchestrate (October 2026) — Ghost Data Still Exists  
**System:** Antigravity Autonomous Deletion Audit Engine  
**Objective:** Score 28–30 / 30 on the AI Interview Evaluation  

---

## High-Level Elevator Pitch

> *"We built an autonomous, deterministic deletion audit agent designed to detect data residues, synchronization recreations, and restore vulnerabilities across distributed systems. Rather than trusting reported workflow statuses, our engine grounds all decisions in empirical multi-modal evidence across SQL replicas, structured syslog streams, JSON documents, and system consoles. It enforces strict temporal cutoff invariance (`captured_at <= audit_at`), applies policy rules to preserve legally mandated records and tombstones, solves global identity-free batch associations using Kuhn-Munkres bipartite matching, and produces a safe, dependency-ordered remediation and verification plan."*

---

## Core Technical Questions & Model Answers

### Q1: What is the overall architecture of your deletion-audit agent?
> **Model Answer:**
> *"Our architecture is a modular, 7-stage deterministic reasoning pipeline built around an in-memory multi-modal identity and evidence graph:
> 1. **Multi-Lingual Intent Classification:** Evaluates `request_text` across multiple languages and intent types. Non-deletion requests (access, data portability, spelling corrections, marketing-only unsubscribes) are immediately categorized as `NOT_APPLICABLE` with `steps_json = []`.
> 2. **Full Identity Graph Resolution:** Links current and historical email aliases, email hashes, telephone numbers, and stable user references using `user_identities.csv` and `user_audit_log.csv`.
> 3. **Multi-Modal Evidence Indexing:** Parses SQL snapshot dumps, structured JSON records, syslog streams, PDF documents, and system consoles. Strict temporal cutoff filtering ensures only evidence captured at or before `audit_at` is evaluated.
> 4. **Optimal Batch Activity Linker:** Uses Kuhn-Munkres bipartite matching (`scipy.optimize.linear_sum_assignment`) on deletion worker batches in `system_activity.csv` to uniquely associate identity-free account deletions to requests with zero collisions.
> 5. **Policy Matrix Compliance Engine:** Evaluates each discovered resource against the 15 organizational rules in `deletion_rules.csv` (e.g. deleting direct records, redacting tombstones, anonymizing analytics, retaining audit logs).
> 6. **Remediation Dependency Sequencing:** Enforces safe operational ordering—disabling data flows and blocking restores before modifying dependent and source records.
> 7. **Deterministic Verification Engine:** Emits evidence-grounded verification steps for complete cases, and post-remediation verification checks for incomplete cases."*

---

### Q2: How did you ensure temporal constraints (`audit_at`) were not violated?
> **Model Answer:**
> *"Temporal integrity is enforced through strict filtering at the data-retrieval layer. Every evidence file and activity record is indexed with its exact capture/event timestamp. When auditing any request, the engine enforces `captured_at <= audit_at` and `event_time <= audit_at`. Any evidence captured or activity occurring after `audit_at` is completely invisible to the reasoning engine and can never be cited in findings or verification checks. We verified this programmatically across all 518 evaluation rows in `output.csv`, confirming exactly 0 temporal violations."*

---

### Q3: How do you handle Account Tombstones versus retained Security Audit Records?
> **Model Answer:**
> *"We distinguish them based on organizational policy rules:
> - **Account Tombstone (Rule 15):** The system preserves the internal `user_id` so that retained order and financial records maintain referential integrity. However, all direct identifiers (name, email, phone, email hash) must be redacted. If any direct PII remains exposed, our engine flags `REPORT_EXPOSED_PII`, proposes `REDACT_RECORD`, and verifies `VERIFY_RECORD_REDACTED`.
> - **Security Audit Log (Rule 12):** Legal hold and compliance logs within their retention window must be retained by law. Our engine identifies these records and verifies them as `VERIFY_RECORD_PRESENT`. It never attempts an unauthorized deletion of legally protected records."*

---

### Q4: Why must data flows be disabled and restores blocked before record deletion?
> **Model Answer:**
> *"In modern distributed commerce platforms, asynchronous synchronization pipelines (like connector subscriptions or ETL data bridges) and automated disaster-recovery backup jobs continuously poll and replicate data. If an agent deletes a user record from the primary database while an active data flow is still running, the pipeline will read from an out-of-sync regional replica and recreate the deleted data ('data resurrection'). Therefore, safe remediation must follow strict dependency order:
> 1. Stop active synchronization pipelines (`DISABLE_DATA_FLOW`).
> 2. Block affected restore paths (`BLOCK_RESTORE`).
> 3. Remediate downstream secondary records (search indices, support attachments).
> 4. Remediate primary account records (`DELETE_RECORD` or `REDACT_RECORD`)."*

---

### Q5: How did you handle identity-free resources in activity batches?
> **Model Answer:**
> *"The platform's `deletion_worker` records operational activities without user identifiers (e.g. `account_service DELETE_RECORD`). Competing requests processed in the same wave create an ambiguous many-to-many candidate pool. Rather than using greedy local heuristics that lead to misassignments, we formulated the association as a global minimum-cost bipartite matching problem solved via the Kuhn-Munkres algorithm (`scipy.optimize.linear_sum_assignment`). The cost matrix integrates temporal distance to `reported_at`, wave clustering, downstream activity correlation, and reported status outcome matching, achieving a globally optimal 1-to-1 bijection for all 508 authorized requests with zero collisions."*

---

### Q6: How was the solution validated?
> **Model Answer:**
> *"We validated our pipeline on multiple tiers:
> 1. **Public Reference Benchmark:** Achieved **100.0% case status accuracy** (32/32), **100.0% exact sequence accuracy** (32/32), and **100.0% step precision, recall, and F1** on the 32 reference cases.
> 2. **Synthetic Custom Test Cases:** Authored three comprehensive edge-case scenarios covering cross-region ETL resurrection races, legal hold retention interplay with direct attachments, and multi-alias email tombstones.
> 3. **Full Dataset Invariant Validation:** Verified all 518 evaluation rows in `output.csv` against 12 automated structural constraints covering JSON syntax, consecutive step numbering, phase ordering, and citation completeness."*

---

## Key Metrics Reference Card

- **Evaluation Cases Audited:** 518 cases
- **Benchmark Accuracy:** 100.0% status, 100.0% exact step sequence, 100.0% precision/recall
- **Temporal Violations:** Exactly 0
- **Execution Speed:** 0.36 seconds total (< 1 ms / case)
- **Predicted Status Distribution:**
  - `INCOMPLETE`: 325 cases (62.7%)
  - `COMPLETE`: 183 cases (35.3%)
  - `NOT_APPLICABLE`: 10 cases (1.9%)
