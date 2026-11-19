# Hashing RQ2 Evidence Discrepancy Audit

## Scope

This was a read-only review of the Hashing RQ2 design, implementation, tests, raw CSV, RQ3 outcome fields, and report references to the expected count. I counted and grouped the existing CSV rows using a read-only CSV parse. I did not run a benchmark or tests, and did not modify source, evidence, or the existing report.

## Files inspected

### Design, implementation, and tests

- `AGENTS.md` — project research scope and Hashing tampering requirements.
- `README.md:67-100` — Hashing runner, the two tampering checks, and the distinction between the baseline outcome CSV and RQ3 timing data.
- `hashing/experiment_runner.py:18-40,103-146,167-184` — algorithms, raw schema, row-generation loops, and command entry point.
- `hashing/digests.py` and `hashing/__init__.py` — digest API used by the runner.
- `hashing/tampering_performance_runner.py:19-63,200-275,277-300` — separate RQ3 scenarios, conditions, outcome fields, timed rows, and metadata.
- `hashing/tampering_performance_analysis.py:538-563` — RQ3 summary's separate outcome summary and timing analysis.
- `tests/test_hashing_experiment.py:19-24,71-111` — configured algorithms/sizes and test of the two baseline scenarios.
- `tests/test_hashing_tampering_performance.py:36-55,149-197,199-235` — preserved-file checksum list, RQ3 outcome checks, and test-only analysis structure.

### Hashing results and reports

- `results/hashing/rq2/baseline/hashing_tampering.csv` — the only file under `results/hashing/rq2/`.
- `results/hashing/rq3/tampering_performance/hashing_tampering_performance.csv`
- `results/hashing/rq3/tampering_performance/hashing_tampering_performance_metadata.json`
- `results/hashing/rq3/tampering_performance/hashing_tampering_performance_descriptive.csv`
- `results/hashing/rq3/tampering_performance/hashing_tampering_performance_paired_tests.csv`
- `results/hashing/rq3/tampering_performance/hashing_tampering_performance_summary.json`
- `reports/final/cryptography_under_adversarial_conditions.md` — RQ2 findings and authoritative evidence paths.
- `reports/final/evidence_matrix.md:10,20-26`
- `reports/final/rubric_audit.md:29-35`
- `reports/final/final_review_checklist.md:28,40-41`
- `reports/final/presentation_plan.md:8`

The complete `results/hashing/` inventory contains no additional Hashing RQ2 raw file, RQ2 summary, RQ2-specific metadata file, or RQ2 execution log. There is no separate Hashing RQ2 analysis module: the functional rows are written directly by `hashing/experiment_runner.py`.

## What one row represents

The RQ2 CSV has these columns: `Algorithm`, `Input size in bytes`, `Scenario`, `Verification passed`, `Tampering detected`, `Computed digest`, `Trusted original digest`, and `Accompanying digest`. It has 30 data rows plus one header line.

Each data row is one functional check for one algorithm × input-size × scenario combination. It is not a timing repetition, an aggregate, or a block observation. The file has no repetition or block field. The two rows for a particular algorithm and size both use modified data:

1. `modified_data_checked_against_trusted_digest`: compare the modified input's digest with the original trusted digest. The comparison rejects the modified input and marks tampering detected.
2. `modified_data_with_recomputed_unkeyed_digest`: compare the modified input's digest with a digest recomputed from that same modified input. The comparison passes; this demonstrates that an unkeyed digest supplied by an attacker does not authenticate the data.

The original input is used to prepare the trusted reference digest. There is no separate valid-original-data verification row in this baseline RQ2 file; the documented two-scenario design does not require one.

## Expected versus observed cases

| Item | Expected by repository design | Observed in saved RQ2 CSV | Result |
|---|---:|---:|---|
| Algorithms | 3: SHA-256, SHA3-256, BLAKE2b-256 | 3 | Complete |
| Input sizes | 5: 1 KiB, 10 KiB, 100 KiB, 1 MiB, 10 MiB | 5 | Complete |
| Scenarios | 2 tampering checks per algorithm and size | 2 | Complete |
| Rows per scenario | 3 algorithms × 5 sizes = 15 | 15 each | Complete |
| Unique algorithm × size × scenario configurations | 3 × 5 × 2 = 30 | 30 | Complete; no duplicate configuration keys |
| Repeated functional observations per configuration | 1; the RQ2 runner does not configure repetitions | 1 | Matches design |
| Total RQ2 rows | 3 × 5 × 2 × 1 = **30** | **30** | Complete under documented design |

The 30-row CSV contains all 15 configurations in each scenario, with exactly one row for every algorithm-size-scenario combination. Direct checks of the saved digest and outcome fields found 15/15 trusted-reference comparisons rejected and marked detected, and 15/15 attacker-recomputed-digest comparisons passed and were not marked detected. The CSV is therefore not an incomplete subset or an aggregate; it is the complete matrix the implemented baseline runner defines.

## Where the count of 90 came from

The count **90** is not present as a Hashing RQ2 target in the repository's design documentation, source, tests, or result metadata. It first appears in the earlier cross-category expected-observation table supplied in the conversation for the final-report task (`Hashing | RQ1 450 | RQ2 90 | RQ3 1,350`). That table gives the number without defining a Hashing RQ2 scenario matrix or repetitions that yield 90.

The project documentation instead says the baseline file records “two checks per algorithm and size” (`README.md:83-87`). The implementation has exactly those two scenarios (`hashing/experiment_runner.py:124-145`), and the test asserts `len(ALGORITHMS) * 2` rows when run with one test size (`tests/test_hashing_experiment.py:71-80`). Together with the three algorithms and five configured sizes, that defines 30 rows. Neither the supplied assignment requirements nor `AGENTS.md` specify a 90-row Hashing RQ2 requirement.

I cannot establish why 90 was entered in the earlier table. It could be a planning/counting error, but attributing a cause would be speculation. The repository evidence does establish that 90 was not generated by the implemented Hashing RQ2 design.

## RQ3 evidence boundary

The separate RQ3 raw file contains 1,350 measured rows: 30 randomized blocks × 45 algorithm-size-scenario conditions. It has 45 unique algorithm × size × scenario conditions, with 30 timed observations in each condition. The three scenarios are valid data versus trusted digest, modified data versus the trusted digest, and modified data versus an attacker-recomputed digest (`hashing/tampering_performance_runner.py:24-30,56-63`). Each timed row also records the verification outcome (`:33-53,241-269`).

The saved RQ3 CSV records 450 outcomes in each scenario: all 450 valid checks passed, all 450 modified-data checks against the trusted digest were rejected/detected, and all 450 checks against a recomputed digest passed. The RQ3 summary explicitly keeps the outcome summary separate from the performance analysis (`hashing/tampering_performance_analysis.py:538-549`). These fields provide outcome evidence from the RQ3 timing run. They are not 1,350 standalone RQ2 cases and do not turn the baseline RQ2 design into a 90-row design. The RQ3 repetitions should remain attributed to RQ3.

## Report wording reviewed and correction status

At the time of this audit, the final report accurately stated the literal row count, but phrased it as “30 rows, not the expected 90” and called it a material discrepancy. The evidence matrix, rubric audit, checklist, and presentation plan repeated that framing. This implied missing RQ2 observations even though the 30 rows completely covered the documented and implemented RQ2 matrix.

Correction status: the final report now states the complete 30-check design and results, without describing them as missing data. The evidence matrix, rubric audit, checklist, and presentation plan use the resolved count. RQ3 outcomes remain labeled as outcomes recorded during the separate RQ3 timing run. No experimental observations or classifications were changed.

## Questions requiring clarification

No lecturer clarification is needed to reconcile the repository's implemented Hashing RQ2 design: it is 30 rows. Clarification is warranted only if the lecturer separately specified 90 Hashing RQ2 cases outside the assignment requirements supplied here. If so, ask for the required scenario matrix and whether the count means additional scenario coverage or repeated cases; the current source and documentation do not define those missing 60 rows.

## Verdict

**RESOLVED: 30 rows are correct.** This verdict applies to the Hashing RQ2 design actually documented and implemented in the repository. The earlier 90-row table is unsupported by that design; it should not be represented as evidence of missing observations unless a separate lecturer instruction requiring 90 is produced.
