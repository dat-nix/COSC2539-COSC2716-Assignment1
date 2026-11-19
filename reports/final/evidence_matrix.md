# Cross-category evidence matrix

This matrix uses the authoritative final runs listed below. It keeps each category's operation and comparison family separate. Times are local measurements, not cross-category rankings.

| RQ | Experiment / operation | Observation count | Important observed values | Statistical method / result | Caveat | Legitimate conclusion |
|---|---|---:|---|---|---|---|
| RQ1 | Hashing digest call; SHA-256, SHA3-256, BLAKE2b-256 | 450 (30 blocks × 15 conditions) | 1 KiB to 10 MiB mean: SHA-256 0.002661→4.833935 ms; SHA3-256 0.003629→16.374917 ms; BLAKE2b-256 0.003696→9.538529 ms | Separate one-way repeated-measures ANOVA; GG correction; Holm across 3. Adjusted p = 2.15e-44, 1.82e-52, 2.17e-36. Friedman supplements significant for all 3. | Residual normality rejected; sequential blocks and one byte buffer per block/size. | Within this run, digest time increased with input size for all three implementations. No cross-algorithm inferential ranking or every-size-pair conclusion. |
| RQ1 | Symmetric full encrypt/decrypt calls; three schemes | 900 (30 × 30) | At 10 MiB encryption/decryption means: AES-GCM 2.764/2.816 ms; ChaCha20-Poly1305 5.396/5.369 ms; CBC-HMAC 14.012/9.592 ms. All series rose with size. | Six separate one-way repeated-measures ANOVAs; GG correction; Holm across 6; all adjusted p < .05. Friedman supplements also significant. | Sphericity and normality rejected; max within-size lag-1 correlation 0.517. No between-scheme tests. | Payload size was associated with longer measured complete symmetric operations in this environment. |
| RQ1 | Asymmetric-based hybrid full encrypt/decrypt workflows; RSA, ECDH P-256, X25519 | 900 (30 × 30) | At 10 MiB encryption/decryption means: RSA 3.453/4.869 ms; ECDH 3.483/3.506 ms; X25519 3.403/3.457 ms. All 10 MiB means exceeded the corresponding 1 KiB means; RSA and X25519 decryption dipped slightly at 10 KiB before rising. | Six separate RM-ANOVAs with GG and Holm; all adjusted p < .05. Position-adjusted block-fixed OLS with CR1 was reported separately as sensitivity analysis; all six adjusted omnibus tests significant. | Residual and difference-score normality rejected; randomized position adjusted only in OLS; no direct between-scheme inference. | Payload size affected the measured hybrid workflows; public-key and derivation overhead is included by design. |
| RQ2 | Hashing trusted-digest comparison and attacker-recomputed unkeyed digest | 30 functional configurations (3 algorithms × 5 sizes × 2 scenarios; 1 check each); separate RQ3 file has 1,350 timed rows (450 per scenario) | RQ2: 15/15 modified inputs rejected against trusted digests; 15/15 comparisons against attacker-recomputed digests passed. RQ3 separately records 450/450 valid, 450/450 trusted-tamper rejection, and 450/450 recomputed-digest matches. | Functional outcome checks; no inferential attack probability. | RQ3 timings remain separate from RQ2 functional counts. | A hash detects change only relative to a trusted reference; an unkeyed digest cannot authenticate the source if an attacker can replace both data and digest. |
| RQ2 | Symmetric functional cases: valid, ciphertext/tag/nonce-or-IV tampering, wrong key, malformed envelope | 90 (15 per scenario) | All 90 outcomes matched expectations; 75/75 invalid cases rejected, 0 released plaintext; 60 authentication-stage and 15 envelope-validation failures. | Expected-versus-observed functional validation. | Finite test matrix; no probability or proof claim. | The implementation rejected the tested invalid messages without releasing plaintext. |
| RQ2 | Hybrid functional cases: valid, ciphertext/tag, wrapped-key, replacement/malformed public keys, malformed envelope | 85 (15 valid, 70 invalid) | 15/15 valid accepted; 70/70 invalid rejected; 0 invalid plaintext release. | Expected-versus-observed functional validation. | Failure stages differ; cases do not test all malformed inputs or sender authentication. | OAEP, parsing/key-agreement, and GCM rejected the tested invalid envelopes at the recorded stages. |
| RQ3 | Hashing digest plus digest comparison; valid and two tampering scenarios | 1,350 (30 × 45) | 45 planned paired contrasts; 0 Holm-significant. At 10 MiB trusted-tamper minus valid: −96.08 µs (SHA-256), +64.51 µs (SHA3-256), +16.25 µs (BLAKE2b-256); adjusted p = 1.0 for each. | Conditional within-block sign-flip tests; Holm across 45. | Block-level trend ρ=.581, p=.00075; inference exploratory; recomputed attacker digest generation excluded. | No adjusted difference was detected in this dataset; timing equivalence is not established. |
| RQ3 | Symmetric complete decryption attempts; five distinct invalid scenarios per scheme-size | 2,700 (30 × 90) | 75 paired contrasts; 36 Holm-significant. Malformed: 5/5 sizes for all schemes; CBC-HMAC: all five scenarios 5/5; AES-GCM ciphertext tamper 1/5; other AEAD cases mostly non-significant. | Conditional within-block label-swap tests; Holm across 75. | Maximum |lag-1|=.422; position/trend flags in some comparisons; exploratory, no equivalence margin. | Processing time depends on which failure stage is reached; tests compare complete decrypt calls, not isolated authentication cost. |
| RQ3 | Hybrid complete decryption attempts; ciphertext, tag, key-material, malformed | 2,250 (30 × 75) | 60 paired contrasts; 17 Holm-significant: 15 malformed and 2 key-material; 0 ciphertext/tag. | Conditional exhaustive label-swap analysis; Holm across 60. | Lag-1 block correlation .426, p=.0213; dependence diagnostic downgraded all inference to exploratory; no bootstrap CIs. | Early parsing and scheme-specific failure stages affect total attempted-decryption time; results are not confirmatory. |

## Authoritative evidence paths

### Hashing

- RQ1 raw: `results/hashing/rq1/randomized_block/hashing_randomized_block_benchmarks.csv`
- RQ1 descriptive: `results/hashing/rq1/randomized_block/hashing_randomized_block_descriptive.csv`
- RQ1 repeated-measures ANOVA and Friedman: `results/hashing/rq1/randomized_block/repeated_measures/hashing_repeated_measures_anova.csv`, `hashing_repeated_measures_friedman.csv`
- RQ2/RQ3 raw: `results/hashing/rq3/tampering_performance/hashing_tampering_performance.csv`
- RQ3 descriptive and tests: `results/hashing/rq3/tampering_performance/hashing_tampering_performance_descriptive.csv`, `hashing_tampering_performance_paired_tests.csv`, `hashing_tampering_performance_summary.json`
- Hashing documentation source: `README.md`. There is no standalone Hashing experiment report in the inspected project tree.

### Symmetric

- RQ1 raw: `results/symmetric/rq1/runs/run_20261119_01/symmetric_rq1_benchmarks.csv`
- RQ1 final analysis: `results/symmetric/rq1/analysis/run_20261119_02/`
- RQ2 raw and final validation: `results/symmetric/rq2/runs/run_20261119_01/symmetric_rq2_outcomes.csv`, `results/symmetric/rq2/analysis/run_20261119_02/`
- Corrected RQ3 raw: `results/symmetric/rq3/runs/run_20261119_02/symmetric_rq3_verification.csv`
- Corrected RQ3 analysis: `results/symmetric/rq3/analysis/run_20261119_03/`. Superseded RQ3 run `run_20261119_01` is not used.
- Category report and independent audit: `results/symmetric/symmetric_experiment_report.md`, `results/symmetric/symmetric_independent_audit.md`.

### Asymmetric-based hybrid

- RQ1 raw and analysis: `results/asymmetric/rq1/runs/run_20261119_01/`, `results/asymmetric/rq1/analysis/run_20261119_01/`
- RQ2 raw and analysis: `results/asymmetric/rq2/runs/run_20261119_01/`, `results/asymmetric/rq2/analysis/run_20261119_01/`
- RQ3 raw and analysis: `results/asymmetric/rq3/runs/run_20261119_01/`, `results/asymmetric/rq3/analysis/run_20261119_01/`
- Category report and interpretation: `results/asymmetric/asymmetric_experiment_report.md`, `asymmetric/interpretation_review.md`.

This matrix intentionally avoids summing observations across categories or treating their operation timings as comparable outcomes. Counts and tests describe separate experimental questions and planned families.
