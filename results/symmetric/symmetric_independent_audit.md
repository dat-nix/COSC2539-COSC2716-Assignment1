# Independent Audit: Symmetric Cryptography Experiments

**Audit date:** 19 November 2026
**Overall verdict: PASS WITH CORRECTIONS**

## Scope and evidence

I inspected the implementation, the experiment report, run metadata, the selected raw CSVs, and their analysis outputs. I independently checked row completeness and pairing, recomputed the RQ1 repeated-measures ANOVA and Friedman calculations, and recomputed the RQ3 paired differences, Monte Carlo sign-flip p-values, and Holm adjustments from the selected raw observations. The saved analysis summaries contain matching SHA-256 checksums for the raw CSVs.

No benchmark or experiment was rerun. No source code, raw data, or historical run was changed. The audit uses only corrected RQ3 `run_20261119_02`; the superseded RQ3 `run_20261119_01` is not included.

| Evidence | File | Rows | SHA-256 |
|---|---|---:|---|
| RQ1 raw | `results/symmetric/rq1/runs/run_20261119_01/symmetric_rq1_benchmarks.csv` | 900 | `52d6fa1949d1b131a18c5576faf5c19c6f30c5b0e0de16f0a81a86c822edc4b4` |
| RQ2 raw | `results/symmetric/rq2/runs/run_20261119_01/symmetric_rq2_outcomes.csv` | 90 | `e97b3441fcb82f0ce120d6b349a45d4da4d43dcefd3da0f98e60d7420b62ce49` |
| Corrected RQ3 raw | `results/symmetric/rq3/runs/run_20261119_02/symmetric_rq3_verification.csv` | 2,700 | `428c62fb7321cdb868c3aa60aa3c5d88ee9bae2366689c634d8f8727c5dbc4c3` |

For each run, the raw-file checksum equals the checksum in its final analysis JSON. The run metadata reports `status: complete` and the expected observation count.

## Cryptographic correctness — PASS, with an auditability note

- **AES-256-GCM:** `symmetric/aes_gcm.py:13-37` sets a 32-byte key, 12-byte nonce, and 16-byte tag; obtains keys from `AESGCM.generate_key(256)` and a new nonce from `secrets.token_bytes(12)` for each encryption call; and binds a scheme-specific associated-data string. Decryption validates envelope fields and returns the library's authenticated plaintext only after tag verification (`:41-61`).
- **ChaCha20-Poly1305:** `symmetric/chacha20_poly1305.py:13-37` uses the library's 32-byte key generator, 12-byte CSPRNG nonce, 16-byte Poly1305 tag, and scheme-specific associated data. The one-shot decrypt API returns plaintext only after successful authentication (`:41-58`).
- **AES-256-CBC + HMAC-SHA256:** `symmetric/aes_cbc_hmac.py:15-24` uses two separately generated 32-byte keys and a 16-byte IV. Encryption applies PKCS#7 padding, AES-256-CBC, and HMAC-SHA256 over a domain-separation value, IV, and ciphertext (`:27-61`). Decryption checks envelope structure, verifies HMAC with `hmac.compare_digest`, and only then decrypts and unpads (`:64-101`). Thus structurally valid tampering cannot reach CBC decryption or padding validation unless the MAC verifies. The public exception type/message is uniform; the local failure-stage attribute is diagnostic and must not be exposed remotely (`symmetric/common.py:18-32`).
- The RQ2 raw outcomes show 15/15 valid cases accepted and returning the expected plaintext, and **0/75 invalid cases releasing plaintext**. Corrected RQ3 likewise records no invalid plaintext release. The CSV schemas contain no key fields, and run metadata says key material was not written.

The source creates a fresh random nonce or IV on every encryption call, and the experiment seed is separate from cryptographic randomness (`symmetric/experiment_utils.py:25-38`; RQ1 metadata). I found no deliberate nonce or IV reuse. However, nonce/IV values are not stored in the raw CSV, so this audit cannot compare the actual generated values to prove that no random collision occurred. With the low number of encryptions under each run key, such a collision is extremely unlikely, but the report should state that uniqueness was not independently audited. For future auditability, record nonces/IVs (they are not secret) or record a per-key uniqueness check. **This is a documentation and auditability correction, not evidence of a cryptographic failure.**

The report correctly limits security claims: shared-key authentication does not identify a sender, replay prevention and key-management policy are outside scope, and finite tamper cases are not a security proof (`results/symmetric/symmetric_experiment_report.md:37-47, 161-164, 261-284`).

### Finding register and disposition

| ID | Severity | Finding | Disposition |
|---|---|---|---|
| AUD-SYM-01 | Low; auditability | Nonce/IV values are absent from raw records, so actual per-key uniqueness cannot be independently checked. | **Deferred for future instrumentation;** add the report disclosure now. No evidence of reuse was found and no experiment rerun is warranted. |
| AUD-SYM-02 | Methodological | RQ1 residual/difference normality is rejected and sequential blocks may be dependent. | **Accepted with disclosure;** the report states the diagnostics and limits the inference. |
| AUD-SYM-03 | Methodological | RQ3 inference depends on conditional label exchangeability and no consequential carry-over. | **Accepted with exploratory qualification;** no confirmatory or equivalence claim is justified. |

### Key inventory

| Key material | Purpose | Generation / storage in this study | Rotation |
|---|---|---|---|
| AES-GCM 256-bit key | AES-GCM encryption/authentication | Library CSPRNG; held in process memory for a run; not written to CSV or metadata | Not evaluated; run-scoped experiment key |
| ChaCha20-Poly1305 256-bit key | ChaCha20-Poly1305 encryption/authentication | Library CSPRNG; held in process memory for a run; not written to CSV or metadata | Not evaluated; run-scoped experiment key |
| CBC AES-256 key and HMAC-SHA256 key | CBC confidentiality and separate message authentication | Two `secrets.token_bytes(32)` results; held in process memory; not written to outputs | Not evaluated; run-scoped experiment keys |

This is an experiment harness, not a key-management system. Persistent storage, key rotation, revocation, and lifecycle controls were not evaluated.

## RQ1 — PASS

### Design and data integrity

The raw CSV contains exactly **900 unique observations**: 30 blocks × 30 scheme/size/operation conditions. Each block has positions 1–30 exactly once, each algorithm-operation-size cell has 30 observations, the five byte sizes are 1,024; 10,240; 102,400; 1,048,576; and 10,485,760, and the algorithms share the same input identifier for a given block and size. I verified that the monotonic end minus start equals the recorded duration for every row.

The runner creates payloads and reference envelopes before timing, performs five shuffled warm-ups for every condition per block, and appends only measured calls to CSV (`symmetric/experiment_runner.py:102-123, 125-168`). The timer encloses only the scheme call (`:129-136`); correctness checks and CSV writing occur after it. The metadata records 4,500 excluded warm-ups and the scope of encryption/decryption timing (`:175-195`).

### Statistical results independently checked

Each test is a separate one-factor repeated-measures ANOVA: input size is within-block and block is the subject. I recalculated the F-statistics, Greenhouse-Geisser epsilon and corrected degrees of freedom and p-values, partial eta-squared, Mauchly results, and Holm adjustment from the raw matrix. All match `symmetric_rq1_repeated_measures_anova.csv`. The six reported mean/median series also match the descriptive CSV; every series increases across the five sizes. The report's rounded means and medians at `results/symmetric/symmetric_experiment_report.md:92-99` are accurate.

| Scheme / operation | F | GG df (numerator, denominator) | Holm p | Partial η² | Mauchly p | Residual Shapiro p |
|---|---:|---:|---:|---:|---:|---:|
| AES-256-GCM encrypt | 2240.416399 | (1.068371, 30.982772) | 1.5553×10⁻³⁰ | 0.987221 | 4.7341×10⁻⁷⁰ | 4.1255×10⁻¹⁶ |
| AES-256-GCM decrypt | 1395.966412 | (1.057273, 30.660912) | 1.9344×10⁻²⁷ | 0.979649 | 1.7893×10⁻⁸⁸ | 7.3504×10⁻¹⁶ |
| ChaCha20-Poly1305 encrypt | 3806.925811 | (1.070936, 31.057154) | 5.7371×10⁻³⁴ | 0.992440 | 4.3330×10⁻⁸¹ | 2.4216×10⁻¹² |
| ChaCha20-Poly1305 decrypt | 7446.178262 | (1.063107, 30.830101) | 5.5961×10⁻³⁸ | 0.996120 | 3.5124×10⁻⁶⁷ | 1.1207×10⁻¹³ |
| AES-256-CBC + HMAC encrypt | 26684.144360 | (1.127879, 32.708498) | 3.7016×10⁻⁴⁹ | 0.998914 | 1.5223×10⁻⁴⁹ | 8.3251×10⁻¹³ |
| AES-256-CBC + HMAC decrypt | 5686.969980 | (1.026557, 29.770149) | 4.3105×10⁻³⁵ | 0.994926 | 2.1372×10⁻⁷⁰ | 1.5808×10⁻¹⁰ |

Mauchly's test rejects sphericity for all six comparisons, and the analysis applies Greenhouse-Geisser correction. Residual Shapiro-Wilk tests reject normality in all six comparisons; all ten pairwise difference-score normality checks per model also have a minimum p-value below 0.001. I recalculated the maximum absolute within-size lag-one correlation as **0.516853**, matching the report's 0.517. The supplementary Friedman statistics, Holm-adjusted p-values, and Kendall's W also match the raw data; all six rank tests are significant after Holm adjustment.

The report describes these assumption problems and the limitations accurately (`results/symmetric/symmetric_experiment_report.md:119-141, 261-284`). Greenhouse-Geisser addresses sphericity, not non-normality or temporal dependence. Friedman is a rank-based supplement, not a repair to the ANOVA mean model. The omnibus results establish an input-size effect under the model, not that every pair of sizes differs; no unsupported pairwise claim is made. Cross-scheme comparisons remain descriptive.

## RQ2 — PASS

The RQ2 raw CSV has exactly **90 distinct algorithm × size × scenario cases**: 15 valid and 75 invalid. All 90 `Outcome matched expectation` values are true. All valid cases were accepted and released the expected plaintext; all 75 invalid cases were rejected and released none. The invalid outcomes comprise **60 authentication-stage failures** and **15 envelope-validation failures**. I recomputed all 18 per-algorithm/per-scenario rows in the saved summary CSV from raw outcomes; they match. The summary JSON also reports 90 cases, all expected outcomes matched, and zero invalid plaintext releases.

This verifies the specific controlled functional cases only. It does not estimate attack probabilities or establish security against untested inputs. The report makes that limitation clear (`results/symmetric/symmetric_experiment_report.md:143-164`).

## RQ3 — PASS WITH EXPLORATORY INFERENCE

### Corrected run and pairing

The audit uses only `results/symmetric/rq3/runs/run_20261119_02/symmetric_rq3_verification.csv`; the analysis summary points to that exact raw file and its checksum matches. It has **2,700 unique rows**: 30 blocks × 90 conditions, with all 90 positions represented exactly once in each block. Each algorithm-size-scenario has one row per block (n=30), for 450 rows per scenario across the design. The timer duration equals end minus start for every row, and no invalid row released plaintext. The runner prepares all mutations before timing and encloses only the complete public decrypt call, including its rejection exception path (`symmetric/adversarial_runner.py:97-115, 130-139`).

The analysis contains exactly **75 paired valid-versus-invalid contrasts**—three schemes × five sizes × five invalid scenarios—and applies Holm adjustment across those 75 p-values. I independently paired rows on block, algorithm, size, and scenario; recalculated the mean and median differences, all matched percentage summaries, all 9,999-permutation Monte Carlo p-values with the recorded seed, and the Holm-adjusted values. The results match the paired-test CSV and summary. **36/75** comparisons are below 0.05 after Holm adjustment, with the same per-scheme/per-scenario counts shown in the report (`results/symmetric/symmetric_experiment_report.md:190-216`).

Examples checked directly against the raw data include:

- AES-GCM ciphertext tampering at 1 KiB: mean paired difference **+3.705 µs**, Holm p **0.0205**. The effect is small in absolute time and is not evidence of a general timing property.
- At 10 MiB, malformed AES-GCM input: mean difference **−2.7459 ms**, Holm p **0.0075**; malformed ChaCha20-Poly1305: **−5.3136 ms**, p **0.0075**. These invalid envelopes fail field validation early.
- At 10 MiB, CBC-HMAC ciphertext tampering: **−3.8711 ms**, p **0.0075**. Valid CBC-HMAC decryption performs HMAC plus CBC decryption/unpadding, while the tampered envelope fails HMAC and short-circuits before CBC. This is a difference between complete decryption workflows, not isolated MAC-verification overhead.
- The report's note that the ChaCha tag-tamper mean Δ is negative (−8.7 µs) while the mean of blockwise percentages is positive (+0.131%) is mathematically consistent: those columns average differently normalized quantities.

The diagnostics independently match: Shapiro-Wilk rejects **34/75** paired-difference sets; the block-trend diagnostic is nominally significant for **4/75**; the position-difference diagnostic is nominally significant for **5/75**; maximum absolute lag-one correlation is **0.422264**. These findings do not establish independence or rule out carry-over. The report appropriately qualifies the tests as conditional/exploratory, states the sharp-null and schedule assumptions, and does not interpret non-significance as equivalence (`results/symmetric/symmetric_experiment_report.md:178-186, 241-251`).

The label-swap/sign-flip calculation is consistent with the randomized complete-block schedule under the stated sharp null: for a given contrast, the valid/invalid labels are conditionally exchangeable across their assigned positions if the within-block shuffle is uniform and there is no consequential carry-over or interference. The implementation uses a seeded finite-state PRNG schedule, so the report's conditional qualification is necessary. Normality rejection alone does not invalidate this randomization test; dependence and carry-over remain more important threats. The results are not evidence of equivalence and do not isolate authentication cost.

## Statistical and methodological limitations

1. **RQ1 normality:** all six residual normality tests and the reported difference-score diagnostics reject. Greenhouse-Geisser corrects the sphericity reference degrees of freedom; it does not cure normality violations.
2. **Sequential dependence:** measurements were collected in sequential blocks on one machine. RQ1's maximum within-size lag-one correlation is 0.517; RQ3's maximum lag-one correlation is 0.422. Randomized positions reduce systematic order confounding but cannot establish independent blocks or remove thermal/cache/system drift or carry-over.
3. **RQ3 conditional inference:** the 75 sign-flip tests rely on conditional label exchangeability under the schedule, an approximate uniform PRNG shuffle, and no consequential carry-over. Diagnostics show reasons for caution; the findings should remain exploratory.
4. **Scope and generalization:** only one machine/software environment and pseudo-random byte payloads were studied. RQ3 measures complete decrypt calls, not the isolated cost of authentication, and no equivalence margin or equivalence test was specified.
5. **Nonce uniqueness auditability:** nonce/IV values were not persisted, so actual per-key uniqueness cannot be independently checked from these artifacts. Source inspection confirms fresh CSPRNG generation on every encryption call, but not a deterministic uniqueness guarantee.

## Exact corrections required

1. Add a short note to `results/symmetric/symmetric_experiment_report.md` (ideally in Section 2 or Section 8): nonce and IV values were generated with the OS/library CSPRNG for each encryption call but were not recorded; therefore this audit did not independently verify absence of a collision. State that collision risk at the observed run sizes is very low, not impossible. For future runs, record non-secret nonce/IV values or an automated per-key uniqueness check.
2. No statistical values, outcomes, implementations, or raw files require correction based on this audit. The existing RQ1 and RQ3 statistical caveats and RQ2 security limitations are accurate.

## Is a rerun necessary?

**No.** I found no incorrect cryptographic operation, missing or duplicated observation, outcome leak, timing-boundary mismatch, or mismatch between raw data and reported statistics. The nonce issue is an observability/documentation limitation; rerunning without recording nonce values would not resolve it. Preserve all runs and make the documentation correction only.

