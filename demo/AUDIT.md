# Demonstration and Presentation Asset Audit

## Repository state and scope

The working tree was clean before this presentation work. The final Markdown report is `reports/final/cryptography_under_adversarial_conditions.md`; its results and technical descriptions are the source of truth. The project environment at `.venv/` uses Python 3.14.10 and cryptography 50.0.2. The report records that experiment environment as CPython 3.14.10 and cryptography 50.0.2 for Symmetric and Hybrid; Hashing backend version metadata was not recorded.

No short, safe command-line demo existed. The existing command-line interfaces are experiment runners and write results, so this task adds a small wrapper that imports the real modules and runs only three in-memory message demonstrations. It does not use timers, result files, or experiment runners.

## Construction inventory

| Construction | Implementation and public API | Invalid/tampering behavior verified in source/tests | Existing automated test | Live-demo suitability |
|---|---|---|---|---|
| SHA-256 | `hashing/digests.py`, exported by `hashing/__init__.py`; `sha256(bytes) -> bytes`. | Digest calculation is deterministic; an external comparison against a trusted digest is needed. The 30-row RQ2 CSV distinguishes trusted-reference mismatch from attacker-recomputed digest match. | `tests/test_hashing.py` tests vectors, 32-byte output, reproducibility, and changed-input digests. | No dedicated CLI. Wrapper uses `sha256` and standard-library `hmac.compare_digest`. |
| SHA3-256 | `hashing/digests.py`; `sha3_256(bytes) -> bytes`. | Same unkeyed-digest limitation; not sender authentication. | `tests/test_hashing.py`. | Audited as part of the Hashing group; SHA-256 is used for the representative live example. |
| BLAKE2b-256 | `hashing/digests.py`; `blake2b_256(bytes) -> bytes` with 32-byte digest size. | Same unkeyed-digest limitation. | `tests/test_hashing.py`. | Audited as part of the Hashing group; SHA-256 is used for the representative live example. |
| AES-256-GCM | `symmetric/aes_gcm.py`; `generate_key`, `encrypt`, `decrypt`; envelope in `symmetric/common.py`. | Generates a 32-byte key and fresh 12-byte nonce; the API returns plaintext only after the library's GCM authentication succeeds. Invalid tags become `InvalidCiphertextError`. | `tests/test_symmetric_crypto.py` round-trips and checks no returned plaintext for invalid fields/tags/keys; `tests/test_demo.py` checks the live wrapper output. | Suitable. The demo alters a tag byte and prints rejection/no plaintext without showing secrets. |
| ChaCha20-Poly1305 | `symmetric/chacha20_poly1305.py`; `generate_key`, `encrypt`, `decrypt`. | Uses 32-byte key, fresh 12-byte nonce and 16-byte tag; invalid tag raises normalized `InvalidCiphertextError`; plaintext is returned only on successful library decryption. | `tests/test_symmetric_crypto.py`. | No need for a second symmetric live example; reported in the RQ2 summary. |
| AES-256-CBC + HMAC-SHA256 | `symmetric/aes_cbc_hmac.py`; `generate_key`, `encrypt`, `decrypt`. | Encrypt-then-MAC uses separate 32-byte keys; HMAC covers a context string, IV and ciphertext. `compare_digest` checks the MAC before `_decrypt_cbc` performs CBC decryption/unpadding. | `tests/test_symmetric_crypto.py`, including a mock asserting decryption is not called for invalid MAC/IV. | No need for a second live example; the exact order is discussed on the results slide. |
| RSA-OAEP + AES-256-GCM | `asymmetric/rsa_oaep_aes_gcm.py`; `generate_keypair`, `encrypt`, `attempt_decrypt`, `decrypt`; dispatch registry in `asymmetric/schemes.py`. | OAEP-SHA256 unwraps the fresh 32-byte AES key; GCM authenticates/decrypts the payload. `attempt_decrypt` records failure stage and leaves `accepted=False`, `plaintext=None`, `plaintext_released=False` on errors. | `tests/test_asymmetric_hybrid.py` verifies round-trip, tampering, OAEP failure, and malformed envelope handling; `tests/test_demo.py` checks the wrapper. | Suitable. The demo creates a fresh recipient pair in memory, then alters the tag and shows the GCM failure stage. |
| ECDH P-256 + HKDF-SHA256 + AES-256-GCM | `asymmetric/ecdh_p256_aes_gcm.py`; `generate_keypair`, `encrypt`, `attempt_decrypt`, `decrypt`. | Ephemeral sender P-256 ECDH and recipient key agreement feed HKDF-SHA256; GCM authenticates payload. Malformed ephemeral public keys fail at parsing; valid replacement-key material can reach GCM and fail authentication. | `tests/test_asymmetric_hybrid.py`. | Audited but not needed for the representative live Hybrid workflow. |
| X25519 + HKDF-SHA256 + AES-256-GCM | `asymmetric/x25519_aes_gcm.py`; `generate_keypair`, `encrypt`, `attempt_decrypt`, `decrypt`. | Ephemeral X25519 agreement and HKDF derive the AES key; malformed key bytes fail before GCM, while valid replacement key material reaches GCM and fails authentication. | `tests/test_asymmetric_hybrid.py`. | Audited but not needed for the representative live Hybrid workflow. |

## Exact project entry points and why they are not demo commands

- `python -m hashing.experiment_runner rq1|rq2|rq3` in `hashing/experiment_runner.py` starts the corresponding experiment. RQ1/RQ3 are benchmark runs; RQ2 writes functional records.
- `python -m symmetric.experiment_runner rq1|rq2|rq3` in `symmetric/experiment_runner.py` starts experiment generation and writes CSV/metadata.
- `python -m asymmetric.experiment_runner rq1|rq2|rq3` in `asymmetric/experiment_runner.py` starts experiment generation and writes CSV/metadata.
- `python -m hashing.statistical_analysis ...`, `python -m symmetric.statistical_analysis ...`, and `python -m asymmetric.statistical_analysis ...` analyze existing data. They are not demonstrations.

No existing CLI was run because it would generate experimental records. The presentation wrapper uses these three copy-ready commands instead:

~~~sh
python -m demo.run_demo hashing
python -m demo.run_demo symmetric
python -m demo.run_demo hybrid
~~~

They call `hashing.sha256`, `symmetric.aes_gcm`, and `asymmetric.rsa_oaep_aes_gcm`, respectively. No new cryptographic primitive or duplicate scheme is implemented.

## RQ2 evidence inventory

These counts are transcribed from current records, not generated by the demo:

| Group | Authoritative functional record | Rows | Observed outcomes |
|---|---|---:|---|
| Hashing | `results/hashing/rq2/baseline/hashing_tampering.csv` | 30 | 15 trusted-digest mismatches; 15 comparisons against attacker-recomputed unkeyed digests matched. |
| Symmetric | `results/symmetric/rq2/runs/run_20261119_01/symmetric_rq2_outcomes.csv` | 90 | 15 valid accepted; 75 invalid rejected with no plaintext returned. Invalid stages: 60 authentication and 15 envelope validation. |
| Hybrid | `results/asymmetric/rq2/runs/run_20261119_01/asymmetric_rq2_outcomes.csv` | 85 | 15 valid accepted; 70 invalid rejected with no plaintext. Of invalid cases, 40 reached AES-GCM authentication, 5 failed RSA-OAEP unwrap, 10 failed public-key parsing, and 15 failed common-envelope validation. |

RQ3 timing observations are separate: Hashing 1,350, Symmetric 2,700, and Hybrid 2,250 raw observations. They are not functional-case counts.

## Existing presentation and evidence assets

| Evidence | Authoritative paths | Recorded size / role |
|---|---|---|
| Hashing RQ1 | Raw: `results/hashing/rq1/randomized_block/hashing_randomized_block_benchmarks.csv`; descriptive: `results/hashing/rq1/randomized_block/hashing_randomized_block_descriptive.csv`; ANOVA/Friedman: `results/hashing/rq1/randomized_block/repeated_measures/hashing_repeated_measures_anova.csv`, `hashing_repeated_measures_friedman.csv`. | 450 raw timing observations; 30 blocks × 3 hashes × 5 sizes. |
| Symmetric RQ1 | Raw: `results/symmetric/rq1/runs/run_20261119_01/symmetric_rq1_benchmarks.csv`; report analysis: `results/symmetric/rq1/analysis/run_20261119_02/symmetric_rq1_descriptive.csv`, `symmetric_rq1_repeated_measures_anova.csv`. | 900 raw timings; 30 blocks × 3 schemes × 5 sizes × 2 operations. |
| Hybrid RQ1 | Raw: `results/asymmetric/rq1/runs/run_20261119_01/asymmetric_rq1_benchmarks.csv`; report analysis: `results/asymmetric/rq1/analysis/run_20261119_01/asymmetric_rq1_descriptive.csv`, `asymmetric_rq1_repeated_measures_anova.csv`. | 900 raw timings; 30 blocks × 3 schemes × 5 sizes × 2 operations. |
| Hashing RQ3 | Raw: `results/hashing/rq3/tampering_performance/hashing_tampering_performance.csv`; paired tests: `results/hashing/rq3/tampering_performance/hashing_tampering_performance_paired_tests.csv`. | 1,350 raw observations; 45 planned matched comparisons. |
| Symmetric RQ3 | Corrected raw run: `results/symmetric/rq3/runs/run_20261119_02/symmetric_rq3_verification.csv`; report paired tests: `results/symmetric/rq3/analysis/run_20261119_03/symmetric_rq3_paired_tests.csv`. | 2,700 raw observations; 75 planned matched comparisons. The report uses the corrected raw run; earlier run 01 is superseded. |
| Hybrid RQ3 | Raw: `results/asymmetric/rq3/runs/run_20261119_01/asymmetric_rq3_verification.csv`; paired tests: `results/asymmetric/rq3/analysis/run_20261119_01/asymmetric_rq3_paired_tests.csv`. | 2,250 raw observations; 60 planned matched comparisons. |

| Asset | Exact path | Use and limitation |
|---|---|---|
| Report Figure B2, Symmetric RQ1 | `results/symmetric/rq1/analysis/run_20261119_02/symmetric_rq1_execution_time.png` | Selected on presentation slide 6; mean encryption/decryption profiles for five sizes and three schemes. It is descriptive. |
| Report Figure C1, corrected Symmetric RQ3 | `results/symmetric/rq3/analysis/run_20261119_03/symmetric_rq3_execution_time.png` | Selected on slide 8. It visualizes complete-path means; authoritative raw data are `results/symmetric/rq3/runs/run_20261119_02/symmetric_rq3_verification.csv`. |
| Report Figure B1, Hybrid RQ1 | `results/asymmetric/rq1/analysis/run_20261119_01/asymmetric_rq1_execution_time.png` | Six small-multiple panels in a square image; not selected because the panels and labels would be too small on a single slide. |
| Hashing legacy baseline plot | `results/hashing/rq1/baseline/hashing_execution_time.png` | Not selected: it represents the obsolete sequential baseline, not the report's randomized-block primary Hashing RQ1. |
| Hashing RQ1 diagnostics | `results/hashing/rq1/randomized_block/hashing_randomized_block_diagnostics.png`; `results/hashing/rq1/randomized_block/repeated_measures/hashing_repeated_measures_diagnostics.png` | Diagnostics, not performance charts. |
| Hybrid RQ3 plot | `results/asymmetric/rq3/analysis/run_20261119_01/asymmetric_rq3_execution_time.png` | Exists but is not embedded in the report; its workload is a complete Hybrid path and is not required for this short demonstration deck. |
| Hashing RQ3 plot | None in current report assets | No plot is available. The report's RQ3 paired results remain the source for counts. |
| RQ2 visualization | None in current report assets | Slide 7 uses the actual outcome counts in the report and raw records; it does not invent a chart. |
| RQ1 ANOVA | `results/hashing/rq1/randomized_block/repeated_measures/hashing_repeated_measures_anova.csv`; `results/symmetric/rq1/analysis/run_20261119_02/symmetric_rq1_repeated_measures_anova.csv`; `results/asymmetric/rq1/analysis/run_20261119_01/asymmetric_rq1_repeated_measures_anova.csv` | Existing outputs support the reported within-series results; no analysis is run for this presentation. |

The RQ3 Holm-adjusted counts on slide 8 come from the final report: Hashing 0/45, Symmetric 36/75, Hybrid 17/60. They are planned paired contrasts, not counts of raw timing rows.

## Limitations

- The live examples demonstrate one Hashing, one Symmetric, and one Hybrid interface; they do not replay every RQ2 case.
- The wrapper does not benchmark and has no access to experimental CSV output paths.
- Fresh cryptographic randomness means ciphertext/envelope bytes vary between runs; only the labelled behavior and output states are expected to repeat.
- The demonstration does not establish formal security, sender identity, replay protection, or security of a deployed protocol.
- The professional IoT context in the report is academic framing; the code is run locally and does not interact with company, industrial, or supermarket systems.
