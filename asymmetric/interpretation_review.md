# Asymmetric Experiments: Interpretation and Research Audit

**Evidence set:** archived run `run_20261119_01`
**Scope:** RSA-OAEP + AES-256-GCM; ECDH P-256 + HKDF-SHA256 + AES-256-GCM; X25519 + HKDF-SHA256 + AES-256-GCM.

This review interprets existing observations and analysis outputs only. It does not modify or regenerate them. References such as “mean” and “median” below come from the saved descriptive CSVs; inferential results come from the saved analysis CSV/JSON files. Architectural explanations are identified as interpretation rather than direct component measurements.

## 1. What the experiment measured

### A hybrid scheme has two jobs

The three tested systems do not encrypt a 1 KiB–10 MiB payload directly with RSA or an elliptic-curve operation. Each is a **hybrid** scheme: an asymmetric-based mechanism establishes or protects a short symmetric key, and AES-256-GCM encrypts the actual payload.

- **RSA-OAEP + AES-256-GCM:** the sender creates a random 32-byte AES session key and a fresh GCM nonce. AES-GCM encrypts the payload. RSA-OAEP, configured with SHA-256, encrypts (wraps) only that AES key. The recipient first unwraps the key with its RSA private key, then asks AES-GCM to authenticate and decrypt the payload. The RSA key is 3,072 bits in this run.
- **ECDH P-256 + HKDF-SHA256 + AES-256-GCM:** the sender creates an ephemeral P-256 key pair and agrees a shared secret with the recipient’s public key. HKDF-SHA256 uses a fresh salt and a scheme-specific context string to derive a 32-byte AES key. AES-GCM encrypts the payload. The recipient uses its private key and the transmitted ephemeral public key to derive the same secret and AES key.
- **X25519 + HKDF-SHA256 + AES-256-GCM:** it follows the same key-agreement pattern as ECDH, using X25519 ephemeral keys and a separate HKDF context string. X25519 and ECDH produce a shared secret; they do not encrypt the payload themselves.
- **HKDF** is a key-derivation function. It turns the shared secret into a fixed-length AES key with the salt and context. HKDF does not encrypt data and does not identify the sender.
- **AES-GCM** encrypts the payload and produces a 16-byte authentication tag. On decryption, the tag is checked before the implementation returns plaintext. The versioned additional authenticated data also binds public envelope information (scheme, version, and, for the agreement schemes, salt and ephemeral public key). The GCM nonce is 12 bytes in this implementation.

These roles are visible in `asymmetric/rsa_oaep_aes_gcm.py` (especially lines 36–63 and 66–107), `asymmetric/ecdh_p256_aes_gcm.py` (lines 30–83 and 86–129), `asymmetric/x25519_aes_gcm.py` (lines 30–81 and 84–127), and `asymmetric/common.py` (key/nonce/tag constants and envelope AAD at lines 9–17 and 60–90).

### Timing boundaries

RQ1 measured the complete `encrypt` or `attempt_decrypt` call with `time.perf_counter()`. For RSA encryption, the timed call includes session-key and nonce creation, AES-GCM encryption, and RSA-OAEP key wrapping. For ECDH/X25519 encryption it includes ephemeral key generation, salt and nonce creation, key agreement, HKDF, and AES-GCM encryption. Decryption includes the corresponding key unwrap or public-key parsing/key agreement/HKDF work, then authenticated AES-GCM decryption. The RQ1 runner creates the payload buffers and valid decryption envelopes before the timer and places only the scheme call between the timer reads (`asymmetric/experiment_runner.py:167–195`). Five warm-ups per condition run before collection and are not recorded as measurements (`:137–165`).

RQ3 measured the full decryption attempt, including whatever work was done before an input was accepted or rejected. Mutated envelopes were constructed before each timer starts (`asymmetric/adversarial_runner.py:337–357`). Input generation, long-term recipient key-pair generation, envelope and mutation preparation, CSV writing, and statistical analysis are outside the measured interval.

RQ1 and RQ3 generate seeded pseudo-random byte buffers before timing. For a given block and size, the same buffer is shared across the schemes (and across operations/scenarios where applicable), so comparisons within that block use the same payload bytes. The contents are reproducible test inputs, not a representative corpus of real application data.

The experiment therefore compares **complete hybrid workflows on this host**. It does not isolate AES-GCM speed from key setup, key agreement, RSA wrapping/unwrapping, Python call overhead, or random-value generation.

## 2. RQ1 — effect of input size

Each cell below contains the observed **mean / median time in milliseconds** across 30 blocks. The five sizes are 1 KiB, 10 KiB, 100 KiB, 1 MiB, and 10 MiB. These are descriptive summaries, not statistical comparisons between schemes.

| Scheme / operation | 1 KiB | 10 KiB | 100 KiB | 1 MiB | 10 MiB |
|---|---:|---:|---:|---:|---:|
| RSA-OAEP + AES-GCM — encrypt | 0.07737 / 0.06942 | 0.09079 / 0.08715 | 0.1117 / 0.1023 | 0.4305 / 0.4119 | 3.4529 / 3.2679 |
| RSA-OAEP + AES-GCM — decrypt | 1.5799 / 1.5388 | 1.5739 / 1.5525 | 1.6118 / 1.5748 | 2.0104 / 1.9303 | 4.8695 / 4.8607 |
| ECDH P-256 + HKDF + AES-GCM — encrypt | 0.1406 / 0.1364 | 0.1448 / 0.1473 | 0.1690 / 0.1667 | 0.4597 / 0.4440 | 3.4832 / 3.2383 |
| ECDH P-256 + HKDF + AES-GCM — decrypt | 0.1102 / 0.1101 | 0.1189 / 0.1157 | 0.1460 / 0.1345 | 0.4987 / 0.4595 | 3.5055 / 3.2450 |
| X25519 + HKDF + AES-GCM — encrypt | 0.1146 / 0.1087 | 0.1241 / 0.1117 | 0.1418 / 0.1350 | 0.4625 / 0.4511 | 3.4026 / 3.2431 |
| X25519 + HKDF + AES-GCM — decrypt | 0.06793 / 0.06474 | 0.06515 / 0.06060 | 0.1035 / 0.09271 | 0.4525 / 0.4282 | 3.4565 / 3.2885 |

The source of these values is `results/asymmetric/rq1/analysis/run_20261119_01/asymmetric_rq1_descriptive.csv`; all per-cell standard deviations, ranges, and throughput values are also there.

### What the trends show

- **RSA encryption:** the mean rises from 0.07737 ms at 1 KiB to 3.4529 ms at 10 MiB. Its 10 MiB median is 3.2679 ms. This is a strong increase with payload size. The fixed-size RSA operation wraps a 32-byte key, while AES-GCM processes the payload. It is therefore plausible that the large-payload increase primarily reflects payload processing by AES-GCM, but this experiment did not time those components separately.
- **RSA decryption:** mean time is about 1.57–1.61 ms for 1–100 KiB, then 2.0104 ms at 1 MiB and 4.8695 ms at 10 MiB. The small dip from 1 KiB to 10 KiB means the observed means are not strictly increasing at every step. The relatively stable small-payload time is consistent with a substantial fixed OAEP-unwrapping cost; the later rise is consistent with more AES-GCM work. Those component explanations are architectural interpretations, not separately measured costs.
- **ECDH P-256 encryption:** mean time increases from 0.1406 ms at 1 KiB to 3.4832 ms at 10 MiB (10 MiB median 3.2383 ms). The small-input agreement/key-derivation work is part of every encryption, while the payload work grows with size.
- **ECDH P-256 decryption:** mean time increases from 0.1102 ms to 3.5055 ms (10 MiB median 3.2450 ms). The same size relationship appears for decryption, with public-key processing, agreement, and HKDF included at every size.
- **X25519 encryption:** mean time increases from 0.1146 ms to 3.4026 ms (10 MiB median 3.2431 ms). The fixed ephemeral-key/agreement work is combined with size-dependent AES-GCM processing.
- **X25519 decryption:** the mean is 0.06793 ms at 1 KiB and 0.06515 ms at 10 KiB, a small dip, before rising to 3.4565 ms at 10 MiB (median 3.2885 ms). Thus the broad endpoint increase is clear, although the first two group means are not monotonic.

The common empirical result is that moving from small payloads to MiB-scale payloads substantially increases the elapsed time of every complete scheme-operation combination. The curve is not purely linear at small sizes because fixed key-management work is a larger share of the total there. This experiment does not isolate the cost of each primitive, so it cannot quantify exactly how many milliseconds came from AES-GCM versus RSA, ECDH, X25519, HKDF, or random generation.

### Statistical interpretation

Six separate conventional one-factor repeated-measures ANOVAs were run: one for each scheme and operation. Within each test, input size has five levels and block is the subject. The null hypothesis is that all five input-size means are equal; the alternative is that at least one mean differs. Holm adjustment covers the six omnibus tests. The saved results are in `asymmetric_rq1_repeated_measures_anova.csv`.

| Scheme / operation | F | Greenhouse–Geisser df | Corrected p, Holm-adjusted | Partial η² |
|---|---:|---:|---:|---:|
| RSA encrypt | 644.63 | (1.043, 30.260) | 3.48×10⁻²²; 1.39×10⁻²¹ | 0.957 |
| RSA decrypt | 1192.94 | (1.689, 48.980) | 8.88×10⁻⁴¹; 5.33×10⁻⁴⁰ | 0.976 |
| ECDH encrypt | 556.36 | (1.035, 30.015) | 4.16×10⁻²¹; 8.33×10⁻²¹ | 0.950 |
| ECDH decrypt | 671.17 | (1.059, 30.717) | 9.66×10⁻²³; 4.83×10⁻²² | 0.959 |
| X25519 encrypt | 542.94 | (1.037, 30.068) | 5.48×10⁻²¹; 8.33×10⁻²¹ | 0.949 |
| X25519 decrypt | 631.29 | (1.046, 30.335) | 4.22×10⁻²²; 1.39×10⁻²¹ | 0.956 |

All six Mauchly tests rejected sphericity, so Greenhouse–Geisser corrected the degrees of freedom and p-values. That correction addresses sphericity; it does not address the other diagnostics. Shapiro–Wilk rejected residual normality in all six tests, and the minimum across the ten within-subject difference-score normality checks was below 0.05 for all six. The ANOVA output therefore supports a strong input-size association **with assumption caveats**, rather than an assumption-free conclusion. A significant omnibus test says at least one size mean differs; it does not identify which pairs differ.

The complementary position-adjusted, block-fixed-effects OLS model also found Holm-adjusted input-size effects in all six scheme-operation groups. It is not conventional repeated-measures ANOVA. Its diagnostics flagged a block-order trend for RSA encryption and serial dependence between blocks for RSA decryption. The other four OLS rows had no diagnostic flag, which does not prove independence or rule out carry-over. These results are in `asymmetric_rq1_model.csv`; supported OLS pairwise comparisons are in `asymmetric_rq1_pairwise.csv`.

**Direct answer to RQ1:** for every tested scheme and operation, the measured complete-workflow mean at 10 MiB was much higher than at 1 KiB. The ANOVAs support an input-size effect within each scheme-operation combination, subject to rejected normality diagnostics and sequential-block limitations. The experiment did not conduct inferential tests ranking the three schemes against one another; any cross-scheme comparison of the table is descriptive only.

## 3. RQ2 — tampering and invalid-input behavior

RQ2 contains 85 planned functional cases across the five sizes. Fifteen valid cases were accepted and released the expected plaintext. All 70 invalid cases were rejected and released no plaintext. The expected-versus-observed table reports that all 85 rows matched the planned outcome. These are controlled functional checks, not estimates of real-world attack success probabilities.

| Scenario | Attacker/input change | Rejecting component and observed stage | Plaintext released? | What this demonstrates | What it does not demonstrate |
|---|---|---|---|---|---|
| Valid control (15) | No change; a correctly formed envelope is supplied. | No failure; decryption completed. | Yes, original plaintext. | The tested scheme can encrypt and decrypt the tested inputs. | It does not test an attack or establish sender identity. |
| Ciphertext tampering (15) | The first ciphertext byte is changed; the tag is left unchanged. | AES-GCM tag check; `aes_gcm_authentication` (15/15). | No. | The tested ciphertext modification was rejected before plaintext was returned. | It does not cover every alteration, protocol attack, implementation, or side channel. |
| Tag tampering (15) | The first tag byte is changed. | AES-GCM authentication; `aes_gcm_authentication` (15/15). | No. | The tested invalid tag was rejected. | It does not establish a general security proof or quantify attacker success probability. |
| RSA wrapped-key tampering (5) | The first byte of the wrapped AES key is changed. | RSA-OAEP unwrapping; `rsa_oaep_unwrap` (5/5). GCM is not reached. | No. | A corrupted wrapped session key was rejected before payload decryption. | It does not measure GCM’s response for this case or prove resistance to every OAEP side channel. |
| Valid replacement ephemeral public key (10) | For ECDH/X25519, a different but well-formed ephemeral public key replaces the original. | Key agreement and HKDF complete; AES-GCM rejects the resulting envelope; `aes_gcm_authentication` (10/10). | No. | A valid replacement key leads to a different derived key and fails the existing envelope’s GCM check. | It does not authenticate the sender or rule out an attacker who can create a new valid envelope. |
| Malformed public key (10) | ECDH point bytes or X25519 public-key bytes are malformed. | Public-key parser; `public_key_parse` (10/10). | No. | These malformed key encodings fail before GCM. | It does not cover every malformed encoding or prove parser safety in general. |
| Malformed common envelope field (15) | The nonce is replaced with a short byte string. | Common envelope validation; `envelope_validation` (15/15). | No. | Invalid nonce length is rejected before decryption. | It does not test all possible invalid envelope fields. |

The case counts and stages above are supported by `results/asymmetric/rq2/runs/run_20261119_01/asymmetric_rq2_outcomes.csv` and `results/asymmetric/rq2/analysis/run_20261119_01/asymmetric_rq2_case_validation.csv`.

### Integrity is not sender authentication

AES-GCM’s tag detects a change to ciphertext or bound metadata when checked with the correct AES key. In this hybrid design that establishes the envelope’s integrity under the derived/session key. It does **not** prove who created the envelope. Anyone can use a recipient’s public key to choose a new session key (RSA scheme) or an ephemeral key agreement (ECDH/X25519), encrypt a message with AES-GCM, and make an internally valid envelope. No sender signature or sender-identity verification is part of these experiments. A successful GCM check means the supplied envelope is valid under the reconstructed key; it is not evidence of a particular person or system having sent it.

### Static recipient keys and forward secrecy

The recipient key pair is generated once for each experiment run, outside message timing. The ECDH and X25519 senders use fresh ephemeral private keys, but the recipient uses a long-term static private key. This arrangement does not provide forward secrecy against later compromise of that static recipient private key: a party holding recorded ECDH/X25519 envelopes can combine their recorded ephemeral public keys with the later-compromised recipient private key, reproduce the shared secret, and derive the AES key. In RSA, later compromise of the static RSA private key can unwrap the AES session keys recorded in old envelopes. This is a protocol-structure implication from the implemented key roles; the experiment did not simulate a later key compromise.

**Direct answer to RQ2:** all six classes of tested invalid input were rejected at their expected processing stage, and none of the invalid cases returned plaintext. This supports the tested implementation’s integrity and input-rejection behavior. It does not establish security against all attacks, authenticate senders, or provide forward secrecy against later recipient-key compromise.

## 4. RQ3 — valid versus invalid processing time

RQ3 contains 2,250 measured observations: 30 blocks × 3 schemes × 5 sizes × 5 scenarios. Each invalid attempt is matched to the valid attempt for the same block, scheme, and size. A positive difference means invalid took longer; a negative difference means invalid took less time. The paired test CSV contains 60 contrasts, each based on 30 block pairs.

| Invalid category | Observed failure stages across the 450 observations | Mean of the 15 scheme-size mean paired differences (ms) | Range of those 15 differences (ms) | Mean of the 15 contrast percentage changes | Holm p < 0.05 |
|---|---|---:|---:|---:|---:|
| Ciphertext tampering | All 450 reached and failed AES-GCM authentication. | +0.04269 | −0.05701 to +0.45033 | +8.66% | 0/15 |
| Tag tampering | All 450 reached and failed AES-GCM authentication. | +0.01042 | −0.08528 to +0.16666 | +5.05% | 0/15 |
| Key-material tampering | 150 RSA attempts failed OAEP unwrap; 300 ECDH/X25519 attempts completed agreement/HKDF and failed at GCM. | −0.22064 | −3.25311 to +0.26839 | −0.21% | 2/15 |
| Malformed envelope/public key | 150 RSA attempts failed envelope validation; 300 ECDH/X25519 attempts failed public-key parsing. | −1.24598 | −4.71800 to −0.05097 | −93.21% | 15/15 |

The “mean of 15” columns average the **15 per-scheme/per-size contrast summaries** for a category; they are not a pooled per-observation estimate. The full rows, medians, standard deviations, percentage differences, and p-values are in `results/asymmetric/rq3/analysis/run_20261119_01/asymmetric_rq3_paired_tests.csv`. Confidence-interval columns are blank for all 60 comparisons.

### What the comparisons mean

The ciphertext- and tag-tampering conditions are the closest comparisons to valid decryption when the question is specifically about GCM verification: they complete RSA unwrapping or ECDH/X25519 agreement and HKDF as appropriate, then reach the GCM authentication check. No such contrast had an adjusted p-value below 0.05. This is **not** proof of equal time or equivalence.

The other invalid categories do different amounts of work. RSA wrapped-key tampering stops at OAEP unwrapping. A valid alternate ECDH/X25519 public key gets as far as GCM and fails there. Malformed RSA envelope data or malformed elliptic-curve public-key data stops earlier in validation/parsing. It is expected that an attempt rejected early can take less time than one that performs key recovery/agreement and processes a large payload. The much lower malformed-input times are evidence about these specific rejection paths, not a universal rule that invalid ciphertext is faster.

Seventeen of the 60 Holm-adjusted p-values were below 0.05: 15 malformed-input contrasts and 2 key-material contrasts. None of the ciphertext-tampering or tag-tampering contrasts survived the family-wide adjustment. These p-values test a sharp null for each pair: swapping the valid and that invalid condition between their two assigned positions would change no outcome at either position in any block. The test is conditional on the recorded within-block shuffle and Python’s finite-state PRNG approximating a uniform shuffle; it also requires no consequential carry-over/interference.

The diagnostics flagged lag-1 dependence in block residual means (`r = 0.425779`, `p = 0.021286`). This indicates adjacent blocks’ residual timing levels were associated in this run. The cause was not established. Randomizing condition order reduces systematic order bias but does not remove temporal dependence or carry-over automatically. The analysis accordingly labels RQ3 conditional/exploratory and emits no block-bootstrap confidence intervals. The 17 nominal family-adjusted findings are exploratory signals, not confirmatory findings. A non-significant result is not evidence of equivalence; no application-specific equivalence margin was defined.

**Direct answer to RQ3:** measured valid-versus-invalid time depended on how far an invalid envelope progressed. Early malformed-input failures were much shorter on average; ciphertext/tag tampering that reached GCM had mixed small differences and no adjusted significant contrasts. Because the block-dependence diagnostic was flagged, these timing inferences remain exploratory, and they do not show that invalid attempts are universally faster or slower.

## 5. Consolidated research-results matrix

| RQ | Measurement | Main observed finding | Evidence | Interpretation | Limitations | Strength of conclusion |
|---|---|---|---|---|---|---|
| RQ1 | Mean/median encryption and decryption times at five sizes, analyzed separately for each scheme-operation group. | All six groups had much higher mean times at 10 MiB than at 1 KiB; e.g., RSA encryption 0.07737→3.4529 ms and X25519 decryption 0.06793→3.4565 ms. | `rq1/analysis/run_20261119_01/asymmetric_rq1_descriptive.csv` | Larger payloads take longer in the complete hybrid operation, consistent with more payload bytes processed by AES-GCM. | Component times are not separated; the X25519 and RSA decryption means have small non-monotonic steps. | **Supported by observed data** for the measured endpoint trend. |
| RQ1 | Six repeated-measures ANOVAs with block as subject and input size as the within-subject factor. | All six Holm-adjusted GG-corrected p-values were < 0.05; partial η² ranged 0.949–0.976. | `rq1/analysis/run_20261119_01/asymmetric_rq1_repeated_measures_anova.csv` | Evidence that at least one of the five size means differs within each scheme-operation group. | Mauchly rejected sphericity for all; GG was applied. Residual and difference-score normality also rejected. Omnibus tests do not identify pairs. | **Supported with statistical caveats.** |
| RQ1 | Position-adjusted block-fixed-effects OLS with CR1 cluster covariance. | All six adjusted omnibus tests had Holm p < 0.05; RSA encryption flagged a block-order trend and RSA decryption flagged between-block serial dependence. | `rq1/analysis/run_20261119_01/asymmetric_rq1_model.csv` | Complementary evidence for an input-size association after block and randomized position adjustment. | This is not conventional one-way RM-ANOVA; finite-cluster inference is approximate; diagnostics flagged two groups. | **Supported with statistical caveats.** |
| RQ1 / main RQ | Between-scheme performance ranking. | Mean and median values can be compared descriptively, but no inferential between-scheme test was performed. | RQ1 descriptive CSV; analysis scope in `asymmetric_experiment_report.md` | The data show observed timings for each scheme, but do not establish a statistically supported fastest scheme. | Distinct key-management workflows; no cross-scheme model or preplanned contrast family. | **Not established by this experiment.** |
| RQ2 | 85 valid/tampered/malformed functional cases, with failure stage and plaintext-release fields. | All 15 valid cases succeeded; all 70 invalid cases were rejected without plaintext; all expected-versus-observed checks matched. | `rq2/runs/run_20261119_01/asymmetric_rq2_outcomes.csv`; `rq2/analysis/run_20261119_01/asymmetric_rq2_case_validation.csv` | The implementation rejected the specific changes and malformed values tested. | Finite set of test cases; not attack probabilities, a security proof, sender authentication, or a complete side-channel analysis. | **Supported by observed data** for the cases tested. |
| RQ3 | 60 matched valid-versus-invalid time contrasts, each with 30 blocks and Holm adjustment. | 17 adjusted p-values were < 0.05 (15 malformed, 2 key-material); none for ciphertext/tag tampering. Malformed-input contrasts averaged −1.24598 ms across the 15 scheme-size summaries. | `rq3/analysis/run_20261119_01/asymmetric_rq3_paired_tests.csv` | Time differs by failure path; early parsing/validation can avoid the remaining decryption work. | Lag-1 block dependence flagged; conditional sharp-null/PRNG/no-carry-over assumptions; no CIs; no equivalence margin. | **Exploratory only.** |
| Main RQ | Combined performance and adversarial-response evidence. | The experiment documents size-related timing within each scheme and rejection of all tested invalid envelopes without plaintext release. | RQ1/RQ2/RQ3 evidence above | The selected hybrid implementations differ in measured workflow and failure-stage behavior under these controlled inputs. | No between-scheme significance tests; one environment/run; RQ1 assumptions and RQ3 dependence caveats; no sender identity or forward-secrecy experiment. | **Partly supported with statistical caveats; broader security claims not established.** |

## 6. Report-ready drafts

### A. Results

In the 30-block RQ1 experiment, mean encryption and decryption times increased substantially between 1 KiB and 10 MiB for all three hybrid schemes. RSA-OAEP + AES-256-GCM encryption increased from 0.07737 ms (median 0.06942 ms) to 3.4529 ms (median 3.2679 ms), while RSA decryption increased from 1.5799 ms (median 1.5388 ms) to 4.8695 ms (median 4.8607 ms). ECDH P-256 encryption increased from 0.1406 ms (median 0.1364 ms) to 3.4832 ms (median 3.2383 ms), and decryption from 0.1102 ms (median 0.1101 ms) to 3.5055 ms (median 3.2450 ms). X25519 encryption increased from 0.1146 ms (median 0.1087 ms) to 3.4026 ms (median 3.2431 ms), and decryption from 0.06793 ms (median 0.06474 ms) to 3.4565 ms (median 3.2885 ms). These values describe complete hybrid operations and should not be read as isolated primitive timings.

Separate repeated-measures ANOVAs tested input size within each scheme-operation group, treating the 30 blocks as subjects. Mauchly’s test rejected sphericity for all six groups, and Greenhouse–Geisser corrections were applied. The corrected Holm-adjusted p-values ranged from 5.33×10⁻⁴⁰ to 8.33×10⁻²¹, with partial η² from 0.949 to 0.976. Residual normality and within-subject difference-score normality diagnostics rejected their nulls for all six groups. Consequently, the ANOVA results indicate strong size-related differences but require caution; the omnibus tests do not identify which specific sizes differ. The complementary position-adjusted OLS analysis also produced six Holm-adjusted p-values below 0.05, while flagging an order trend for RSA encryption and serial dependence for RSA decryption.

The RQ2 functional matrix contained 85 cases. All 15 valid envelopes were accepted and released the original plaintext. All 70 invalid cases were rejected without plaintext release: ciphertext and tag changes and valid replacement ECDH/X25519 public keys failed at AES-GCM authentication; RSA wrapped-key changes failed at OAEP unwrapping; malformed common fields failed envelope validation; and malformed ECDH/X25519 public keys failed parsing. All 85 observed outcomes matched the expected case table.

RQ3 recorded 2,250 attempts and analyzed 60 matched valid-versus-invalid contrasts with Holm adjustment. Seventeen adjusted p-values were below 0.05: 15 malformed-input contrasts and 2 key-material contrasts. No ciphertext-tampering or tag-tampering contrast was significant after that correction. Across the 15 scheme-size summaries per category, malformed-input attempts averaged 1.24598 ms less than valid attempts (mean paired percentage change −93.21%); ciphertext- and tag-tampering differences averaged +0.04269 ms and +0.01042 ms, respectively. The analysis flagged lag-1 dependence between block residual means (`r = 0.425779`, `p = 0.021286`), downgraded inference to conditional/exploratory, and did not report confidence intervals.

### B. Discussion

The RQ1 measurements show that payload size is associated with the time required by each complete hybrid operation. At small sizes, the measured total also contains fixed work such as generating or deriving a key and wrapping/unwrapping the RSA session key. At large sizes, AES-GCM must process many more bytes. Because the implementation times each workflow as a whole, the apparent fixed overhead and payload-processing contribution are architectural interpretations; the experiment did not isolate or directly compare primitive-level costs. In particular, the descriptive timing table does not statistically establish that RSA, ECDH, or X25519 is the fastest scheme.

The RQ1 repeated-measures tests satisfy the lecturer’s one-way ANOVA requirement in a way that respects block pairing, but the rejected normality diagnostics limit the strength of their nominal p-values. Greenhouse–Geisser correction handles the observed sphericity violations only. The position-adjusted OLS analysis offers a distinct sensitivity analysis, not a substitute for the RM-ANOVA; its own RSA order/dependence flags and finite number of blocks should remain visible in the report. The appropriate conclusion is a strong observed payload-size association in this run, with statistical caveats—not proof that every adjacent size differs or that the results generalize to every machine or workload.

The RQ2 cases demonstrate that AES-GCM rejected the selected ciphertext/tag modifications without releasing plaintext. They also show why failure stage matters: RSA wrapped-key tampering failed before GCM, while altered valid ECDH/X25519 ephemeral public keys allowed agreement and HKDF to complete before the existing ciphertext failed authentication. The results demonstrate integrity checking for the tested envelopes, not sender authentication. Since anyone can encrypt to the recipient’s public key, the recipient needs a separate sender-authentication mechanism if it must know who authored a message.

RQ3 shows that “invalid input” is not one uniform workload. A malformed field can be rejected during validation, while a ciphertext or tag modification can consume key-recovery/key-agreement work and process the payload through GCM before rejection. The large negative timing differences for malformed inputs therefore reflect early rejection, not an inherent speed advantage of invalid data. The 17 nominal Holm-adjusted results are exploratory because sequential blocks showed lag-1 residual association and the conditional label-swap inference depends on its assignment and no-carry-over assumptions. The absence of significant ciphertext/tag comparisons cannot support an equivalence claim: no application-specific equivalence margin was specified, and confidence intervals were omitted after the dependence diagnostic.

The main research question is answered only within the tested scope: these runs provide performance observations by size and functional evidence for the selected tampering cases. They do not prove general security, sender identity, forward secrecy, or a statistically tested ranking among the three schemes. Later compromise of the static recipient private key would expose recorded RSA-wrapped session keys and allow recomputation of ECDH/X25519 shared secrets from recorded ephemeral public keys; this limitation follows from the key arrangement and was not itself tested as an attack scenario.

## 7. Researcher comprehension check (Tiếng Việt)

1. **Ba phát hiện quan trọng nhất:** (a) dữ liệu lớn hơn làm thời gian của cả ba quy trình hybrid tăng đáng kể; (b) cả 70 trường hợp đầu vào sai trong bộ kiểm tra đều bị từ chối và không trả plaintext; (c) thời gian xử lý đầu vào sai phụ thuộc vào lỗi xảy ra ở bước nào.
2. **Insight bảo mật quan trọng nhất:** AES-GCM phát hiện các thay đổi đã thử, nhưng điều đó không chứng minh ai gửi thông điệp. Bất kỳ ai có public key của người nhận đều có thể tạo một envelope mới hợp lệ; muốn xác thực người gửi cần cơ chế riêng. Khóa riêng dài hạn của người nhận bị lộ về sau cũng có thể làm lộ dữ liệu đã ghi lại trong cấu hình này.
3. **Insight hiệu năng quan trọng nhất:** tệp lớn làm AES-GCM phải xử lý nhiều byte hơn nên toàn bộ quy trình lâu hơn; đầu vào sai bị phát hiện sớm có thể nhanh hơn vì bỏ qua các bước giải mã phía sau. Đây là giải thích phù hợp với kiến trúc, không phải phép đo tách riêng thời gian của AES-GCM.
4. **Điều chưa thể kết luận:** không thể khẳng định scheme nào nhanh nhất về mặt thống kê, không thể nói mọi đầu vào sai đều nhanh hơn/chậm hơn, không thể xem kết quả không có ý nghĩa thống kê là tương đương, và không thể tuyên bố hệ thống an toàn trước mọi kiểu tấn công.
5. **Câu trả lời 30 giây:** “Nhóm thử nghiệm ba hệ mã hóa hybrid, trong đó RSA hoặc ECDH/X25519 bảo vệ/tạo khóa AES và AES-GCM mã hóa dữ liệu. Với cả ba nhóm, thời gian tăng rõ khi kích thước tăng từ 1 KiB lên 10 MiB. Các thay đổi ciphertext/tag đã thử đều bị phát hiện, không trả plaintext. Thời gian xử lý dữ liệu sai phụ thuộc vào lỗi bị phát hiện sớm hay muộn; kết quả thời gian RQ3 chỉ mang tính khám phá vì có dấu hiệu phụ thuộc giữa các block. Thử nghiệm không chứng minh danh tính người gửi hoặc scheme nào nhanh nhất trong mọi điều kiện.”

## 8. Evidence files and remaining information gaps

### Evidence consulted

- Project requirements: `AGENTS.md`; project documentation: `README.md` and `results/asymmetric/asymmetric_experiment_report.md`.
- Scheme implementation: `asymmetric/rsa_oaep_aes_gcm.py`, `asymmetric/ecdh_p256_aes_gcm.py`, `asymmetric/x25519_aes_gcm.py`, and shared envelope/AAD behavior in `asymmetric/common.py`.
- Measurement and scenario implementation: `asymmetric/experiment_runner.py` and `asymmetric/adversarial_runner.py`.
- Statistical methods: `asymmetric/repeated_measures.py` and `asymmetric/statistical_analysis.py`.
- RQ1 raw and metadata: `results/asymmetric/rq1/runs/run_20261119_01/asymmetric_rq1_benchmarks.csv` and `asymmetric_rq1_metadata.json`.
- RQ1 results: `results/asymmetric/rq1/analysis/run_20261119_01/asymmetric_rq1_descriptive.csv`, `asymmetric_rq1_repeated_measures_anova.csv`, `asymmetric_rq1_model.csv`, `asymmetric_rq1_pairwise.csv`, and `asymmetric_rq1_summary.json`.
- RQ2 raw and metadata: `results/asymmetric/rq2/runs/run_20261119_01/asymmetric_rq2_outcomes.csv` and `asymmetric_rq2_metadata.json`.
- RQ2 validation/results: `results/asymmetric/rq2/analysis/run_20261119_01/asymmetric_rq2_case_validation.csv`, `asymmetric_rq2_summary.csv`, and `asymmetric_rq2_summary.json`.
- RQ3 raw and metadata: `results/asymmetric/rq3/runs/run_20261119_01/asymmetric_rq3_verification.csv` and `asymmetric_rq3_metadata.json`.
- RQ3 results: `results/asymmetric/rq3/analysis/run_20261119_01/asymmetric_rq3_descriptive.csv`, `asymmetric_rq3_paired_tests.csv`, `asymmetric_rq3_diagnostics.csv`, and `asymmetric_rq3_summary.json`.
- The aggregate test result is recorded in `results/asymmetric/asymmetric_experiment_report.md`: 58 tests passed, 0 failed. The test source files include `tests/test_asymmetric_hybrid.py`, `tests/test_asymmetric_experiments.py`, and `tests/test_asymmetric_statistical_analysis.py`.

### Information not established by these files

- No component-level timers separate AES-GCM from RSA, ECDH/X25519, HKDF, or randomness costs; architectural attributions must remain qualified.
- No inferential between-scheme ranking or direct performance contrast was conducted.
- RQ3 confidence intervals were not produced because the dependence diagnostic was flagged; there is no pre-specified equivalence margin.
- Only one recorded host/software environment and one full run per RQ were used. The payloads are deterministic seeded pseudo-random test data, not a representative application corpus.
- Sender authentication and a simulated later recipient-private-key compromise were not tested. The related conclusions above are implications of the implemented cryptographic roles, not experimental outcomes.
- The report contains the aggregate test count, but a separate full test-run transcript was not found among the experiment output files.
