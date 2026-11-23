# Symmetric Cryptography Experiment Report

**Project:** Cryptography Under Adversarial Conditions (COSC2539)
**Research group:** Symmetric encryption
**Analysis date:** 19 November 2026

## 1. Experiment overview

The Symmetric study uses these research questions:

- **RQ1:** How does input data size affect the execution time of selected cryptographic algorithms?
- **RQ2:** How do selected cryptographic schemes respond to tampered data and invalid ciphertext?
- **RQ3:** How do integrity verification and rejection of invalid inputs affect the processing time of selected cryptographic schemes under adversarial conditions?

It evaluated three byte-protection schemes: AES-256-GCM,
ChaCha20-Poly1305, and AES-256-CBC with HMAC-SHA256 in Encrypt-then-MAC
order. It addresses the project's RQ1 size/performance question, RQ2
tampering/rejection question, and RQ3 valid/invalid processing-time question.
The performance numbers below are measurements from the saved CSV files; the
security descriptions explain the implemented mechanisms and are not formal
security proofs.

The five payloads were 1 KiB, 10 KiB, 100 KiB, 1 MiB, and 10 MiB. Inputs were
generated deterministically with Python's pseudo-random generator, outside
timed regions. For each block and size, all three schemes received the same
payload bytes. Cryptographic keys, AEAD nonces, CBC IVs, and wrong keys used
cryptographic randomness independent of the experiment seed.

## 2. Schemes and security behavior

| Scheme | Encryption/authentication operation | Decryption behavior |
|---|---|---|
| AES-256-GCM | AES with a 32-byte key, fresh 12-byte nonce, fixed scheme context as associated data, and 16-byte tag | GCM returns plaintext only after the tag verifies |
| ChaCha20-Poly1305 | ChaCha20 with a 32-byte key, fresh 12-byte nonce, fixed scheme context as associated data, and 16-byte Poly1305 tag | The library returns plaintext only after Poly1305 authentication succeeds |
| AES-256-CBC + HMAC-SHA256 | AES-256-CBC with PKCS#7 padding and fresh 16-byte IV; independent 32-byte AES and HMAC keys; HMAC covers a domain-separation string, IV, and ciphertext | HMAC is checked with constant-time comparison before CBC decryption or unpadding |

All three use symmetric keys. A valid tag or MAC establishes that the envelope
was made by someone holding the corresponding key; it does not identify a
particular person when multiple parties share that key. The experiment does
not implement sender signatures, replay protection, key rotation, or key
storage policy.

Invalid messages raise one public error type with one public message. A private
local diagnostic stage is recorded in the controlled experiment files. That
diagnostic field must not be exposed to a remote caller. In CBC-HMAC, malformed
field validation may fail before MAC verification; for structurally valid
tampering, the MAC check precedes decryption and padding checks.

## 3. Experimental environment

The recorded environment was Python 3.14.10, Gentoo Linux on kernel 6.18.60,
an Intel Core i5-13420H (12 logical CPUs), OpenSSL 3.6.5, and `cryptography`
50.0.2. Analysis used NumPy 2.5.5, SciPy 1.18.1, and Matplotlib 3.11.2.
Platform and package details are in each run's metadata JSON. Only this one
machine and software environment were measured.

## 4. RQ1: payload size and execution time

### Method

The RQ1 randomized complete-block design used 30 blocks. Every block included
3 schemes × 5 sizes × 2 operations = 30 conditions, for 900 measured
observations. Each condition received five warm-up calls per block (4,500
warm-ups total); these do not appear in the raw benchmark CSV. Condition order
and warm-up call order were independently shuffled within each block.

Encryption timing includes fresh nonce/IV generation, encryption, CBC padding
where used, authentication tag/MAC generation, and in-memory envelope
construction. Decryption timing includes envelope validation, authentication,
decryption, and CBC unpadding where used. Run-level key creation, payload and
valid-envelope preparation, correctness checks, file I/O, CSV writing, and
analysis were outside the measured interval. `time.perf_counter()` surrounded
the scheme call.

The primary test was a separate one-factor repeated-measures ANOVA for each
scheme-operation combination. Input size was the five-level within-block
factor, and block was the subject. Mauchly's test evaluated sphericity;
Greenhouse-Geisser correction was applied when Mauchly rejected. Holm
adjustment covered the six ANOVA omnibus p-values. Partial eta-squared is the
ANOVA effect size. The supplementary Friedman tests use within-block ranks,
test a rank-based hypothesis rather than equality of arithmetic means, and
have a separate Holm family of six tests. No pairwise post-hoc tests were
performed, so the omnibus tests do not identify which particular sizes differ.

### Descriptive results

Times below are means and medians across 30 measured blocks, rounded to four
decimal places in milliseconds. The complete mean, median, sample standard
deviation, range, and MiB/s values are in
`results/symmetric/rq1/analysis/run_20261119_02/symmetric_rq1_descriptive.csv`.

| Scheme | Operation | 1 KiB mean / median | 10 KiB mean / median | 100 KiB mean / median | 1 MiB mean / median | 10 MiB mean / median |
|---|---|---:|---:|---:|---:|---:|
| AES-256-GCM | Encrypt | 0.0115 / 0.0091 | 0.0135 / 0.0123 | 0.0353 / 0.0356 | 0.2801 / 0.2853 | 2.7645 / 2.6381 |
| AES-256-GCM | Decrypt | 0.0073 / 0.0062 | 0.0101 / 0.0093 | 0.0344 / 0.0345 | 0.2989 / 0.2924 | 2.8162 / 2.6410 |
| ChaCha20-Poly1305 | Encrypt | 0.0105 / 0.0083 | 0.0173 / 0.0168 | 0.0594 / 0.0593 | 0.5489 / 0.5415 | 5.3960 / 5.1638 |
| ChaCha20-Poly1305 | Decrypt | 0.0078 / 0.0062 | 0.0143 / 0.0130 | 0.0671 / 0.0651 | 0.5621 / 0.5605 | 5.3689 / 5.2276 |
| AES-256-CBC + HMAC-SHA256 | Encrypt | 0.0332 / 0.0370 | 0.0466 / 0.0460 | 0.1709 / 0.1688 | 1.4324 / 1.4180 | 14.0120 / 13.9432 |
| AES-256-CBC + HMAC-SHA256 | Decrypt | 0.0283 / 0.0284 | 0.0395 / 0.0438 | 0.1104 / 0.1094 | 0.8951 / 0.8772 | 9.5919 / 9.2171 |

All six mean-time sequences increased across the configured payload sizes.
At 10 MiB, AES-256-GCM had the lowest observed mean time for both operations,
ChaCha20-Poly1305 was intermediate, and CBC-HMAC had the highest observed
mean. These are descriptive comparisons between schemes; this analysis did
not test cross-scheme differences statistically. The separate tests below
test size effects within each scheme and operation.

### Repeated-measures ANOVA and diagnostics

| Scheme | Operation | F | GG-corrected df | Holm-adjusted p | Partial eta² | Mauchly p | GG epsilon | Residual Shapiro p |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| AES-256-GCM | Encrypt | 2240.416 | (1.068, 30.983) | 1.56×10⁻³⁰ | 0.9872 | 4.73×10⁻⁷⁰ | 0.2671 | 4.13×10⁻¹⁶ |
| AES-256-GCM | Decrypt | 1395.966 | (1.057, 30.661) | 1.93×10⁻²⁷ | 0.9796 | 1.79×10⁻⁸⁸ | 0.2643 | 7.35×10⁻¹⁶ |
| ChaCha20-Poly1305 | Encrypt | 3806.926 | (1.071, 31.057) | 5.74×10⁻³⁴ | 0.9924 | 4.33×10⁻⁸¹ | 0.2677 | 2.42×10⁻¹² |
| ChaCha20-Poly1305 | Decrypt | 7446.178 | (1.063, 30.830) | 5.60×10⁻³⁸ | 0.9961 | 3.51×10⁻⁶⁷ | 0.2658 | 1.12×10⁻¹³ |
| AES-256-CBC + HMAC-SHA256 | Encrypt | 26684.144 | (1.128, 32.708) | 3.70×10⁻⁴⁹ | 0.9989 | 1.52×10⁻⁴⁹ | 0.2820 | 8.33×10⁻¹³ |
| AES-256-CBC + HMAC-SHA256 | Decrypt | 5686.970 | (1.027, 29.770) | 4.31×10⁻³⁵ | 0.9949 | 2.14×10⁻⁷⁰ | 0.2566 | 1.58×10⁻¹⁰ |

All six Holm-adjusted ANOVA p-values are below α = 0.05. For each
scheme-operation combination, the result supports an input-size effect on mean
time, conditional on the repeated-measures model. It does not mean that every
pair of sizes differs. Mauchly's test rejected sphericity for all six models;
the reported primary degrees of freedom and p-values use Greenhouse-Geisser
correction. Shapiro-Wilk rejected residual normality in all six models, and
the minimum difference-score Shapiro p-value was below 0.001 for every model.
The ANOVA assumptions are therefore not fully met.

The supplementary Friedman tests also detected size-related rank differences
for all six scheme-operation combinations after Holm correction; their
Kendall W values ranged from 0.940 to 0.977. This supports the observed
monotonic size trend using a different, rank-based estimand, but it does not
repair dependence between sequential blocks. Across the six models, the
largest absolute within-size lag-one correlation was 0.517. Randomized
condition positions reduce systematic ordering bias, but do not guarantee
independent blocks or eliminate thermal, cache, load, or carry-over effects.

The increasing processing cost is consistent with each scheme processing
more payload bytes. CBC-HMAC performs both a full HMAC pass and CBC encryption
or decryption for valid messages; that architectural work plausibly contributes
to its larger measured times, but the experiment did not separately time
components. Library backend and hardware effects were not isolated.

## 5. RQ2: tampering and invalid-input outcomes

The functional experiment covered 3 schemes × 5 sizes × 6 scenarios = 90
cases. All 90 observed outcomes matched their expected outcomes. All 15 valid
cases were accepted and released the original plaintext. None of the 75
invalid cases released plaintext. Sixty structurally valid tampering/wrong-key
cases failed at authentication; the 15 malformed envelopes failed at
envelope validation.

| Scenario | Change made | Observed result | Failure stage / component | What this demonstrates |
|---|---|---|---|---|
| Valid envelope | None | 15/15 accepted; plaintext released | Authentication succeeded | Correct-key round trips worked for the tested payloads |
| Ciphertext tampering | First ciphertext byte changed | 15/15 rejected; no plaintext | AEAD authentication, or HMAC verification for CBC-HMAC | Payload modifications were detected in these test cases |
| Tag/MAC tampering | One tag or MAC byte changed | 15/15 rejected; no plaintext | AEAD authentication, or CBC-HMAC verification | Authentication data is required for acceptance |
| Nonce/IV tampering | One nonce or IV byte changed | 15/15 rejected; no plaintext | AEAD authentication, or CBC-HMAC verification | The nonce/IV is cryptographically bound to acceptance (CBC IV is included in HMAC) |
| Wrong key | Replaced with independent valid-length key material | 15/15 rejected; no plaintext | AEAD authentication, or CBC-HMAC verification | The tested key mismatch did not yield plaintext |
| Malformed envelope | Ciphertext field set to an invalid/missing value | 15/15 rejected; no plaintext | Envelope validation | Malformed fields are rejected before authenticated decryption |

These 90 observations are controlled functional examples, not a probability
that an attack will succeed and not evidence against untested attacks. A
successful AEAD tag or HMAC does not establish sender identity when keys are
shared. The code also does not prevent replay of a previously valid envelope.

## 6. RQ3: processing time for valid and invalid decryption

### Method

RQ3 used 30 blocks with 90 conditions per block: 3 schemes × 5 sizes × 6
scenarios. The corrected run contains 2,700 measured rows and 13,500 excluded
warm-up calls. Each invalid case is paired to the valid decryption in the
same block, scheme, and input size. Mutations, wrong-key creation, payload
generation, and envelope generation were outside the timer. The measured
interval is the complete public `decrypt` call; it does not isolate tag/MAC
verification cost.

For each invalid-versus-valid contrast, ΔT is the mean of the within-block
time differences, `T_invalid − T_valid`. The mean and median of the matched
per-block percentage differences, `100 × (T_invalid − T_valid) / T_valid`,
are also reported. The two-sided Monte Carlo conditional label-swap test used
9,999 sign permutations and a fixed analysis seed. Holm correction covered
exactly 75 contrasts: five invalid scenarios for each of 3 schemes and 5
sizes. Its sharp-null inference is conditional on the generated block orders
approximating uniform assignment and on no consequential carry-over or
interference.

### Main observations

After Holm correction, 36 of 75 comparisons had p < 0.05:

| Scheme | Ciphertext tampered | Tag/MAC tampered | Nonce/IV tampered | Wrong key | Malformed envelope |
|---|---:|---:|---:|---:|---:|
| AES-256-GCM | 1/5 sizes | 0/5 | 0/5 | 0/5 | 5/5 |
| ChaCha20-Poly1305 | 0/5 | 0/5 | 0/5 | 0/5 | 5/5 |
| AES-256-CBC + HMAC-SHA256 | 5/5 | 5/5 | 5/5 | 5/5 | 5/5 |

At 10 MiB, the observed means and paired differences were:

| Scheme | Invalid scenario | Valid mean (ms) | Invalid mean (ms) | Mean ΔT (µs) | Mean matched ΔT% | Holm p |
|---|---|---:|---:|---:|---:|---:|
| AES-256-GCM | Ciphertext tampered | 2.748 | 2.800 | +51.8 | +2.860% | 1.0000 |
| AES-256-GCM | Tag tampered | 2.748 | 2.889 | +141.1 | +5.859% | 1.0000 |
| AES-256-GCM | Nonce tampered | 2.748 | 2.917 | +168.8 | +7.238% | 1.0000 |
| AES-256-GCM | Wrong key | 2.748 | 2.978 | +230.0 | +9.694% | 1.0000 |
| AES-256-GCM | Malformed envelope | 2.748 | 0.0020 | −2745.9 | −99.928% | 0.0075 |
| ChaCha20-Poly1305 | Ciphertext tampered | 5.315 | 5.444 | +129.2 | +2.870% | 1.0000 |
| ChaCha20-Poly1305 | Tag tampered | 5.315 | 5.306 | −8.7 | +0.131% | 1.0000 |
| ChaCha20-Poly1305 | Nonce tampered | 5.315 | 5.490 | +175.2 | +3.580% | 1.0000 |
| ChaCha20-Poly1305 | Wrong key | 5.315 | 5.372 | +57.3 | +1.299% | 1.0000 |
| ChaCha20-Poly1305 | Malformed envelope | 5.315 | 0.0015 | −5313.6 | −99.971% | 0.0075 |
| AES-256-CBC + HMAC-SHA256 | Ciphertext tampered | 9.463 | 5.592 | −3871.1 | −40.703% | 0.0075 |
| AES-256-CBC + HMAC-SHA256 | MAC tampered | 9.463 | 5.548 | −3915.1 | −41.140% | 0.0075 |
| AES-256-CBC + HMAC-SHA256 | IV tampered | 9.463 | 5.628 | −3835.2 | −40.268% | 0.0075 |
| AES-256-CBC + HMAC-SHA256 | Wrong key | 9.463 | 5.688 | −3775.0 | −39.656% | 0.0075 |
| AES-256-CBC + HMAC-SHA256 | Malformed envelope | 9.463 | 0.0026 | −9460.4 | −99.973% | 0.0075 |

The 10 MiB percentage column is the mean of per-block percentages. It can
occasionally have a slightly different sign from ΔT, as the ChaCha tag row
shows, because the former divides each block difference by that block's valid
time before averaging. The raw paired CSV contains all 75 contrasts and all
per-size values.

The large malformed-envelope differences reflect early structural rejection.
For CBC-HMAC, valid decryption performs HMAC and then CBC decryption/unpadding;
the tested valid-length tampering and wrong-key cases failed HMAC and skipped
the AES-CBC decryption stage. That short-circuit explains why those invalid
attempts were faster in this implementation. For GCM and ChaCha20-Poly1305,
large ciphertext/tag/nonce/wrong-key cases generally had no Holm-significant
difference from valid decryption, consistent with the AEAD implementation
processing the payload before authentication can fail. This interpretation
describes the observed workflow and does not isolate authentication overhead.

One small-payload result deserves caution: AES-GCM ciphertext tampering at
1 KiB had a +3.705 µs mean difference and +117.844% mean matched percentage,
with Holm-adjusted p = 0.0205. The absolute difference is only a few
microseconds and the valid baseline is itself only about 5 µs. It is not a
useful basis for a broad performance or security claim; timer resolution and
system noise are material at this scale.

Shapiro-Wilk rejected normality for 34/75 paired-difference sets. This does
not itself invalidate the label-swap procedure, which does not assume normal
differences under the stated sharp null. More consequentially, 4/75 block
trend and 5/75 position-difference diagnostics were nominally significant,
and the maximum absolute lag-one correlation was 0.422. The predecessor
summary is descriptive and cannot prove or rule out carry-over. Because the
blocks are sequential and run on one machine, the no-carry-over and
block-independence assumptions remain uncertain. Therefore all RQ3 inference
is conditional/exploratory. Non-significance is not evidence of equivalent
times; no application-specific equivalence margin was set, and no confidence
intervals are claimed.

## 7. Results matrix

| Research question | Measurement | Main finding | Evidence | Interpretation | Limitations | Strength |
|---|---|---|---|---|---|---|
| RQ1 | Per-message encryption/decryption at five sizes | Mean times increased with size for all six scheme-operation series; all six corrected repeated-measures omnibus tests and all six supplementary Friedman tests were significant | RQ1 descriptive, ANOVA, Friedman CSVs | Payload size is strongly associated with processing time in this environment | Residual normality rejected; sphericity rejected but GG-corrected; sequential block dependence possible; no post-hoc size-pair tests | Supported with statistical caveats |
| RQ2 | 90 controlled valid/tampered/malformed cases | All expected outcomes matched; all 75 invalid cases were rejected without plaintext release | RQ2 raw outcomes and case-validation CSV | The implemented checks rejected the specified modifications and malformed envelopes | Finite test matrix, not attack probabilities or a proof; no sender identity or replay protection | Supported by observed data |
| RQ3 | Complete valid/invalid decrypt-call times paired by block | 36/75 Holm-adjusted comparisons were significant; effects depended on failure stage and scheme | RQ3 paired tests, diagnostics, predecessor CSVs | Malformed fields and CBC MAC failures often short-circuited work; AEAD invalid payload cases generally processed similarly to valid messages | Conditional randomization assumptions, sequential dependence, possible carry-over, single machine; no equivalence margin | Exploratory only |

## 8. Limitations and threats to validity

- Only one laptop and one software environment were evaluated.
- Pseudo-random byte payloads do not represent compressed files, structured
  documents, streaming workloads, or all application data.
- Each run is a sequential local benchmark; scheduler activity, CPU frequency,
  caches, thermal conditions, and system load can affect timings.
- AEAD nonces and CBC IVs are generated with cryptographically secure randomness
  for each encryption call, but their values were not saved in the raw CSVs.
  Source inspection confirmed fresh generation; this audit could not independently
  verify per-key uniqueness or rule out a random collision. Collision risk at
  the observed experiment scale is very low, but not zero. Future runs should
  record non-secret nonce/IV values or perform an automated per-key uniqueness
  check.
- Randomization reduces systematic position confounding but does not ensure
  independent blocks or remove predecessor/carry-over effects.
- Residual and difference-score normality diagnostics rejected for RQ1; all
  sphericity tests rejected. Greenhouse-Geisser corrects sphericity, not
  nonnormality or dependence. Friedman is a rank-based supplement, not an
  ANOVA for means.
- RQ3 measures complete decryption attempts, including early validation and
  exception handling. It does not isolate tag/MAC verification cost or
  end-to-end attacker cost.
- Timing differences do not by themselves demonstrate a remotely exploitable
  side channel. Network/application behavior and repeated remote observations
  were not evaluated.
- The experiment does not evaluate key management, key compromise, replay,
  sender authentication, or resistance to attacks outside the enumerated
  mutations; it is not a formal security proof.
- No observations were filtered or removed. No RQ1 pairwise post-hoc claims
  were made, and RQ3 non-significance is not treated as equivalence.

## 9. Reproducibility and file locations

The completed data and analysis are organized as follows:

- RQ1 raw CSV, metadata, and execution log:
  `results/symmetric/rq1/runs/run_20261119_01/`
- RQ1 descriptive statistics, repeated-measures ANOVA, Friedman tests,
  summary, and plot:
  `results/symmetric/rq1/analysis/run_20261119_02/`
- RQ2 raw outcomes, metadata, and execution log:
  `results/symmetric/rq2/runs/run_20261119_01/`
- RQ2 expected-versus-observed validation and summaries:
  `results/symmetric/rq2/analysis/run_20261119_02/`
- Corrected RQ3 raw observations, metadata, and execution log:
  `results/symmetric/rq3/runs/run_20261119_02/`
- Corrected RQ3 descriptives, 75 paired tests, diagnostics, predecessor
  summaries, JSON summary, and plot:
  `results/symmetric/rq3/analysis/run_20261119_03/`

RQ3 `run_20261119_01` is preserved unchanged but is superseded because its
timer included outcome bookkeeping after the decrypt call. It was not used for
the results in this report. The corrected timer stops immediately when the
scheme call returns or raises. Earlier RQ1/RQ2 analysis directories and the
initial RQ3 analysis directories remain preserved; this report cites the final
RQ1/RQ2 analysis `run_20261119_02` and corrected RQ3 analysis
`run_20261119_03`.

Install dependencies with `python3 -m pip install -r requirements/symmetric.txt`.
The commands to run each experiment and its analysis are documented in the
Symmetric section of `README.md`. For a new measurement, use a fresh output
directory; existing files are not overwritten.

## 10. Overall interpretation

The experiment supports a clear size-related performance finding: all three
schemes take longer as payload size increases, and the repeated-measures
omnibus tests detect size effects for encryption and decryption. On this
machine, AES-GCM had the lowest observed means at 10 MiB, while CBC-HMAC had
the highest; these descriptive cross-scheme differences were not tested as
formal pairwise hypotheses. Functionally, each specified tampering scenario
was rejected and no invalid case released plaintext. RQ3 shows that rejection
time depends on the implemented failure path: malformed envelopes are
validated quickly, CBC-HMAC rejects authenticated-field changes before CBC
decryption, and AEAD authentication failures generally process the ciphertext.
Because of assumption failures and possible temporal dependence, the RQ3
significance results remain exploratory and do not establish equivalence,
general performance rankings, or a practical side-channel vulnerability.

## 11. Completion status

The full project test suite passed: **75 tests, 0 failures**. Independent
output checks confirmed 900 unique RQ1 observations, 90 RQ2 cases, 2,700
unique corrected RQ3 observations, and 75 recalculated RQ3 Holm comparisons
matching the saved analysis. No invalid case released plaintext. All 51
pre-existing Hashing and Asymmetric result files matched their pre-Symmetric
SHA-256 checksums. `git diff --check` passed. The superseded RQ3 run is retained
unchanged and excluded from the reported findings.
