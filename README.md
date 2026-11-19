# COSC2539-COSC2716-Assignment1

## Project organization

Implementation, tests, dependencies, and saved results are grouped by role and
algorithm family:

```text
hashing/                              hashing source modules
symmetric/                            symmetric schemes, runners, and analysis
asymmetric/                           asymmetric-based hybrid source modules
tests/                                hashing, symmetric, and asymmetric tests
requirements/analysis.txt             analysis dependencies
requirements/asymmetric.txt          asymmetric crypto and analysis dependencies
requirements/symmetric.txt           symmetric crypto and analysis dependencies
results/hashing/
  rq1/
    baseline/                         original sequential benchmark and analysis
    randomized_block/                 blocked benchmark and repeated-measures analysis
  rq2/
    baseline/                         original tampering outcome observations
  rq3/
    tampering_performance/            matched verification timing experiment
results/symmetric/
  rq1/{runs,analysis}/                 payload-size encryption/decryption
  rq2/{runs,analysis}/                 functional adversarial outcomes
  rq3/{runs,analysis}/                 valid/invalid decryption timings
  symmetric_experiment_report.md       measured results and interpretation
```

The old top-level result aliases and `requirements-analysis.txt` have been
removed. Use the RQ1/RQ2/RQ3 paths shown above. Historical CSV observations and
numerical analysis values are preserved; JSON path fields now point to their
new categorized locations. The `asymmetric/` package contains the hybrid
encryption module described below.

## Hashing component

The `hashing` package provides reusable SHA-256, SHA3-256, and BLAKE2b-256
functions. Each function accepts `bytes` and returns the raw 32-byte digest:

```python
from hashing import blake2b_256, sha256, sha3_256

message = b"example message"
digest = sha256(message)
print(digest.hex())
```

Use `.hex()` to display a digest as 64 lowercase hexadecimal characters. The
functions use Python's standard-library `hashlib`; BLAKE2b is explicitly
configured with `digest_size=32`, which produces a 256-bit digest. Keeping the
input as bytes avoids tying hashing to terminal input or an implicit text
encoding. To hash text, encode it explicitly, for example `text.encode("utf-8")`.

A digest can detect a changed message only when compared with a trusted digest.
If an attacker can replace both the message and its digest, an ordinary hash
does not authenticate the message; use a keyed MAC or digital signature when
authentication is required.

Run the hashing unit tests from the project root with:

```sh
python3 -m unittest discover -s tests -v
```

## Hashing experiments

Use one command entry point for all three reported Hashing questions. Select a
new output directory for each experiment run:

```sh
python3 -m hashing.experiment_runner rq1 \
  --output-dir results/hashing/rq1/randomized_block/runs/new_run \
  --seed 20261118
python3 -m hashing.experiment_runner rq2 \
  --output-dir results/hashing/rq2/runs/new_run
python3 -m hashing.experiment_runner rq3 \
  --output-dir results/hashing/rq3/tampering_performance/runs/new_run \
  --seed 20261118
```

RQ1 uses 30 randomized complete blocks, five shuffled warm-ups, and 30 measured
observations per algorithm-size condition. The three algorithms receive the
same seeded pseudo-random input within each block and size. The timer surrounds
only the digest call. RQ2 records one functional check for each of 3 algorithms
× 5 sizes × 2 scenarios; its input is a deterministic repeated byte pattern.
The trusted-digest comparison rejects modified data, while an attacker-recomputed
unkeyed digest matches it and does not authenticate its source. RQ3 records
1,350 matched timing observations; input and digest preparation are outside the
timed hash-and-compare operation. Historical sequential baseline results remain
archived under `results/hashing/rq1/baseline/`.

## Hashing tampering-verification performance

The original `hashing_benchmarks.csv` times only the hash call. The original
`hashing_tampering.csv` records verification outcomes and digests, but has no
timing fields. Neither file measures valid-versus-tampered verification time.
The new experiment writes separate files and does not overwrite either result.

Run the matched randomized-block experiment with:

```sh
python3 -m hashing.experiment_runner rq3 \
  --output-dir results/hashing/rq3/tampering_performance/runs/new_run \
  --seed 20261118
```

By default it uses the five existing input sizes, three algorithms, and three
scenarios in 30 blocks: 45 conditions per block and 1,350 measured rows. There
are five randomized warm-up calls per condition, excluded from the raw CSV.
Within each block and size, one original byte buffer and its one-byte-modified
copy are shared across all algorithms. Condition order is randomized within
each block. Input generation, byte modification, and both reference digests
happen before timing.

The scenarios are:

1. Original data checked against its trusted original digest.
2. Modified data checked against the original trusted digest; rejection means
   the modification was detected.
3. Modified data checked against an attacker-recomputed unkeyed digest; passing
   this comparison demonstrates that the unkeyed digest cannot authenticate
   data when the attacker may replace both values.

Each measured interval contains only the hash call and
`hmac.compare_digest` comparison. CSV writing, digest hex formatting, and data
preparation are outside the interval. The third scenario measures verification
using an already available attacker-recomputed digest; it does not include the
attacker's digest-generation time. Raw timings and environment/seed metadata
are saved as `hashing_tampering_performance.csv` and
`hashing_tampering_performance_metadata.json`. Existing filenames are
protected from overwrite; use a new output directory for another run.

Analyze the raw timings without rerunning the experiment:

```sh
python3 -m hashing.statistical_analysis rq3 \
  --input-csv results/hashing/rq3/tampering_performance/runs/new_run/hashing_tampering_performance.csv \
  --output-dir results/hashing/rq3/tampering_performance/analysis/new_run \
  --seed 55 \
  --permutations 9999
```

The analyzer writes `hashing_tampering_performance_descriptive.csv`,
`hashing_tampering_performance_paired_tests.csv`, and
`hashing_tampering_performance_summary.json`. It compares all three scenario
pairs within matched blocks, reports absolute and percentage time differences,
and applies Holm correction across all 45 algorithm/size/comparison tests. The
test is a paired sign-flip randomization test of the mean difference. Within
each block the runner assigns all 45 conditions to positions by a randomized
permutation. Conditional on the three positions for one algorithm/size's
scenarios, swapping the two labels in a pair is equally likely; the block
schedules are randomized separately. The test is therefore interpreted as a
conditional, design-based test of the **sharp null** that scenario labels have
no effect on any verification time. It is not a generic paired sign-flip test
whose validity comes from assuming a symmetric distribution of sampled
differences, and it does not test only the weaker claim that the average effect
is zero under arbitrary heterogeneous effects.

This design-based test does not require normally distributed paired
differences. Shapiro-Wilk, skewness, lag-1 correlation, and block-trend values
are reported as diagnostics; Shapiro-Wilk rejection does not invalidate this
randomization test. Validity still depends on the actual within-block
randomization and on there being no consequential carry-over or interference
between successive conditions. Randomized order can balance position effects
under the design, but it cannot repair carry-over caused by a preceding hash
condition. The reported estimates are point estimates; the generated outputs
do not include confidence intervals.

The summary reports verification pass and tampering-detection rates separately
from timings. A failed trusted-digest comparison is detection; acceptance with
an attacker-recomputed digest is not authentication. No universal practical
time threshold is assumed: interpret absolute and percentage differences
against the measured baseline and the experiment's timing resolution, not from
statistical significance alone.

### Results from the recorded run

The run used seed `20261118` and recorded 1,350 rows (30 blocks for each of 45
algorithm/size/scenario conditions). Across the three algorithms and five
sizes, valid original-data checks passed 450/450 times. Modified data compared
with the trusted original digest was rejected and detected 450/450 times.
Modified data accompanied by its recomputed unkeyed digest passed 450/450 times;
this is not successful authentication or tampering detection.

For the primary timing contrast (modified data against the trusted digest minus
valid original data), the 10 MiB observations were:

| Algorithm | Valid mean | Modified/trusted mean | Mean paired difference | Difference vs valid mean | Raw p | Holm adjusted p |
|---|---:|---:|---:|---:|---:|---:|
| SHA-256 | 4.906 ms | 4.810 ms | -96.08 µs | -1.96% | 0.0258 | 1.0000 |
| SHA3-256 | 17.078 ms | 17.142 ms | +64.51 µs | +0.38% | 0.3659 | 1.0000 |
| BLAKE2b-256 | 9.452 ms | 9.468 ms | +16.25 µs | +0.17% | 0.5537 | 1.0000 |

Across all 45 paired comparisons, no Holm-adjusted p-value was below 0.05 (the
smallest was 0.3915). At 10 MiB the measured differences were below each
scenario's observed run-to-run standard deviation. At 1 KiB, the measured
hash-and-compare operations took only a few microseconds, so timer and system
noise are a substantial part of the observation. These data do not establish a
meaningful verification-time difference, and failure to find one is not proof
that the scenarios are equivalent. No application-specific equivalence margin
was set. The detailed results for every size and comparison are in the paired
tests CSV and JSON summary.

The paired sign-flip test compares within-block time differences under the
randomized condition order; its inference depends on the randomization and on
there being no consequential carry-over between successive conditions. The
test follows that randomized design and does not require normally distributed
paired differences. Shapiro-Wilk rejected normality for 18 of 45 paired-
difference sets at the nominal 0.05 level; this is reported as a diagnostic,
not used to choose a test based on its p-value. The largest absolute lag-1
correlation across the paired-difference series was 0.421, and one of 45
uncorrected block-trend diagnostics had p < 0.05. These exploratory checks
cannot rule out temporal dependence. The design still has only 30 sequential
blocks on one machine. The attacker-recomputed scenario times verification
with a precomputed digest; the attacker's digest-generation time is
intentionally not part of the measured verification operation.

A separate read-only audit of the raw CSV also found an upward block-level time
trend. It log-transformed execution times, subtracted each algorithm/size/
scenario's mean log time across blocks, then correlated the 30 block-average
residuals with block ID (Spearman rho = 0.581, nominal p = 0.00075). This is an
exploratory diagnostic, not part of the 45-test family. Within-block pairing
reduces confounding from conditions shared by scenarios in a block, but the
trend shows that timings were not stationary over the run. It does not
establish whether the drift was caused by environment or carry-over, and it
does not remove the no-interference assumption needed for the randomized test.

## COSC2539 repeated-measures analysis

Use the existing randomized-block CSV. This command produces the descriptive
CSV used by the report together with repeated-measures statistics and does not
rerun the benchmark:

```sh
python3 -m pip install -r requirements/analysis.txt
python3 -m hashing.statistical_analysis rq1 \
  --input-csv results/hashing/rq1/randomized_block/hashing_randomized_block_benchmarks.csv \
  --output-dir results/hashing/rq1/randomized_block/analysis/new_run \
  --alpha 0.05
```

Analysis outputs are also protected from overwrite. To repeat the analysis,
choose a new `--output-dir` while keeping the same input CSV and alpha value.

The lecturer's one-way ANOVA requirement is addressed with a **one-way
repeated-measures ANOVA**, run separately for each algorithm. Input size is the
five-level within-block factor, and each of the 30 blocks is a subject with one
timing at every size. The null hypothesis is equal mean execution time at all
five sizes; the alternative is that at least one mean differs. This is not an
ordinary independent-groups ANOVA, and its omnibus result does not identify
which size pairs differ.

The analysis reports uncorrected F results, Mauchly's sphericity diagnostic,
Greenhouse-Geisser epsilon and corrected degrees of freedom and p-values,
partial eta-squared, Shapiro-Wilk residual normality, and a supplementary
Levene residual-variance diagnostic. Holm correction is applied across the
three algorithm-level tests for each omnibus method. Levene's test is only a
supporting variance diagnostic; sphericity is the repeated-measures covariance
assumption. Greenhouse-Geisser corrects the sphericity reference distribution,
not nonnormal residuals.

Because the residuals are not well modeled by a normal distribution, the
module also reports a **Friedman repeated-block rank test** and Kendall's W for
each algorithm. Friedman tests systematic differences in within-block ranks,
not equality of arithmetic means. After a significant Holm-adjusted Friedman
test, paired exact sign tests compare size ranks within blocks. Their Holm
adjusted p-values cover all reported pairs; exact binomial intervals describe
the probability that one size ranks faster. These pairwise tests concern rank
direction, not mean time differences. They assume blocks are sufficiently
independent; sequential runs do not guarantee that assumption.

The analysis outputs use the selected `--output-dir`:

- `hashing_randomized_block_descriptive.csv`
- `hashing_repeated_measures_anova.csv`
- `hashing_repeated_measures_friedman.csv`
- `hashing_repeated_measures_posthoc.csv`
- `hashing_repeated_measures_summary.json`
- `hashing_repeated_measures_diagnostics.png`

The JSON records the raw CSV SHA-256, analysis parameters, and Python,
NumPy, SciPy, and Matplotlib versions. Historical blocked-model outputs remain
archived but are not part of the final report's primary analysis. Neither ANOVA
nor Friedman is evidence of a security advantage; disclose the assumption
failures and possible temporal dependence.

## Asymmetric-based hybrid encryption

This package implements exactly three schemes:

1. RSA-OAEP with SHA-256 wraps a fresh 256-bit AES session key; AES-256-GCM
   encrypts and authenticates the payload.
2. Ephemeral ECDH on P-256 derives a shared secret; HKDF-SHA256 derives the
   AES key; AES-256-GCM protects the payload.
3. Ephemeral X25519 derives a shared secret; HKDF-SHA256 derives the AES key;
   AES-256-GCM protects the payload.

The implementation is in `asymmetric/`. `common.py` defines the in-memory
envelope and normalized result types. Each scheme has a separate implementation
module. The consolidated command `python -m asymmetric.experiment_runner rq1|rq2|rq3`
runs the corresponding experiment; `statistical_analysis.py` analyzes each
raw dataset. Install dependencies with:

```sh
python3 -m pip install -r requirements/asymmetric.txt
```

### RQ1: payload-size performance

The default design has 30 randomized complete blocks. Each block contains one
observation for each of 3 schemes × 5 sizes × 2 operations, giving 900 measured
rows. Five warm-ups per condition are randomized and excluded. For a given
block and size, the same plaintext bytes are shared across all three schemes.
The buffer and a valid decryption envelope are prepared before the timer.

Long-term recipient keys are generated once outside the timed observations.
Encryption timing includes per-message session or ephemeral key generation,
nonce/salt generation, key agreement and HKDF where applicable, payload
encryption, and RSA key wrapping where applicable. Decryption timing includes
key unwrapping or public-key parsing/agreement, HKDF where applicable, and
authenticated AES-GCM decryption. `time.perf_counter()` surrounds the scheme
operation; input creation, key-pair setup, envelope preparation, and CSV output
are outside the timed section. The raw CSV records block, position, repetition,
shared input identifier, previous condition, timing, and outcome-stage fields.

Run RQ1 explicitly with:

```sh
PYTHONDONTWRITEBYTECODE=1 MPLCONFIGDIR=/tmp/cosc2539-mpl \
  .venv/bin/python -u -m asymmetric.experiment_runner rq1 \
  --output-dir results/asymmetric/rq1/runs/run_20261119_01
```

The default experiment seed is drawn from OS entropy and written to metadata.
Each block also receives a separate, independently drawn 256-bit shuffle seed;
both the experiment seed and block seeds are recorded. An explicit `--seed` is
useful for replaying a schedule, but RQ3 design-based randomization inference is
then marked ineligible because the assignment was fixed in advance.
Cryptographic keys, nonces, salts, and ephemeral private keys are generated
independently by the cryptographic library or OS randomness.

RQ1's primary analysis is a conventional one-factor **repeated-measures ANOVA**
run separately for each scheme and operation. Input size is the five-level
within-subject factor and experimental block is the subject. Each analysis uses
a complete 30 × 5 matrix; its uncorrected degrees of freedom are 4 and 116.
Mauchly's approximate test checks sphericity. If it rejects at α = 0.05,
Greenhouse-Geisser epsilon multiplies both degrees of freedom and the primary
p-value is recalculated from the same F statistic. The reported effect size is
partial eta-squared. Holm correction is applied across the six primary omnibus
tests. A significant omnibus test means at least one size mean differs; it does
not identify which pair differs.

Residual and within-subject difference-score Shapiro-Wilk results are
diagnostics, not proof of normality. Mauchly's test is the sphericity diagnostic;
Levene's test is not a substitute for it. The 30 blocks are sequential
measurements, so independent subjects and absence of carry-over cannot be
assumed merely because conditions were randomized.

The existing position-adjusted analysis is retained as a **complementary OLS
sensitivity analysis**, not labeled as conventional ANOVA:

```text
execution_time ~ categorical_input_size + block_fixed_effects + centered_position
```

It is fit by ordinary least squares with CR1 cluster-robust sandwich covariance
clustered by block. The joint input-size Wald statistic is reported as
`F = Wald chi-square / 4`, with numerator df 4 and denominator df equal to
blocks − 1 (29 for the full run). The hypothesis tests the input-size effect
after accounting for block and the pre-specified linear position covariate.
This adjusted test asks about the input-size effect conditional on block and
linear randomized position. It has a different estimand from the conventional
RM-ANOVA and does not use a sphericity correction. Its finite-cluster F
reference is approximate with 30 blocks.

The analyzer checks residual and within-block difference-score shapes,
residual variance patterns, linear and quadratic position trends, size-by-
position effects, previous-condition associations, trends across blocks, and
lag-1 dependence of paired block contrasts. A log-time model is a sensitivity
analysis and has a multiplicative interpretation. Holm correction covers the
six scheme-operation omnibus tests. Ten paired size contrasts for a
scheme-operation are reported only after its Holm-adjusted omnibus test is
significant and no diagnostic flag is raised; those ten p-values receive Holm
correction within that family. Diagnostics cannot prove independence or absence
of carry-over.

Analyze the resulting file with:

```sh
PYTHONDONTWRITEBYTECODE=1 MPLCONFIGDIR=/tmp/cosc2539-mpl \
  .venv/bin/python -u -m asymmetric.statistical_analysis rq1 \
  --input-csv results/asymmetric/rq1/runs/run_20261119_01/asymmetric_rq1_benchmarks.csv \
  --metadata results/asymmetric/rq1/runs/run_20261119_01/asymmetric_rq1_metadata.json \
  --output-dir results/asymmetric/rq1/analysis/run_20261119_01
```

The analysis writes descriptive statistics, repeated-measures ANOVA results,
the complementary position-adjusted OLS results, supported OLS pairwise
comparisons, a JSON summary, and an execution-time plot:
`asymmetric_rq1_descriptive.csv`,
`asymmetric_rq1_repeated_measures_anova.csv`, `asymmetric_rq1_model.csv`,
`asymmetric_rq1_pairwise.csv`, `asymmetric_rq1_summary.json`, and
`asymmetric_rq1_execution_time.png`. The run directory contains
`asymmetric_rq1_benchmarks.csv` and `asymmetric_rq1_metadata.json`. Analysis
records the raw CSV checksum and software versions.

### RQ2: tampering and malformed-envelope outcomes

The functional matrix records valid envelopes; ciphertext and tag bit changes;
modified RSA wrapped keys; valid replacement ECDH/X25519 ephemeral public
keys; malformed public keys; and malformed common envelope fields. The default
matrix contains 85 cases across the five sizes. Each row reports acceptance,
whether plaintext was released, failure stage, exception category, key unwrap
or agreement completion, HKDF completion, and whether AES-GCM verification
was reached. Invalid envelopes must never release plaintext. Failure stages
remain separate; a malformed public key is not pooled with a GCM tag failure.

Run RQ2 explicitly with:

```sh
PYTHONDONTWRITEBYTECODE=1 MPLCONFIGDIR=/tmp/cosc2539-mpl \
  .venv/bin/python -u -m asymmetric.experiment_runner rq2 \
  --output-dir results/asymmetric/rq2/runs/run_20261119_01
```

Analyze its outcome counts with:

```sh
PYTHONDONTWRITEBYTECODE=1 MPLCONFIGDIR=/tmp/cosc2539-mpl \
  .venv/bin/python -u -m asymmetric.statistical_analysis rq2 \
  --input-csv results/asymmetric/rq2/runs/run_20261119_01/asymmetric_rq2_outcomes.csv \
  --metadata results/asymmetric/rq2/runs/run_20261119_01/asymmetric_rq2_metadata.json \
  --output-dir results/asymmetric/rq2/analysis/run_20261119_01
```

These are functional observations, not estimates of real-world attack
probabilities. The run directory contains `asymmetric_rq2_outcomes.csv` and
`asymmetric_rq2_metadata.json`; analysis writes
`asymmetric_rq2_summary.csv`, the expected-versus-observed case table
`asymmetric_rq2_case_validation.csv`, and `asymmetric_rq2_summary.json`.

### RQ3: valid and invalid decryption timing

Each block contains 3 schemes × 5 sizes × 5 scenarios (valid, ciphertext
tampering, tag tampering, scheme-specific key-material tampering, and malformed
envelope/public-key material). That is 75 observations per block, 2,250 total,
plus five excluded randomized warm-ups per condition. Each observation records
total attempted-decryption time, block and position, previous condition,
failure stage, key unwrap/agreement and HKDF flags, GCM reachability, acceptance,
and plaintext release. A different valid ECDH/X25519 public key must complete
agreement and HKDF, then fail GCM; malformed public-key material fails earlier.

The analysis pairs each invalid scenario with valid observations by block,
scheme, and size. The planned Holm family contains all four valid-versus-invalid
contrasts for every scheme-size pair: 60 comparisons for the five configured
sizes. It reports absolute and percentage differences. The conditional
randomization analysis swaps the valid and one invalid condition’s labels
between their two assigned positions in each block. It exhaustively enumerates
the paired sign-swap reference distribution for the sharp null that swapping
labels changes no outcome at either position. Its interpretation is
conditional/exploratory: it relies on the finite-state PRNG shuffle
approximating a uniform assignment, and is not an unqualified exact
design-based p-value. The test is computed only when metadata records an
OS-entropy seed and the complete block shuffle; explicit fixed seeds do not
qualify. It also requires no consequential carry-over or interference.

The analyzer checks position effects, predecessor proxies, block-level trends
and lag-1 dependence. These predecessor checks are limited summaries; they do
not prove independence or absence of carry-over. The output always labels RQ3
inference conditional/exploratory, and diagnostic or assignment issues further
downgrade it.
Bootstrap confidence intervals are emitted only when those diagnostics show no
flag and assume independent blocks. A non-significant result is not proof of
equal timing or equivalence; an application-specific equivalence margin has
not been supplied.

Run RQ3 explicitly with:

```sh
PYTHONDONTWRITEBYTECODE=1 MPLCONFIGDIR=/tmp/cosc2539-mpl \
  .venv/bin/python -u -m asymmetric.experiment_runner rq3 \
  --output-dir results/asymmetric/rq3/runs/run_20261119_01
```

Analyze it with:

```sh
PYTHONDONTWRITEBYTECODE=1 MPLCONFIGDIR=/tmp/cosc2539-mpl \
  .venv/bin/python -u -m asymmetric.statistical_analysis rq3 \
  --input-csv results/asymmetric/rq3/runs/run_20261119_01/asymmetric_rq3_verification.csv \
  --metadata results/asymmetric/rq3/runs/run_20261119_01/asymmetric_rq3_metadata.json \
  --output-dir results/asymmetric/rq3/analysis/run_20261119_01 \
  --analysis-seed 20261118
```

Outputs include descriptive and paired-test CSVs, diagnostics, a JSON summary,
and a plot: `asymmetric_rq3_descriptive.csv`,
`asymmetric_rq3_paired_tests.csv`, `asymmetric_rq3_diagnostics.csv`,
`asymmetric_rq3_summary.json`, and `asymmetric_rq3_execution_time.png`. The run
directory contains `asymmetric_rq3_verification.csv` and
`asymmetric_rq3_metadata.json`. All runners refuse to overwrite existing
output files. They are only invoked by explicit commands; importing the
modules does not run an experiment.

### Security limits

These schemes provide recipient confidentiality and AEAD integrity, not sender
authentication. Anyone with the recipient’s public key can create an envelope.
AES-GCM plaintext is returned only after tag verification succeeds. OAEP
failure, key-agreement failure, malformed input, and GCM authentication failure
have different timings and are retained as different stages. The experiments
measure local cryptographic processing, not network, disk, application, or
end-to-end attacker costs. The results must not be compared with standalone
hashing or symmetric operations as though they measured the same work.

Run the project tests with:

```sh
python3 -m unittest discover -s tests -v
```

The asymmetric runner tests use tiny payloads and one-block smoke runs; this
command does not run either full benchmark.

The commands above identify the archived run `run_20261119_01`. Its output
files already exist, and the runners refuse to overwrite them. To collect a new
experiment or regenerate analysis, choose a fresh run directory and update the
corresponding input paths. The complete measured findings, assumption
diagnostics, generated-file inventory, and interpretation are in
`results/asymmetric/asymmetric_experiment_report.md`.

## Symmetric cryptography

The `symmetric` package implements and measures three message-protection
schemes:

1. **AES-256-GCM**: AES with a 32-byte key, a fresh 12-byte nonce, and a
   16-byte authentication tag.
2. **ChaCha20-Poly1305**: a 32-byte key, fresh 12-byte nonce, and 16-byte
   Poly1305 tag.
3. **AES-256-CBC + HMAC-SHA256**: AES-CBC with PKCS#7 padding, a fresh
   16-byte IV, and Encrypt-then-MAC with separate 32-byte encryption and MAC
   keys. The HMAC covers a domain-separation string, IV, and ciphertext and is
   compared with `hmac.compare_digest` before CBC decryption or unpadding.

The Symmetric experiments use these research questions verbatim:

- **RQ1:** How does input data size affect the execution time of selected cryptographic algorithms?
- **RQ2:** How do selected cryptographic schemes respond to tampered data and invalid ciphertext?
- **RQ3:** How do integrity verification and rejection of invalid inputs affect the processing time of selected cryptographic schemes under adversarial conditions?

Install its cryptography and analysis dependencies with:

```sh
python3 -m pip install -r requirements/symmetric.txt
```

Keys are generated with the operating system/library cryptographic random
source once per run and kept in memory. AEAD nonces and CBC IVs are freshly
generated for every encryption. The experiment seed only controls payload
generation and condition order; it is never used for key, nonce, IV, or MAC
material. Secret keys are not written to output files. The Python functions
accept byte strings and return an in-memory `CiphertextEnvelope`; invalid
messages raise the same public `InvalidCiphertextError`. A private local stage
label is used only for controlled experiment diagnostics and must not be
returned to a remote caller.

### RQ1: payload-size performance

The five payload sizes are 1 KiB, 10 KiB, 100 KiB, 1 MiB, and 10 MiB. RQ1
uses 30 randomized complete blocks, each with all three schemes, all five
sizes, and both `encrypt` and `decrypt` operations: 30 conditions per block and
900 measured observations. There are five randomized warm-ups for each
condition in each block (4,500 calls total); warm-ups are not written to the
measured CSV. Within each block and size, all schemes receive the same
deterministic pseudo-random payload bytes. Inputs, run-level keys, and valid
decryption envelopes are prepared outside timed intervals.

Encryption timing covers the full per-message operation: nonce/IV generation,
encryption, CBC padding where applicable, tag/MAC creation, and in-memory
envelope construction. Decryption timing covers envelope validation,
authentication verification, decryption, and CBC unpadding. Long-term key
generation, payload generation, result checks, file I/O, CSV writing, plotting,
and statistical analysis are excluded. `time.perf_counter()` surrounds the
scheme call only.

Run RQ1 from the repository root:

```sh
MPLCONFIGDIR=/tmp/cosc2539-mpl .venv/bin/python -u -m symmetric.experiment_runner rq1 \
  --output-dir results/symmetric/rq1/runs/run_20261119_01 \
  --seed 20261119
```

Analyze the saved data without rerunning it:

```sh
MPLCONFIGDIR=/tmp/cosc2539-mpl .venv/bin/python -u -m symmetric.statistical_analysis rq1 \
  --input-csv results/symmetric/rq1/runs/run_20261119_01/symmetric_rq1_benchmarks.csv \
  --metadata results/symmetric/rq1/runs/run_20261119_01/symmetric_rq1_metadata.json \
  --output-dir results/symmetric/rq1/analysis/run_20261119_02
```

The primary analysis is a conventional one-factor repeated-measures ANOVA for
each scheme-operation combination separately. Block is the subject and input
size is the five-level within-subject factor. Mauchly's test evaluates
sphericity; Greenhouse-Geisser adjusts both degrees of freedom and the
reference p-value when sphericity is rejected. Partial eta-squared is reported
as the ANOVA effect size. Holm adjustment covers the six omnibus ANOVA tests.
The supplementary Friedman test analyzes within-block ranks, not arithmetic
means, and has its own Holm correction across six tests. Shapiro-Wilk tests on
model residuals and pairwise difference scores are diagnostics. Randomized
position, residual trend across sequential blocks, and lag-one correlations
are also summarized. A corrected significant omnibus test means at least one
input-size mean differs; it does not identify which pairs differ.

Files in the analysis directory:

- `symmetric_rq1_descriptive.csv`: mean, median, sample standard deviation,
  range, and MiB/s for each size/scheme/operation.
- `symmetric_rq1_repeated_measures_anova.csv`: six ANOVAs, sphericity and
  residual diagnostics, effect sizes, and Holm-adjusted p-values.
- `symmetric_rq1_friedman.csv`: supplementary repeated-block rank tests.
- `symmetric_rq1_summary.json`: reproducibility information and complete
  numerical summary.
- `symmetric_rq1_execution_time.png`: encryption/decryption size trends.

### RQ2: functional adversarial outcomes

RQ2 evaluates 90 controlled cases: three schemes × five sizes × six scenarios.
The scenarios are valid ciphertext; modified ciphertext; modified tag/MAC;
modified nonce/IV; wrong key; and malformed envelope. Each row records expected
and observed acceptance, whether plaintext was released, and a local failure
stage. CBC ciphertext, IV, or MAC modifications must fail at HMAC verification
before any decryption or unpadding. AEAD changes fail authentication. Malformed
fields fail envelope validation. Invalid cases must not return plaintext.
These examples are functional checks, not attack probabilities or proofs of
security.

```sh
MPLCONFIGDIR=/tmp/cosc2539-mpl .venv/bin/python -u -m symmetric.experiment_runner rq2 \
  --output-dir results/symmetric/rq2/runs/run_20261119_01
MPLCONFIGDIR=/tmp/cosc2539-mpl .venv/bin/python -u -m symmetric.statistical_analysis rq2 \
  --input-csv results/symmetric/rq2/runs/run_20261119_01/symmetric_rq2_outcomes.csv \
  --metadata results/symmetric/rq2/runs/run_20261119_01/symmetric_rq2_metadata.json \
  --output-dir results/symmetric/rq2/analysis/run_20261119_02
```

The analysis writes `symmetric_rq2_case_validation.csv`,
`symmetric_rq2_summary.csv`, and `symmetric_rq2_summary.json`. No inferential
test is applied to functional case counts.

### RQ3: valid and invalid decryption processing time

RQ3 uses 30 blocks with 90 conditions per block: three schemes × five sizes ×
six scenarios. It records 2,700 measured decryption attempts plus 13,500
randomized warm-up attempts, which are excluded from the raw CSV. The original
payload and its valid encrypted envelope are prepared before timing; ciphertext,
tag/MAC, nonce/IV, wrong-key, and malformed variants are also prepared outside
timed intervals. For a matched scheme, size, and block, the five invalid
attempts are compared with the valid attempt. Timing covers the complete public
decryption call, including validation, authentication, decryption, and CBC
unpadding where reached. It does not isolate authentication overhead or include
the attacker's time to modify data or obtain a wrong key.

```sh
MPLCONFIGDIR=/tmp/cosc2539-mpl .venv/bin/python -u -m symmetric.experiment_runner rq3 \
  --output-dir results/symmetric/rq3/runs/run_20261119_02
MPLCONFIGDIR=/tmp/cosc2539-mpl .venv/bin/python -u -m symmetric.statistical_analysis rq3 \
  --input-csv results/symmetric/rq3/runs/run_20261119_02/symmetric_rq3_verification.csv \
  --metadata results/symmetric/rq3/runs/run_20261119_02/symmetric_rq3_metadata.json \
  --output-dir results/symmetric/rq3/analysis/run_20261119_03 \
  --permutations 9999 --seed 20261119
```

The analyzer reports scenario descriptives and paired differences
`ΔT = T_invalid − T_valid`, including each block's percentage difference
`100 × ΔT / T_valid` and the mean/median of those matched percentages. It also
reports the ratio of the group mean difference to the valid group mean. It
runs a two-sided Monte Carlo within-block label-swap
test for each invalid-versus-valid contrast and applies Holm correction across
all 75 planned contrasts. Its sharp-null interpretation is conditional on the
PRNG-generated complete-block schedules approximating uniform assignment and
on no consequential carry-over or interference. Shapiro-Wilk, block trend,
lag-one correlation, position-difference, and predecessor summaries are
diagnostics; they cannot establish independence. These tests do not require
normally distributed paired differences under the stated randomization null,
but schedule validity and no carry-over remain material assumptions. Findings
are exploratory. A non-significant result is not evidence of equivalence; no
application-specific equivalence margin is defined.

The analysis writes `symmetric_rq3_descriptive.csv`,
`symmetric_rq3_paired_tests.csv`, `symmetric_rq3_diagnostics.csv`,
`symmetric_rq3_predecessor_diagnostics.csv`, `symmetric_rq3_summary.json`, and
`symmetric_rq3_execution_time.png`.

### Output layout and limitations

Each command writes raw observations/outcomes, run metadata, and an execution
log into a new `results/symmetric/rqN/runs/<run-name>/` directory. Analyses go
to separate `results/symmetric/rqN/analysis/<analysis-name>/` directories.
Existing filenames are protected against overwrite; choose a new directory for
each run. RQ3 run `run_20261119_01` is retained unchanged but superseded after
the audit found outcome bookkeeping inside its timed interval; use corrected
run `run_20261119_02` for interpretation. Earlier analysis directories are
also retained; the final analyses use RQ1/RQ2 `analysis/run_20261119_02` and
RQ3 `analysis/run_20261119_03`. The completed interpretation will be saved as
`results/symmetric/symmetric_experiment_report.md`.

The experiments use one machine and one software environment. Deterministic
pseudo-random payloads do not represent all real workloads; sequential
measurements can be affected by thermal state, scheduling, and system load.
Timing differences do not by themselves establish a practical side-channel
vulnerability. AES-GCM, ChaCha20-Poly1305, and CBC-HMAC provide integrity only
to parties with the relevant key; none of these symmetric constructions
identifies a human sender. CBC-HMAC is safe here only because it follows
Encrypt-then-MAC with independent keys and authenticates IV plus ciphertext
before decryption. This educational experiment is not a formal security proof.
