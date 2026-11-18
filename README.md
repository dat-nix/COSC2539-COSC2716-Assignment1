# COSC2539-COSC2716-Assignment1

## Project organization

Implementation, tests, dependencies, and saved results are grouped by role and
algorithm family:

```text
hashing/                              hashing source modules
symmetric/                            reserved for symmetric schemes (empty)
asymmetric/                           reserved for hybrid schemes (empty)
tests/                                hashing tests
requirements/analysis.txt             analysis dependencies
results/hashing/
  baseline/                           original sequential experiment
  randomized_block/                   blocked experiment and analysis
  tampering_performance/              verification timing experiment
```

The old top-level result aliases and `requirements-analysis.txt` have been
removed. Use the categorized paths shown above. Saved JSON metadata paths were
updated to those locations; the CSV observations and numerical analysis values
were not changed. The `symmetric/` and `asymmetric/` directories are reserved
and currently empty; this cleanup adds no encryption code.

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

## Hashing experiment runner

From the project root, run:

```sh
python3 -m hashing.experiment_runner --output-dir results/hashing/runs/new_run
```

The runner creates deterministic byte inputs of 1 KiB, 10 KiB, 100 KiB, 1 MiB,
and 10 MiB (1024 bytes per KiB). It uses the same input for SHA-256, SHA3-256,
and BLAKE2b-256 at each size, performs 5 warm-ups and 30 timed repetitions per
algorithm and size, and writes results under the selected output directory:

- `hashing_benchmarks.csv` contains every measured repetition, including its
  digest and elapsed time. Only the hash call is inside the timed interval;
  input creation, digest formatting, and CSV writing are outside it.
- `hashing_tampering.csv` records two checks per algorithm and size. The
  trusted-digest scenario detects a changed input. In the second scenario, the
  changed input is accompanied by a newly computed unkeyed digest, so the check
  passes and cannot detect that the data was changed. Each row includes both
  the original trusted digest and the digest used for that check.
- `hashing_metadata.json` records Python and platform details and the
  experiment configuration.

The command writes into the selected run directory; choose an unused directory
for each new measurement. The saved historical sequential results are kept in
`results/hashing/baseline/`. The CSV timings are measurements from the machine
running the command, not expected or pre-filled results.

## Hashing tampering-verification performance

The original `hashing_benchmarks.csv` times only the hash call. The original
`hashing_tampering.csv` records verification outcomes and digests, but has no
timing fields. Neither file measures valid-versus-tampered verification time.
The new experiment writes separate files and does not overwrite either result.

Run the matched randomized-block experiment with:

```sh
python3 -m hashing.tampering_performance_runner \
  --output-dir results/hashing/tampering_performance/runs/new_run \
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
python3 -m hashing.tampering_performance_analysis \
  --input-csv results/hashing/tampering_performance/runs/new_run/hashing_tampering_performance.csv \
  --output-dir results/hashing/tampering_performance/analysis/new_run \
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

## Hashing statistical analysis

Install the analysis dependencies and analyze the existing raw benchmark file:

```sh
python3 -m pip install -r requirements/analysis.txt
python3 -m hashing.statistical_analysis \
  --input-csv results/hashing/baseline/hashing_benchmarks.csv \
  --output-dir results/hashing/analysis/new_run
```

The analysis reads but does not rewrite the benchmark CSV. It creates
`hashing_descriptive_statistics.csv`, `hashing_anova_results.csv`,
`hashing_analysis_summary.json`, and `hashing_execution_time.png` in the output
directory. Sizes and throughput use binary units (KiB and MiB). Standard
deviations are sample standard deviations, and throughput is MiB divided by
mean execution time.

This command analyzes the original sequential benchmark CSV. Its independent-
groups analyses do not apply to the newer randomized-block CSV below. The
module runs separate one-way ANOVAs for each algorithm, Shapiro-Wilk tests
on within-size residuals, and median-centered Levene tests. Tukey HSD is only
run when those diagnostics do not reject normality or equal variance and the
omnibus ANOVA is significant. If diagnostics fail, the summary reports a
Welch ANOVA or Kruskal-Wallis alternative as appropriate; these alternatives
still require independent observations. The ANOVA result only tests whether
at least one group mean differs and cannot identify the differing groups.

The 30 observations per configuration reuse one input and are sequential
timings, so independence and temporal autocorrelation are not established.
The input content is also one repeated byte pattern. Interpret inferential
results as exploratory and disclose these limitations; no outliers are
silently removed.

## Randomized-block hashing experiment

The revised runner writes to a new directory so it does not replace the
original `results/hashing/baseline/hashing_benchmarks.csv` or the original
analysis outputs:

```sh
python3 -m hashing.randomized_block_runner \
  --output-dir results/hashing/randomized_block/runs/new_run \
  --seed 20261118
```

It runs 30 complete blocks. Each block contains all 15 algorithm and input-size
conditions in an independently shuffled order. The 75 warm-up calls (five per
condition) are also shuffled individually and are not included in the raw CSV.
For each block and size, one seeded pseudo-random input buffer is prepared
before timing and shared by all three algorithms at that size. Each measured
row includes its block, randomized position, repetition, input identifier,
monotonic start/end times, execution time, and digest. The seed and machine
metadata are saved in `hashing_randomized_block_metadata.json` beside the raw
`hashing_randomized_block_benchmarks.csv`. The runner refuses to overwrite
those files; choose a new output directory for another run.

Analyze the new CSV with:

```sh
python3 -m hashing.randomized_block_analysis \
  --input-csv results/hashing/randomized_block/runs/new_run/hashing_randomized_block_benchmarks.csv \
  --output-dir results/hashing/randomized_block/analysis/new_run \
  --seed 55 \
  --permutations 9999
```

This creates `hashing_randomized_block_descriptive.csv`,
`hashing_randomized_block_model.csv`,
`hashing_randomized_block_pairwise.csv`,
`hashing_randomized_block_summary.json`, and
`hashing_randomized_block_diagnostics.png`. Analysis outputs are also protected
from accidental overwrite.

### How the block model works

Input size is treated as a fixed five-level factor, while block terms account
for conditions shared by the measurements in each block. The parametric model
also includes randomized position as a linear covariate. A restricted
randomization test shuffles size labels only within each block and is reported
alongside the parametric randomized-block F test. The summary includes
partial eta-squared and omega-squared, residual Shapiro-Wilk and Levene tests,
position and time-order diagnostics, and Holm-adjusted pairwise contrasts
with simultaneous confidence intervals only when the omnibus result and
residual diagnostics support them. No outliers are automatically removed.

Randomizing order reduces systematic association between a condition and its
position, but does not guarantee independent observations or blocks. The
blocks still run sequentially in one process and can share thermal or system
load drift. The position term models only a linear within-block trend. Results
also reflect seeded pseudo-random input content, one machine, and timing
overhead that is substantial for 1 KiB inputs. Report these limits and do not
interpret a small p-value as proof of a security advantage.

## COSC2539 repeated-measures analysis

Use the existing randomized-block CSV. This analysis writes to a new directory
and does not rerun the benchmark or overwrite the earlier blocked-model results:

```sh
python3 -m pip install -r requirements/analysis.txt
python3 -m hashing.repeated_measures_analysis \
  --input-csv results/hashing/randomized_block/hashing_randomized_block_benchmarks.csv \
  --output-dir results/hashing/randomized_block/repeated_measures/analysis/new_run \
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

The existing repeated-measures outputs are archived under
`results/hashing/randomized_block/repeated_measures/`. New analysis outputs use
the selected `--output-dir`, for example
`results/hashing/randomized_block/repeated_measures/analysis/new_run/`:

- `hashing_repeated_measures_anova.csv`
- `hashing_repeated_measures_friedman.csv`
- `hashing_repeated_measures_posthoc.csv`
- `hashing_repeated_measures_summary.json`
- `hashing_repeated_measures_diagnostics.png`

The JSON records the raw CSV SHA-256, analysis parameters, and Python,
NumPy, SciPy, and Matplotlib versions. The prior descriptive statistics,
block-plus-position model, restricted permutation results, and diagnostics
remain in `results/hashing/randomized_block/`. Neither ANOVA nor Friedman is evidence
of a security advantage; report the measured timing scope, assumption failures,
and possible temporal dependence.

The existing `execution_time ~ input_size + block + randomized_position`
analysis is a fixed-block regression with a position covariate. Its position
adjustment means its parametric test is not the same model as the one-way
repeated-measures ANOVA. In this balanced design, the fixed-block model without
the position term has the same uncorrected input-size F test as the classical
repeated-measures ANOVA. The existing restricted permutation result is a
separate design-based test; it does not become an ANOVA because it uses an F
statistic.
