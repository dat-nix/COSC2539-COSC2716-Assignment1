"""Repeated-measures analysis for randomized-block hashing observations.

The module reads the existing raw benchmark and writes a separate set of
statistical results. It never edits benchmark observations or previous outputs.
"""

import argparse
import csv
import hashlib
import json
import math
import platform
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import scipy
from scipy import stats
from scipy.linalg import helmert

from hashing.experiment_runner import ALGORITHMS, INPUT_SIZES
from hashing.randomized_block_runner import BLOCK_COUNT, RAW_FIELDS


DEFAULT_ALPHA = 0.05
MIB_BYTES = 1024 * 1024
ANOVA_NAME = "hashing_repeated_measures_anova.csv"
FRIEDMAN_NAME = "hashing_repeated_measures_friedman.csv"
POSTHOC_NAME = "hashing_repeated_measures_posthoc.csv"
SUMMARY_NAME = "hashing_repeated_measures_summary.json"
PLOT_NAME = "hashing_repeated_measures_diagnostics.png"
LEGACY_SUMMARY_NAME = "hashing_randomized_block_summary.json"

ANOVA_FIELDS = (
    "Algorithm",
    "Test",
    "Blocks",
    "Input size levels",
    "Null hypothesis",
    "Alternative hypothesis",
    "F statistic",
    "Uncorrected numerator df",
    "Uncorrected denominator df",
    "Uncorrected p-value",
    "Sphericity correction used",
    "Primary numerator df",
    "Primary denominator df",
    "Primary p-value",
    "Holm adjusted primary p-value across algorithms",
    "Partial eta squared",
    "Mauchly W",
    "Mauchly chi-square",
    "Mauchly df",
    "Mauchly p-value",
    "Greenhouse-Geisser epsilon",
    "GG corrected numerator df",
    "GG corrected denominator df",
    "GG corrected p-value",
    "Residual Shapiro-Wilk statistic",
    "Residual Shapiro-Wilk p-value",
    "Residual Levene statistic",
    "Residual Levene p-value",
    "Pairwise status",
)
FRIEDMAN_FIELDS = (
    "Algorithm",
    "Test",
    "Blocks",
    "Input size levels",
    "Chi-square statistic",
    "Degrees of freedom",
    "Raw p-value",
    "Holm adjusted p-value across algorithms",
    "Kendall W",
    "Interpretation",
    "Pairwise status",
)
POSTHOC_FIELDS = (
    "Algorithm",
    "Input size 1 (bytes)",
    "Input size 2 (bytes)",
    "Blocks with usable non-tied ranks",
    "Tied rank pairs",
    "Size 1 faster-rank count",
    "Size 2 faster-rank count",
    "Probability size 1 has faster rank",
    "Rank-direction effect (2p - 1)",
    "Bonferroni simultaneous CI low for probability",
    "Bonferroni simultaneous CI high for probability",
    "Exact paired sign-test p-value",
    "Holm adjusted p-value across all reported pairs",
    "Tested hypothesis",
)


def _holm_adjust(p_values: list[float]) -> list[float]:
    """Return Holm step-down adjusted p-values in their input order."""
    count = len(p_values)
    order = sorted(range(count), key=p_values.__getitem__)
    adjusted = [0.0] * count
    running_max = 0.0
    for rank, index in enumerate(order):
        candidate = min(1.0, (count - rank) * p_values[index])
        running_max = max(running_max, candidate)
        adjusted[index] = running_max
    return adjusted


def _load_and_validate(path: str | Path) -> tuple[list[dict], str]:
    """Read a complete 30-block CSV and validate its repeated-measures layout."""
    input_path = Path(path)
    raw_bytes = input_path.read_bytes()
    with input_path.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        if tuple(reader.fieldnames or ()) != RAW_FIELDS:
            raise ValueError(f"Unexpected benchmark CSV columns in {input_path}")
        records = []
        for line_number, row in enumerate(reader, start=2):
            try:
                record = {
                    "Algorithm": row["Algorithm"],
                    "Input size in bytes": int(row["Input size in bytes"]),
                    "Block ID": int(row["Block ID"]),
                    "Randomized position within block": int(
                        row["Randomized position within block"]
                    ),
                    "Repetition number": int(row["Repetition number"]),
                    "Execution time in seconds": float(row["Execution time in seconds"]),
                    "Input identifier": row["Input identifier"],
                    "Measurement start monotonic seconds": float(
                        row["Measurement start monotonic seconds"]
                    ),
                    "Measurement end monotonic seconds": float(
                        row["Measurement end monotonic seconds"]
                    ),
                }
            except (TypeError, ValueError) as error:
                raise ValueError(f"Invalid numeric value on CSV row {line_number}") from error

            if record["Algorithm"] not in {name for name, _ in ALGORITHMS}:
                raise ValueError(f"Unknown algorithm on CSV row {line_number}")
            if record["Input size in bytes"] not in INPUT_SIZES:
                raise ValueError(f"Unexpected input size on CSV row {line_number}")
            if record["Block ID"] not in range(1, BLOCK_COUNT + 1):
                raise ValueError(f"Invalid block ID on CSV row {line_number}")
            if record["Repetition number"] != record["Block ID"]:
                raise ValueError(f"Repetition number does not match block on row {line_number}")
            if not 1 <= record["Randomized position within block"] <= 15:
                raise ValueError(f"Invalid randomized position on CSV row {line_number}")
            for field in (
                "Execution time in seconds",
                "Measurement start monotonic seconds",
                "Measurement end monotonic seconds",
            ):
                if not math.isfinite(record[field]):
                    raise ValueError(f"Non-finite {field} on CSV row {line_number}")
            if record["Execution time in seconds"] <= 0:
                raise ValueError(f"Non-positive execution time on CSV row {line_number}")
            start = record["Measurement start monotonic seconds"]
            end = record["Measurement end monotonic seconds"]
            if end <= start or not math.isclose(
                end - start,
                record["Execution time in seconds"],
                rel_tol=1e-6,
                abs_tol=1e-12,
            ):
                raise ValueError(f"Invalid monotonic timing boundaries on row {line_number}")
            records.append(record)

    algorithms = tuple(name for name, _ in ALGORITHMS)
    blocks = tuple(range(1, BLOCK_COUNT + 1))
    expected = {
        (algorithm, size, block)
        for algorithm in algorithms
        for size in INPUT_SIZES
        for block in blocks
    }
    actual = [
        (row["Algorithm"], row["Input size in bytes"], row["Block ID"])
        for row in records
    ]
    if len(records) != len(expected) or set(actual) != expected:
        raise ValueError(
            "CSV must contain exactly one observation for every algorithm, size, and block"
        )
    if len(set(actual)) != len(actual):
        raise ValueError("Duplicate algorithm, size, and block observation")

    for block_id in blocks:
        block_rows = [row for row in records if row["Block ID"] == block_id]
        if sorted(row["Randomized position within block"] for row in block_rows) != list(
            range(1, 16)
        ):
            raise ValueError(f"Block {block_id} does not contain positions 1 through 15")
        for algorithm in algorithms:
            algorithm_rows = [
                row for row in block_rows if row["Algorithm"] == algorithm
            ]
            sizes = [row["Input size in bytes"] for row in algorithm_rows]
            if sorted(sizes) != list(INPUT_SIZES):
                raise ValueError(
                    f"Block {block_id} lacks one or more sizes for {algorithm}"
                )
        for size in INPUT_SIZES:
            identifiers = {
                row["Input identifier"]
                for row in block_rows
                if row["Input size in bytes"] == size
            }
            if len(identifiers) != 1:
                raise ValueError(
                    f"Algorithms do not share one input identifier in block {block_id}, "
                    f"size {size}"
                )
    return records, hashlib.sha256(raw_bytes).hexdigest()


def _build_matrix(
    records: list[dict], algorithm: str
) -> tuple[np.ndarray, tuple[int, ...]]:
    """Return a block-by-size matrix, keeping all five repeated values paired."""
    blocks = tuple(range(1, BLOCK_COUNT + 1))
    matrix = np.empty((len(blocks), len(INPUT_SIZES)), dtype=float)
    lookup = {
        (row["Block ID"], row["Input size in bytes"]): row["Execution time in seconds"]
        for row in records
        if row["Algorithm"] == algorithm
    }
    for block_index, block_id in enumerate(blocks):
        for size_index, size_bytes in enumerate(INPUT_SIZES):
            try:
                matrix[block_index, size_index] = lookup[(block_id, size_bytes)]
            except KeyError as error:
                raise ValueError(
                    f"Missing repeated observation for {algorithm}, block {block_id}, "
                    f"size {size_bytes}"
                ) from error
    return matrix, blocks


def _mauchly_sphericity(matrix: np.ndarray) -> dict:
    """Calculate Mauchly's approximate test and Greenhouse-Geisser epsilon."""
    block_count, level_count = matrix.shape
    dimension = level_count - 1
    contrasts = matrix @ helmert(level_count, full=False).T
    covariance = np.cov(contrasts, rowvar=False, ddof=1)
    eigenvalues = np.linalg.eigvalsh(covariance)
    trace = float(eigenvalues.sum())
    squared_trace = float(np.square(eigenvalues).sum())
    if trace <= 0 or squared_trace <= 0:
        epsilon_gg = 1.0 / dimension
    else:
        epsilon_gg = trace**2 / (dimension * squared_trace)
        epsilon_gg = min(1.0, max(1.0 / dimension, epsilon_gg))

    sign, log_determinant = np.linalg.slogdet(covariance)
    if sign <= 0 or trace <= 0:
        log_w = math.log(np.finfo(float).tiny)
    else:
        log_w = float(log_determinant - dimension * math.log(trace / dimension))
        log_w = min(0.0, max(math.log(np.finfo(float).tiny), log_w))
    mauchly_w = math.exp(log_w)
    correction = 1.0 - (
        2 * dimension**2 + dimension + 2
    ) / (6 * dimension * (block_count - 1))
    chi_square = -(block_count - 1) * correction * log_w
    mauchly_df = dimension * (dimension + 1) / 2 - 1
    mauchly_p = float(stats.chi2.sf(chi_square, mauchly_df))
    return {
        "mauchly_w": mauchly_w,
        "mauchly_chi_square": chi_square,
        "mauchly_df": mauchly_df,
        "mauchly_p_value": mauchly_p,
        "greenhouse_geisser_epsilon": epsilon_gg,
    }


def _repeated_measures_anova(matrix: np.ndarray, alpha: float = DEFAULT_ALPHA) -> dict:
    """Fit a one-factor repeated-measures ANOVA with block as subject."""
    if matrix.ndim != 2 or matrix.shape != (BLOCK_COUNT, len(INPUT_SIZES)):
        raise ValueError(
            f"Expected a {BLOCK_COUNT} by {len(INPUT_SIZES)} block-size matrix"
        )
    block_count, level_count = matrix.shape
    grand_mean = float(matrix.mean())
    size_means = matrix.mean(axis=0)
    block_means = matrix.mean(axis=1)
    residuals = (
        matrix
        - size_means[None, :]
        - block_means[:, None]
        + grand_mean
    )
    ss_size = block_count * float(np.square(size_means - grand_mean).sum())
    ss_error = float(np.square(residuals).sum())
    df_size = level_count - 1
    df_error = (block_count - 1) * df_size
    mse = ss_error / df_error
    if mse <= 0:
        f_statistic = math.inf if ss_size > 0 else 0.0
        raw_p_value = 0.0 if ss_size > 0 else 1.0
    else:
        f_statistic = (ss_size / df_size) / mse
        raw_p_value = float(stats.f.sf(f_statistic, df_size, df_error))
    partial_eta_squared = (
        ss_size / (ss_size + ss_error) if ss_size + ss_error > 0 else 0.0
    )

    sphericity = _mauchly_sphericity(matrix)
    gg_epsilon = sphericity["greenhouse_geisser_epsilon"]
    gg_df_size = gg_epsilon * df_size
    gg_df_error = gg_epsilon * df_error
    gg_p_value = float(stats.f.sf(f_statistic, gg_df_size, gg_df_error))
    sphericity_rejected = sphericity["mauchly_p_value"] < alpha
    primary_df_size = gg_df_size if sphericity_rejected else df_size
    primary_df_error = gg_df_error if sphericity_rejected else df_error
    primary_p_value = gg_p_value if sphericity_rejected else raw_p_value
    shapiro_result = stats.shapiro(residuals.ravel())
    levene_result = stats.levene(
        *[residuals[:, index] for index in range(level_count)], center="median"
    )
    return {
        "f_statistic": f_statistic,
        "ss_size": ss_size,
        "ss_error": ss_error,
        "df_size": df_size,
        "df_error": df_error,
        "raw_p_value": raw_p_value,
        "partial_eta_squared": partial_eta_squared,
        **sphericity,
        "gg_df_size": gg_df_size,
        "gg_df_error": gg_df_error,
        "gg_p_value": gg_p_value,
        "primary_df_size": primary_df_size,
        "primary_df_error": primary_df_error,
        "primary_p_value": primary_p_value,
        "sphericity_correction_used": (
            "Greenhouse-Geisser" if sphericity_rejected else "None"
        ),
        "residuals": residuals,
        "residual_shapiro_statistic": float(shapiro_result.statistic),
        "residual_shapiro_p_value": float(shapiro_result.pvalue),
        "residual_levene_statistic": float(levene_result.statistic),
        "residual_levene_p_value": float(levene_result.pvalue),
        "sphericity_rejected": sphericity_rejected,
        "residual_normality_rejected": float(shapiro_result.pvalue) < alpha,
        "residual_variance_diagnostic_rejected": float(levene_result.pvalue) < alpha,
    }


def _friedman_test(matrix: np.ndarray) -> dict:
    """Run Friedman repeated-block rank test and return Kendall's W."""
    if matrix.ndim != 2 or matrix.shape[1] < 3:
        raise ValueError("Friedman analysis requires at least three repeated conditions")
    result = stats.friedmanchisquare(
        *[matrix[:, index] for index in range(matrix.shape[1])]
    )
    degrees_of_freedom = matrix.shape[1] - 1
    kendall_w = float(result.statistic) / (matrix.shape[0] * degrees_of_freedom)
    return {
        "chi_square": float(result.statistic),
        "degrees_of_freedom": degrees_of_freedom,
        "p_value": float(result.pvalue),
        "kendall_w": min(1.0, max(0.0, kendall_w)),
    }


def _exact_binomial_interval(successes: int, trials: int, tail_probability: float):
    """Return a two-sided Clopper-Pearson interval for a binomial proportion."""
    if trials == 0:
        return None, None
    lower = (
        0.0
        if successes == 0
        else float(stats.beta.ppf(tail_probability, successes, trials - successes + 1))
    )
    upper = (
        1.0
        if successes == trials
        else float(
            stats.beta.ppf(
                1.0 - tail_probability,
                successes + 1,
                trials - successes,
            )
        )
    )
    return lower, upper


def _rank_sign_rows(algorithm: str, matrix: np.ndarray) -> list[dict]:
    """Build paired sign-test comparisons on within-block input-size ranks."""
    ranks = np.vstack([stats.rankdata(block, method="average") for block in matrix])
    rows = []
    for first_index, first_size in enumerate(INPUT_SIZES):
        for second_index in range(first_index + 1, len(INPUT_SIZES)):
            second_size = INPUT_SIZES[second_index]
            difference = ranks[:, first_index] - ranks[:, second_index]
            first_faster = int(np.count_nonzero(difference < 0))
            second_faster = int(np.count_nonzero(difference > 0))
            ties = int(np.count_nonzero(difference == 0))
            usable = first_faster + second_faster
            raw_p_value = (
                float(stats.binomtest(first_faster, usable, 0.5, alternative="two-sided").pvalue)
                if usable
                else 1.0
            )
            probability = first_faster / usable if usable else None
            rows.append(
                {
                    "Algorithm": algorithm,
                    "Input size 1 (bytes)": first_size,
                    "Input size 2 (bytes)": second_size,
                    "Blocks with usable non-tied ranks": usable,
                    "Tied rank pairs": ties,
                    "Size 1 faster-rank count": first_faster,
                    "Size 2 faster-rank count": second_faster,
                    "Probability size 1 has faster rank": probability,
                    "Rank-direction effect (2p - 1)": (
                        2.0 * probability - 1.0 if probability is not None else None
                    ),
                    "Bonferroni simultaneous CI low for probability": None,
                    "Bonferroni simultaneous CI high for probability": None,
                    "Exact paired sign-test p-value": raw_p_value,
                    "Holm adjusted p-value across all reported pairs": None,
                    "Tested hypothesis": (
                        "Across independent blocks, either size is equally likely to have "
                        "the lower (faster) within-block rank; ties are excluded."
                    ),
                    "_raw_p_value": raw_p_value,
                    "_probability_successes": first_faster,
                }
            )

    return rows


def _finalize_pairwise_rows(rows: list[dict], alpha: float) -> None:
    """Apply one Holm family and simultaneous intervals across all reported pairs."""
    if rows:
        adjusted = _holm_adjust([row["_raw_p_value"] for row in rows])
        family_tail_probability = alpha / (2 * len(rows))
        for row, adjusted_p in zip(rows, adjusted):
            row["Holm adjusted p-value across all reported pairs"] = adjusted_p
            lower, upper = _exact_binomial_interval(
                row["_probability_successes"],
                row["Blocks with usable non-tied ranks"],
                family_tail_probability,
            )
            row["Bonferroni simultaneous CI low for probability"] = lower
            row["Bonferroni simultaneous CI high for probability"] = upper
    for row in rows:
        row.pop("_raw_p_value")
        row.pop("_probability_successes")


def _related_existing_results(input_path: Path, source_hash: str) -> dict:
    """Include existing blocked-model results only when they match this raw CSV."""
    summary_path = input_path.parent / LEGACY_SUMMARY_NAME
    if not summary_path.is_file():
        return {"status": "not available beside input CSV", "path": str(summary_path)}
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        return {"status": f"could not read existing summary: {error}", "path": str(summary_path)}
    if summary.get("source_csv_sha256") != source_hash:
        return {
            "status": "not included because the existing summary refers to another raw CSV",
            "path": str(summary_path),
        }
    return {
        "status": "included as a separate, previously generated analysis; not overwritten",
        "path": str(summary_path),
        "per_algorithm": summary.get("model_results_by_algorithm", []),
    }


def _write_csv(path: Path, fields: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("x", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _write_diagnostic_plot(path: Path, residuals_by_algorithm: dict[str, np.ndarray]) -> None:
    figure, axes = plt.subplots(1, len(ALGORITHMS), figsize=(14, 4.5))
    for axis, (algorithm, _) in zip(axes, ALGORITHMS):
        stats.probplot(residuals_by_algorithm[algorithm].ravel(), dist="norm", plot=axis)
        axis.set_title(algorithm)
        axis.set_xlabel("Theoretical normal quantiles")
        axis.set_ylabel("Repeated-measures residuals (seconds)")
        axis.grid(True, alpha=0.25)
    figure.suptitle("One-way repeated-measures ANOVA residual Q-Q plots")
    figure.tight_layout()
    figure.savefig(path, dpi=160)
    plt.close(figure)


def analyze_repeated_measures(
    input_csv: str | Path,
    output_dir: str | Path,
    alpha: float = DEFAULT_ALPHA,
) -> dict:
    """Analyze the five input sizes as repeated measures within each block."""
    if not 0 < alpha < 1:
        raise ValueError("alpha must be between 0 and 1")
    input_path = Path(input_csv)
    output_path = Path(output_dir)
    records, source_hash = _load_and_validate(input_path)
    output_paths = {
        "repeated_measures_anova_csv": output_path / ANOVA_NAME,
        "friedman_csv": output_path / FRIEDMAN_NAME,
        "posthoc_csv": output_path / POSTHOC_NAME,
        "summary_json": output_path / SUMMARY_NAME,
        "diagnostic_qq_plot": output_path / PLOT_NAME,
    }
    collisions = [path for path in output_paths.values() if path.exists()]
    if collisions:
        raise FileExistsError(f"Analysis output already exists: {collisions[0]}")
    output_path.mkdir(parents=True, exist_ok=True)

    anova_results = []
    friedman_results = []
    matrices = {}
    residuals_by_algorithm = {}
    for algorithm, _ in ALGORITHMS:
        matrix, _ = _build_matrix(records, algorithm)
        matrices[algorithm] = matrix
        anova = _repeated_measures_anova(matrix, alpha)
        friedman = _friedman_test(matrix)
        residuals_by_algorithm[algorithm] = anova["residuals"]
        anova_results.append({"algorithm": algorithm, **anova})
        friedman_results.append({"algorithm": algorithm, **friedman})

    anova_holm = _holm_adjust([result["primary_p_value"] for result in anova_results])
    friedman_holm = _holm_adjust([result["p_value"] for result in friedman_results])
    pairwise_rows = []
    pairwise_status = {}
    for anova, friedman, anova_adjusted, friedman_adjusted in zip(
        anova_results, friedman_results, anova_holm, friedman_holm
    ):
        anova["holm_adjusted_primary_p_value"] = anova_adjusted
        anova["reject_h0"] = anova_adjusted < alpha
        anova["pairwise_status"] = (
            "Not performed from ANOVA: residual normality is rejected; use the separately "
            "reported rank-based post-hoc procedure with its stated assumptions."
            if anova["residual_normality_rejected"]
            else "ANOVA-based paired contrasts are not part of this analysis."
        )
        friedman["holm_adjusted_p_value"] = friedman_adjusted
        friedman["reject_h0"] = friedman_adjusted < alpha
        if friedman_adjusted < alpha:
            pairwise_rows.extend(
                _rank_sign_rows(anova["algorithm"], matrices[anova["algorithm"]])
            )
            pairwise_status[anova["algorithm"]] = (
                "Performed paired exact sign tests on within-block ranks after significant "
                "Friedman omnibus test; Holm adjusted across reported pairs. The tests "
                "compare rank direction, not mean execution times."
            )
        else:
            pairwise_status[anova["algorithm"]] = (
                "Not performed because the Holm-adjusted Friedman omnibus test was not significant."
            )

    _finalize_pairwise_rows(pairwise_rows, alpha)

    anova_rows = []
    friedman_rows = []
    for anova, friedman in zip(anova_results, friedman_results):
        anova_rows.append(
            {
                "Algorithm": anova["algorithm"],
                "Test": "One-way repeated-measures ANOVA (block is subject)",
                "Blocks": BLOCK_COUNT,
                "Input size levels": len(INPUT_SIZES),
                "Null hypothesis": "Mean execution time is equal across all five input sizes.",
                "Alternative hypothesis": "At least one input-size mean execution time differs.",
                "F statistic": anova["f_statistic"],
                "Uncorrected numerator df": anova["df_size"],
                "Uncorrected denominator df": anova["df_error"],
                "Uncorrected p-value": anova["raw_p_value"],
                "Sphericity correction used": anova["sphericity_correction_used"],
                "Primary numerator df": anova["primary_df_size"],
                "Primary denominator df": anova["primary_df_error"],
                "Primary p-value": anova["primary_p_value"],
                "Holm adjusted primary p-value across algorithms": anova[
                    "holm_adjusted_primary_p_value"
                ],
                "Partial eta squared": anova["partial_eta_squared"],
                "Mauchly W": anova["mauchly_w"],
                "Mauchly chi-square": anova["mauchly_chi_square"],
                "Mauchly df": anova["mauchly_df"],
                "Mauchly p-value": anova["mauchly_p_value"],
                "Greenhouse-Geisser epsilon": anova["greenhouse_geisser_epsilon"],
                "GG corrected numerator df": anova["gg_df_size"],
                "GG corrected denominator df": anova["gg_df_error"],
                "GG corrected p-value": anova["gg_p_value"],
                "Residual Shapiro-Wilk statistic": anova[
                    "residual_shapiro_statistic"
                ],
                "Residual Shapiro-Wilk p-value": anova[
                    "residual_shapiro_p_value"
                ],
                "Residual Levene statistic": anova["residual_levene_statistic"],
                "Residual Levene p-value": anova["residual_levene_p_value"],
                "Pairwise status": anova["pairwise_status"],
            }
        )
        friedman_rows.append(
            {
                "Algorithm": friedman["algorithm"],
                "Test": "Friedman repeated-block rank test",
                "Blocks": BLOCK_COUNT,
                "Input size levels": len(INPUT_SIZES),
                "Chi-square statistic": friedman["chi_square"],
                "Degrees of freedom": friedman["degrees_of_freedom"],
                "Raw p-value": friedman["p_value"],
                "Holm adjusted p-value across algorithms": friedman[
                    "holm_adjusted_p_value"
                ],
                "Kendall W": friedman["kendall_w"],
                "Interpretation": (
                    "Tests whether within-block input-size rank distributions differ; "
                    "it is not a test of equality of arithmetic means."
                ),
                "Pairwise status": pairwise_status[friedman["algorithm"]],
            }
        )

    existing_results = _related_existing_results(input_path, source_hash)
    summary = {
        "analysis": "One-way repeated-measures hashing analysis for COSC2539",
        "source_csv": str(input_path),
        "source_csv_sha256": source_hash,
        "observation_count": len(records),
        "block_count": BLOCK_COUNT,
        "conditions_per_algorithm_per_block": len(INPUT_SIZES),
        "input_sizes_bytes": list(INPUT_SIZES),
        "algorithms_analyzed_separately": [name for name, _ in ALGORITHMS],
        "alpha": alpha,
        "multiple_testing": {
            "omnibus_holm_families": "Each omnibus method is adjusted across the three algorithms.",
            "pairwise_holm_family": "All reported pairwise comparisons across algorithms.",
            "pairwise_confidence_intervals": (
                "Two-sided exact Clopper-Pearson intervals with Bonferroni familywise "
                "coverage across all reported pairwise comparisons."
            ),
        },
        "methods": {
            "minimum_one_way_anova_requirement": (
                "Addressed with a one-way repeated-measures ANOVA per algorithm; input size "
                "is the five-level within-block factor and block is the subject. This is "
                "not an independent-groups one-way ANOVA."
            ),
            "anova_null": "All five population mean execution times are equal for an algorithm.",
            "anova_alternative": "At least one input-size mean execution time differs.",
            "anova_reference_test": (
                "Classical repeated-measures F test with Greenhouse-Geisser corrected "
                "degrees of freedom when Mauchly's test rejects sphericity."
            ),
            "anova_effect_size": "Partial eta squared; reported as a point estimate.",
            "friedman": (
                "Nonparametric repeated-block test on within-block ranks. It addresses rank "
                "distributions/systematic rank differences, not equality of arithmetic means."
            ),
            "friedman_effect_size": "Kendall's W.",
            "posthoc": (
                "After a Holm-significant Friedman test, exact paired sign tests compare "
                "within-block rank direction; ties are excluded. The effect is the probability "
                "that size 1 has a lower/faster rank, with a Bonferroni simultaneous exact CI."
            ),
            "posthoc_limitation": (
                "These are rank-direction comparisons, not pairwise tests of mean execution time."
            ),
            "preserved_existing_analysis": existing_results,
        },
        "assumptions_and_diagnostics_by_algorithm": [
            {
                "algorithm": anova["algorithm"],
                "mauchly_sphericity": {
                    "W": anova["mauchly_w"],
                    "chi_square": anova["mauchly_chi_square"],
                    "degrees_of_freedom": anova["mauchly_df"],
                    "p_value": anova["mauchly_p_value"],
                    "rejected_at_alpha": anova["sphericity_rejected"],
                },
                "greenhouse_geisser_epsilon": anova[
                    "greenhouse_geisser_epsilon"
                ],
                "residual_normality_shapiro_wilk": {
                    "statistic": anova["residual_shapiro_statistic"],
                    "p_value": anova["residual_shapiro_p_value"],
                    "rejected_at_alpha": anova["residual_normality_rejected"],
                },
                "residual_variance_levene_diagnostic": {
                    "statistic": anova["residual_levene_statistic"],
                    "p_value": anova["residual_levene_p_value"],
                    "rejected_at_alpha": anova[
                        "residual_variance_diagnostic_rejected"
                    ],
                    "caution": (
                        "Levene is a supplementary variance diagnostic; sphericity, not "
                        "independent-group variance homogeneity, is the repeated-measures covariance assumption."
                    ),
                },
                "anova": {
                    "F": anova["f_statistic"],
                    "uncorrected_df": [anova["df_size"], anova["df_error"]],
                    "raw_p_value": anova["raw_p_value"],
                    "sphericity_correction_used": anova[
                        "sphericity_correction_used"
                    ],
                    "primary_df": [anova["primary_df_size"], anova["primary_df_error"]],
                    "primary_p_value": anova["primary_p_value"],
                    "holm_adjusted_primary_p_value": anova[
                        "holm_adjusted_primary_p_value"
                    ],
                    "GG_corrected_df": [anova["gg_df_size"], anova["gg_df_error"]],
                    "GG_corrected_p_value": anova["gg_p_value"],
                    "partial_eta_squared": anova["partial_eta_squared"],
                    "interpretation": (
                        "The omnibus test evaluates whether at least one input-size mean differs; "
                        "it does not identify a specific pair."
                    ),
                },
                "friedman": {
                    "chi_square": friedman["chi_square"],
                    "degrees_of_freedom": friedman["degrees_of_freedom"],
                    "raw_p_value": friedman["p_value"],
                    "holm_adjusted_p_value": friedman[
                        "holm_adjusted_p_value"
                    ],
                    "kendall_w": friedman["kendall_w"],
                },
                "pairwise_status": pairwise_status[anova["algorithm"]],
            }
            for anova, friedman in zip(anova_results, friedman_results)
        ],
        "pairwise_comparisons": pairwise_rows,
        "limitations": [
            "The one-way repeated-measures ANOVA is assumption-limited when residual normality fails; Greenhouse-Geisser corrects sphericity, not nonnormality.",
            "Friedman is rank-based and does not test equality of arithmetic mean execution times.",
            "Pairwise sign tests require blocks to be sufficiently independent; measurements were collected sequentially in one process, so temporal dependence cannot be ruled out.",
            "A significant omnibus ANOVA or Friedman test does not by itself identify which input sizes differ.",
            "No observations are removed, and the analysis does not establish performance or security generalization beyond the measured environment and inputs.",
            "The repeated-measures model does not include randomized position; the position-adjusted model and restricted randomization results remain in the separate existing randomized-block analysis.",
        ],
        "outlier_policy": "All raw observations retained; none were automatically removed.",
        "reproducibility": {
            "random_seed": None,
            "randomness_used": False,
            "note": "This module's calculations are deterministic; the existing restricted permutation analysis records its own seed separately.",
            "python_version": sys.version,
            "python_implementation": platform.python_implementation(),
            "numpy_version": np.__version__,
            "scipy_version": scipy.__version__,
            "matplotlib_version": matplotlib.__version__,
        },
        "generated_files": {key: str(value) for key, value in output_paths.items()},
    }

    _write_csv(output_paths["repeated_measures_anova_csv"], ANOVA_FIELDS, anova_rows)
    _write_csv(output_paths["friedman_csv"], FRIEDMAN_FIELDS, friedman_rows)
    _write_csv(output_paths["posthoc_csv"], POSTHOC_FIELDS, pairwise_rows)
    _write_diagnostic_plot(output_paths["diagnostic_qq_plot"], residuals_by_algorithm)
    with output_paths["summary_json"].open("x", encoding="utf-8") as summary_file:
        json.dump(summary, summary_file, indent=2, allow_nan=False)
        summary_file.write("\n")
    return summary["generated_files"]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run repeated-measures and block-aware hashing analysis."
    )
    parser.add_argument(
        "--input-csv",
        type=Path,
        default=Path("results/hashing/randomized_block") / "hashing_randomized_block_benchmarks.csv",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/hashing/randomized_block/repeated_measures/analysis/new_run"),
    )
    parser.add_argument("--alpha", type=float, default=DEFAULT_ALPHA)
    args = parser.parse_args()
    files = analyze_repeated_measures(args.input_csv, args.output_dir, args.alpha)
    for name, path in files.items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()
