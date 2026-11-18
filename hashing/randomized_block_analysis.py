"""Analyze randomized complete-block hashing benchmark observations."""

import argparse
import csv
import hashlib
import json
import math
import statistics
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import scipy
from scipy import stats

from hashing.randomized_block_runner import (
    BLOCK_COUNT,
    RAW_FIELDS,
    RAW_CSV_NAME,
)
from hashing.experiment_runner import ALGORITHMS, INPUT_SIZES


ALPHA = 0.05
PERMUTATIONS = 9_999
MIB_BYTES = 1024 * 1024
DESCRIPTIVE_NAME = "hashing_randomized_block_descriptive.csv"
MODEL_NAME = "hashing_randomized_block_model.csv"
PAIRWISE_NAME = "hashing_randomized_block_pairwise.csv"
SUMMARY_NAME = "hashing_randomized_block_summary.json"
PLOT_NAME = "hashing_randomized_block_diagnostics.png"

DESCRIPTIVE_FIELDS = (
    "Algorithm",
    "Input size (KiB)",
    "Input size (MiB)",
    "Observations",
    "Mean time (seconds)",
    "Median time (seconds)",
    "Standard deviation (seconds)",
    "Minimum time (seconds)",
    "Maximum time (seconds)",
    "Throughput (MiB/s)",
)
MODEL_FIELDS = (
    "Algorithm",
    "Blocks",
    "Observations",
    "Input size effect df",
    "Residual df",
    "RCBD F-statistic",
    "RCBD p-value",
    "Partial eta squared",
    "Partial omega squared",
    "Restricted permutation count",
    "Restricted permutation F-statistic",
    "Restricted permutation p-value",
    "Residual Shapiro-Wilk statistic",
    "Residual Shapiro-Wilk p-value",
    "Residual Levene statistic",
    "Residual Levene p-value",
    "Order slope seconds per position",
    "Order effect p-value",
    "Residual lag-1 correlation by clock order",
    "Block mean log-time Spearman rho",
    "Block mean log-time Spearman p-value",
    "Pairwise status",
)
PAIRWISE_FIELDS = (
    "Algorithm",
    "Input size 1 (KiB)",
    "Input size 2 (KiB)",
    "Adjusted mean difference (seconds; size 1 minus size 2)",
    "Standard error (seconds)",
    "Bonferroni simultaneous CI low (seconds)",
    "Bonferroni simultaneous CI high (seconds)",
    "Unadjusted p-value",
    "Holm adjusted p-value",
    "Partial model effect (difference / residual SD)",
)


def _model_matrix(
    records: list[dict], input_sizes: tuple[int, ...], blocks: tuple[int, ...],
    include_size: bool = True, include_position: bool = True,
) -> tuple[np.ndarray, list[str]]:
    columns = [np.ones(len(records))]
    names = ["intercept"]
    if include_size:
        for size in input_sizes[1:]:
            columns.append(
                np.asarray([1.0 if row["Input size in bytes"] == size else 0.0 for row in records])
            )
            names.append(f"size_{size}")
    for block in blocks[1:]:
        columns.append(np.asarray([1.0 if row["Block ID"] == block else 0.0 for row in records]))
        names.append(f"block_{block}")
    if include_position:
        columns.append(
            np.asarray(
                [row["Randomized position within block"] - 8.0 for row in records],
                dtype=float,
            )
        )
        names.append("position_centered")
    return np.column_stack(columns), names


def _fit_ols(response: np.ndarray, design: np.ndarray) -> dict:
    coefficients, _, rank, _ = np.linalg.lstsq(design, response, rcond=None)
    residuals = response - design @ coefficients
    return {
        "coefficients": coefficients,
        "residuals": residuals,
        "rank": int(rank),
        "sse": float(residuals @ residuals),
        "covariance_factor": np.linalg.pinv(design.T @ design),
    }


def _rcbd_f_statistic(matrix: np.ndarray) -> float:
    """Classical randomized complete-block F statistic for a balanced matrix."""
    block_count, size_count = matrix.shape
    grand_mean = float(matrix.mean())
    total_ss = float(((matrix - grand_mean) ** 2).sum())
    block_ss = size_count * float(((matrix.mean(axis=1) - grand_mean) ** 2).sum())
    size_ss = block_count * float(((matrix.mean(axis=0) - grand_mean) ** 2).sum())
    error_ss = max(0.0, total_ss - block_ss - size_ss)
    size_df = size_count - 1
    error_df = (block_count - 1) * (size_count - 1)
    if error_ss <= 0:
        return math.inf if size_ss > 0 else 0.0
    return (size_ss / size_df) / (error_ss / error_df)


def _restricted_permutation_test(
    matrix: np.ndarray, seed: int, permutation_count: int = PERMUTATIONS
) -> tuple[float, float]:
    """Permute size labels within each complete block, preserving block values."""
    if permutation_count <= 0:
        raise ValueError("permutation_count must be positive")
    block_count, size_count = matrix.shape
    observed_f = _rcbd_f_statistic(matrix)

    rng = np.random.default_rng(seed)
    permutations = rng.random((permutation_count, block_count, size_count)).argsort(axis=2)
    permuted_values = np.take_along_axis(matrix[None, :, :], permutations, axis=2)
    grand_means = permuted_values.mean(axis=(1, 2))
    permuted_size_means = permuted_values.mean(axis=1)
    total_ss = ((permuted_values - grand_means[:, None, None]) ** 2).sum(axis=(1, 2))
    block_ss = size_count * (
        (permuted_values.mean(axis=2) - grand_means[:, None]) ** 2
    ).sum(axis=1)
    size_ss = block_count * (
        (permuted_size_means - grand_means[:, None]) ** 2
    ).sum(axis=1)
    error_ss = np.maximum(0.0, total_ss - block_ss - size_ss)
    size_df = size_count - 1
    error_df = (block_count - 1) * size_df
    permutation_f = (size_ss / size_df) / (error_ss / error_df)
    exceedances = int(np.count_nonzero(permutation_f >= observed_f))
    permutation_p = (exceedances + 1) / (permutation_count + 1)
    return observed_f, permutation_p


def _holm_adjust(p_values: list[float]) -> list[float]:
    count = len(p_values)
    order = sorted(range(count), key=p_values.__getitem__)
    adjusted = [0.0] * count
    running_max = 0.0
    for rank, index in enumerate(order):
        candidate = min(1.0, (count - rank) * p_values[index])
        running_max = max(running_max, candidate)
        adjusted[index] = running_max
    return adjusted


def _pairwise_contrasts(
    algorithm: str,
    records: list[dict],
    input_sizes: tuple[int, ...],
    blocks: tuple[int, ...],
    fit: dict,
    design: np.ndarray,
    residual_df: int,
    mse: float,
) -> list[dict]:
    size_index = {size: index for index, size in enumerate(input_sizes)}
    beta = fit["coefficients"]
    cov_factor = fit["covariance_factor"]
    size_effect_df = len(input_sizes) - 1
    critical_value = stats.t.ppf(
        1 - ALPHA / (2 * size_effect_df * (size_effect_df + 1) / 2), residual_df
    )
    contrasts = []

    for first_index, first_size in enumerate(input_sizes):
        for second_size in input_sizes[first_index + 1 :]:
            contrast = np.zeros(design.shape[1])
            if first_size != input_sizes[0]:
                contrast[size_index[first_size]] = 1.0
            if second_size != input_sizes[0]:
                contrast[size_index[second_size]] -= 1.0
            estimate = float(contrast @ beta)
            standard_error = math.sqrt(max(0.0, mse * float(contrast @ cov_factor @ contrast)))
            t_statistic = estimate / standard_error if standard_error else math.inf
            unadjusted_p = float(2 * stats.t.sf(abs(t_statistic), residual_df))
            half_width = critical_value * standard_error
            contrasts.append(
                {
                    "Algorithm": algorithm,
                    "Input size 1 (KiB)": first_size / 1024,
                    "Input size 2 (KiB)": second_size / 1024,
                    "Adjusted mean difference (seconds; size 1 minus size 2)": estimate,
                    "Standard error (seconds)": standard_error,
                    "Bonferroni simultaneous CI low (seconds)": estimate - half_width,
                    "Bonferroni simultaneous CI high (seconds)": estimate + half_width,
                    "Unadjusted p-value": unadjusted_p,
                    "Partial model effect (difference / residual SD)": (
                        estimate / math.sqrt(mse) if mse > 0 else math.inf
                    ),
                }
            )

    adjusted = _holm_adjust([row["Unadjusted p-value"] for row in contrasts])
    for row, adjusted_p in zip(contrasts, adjusted):
        row["Holm adjusted p-value"] = adjusted_p
    return contrasts


def _analyze_algorithm(
    algorithm: str,
    records: list[dict],
    input_sizes: tuple[int, ...] = INPUT_SIZES,
    permutation_count: int = PERMUTATIONS,
    analysis_seed: int = 0,
) -> tuple[dict, dict, list[dict]]:
    blocks = tuple(range(1, BLOCK_COUNT + 1))
    records = sorted(
        records,
        key=lambda row: (row["Block ID"], row["Input size in bytes"]),
    )
    response = np.asarray([row["Execution time in seconds"] for row in records])
    full_design, full_names = _model_matrix(records, input_sizes, blocks, True, True)
    no_size_design, _ = _model_matrix(records, input_sizes, blocks, False, True)
    no_position_design, _ = _model_matrix(records, input_sizes, blocks, True, False)
    full_fit = _fit_ols(response, full_design)
    no_size_fit = _fit_ols(response, no_size_design)
    no_position_fit = _fit_ols(response, no_position_design)

    size_df = full_fit["rank"] - no_size_fit["rank"]
    residual_df = len(response) - full_fit["rank"]
    size_ss = max(0.0, no_size_fit["sse"] - full_fit["sse"])
    mse = full_fit["sse"] / residual_df
    model_f = (size_ss / size_df) / mse if mse > 0 else math.inf
    model_p = float(stats.f.sf(model_f, size_df, residual_df))
    partial_eta_squared = size_ss / (size_ss + full_fit["sse"]) if size_ss + full_fit["sse"] else 0.0
    partial_omega_squared = max(
        0.0,
        (size_ss - size_df * mse) / (size_ss + full_fit["sse"] + mse),
    )

    position_df = full_fit["rank"] - no_position_fit["rank"]
    position_ss = max(0.0, no_position_fit["sse"] - full_fit["sse"])
    position_f = (position_ss / position_df) / mse if mse > 0 else math.inf
    position_p = float(stats.f.sf(position_f, position_df, residual_df))
    position_index = full_names.index("position_centered")
    position_beta = float(full_fit["coefficients"][position_index])
    position_se = math.sqrt(
        max(0.0, mse * full_fit["covariance_factor"][position_index, position_index])
    )

    residual_groups = [
        [
            float(full_fit["residuals"][index])
            for index, row in enumerate(records)
            if row["Input size in bytes"] == size
        ]
        for size in input_sizes
    ]
    shapiro_result = stats.shapiro(full_fit["residuals"])
    levene_result = stats.levene(*residual_groups, center="median")

    rcbd_matrix = np.asarray(
        [
            [
                next(
                    row["Execution time in seconds"]
                    for row in records
                    if row["Block ID"] == block and row["Input size in bytes"] == size
                )
                for size in input_sizes
            ]
            for block in blocks
        ],
        dtype=float,
    )
    rcbd_f, randomization_p = _restricted_permutation_test(
        rcbd_matrix, analysis_seed, permutation_count
    )

    ordered_records = sorted(records, key=lambda row: row["Measurement start monotonic seconds"])
    ordered_residuals = np.asarray(
        [
            full_fit["residuals"][records.index(row)]
            for row in ordered_records
        ]
    )
    lag1_correlation = (
        float(np.corrcoef(ordered_residuals[:-1], ordered_residuals[1:])[0, 1])
        if np.std(ordered_residuals[:-1]) > 0 and np.std(ordered_residuals[1:]) > 0
        else 0.0
    )
    block_mean_log = [
        statistics.mean(
            math.log(row["Execution time in seconds"])
            for row in records
            if row["Block ID"] == block
        )
        for block in blocks
    ]
    block_trend = stats.spearmanr(blocks, block_mean_log)

    diagnostics_pass = (
        float(shapiro_result.pvalue) >= ALPHA
        and float(levene_result.pvalue) >= ALPHA
    )
    if randomization_p < ALPHA and diagnostics_pass:
        pairwise_status = (
            "Performed: blocked model contrasts; Holm-adjusted p-values and "
            "Bonferroni simultaneous 95% CIs"
        )
        pairwise_rows = _pairwise_contrasts(
            algorithm, records, input_sizes, blocks, full_fit, full_design, residual_df, mse
        )
    elif randomization_p >= ALPHA:
        pairwise_status = "Not performed: block-restricted omnibus test was not significant"
        pairwise_rows = []
    else:
        pairwise_status = (
            "Not performed: residual normality or variance diagnostics did not support "
            "parametric pairwise contrasts"
        )
        pairwise_rows = []

    model_row = {
        "Algorithm": algorithm,
        "Blocks": BLOCK_COUNT,
        "Observations": len(records),
        "Input size effect df": size_df,
        "Residual df": residual_df,
        "RCBD F-statistic": model_f,
        "RCBD p-value": model_p,
        "Partial eta squared": partial_eta_squared,
        "Partial omega squared": partial_omega_squared,
        "Restricted permutation count": permutation_count,
        "Restricted permutation F-statistic": rcbd_f,
        "Restricted permutation p-value": randomization_p,
        "Residual Shapiro-Wilk statistic": float(shapiro_result.statistic),
        "Residual Shapiro-Wilk p-value": float(shapiro_result.pvalue),
        "Residual Levene statistic": float(levene_result.statistic),
        "Residual Levene p-value": float(levene_result.pvalue),
        "Order slope seconds per position": position_beta,
        "Order effect p-value": position_p,
        "Residual lag-1 correlation by clock order": lag1_correlation,
        "Block mean log-time Spearman rho": float(block_trend.statistic),
        "Block mean log-time Spearman p-value": float(block_trend.pvalue),
        "Pairwise status": pairwise_status,
    }
    summary = {
        "algorithm": algorithm,
        "model": "execution_time ~ input_size + block + randomized_position",
        "block_handling": "complete blocks are included as nuisance block effects; the size test is adjusted for block and linear within-block position",
        "input_size_test": {
            "f_statistic": model_f,
            "p_value": model_p,
            "degrees_of_freedom": {"input_size": size_df, "residual": residual_df},
            "partial_eta_squared": partial_eta_squared,
            "partial_omega_squared": partial_omega_squared,
            "interpretation": "The blocked model tests whether any input-size mean differs; it does not identify pairs.",
        },
        "design_based_sensitivity": {
            "method": "Monte Carlo restricted randomization test using the RCBD F statistic; size labels permuted only within blocks",
            "permutations": permutation_count,
            "analysis_seed": analysis_seed,
            "f_statistic": rcbd_f,
            "p_value": randomization_p,
            "assumption": "Requires the within-block randomized assignment and independent block randomization to be credible; randomization does not guarantee temporally independent blocks.",
        },
        "diagnostics": {
            "residual_normality": {
                "test": "Shapiro-Wilk on block-, size-, and position-adjusted residuals",
                "statistic": float(shapiro_result.statistic),
                "p_value": float(shapiro_result.pvalue),
                "passed_at_alpha": float(shapiro_result.pvalue) >= ALPHA,
            },
            "residual_variance_by_size": {
                "test": "Median-centered Levene test on model residuals grouped by input size",
                "statistic": float(levene_result.statistic),
                "p_value": float(levene_result.pvalue),
                "passed_at_alpha": float(levene_result.pvalue) >= ALPHA,
            },
            "within_block_position": {
                "slope_seconds_per_position": position_beta,
                "p_value": position_p,
            },
            "residual_lag1_correlation_in_clock_order": lag1_correlation,
            "block_mean_log_time_trend": {
                "spearman_rho": float(block_trend.statistic),
                "p_value": float(block_trend.pvalue),
            },
            "no_outliers_removed": True,
        },
        "pairwise": {
            "status": pairwise_status,
            "adjustment": "Holm p-value adjustment; Bonferroni simultaneous 95% confidence intervals",
            "comparisons": pairwise_rows,
        },
        "limitations": [
            "A randomized order reduces systematic treatment-order confounding but does not guarantee independent observations or independent blocks.",
            "Each block is run sequentially in one process; residual temporal dependence may remain.",
            "The restricted randomization test depends on the recorded within-block randomization being implemented correctly.",
            "The position adjustment models only a linear within-block order trend.",
            "The input content is seeded pseudo-random bytes; conclusions generalize to these generated inputs and environment, not all data or machines.",
            "The primary response is elapsed time; very small inputs remain sensitive to Python and timer overhead.",
            "No observations are removed; potential timing outliers require documented investigation rather than automatic exclusion.",
        ],
    }
    return model_row, summary, pairwise_rows


def _load_raw_csv(path: Path) -> tuple[list[dict], str]:
    raw_bytes = path.read_bytes()
    with path.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        if tuple(reader.fieldnames or ()) != RAW_FIELDS:
            raise ValueError(f"Unexpected randomized-block CSV columns in {path}")
        records = []
        for row in reader:
            record = {
                "Algorithm": row["Algorithm"],
                "Input size in bytes": int(row["Input size in bytes"]),
                "Block ID": int(row["Block ID"]),
                "Randomized position within block": int(row["Randomized position within block"]),
                "Repetition number": int(row["Repetition number"]),
                "Execution time in seconds": float(row["Execution time in seconds"]),
                "Input identifier": row["Input identifier"],
                "Measurement start monotonic seconds": float(
                    row["Measurement start monotonic seconds"]
                ),
                "Measurement end monotonic seconds": float(
                    row["Measurement end monotonic seconds"]
                ),
                "Digest": row["Digest"],
            }
            if not math.isfinite(record["Execution time in seconds"]) or record["Execution time in seconds"] <= 0:
                raise ValueError("Execution times must be finite and positive")
            if (
                not math.isfinite(record["Measurement start monotonic seconds"])
                or not math.isfinite(record["Measurement end monotonic seconds"])
                or record["Measurement end monotonic seconds"] <= record["Measurement start monotonic seconds"]
            ):
                raise ValueError("Monotonic measurement boundaries must be finite and increasing")
            duration_from_boundaries = (
                record["Measurement end monotonic seconds"]
                - record["Measurement start monotonic seconds"]
            )
            if not math.isclose(
                duration_from_boundaries,
                record["Execution time in seconds"],
                rel_tol=1e-6,
                abs_tol=1e-12,
            ):
                raise ValueError("Recorded duration does not match its monotonic boundaries")
            if record["Block ID"] not in range(1, BLOCK_COUNT + 1):
                raise ValueError(f"Invalid block ID: {record['Block ID']}")
            if record["Repetition number"] != record["Block ID"]:
                raise ValueError("Repetition number must match the block ID")
            records.append(record)

    expected = {
        (algorithm, size, block)
        for algorithm, _ in ALGORITHMS
        for size in INPUT_SIZES
        for block in range(1, BLOCK_COUNT + 1)
    }
    actual = [
        (row["Algorithm"], row["Input size in bytes"], row["Block ID"])
        for row in records
    ]
    if len(records) != len(expected) or set(actual) != expected:
        raise ValueError("CSV must contain exactly one observation for every algorithm, size, and block")
    if len(set(actual)) != len(actual):
        raise ValueError("Duplicate algorithm, size, and block observation")

    for block in range(1, BLOCK_COUNT + 1):
        block_rows = [row for row in records if row["Block ID"] == block]
        positions = [row["Randomized position within block"] for row in block_rows]
        if sorted(positions) != list(range(1, len(conditions_for_csv()) + 1)):
            raise ValueError(f"Block {block} does not have positions 1 through 15 exactly once")
        for size in INPUT_SIZES:
            identifiers = {
                row["Input identifier"]
                for row in block_rows
                if row["Input size in bytes"] == size
            }
            if len(identifiers) != 1:
                raise ValueError(f"Algorithms do not share one input identifier in block {block}, size {size}")
    return records, hashlib.sha256(raw_bytes).hexdigest()


def conditions_for_csv() -> tuple[tuple[str, int], ...]:
    return tuple((name, size) for name, _ in ALGORITHMS for size in INPUT_SIZES)


def _descriptive_row(algorithm: str, size_bytes: int, values: list[float]) -> dict:
    mean_time = statistics.mean(values)
    return {
        "Algorithm": algorithm,
        "Input size (KiB)": size_bytes / 1024,
        "Input size (MiB)": size_bytes / MIB_BYTES,
        "Observations": len(values),
        "Mean time (seconds)": mean_time,
        "Median time (seconds)": statistics.median(values),
        "Standard deviation (seconds)": statistics.stdev(values),
        "Minimum time (seconds)": min(values),
        "Maximum time (seconds)": max(values),
        "Throughput (MiB/s)": (size_bytes / MIB_BYTES) / mean_time,
    }


def _write_csv(path: Path, fields: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("x", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _write_diagnostic_plot(path: Path, residuals_by_algorithm: dict[str, np.ndarray]) -> None:
    figure, axes = plt.subplots(1, len(ALGORITHMS), figsize=(14, 4.5))
    for axis, (algorithm, _) in zip(axes, ALGORITHMS):
        stats.probplot(residuals_by_algorithm[algorithm], dist="norm", plot=axis)
        axis.set_title(algorithm)
        axis.set_xlabel("Theoretical normal quantiles")
        axis.set_ylabel("Adjusted residuals (seconds)")
        axis.grid(True, alpha=0.25)
    figure.suptitle("Randomized-block model residual Q–Q plots")
    figure.tight_layout()
    figure.savefig(path, dpi=160)
    plt.close(figure)


def analyze_randomized_blocks(
    input_csv: str | Path,
    output_dir: str | Path,
    seed: int = 0,
    permutation_count: int = PERMUTATIONS,
) -> dict:
    input_path = Path(input_csv)
    output_path = Path(output_dir)
    records, source_sha256 = _load_raw_csv(input_path)
    output_paths = {
        "descriptive_csv": output_path / DESCRIPTIVE_NAME,
        "model_csv": output_path / MODEL_NAME,
        "pairwise_csv": output_path / PAIRWISE_NAME,
        "summary_json": output_path / SUMMARY_NAME,
        "diagnostic_qq_plot": output_path / PLOT_NAME,
    }
    collisions = [path for path in output_paths.values() if path.exists()]
    if collisions:
        raise FileExistsError(f"Analysis output already exists: {collisions[0]}")
    output_path.mkdir(parents=True, exist_ok=True)

    descriptive_rows = []
    model_rows = []
    algorithm_results = []
    pairwise_rows = []
    residuals_by_algorithm = {}

    for algorithm_index, (algorithm, _) in enumerate(ALGORITHMS):
        algorithm_records = [row for row in records if row["Algorithm"] == algorithm]
        for size in INPUT_SIZES:
            values = [
                row["Execution time in seconds"]
                for row in algorithm_records
                if row["Input size in bytes"] == size
            ]
            descriptive_rows.append(_descriptive_row(algorithm, size, values))

        model_row, model_summary, pairwise = _analyze_algorithm(
            algorithm,
            algorithm_records,
            permutation_count=permutation_count,
            analysis_seed=_derived_analysis_seed(seed, algorithm_index),
        )
        model_rows.append(model_row)
        algorithm_results.append(model_summary)
        pairwise_rows.extend(pairwise)
        # Recreate residuals in the same sorted order used in the model fit for Q-Q plots.
        sorted_records = sorted(
            algorithm_records,
            key=lambda row: (row["Block ID"], row["Input size in bytes"]),
        )
        design, _ = _model_matrix(
            sorted_records, INPUT_SIZES, tuple(range(1, BLOCK_COUNT + 1)), True, True
        )
        fit = _fit_ols(
            np.asarray([row["Execution time in seconds"] for row in sorted_records]), design
        )
        residuals_by_algorithm[algorithm] = fit["residuals"]

    _write_csv(output_paths["descriptive_csv"], DESCRIPTIVE_FIELDS, descriptive_rows)
    _write_csv(output_paths["model_csv"], MODEL_FIELDS, model_rows)
    _write_csv(output_paths["pairwise_csv"], PAIRWISE_FIELDS, pairwise_rows)
    _write_diagnostic_plot(output_paths["diagnostic_qq_plot"], residuals_by_algorithm)

    summary = {
        "analysis": "Randomized complete-block hashing experiment",
        "source_csv": str(input_path),
        "source_csv_sha256": source_sha256,
        "observation_count": len(records),
        "block_count": BLOCK_COUNT,
        "conditions_per_block": len(conditions_for_csv()),
        "input_sizes": [
            {"bytes": size, "kib": size / 1024, "mib": size / MIB_BYTES}
            for size in INPUT_SIZES
        ],
        "alpha": ALPHA,
        "primary_method": "Restricted within-block randomization test of the RCBD F statistic; parametric block-plus-size-plus-position model reported as a model-based analysis.",
        "algorithms_analyzed_separately": [name for name, _ in ALGORITHMS],
        "descriptive_statistics": descriptive_rows,
        "model_results_by_algorithm": algorithm_results,
        "outlier_policy": "All observations retained; none were automatically removed.",
        "method_notes": [
            "Input size is a five-level fixed factor. Each block contains every algorithm-size condition once.",
            "Parametric size tests include block indicator terms and a linear randomized-position covariate.",
            "Restricted permutations shuffle the five size labels within each algorithm's block while preserving the block's observed timing values.",
            "The randomization p-value depends on the recorded assignment mechanism; it does not establish temporal independence between blocks.",
            "Holm-adjusted pairwise contrasts are only produced when the blocked randomization omnibus test is significant and residual normality and variance diagnostics support the parametric contrasts.",
            "Confidence intervals for pairwise mean differences are Bonferroni simultaneous intervals across ten comparisons; main-effect partial eta squared is reported as a point effect size.",
        ],
        "limitations": [
            "Randomized order reduces treatment-order confounding but does not guarantee independent observations or independent blocks.",
            "Thirty blocks are still executed sequentially in one process; shared thermal or system-load drift may remain.",
            "The position covariate models a linear within-block timing trend only.",
            "Randomized pseudo-random input content improves coverage relative to one repeated byte pattern but does not represent every real-world file type.",
            "The 1 KiB measurements remain sensitive to Python dispatch and timer overhead.",
        ],
        "runtime": {
            "python_version": sys.version,
            "numpy_version": np.__version__,
            "scipy_version": scipy.__version__,
            "matplotlib_version": matplotlib.__version__,
        },
        "generated_files": {key: str(value) for key, value in output_paths.items()},
    }
    with output_paths["summary_json"].open("x", encoding="utf-8") as summary_file:
        json.dump(summary, summary_file, indent=2, allow_nan=False)
        summary_file.write("\n")
    return summary["generated_files"]


def _derived_analysis_seed(seed: int, algorithm_index: int) -> int:
    material = f"{seed}:analysis:{algorithm_index}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze randomized-block hashing results with block-aware methods."
    )
    parser.add_argument(
        "--input-csv",
        type=Path,
        default=Path("results/hashing/randomized_block") / RAW_CSV_NAME,
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/hashing/randomized_block/analysis/new_run"),
    )
    parser.add_argument("--seed", type=int, default=0, help="seed for reproducible restricted permutations")
    parser.add_argument("--permutations", type=int, default=PERMUTATIONS)
    args = parser.parse_args()
    files = analyze_randomized_blocks(args.input_csv, args.output_dir, args.seed, args.permutations)
    for name, path in files.items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()
