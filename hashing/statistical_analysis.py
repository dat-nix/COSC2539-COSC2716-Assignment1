"""Analyze raw hashing benchmark observations without changing the source CSV."""

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
import numpy
import scipy
from scipy import stats

from hashing.experiment_runner import ALGORITHMS, INPUT_SIZES, MEASURED_ITERATIONS


ALPHA = 0.05
MIB_BYTES = 1024 * 1024
BENCHMARK_FIELDS = (
    "Algorithm",
    "Input size in bytes",
    "Repetition number",
    "Execution time in seconds",
    "Digest",
)
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
ANOVA_FIELDS = (
    "Algorithm",
    "Input size groups (KiB)",
    "Observations",
    "Alpha",
    "F-statistic",
    "p-value",
    "ANOVA interpretation",
    "Shapiro-Wilk statistic",
    "Shapiro-Wilk p-value",
    "Residual normality passed",
    "Levene statistic (median)",
    "Levene p-value",
    "Equal variance passed",
    "Assumption status",
    "Alternative test",
    "Alternative statistic",
    "Alternative p-value",
    "Alternative interpretation",
    "Tukey HSD status",
)


def calculate_descriptive_row(
    algorithm: str, input_size_bytes: int, execution_times: list[float]
) -> dict:
    """Calculate descriptive statistics using every supplied observation."""
    mean_time = statistics.mean(execution_times)
    return {
        "Algorithm": algorithm,
        "Input size (KiB)": input_size_bytes / 1024,
        "Input size (MiB)": input_size_bytes / MIB_BYTES,
        "Observations": len(execution_times),
        "Mean time (seconds)": mean_time,
        "Median time (seconds)": statistics.median(execution_times),
        "Standard deviation (seconds)": statistics.stdev(execution_times),
        "Minimum time (seconds)": min(execution_times),
        "Maximum time (seconds)": max(execution_times),
        "Throughput (MiB/s)": (input_size_bytes / MIB_BYTES) / mean_time,
    }


def _load_benchmarks(input_csv: Path) -> tuple[dict, str, int]:
    """Load and validate the complete, unfiltered benchmark CSV."""
    source_bytes = input_csv.read_bytes()
    groups = {(name, size): [] for name, _ in ALGORITHMS for size in INPUT_SIZES}
    repetitions = {(name, size): [] for name, _ in ALGORITHMS for size in INPUT_SIZES}

    with input_csv.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        if tuple(reader.fieldnames or ()) != BENCHMARK_FIELDS:
            raise ValueError(f"Unexpected benchmark CSV columns in {input_csv}")

        row_count = 0
        for row in reader:
            row_count += 1
            algorithm = row["Algorithm"]
            size_bytes = int(row["Input size in bytes"])
            repetition = int(row["Repetition number"])
            elapsed = float(row["Execution time in seconds"])
            digest = row["Digest"]

            if (algorithm, size_bytes) not in groups:
                raise ValueError(
                    f"Unexpected algorithm or input size: {algorithm}, {size_bytes}"
                )
            if not math.isfinite(elapsed) or elapsed <= 0:
                raise ValueError("Execution times must be finite and positive")
            if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                raise ValueError("Each digest must be 64 lowercase hexadecimal characters")

            groups[(algorithm, size_bytes)].append(elapsed)
            repetitions[(algorithm, size_bytes)].append(repetition)

    expected_repetitions = list(range(1, MEASURED_ITERATIONS + 1))
    for key, times in groups.items():
        if len(times) != MEASURED_ITERATIONS:
            raise ValueError(
                f"Expected {MEASURED_ITERATIONS} observations for {key}; found {len(times)}"
            )
        if sorted(repetitions[key]) != expected_repetitions:
            raise ValueError(f"Unexpected repetition numbers for {key}")

    if row_count != len(ALGORITHMS) * len(INPUT_SIZES) * MEASURED_ITERATIONS:
        raise ValueError(f"Unexpected benchmark row count: {row_count}")

    return groups, hashlib.sha256(source_bytes).hexdigest(), row_count


def _interpret_test(test_name: str, statistic: float, p_value: float, alpha: float) -> str:
    decision = "reject" if p_value < alpha else "fail to reject"
    if test_name == "Kruskal-Wallis":
        null_description = "the input-size groups have the same rank distribution"
        conclusion = "evidence of a difference in rank distributions"
    elif test_name == "Welch one-way ANOVA":
        null_description = "all input-size group means are equal"
        conclusion = "evidence that at least one input-size group mean differs"
    else:
        null_description = "all input-size group means are equal"
        conclusion = (
            "evidence that at least one input-size group mean differs; this test does not "
            "identify which groups differ"
        )
    return (
        f"At alpha={alpha:g}, {decision} the null hypothesis that {null_description}; "
        f"{conclusion}."
    )


def _analyze_algorithm(algorithm: str, input_sizes: tuple[int, ...], groups: list[list[float]]) -> tuple[dict, dict]:
    """Run separate one-way ANOVA, diagnostics, and appropriate follow-up tests."""
    anova_result = stats.f_oneway(*groups)
    residuals = []
    for values in groups:
        group_mean = statistics.mean(values)
        residuals.extend(value - group_mean for value in values)

    shapiro_result = stats.shapiro(residuals)
    levene_result = stats.levene(*groups, center="median")
    residual_normality_passed = float(shapiro_result.pvalue) >= ALPHA
    equal_variance_passed = float(levene_result.pvalue) >= ALPHA
    assumptions_passed = residual_normality_passed and equal_variance_passed

    anova_interpretation = _interpret_test(
        "one-way ANOVA", float(anova_result.statistic), float(anova_result.pvalue), ALPHA
    )
    if not assumptions_passed:
        rejected = []
        if not residual_normality_passed:
            rejected.append("residual normality")
        if not equal_variance_passed:
            rejected.append("equal variance")
        anova_interpretation += (
            " Assumption diagnostics rejected " + " and ".join(rejected)
            + "; treat this classical ANOVA result as nominal, not confirmatory."
        )
    if assumptions_passed:
        assumption_status = "Shapiro-Wilk and median-centered Levene did not reject assumptions"
        alternative_name = ""
        alternative_statistic = None
        alternative_p_value = None
        alternative_interpretation = ""
        posthoc_status = "Not needed; omnibus ANOVA was not significant"
        posthoc_results = []

        if float(anova_result.pvalue) < ALPHA:
            tukey_result = stats.tukey_hsd(*groups)
            confidence_intervals = tukey_result.confidence_interval(confidence_level=1 - ALPHA)
            posthoc_results = []
            for first_index in range(len(input_sizes)):
                for second_index in range(first_index + 1, len(input_sizes)):
                    posthoc_results.append(
                        {
                            "group_1_size_kib": input_sizes[first_index] / 1024,
                            "group_2_size_kib": input_sizes[second_index] / 1024,
                            "mean_difference_seconds": float(
                                tukey_result.statistic[first_index, second_index]
                            ),
                            "p_value": float(tukey_result.pvalue[first_index, second_index]),
                            "confidence_interval_low_seconds": float(
                                confidence_intervals.low[first_index, second_index]
                            ),
                            "confidence_interval_high_seconds": float(
                                confidence_intervals.high[first_index, second_index]
                            ),
                        }
                    )
            posthoc_status = "Tukey HSD performed; pairwise results are in the JSON summary"
    else:
        failed_assumptions = []
        if not residual_normality_passed:
            failed_assumptions.append("residual normality")
        if not equal_variance_passed:
            failed_assumptions.append("equal variance")
        assumption_status = "Rejected diagnostic(s): " + ", ".join(failed_assumptions)
        posthoc_results = []
        posthoc_status = "Not performed; standard Tukey HSD assumptions were not supported"

        if residual_normality_passed and not equal_variance_passed:
            alternative_name = "Welch one-way ANOVA"
            alternative_result = stats.f_oneway(*groups, equal_var=False)
            alternative_statistic = float(alternative_result.statistic)
            alternative_p_value = float(alternative_result.pvalue)
            alternative_interpretation = _interpret_test(
                alternative_name, alternative_statistic, alternative_p_value, ALPHA
            )
        else:
            alternative_name = "Kruskal-Wallis"
            alternative_result = stats.kruskal(*groups)
            alternative_statistic = float(alternative_result.statistic)
            alternative_p_value = float(alternative_result.pvalue)
            alternative_interpretation = _interpret_test(
                alternative_name, alternative_statistic, alternative_p_value, ALPHA
            )

    anova_row = {
        "Algorithm": algorithm,
        "Input size groups (KiB)": "; ".join(str(size // 1024) for size in input_sizes),
        "Observations": sum(len(values) for values in groups),
        "Alpha": ALPHA,
        "F-statistic": float(anova_result.statistic),
        "p-value": float(anova_result.pvalue),
        "ANOVA interpretation": anova_interpretation,
        "Shapiro-Wilk statistic": float(shapiro_result.statistic),
        "Shapiro-Wilk p-value": float(shapiro_result.pvalue),
        "Residual normality passed": residual_normality_passed,
        "Levene statistic (median)": float(levene_result.statistic),
        "Levene p-value": float(levene_result.pvalue),
        "Equal variance passed": equal_variance_passed,
        "Assumption status": assumption_status,
        "Alternative test": alternative_name,
        "Alternative statistic": alternative_statistic,
        "Alternative p-value": alternative_p_value,
        "Alternative interpretation": alternative_interpretation,
        "Tukey HSD status": posthoc_status,
    }
    summary = {
        "algorithm": algorithm,
        "input_size_groups_kib": [size / 1024 for size in input_sizes],
        "observations": sum(len(values) for values in groups),
        "alpha": ALPHA,
        "classical_one_way_anova": {
            "f_statistic": float(anova_result.statistic),
            "p_value": float(anova_result.pvalue),
            "interpretation": anova_interpretation,
        },
        "assumption_checks": {
            "residual_normality": {
                "test": "Shapiro-Wilk on residuals centered within each size group",
                "statistic": float(shapiro_result.statistic),
                "p_value": float(shapiro_result.pvalue),
                "passed_at_alpha": residual_normality_passed,
            },
            "variance_homogeneity": {
                "test": "Levene test centered on group medians",
                "statistic": float(levene_result.statistic),
                "p_value": float(levene_result.pvalue),
                "passed_at_alpha": equal_variance_passed,
            },
            "independence": {
                "status": "not established by these data",
                "note": "The 30 observations per configuration are sequential repeated timings of the same input; temporal dependence cannot be assessed from the CSV.",
            },
        },
        "assumption_status": assumption_status,
        "alternative_test": (
            {
                "name": alternative_name,
                "statistic": alternative_statistic,
                "p_value": alternative_p_value,
                "interpretation": alternative_interpretation,
                "limitation": (
                    "Kruskal-Wallis tests rank distributions rather than group means; "
                    "it also assumes independent observations."
                    if alternative_name == "Kruskal-Wallis"
                    else "Welch ANOVA addresses unequal variances but assumes independent, approximately normal observations."
                ),
            }
            if alternative_name
            else None
        ),
        "post_hoc": {
            "method": "Tukey HSD" if posthoc_results else None,
            "status": posthoc_status,
            "pairwise_results": posthoc_results,
        },
    }
    return anova_row, summary


def _write_csv(path: Path, fieldnames: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_plot(path: Path, descriptive_rows: list[dict]) -> None:
    figure, axis = plt.subplots(figsize=(9, 5.5))
    for algorithm, _ in ALGORITHMS:
        algorithm_rows = [row for row in descriptive_rows if row["Algorithm"] == algorithm]
        sizes_kib = [row["Input size (KiB)"] for row in algorithm_rows]
        medians = [row["Median time (seconds)"] for row in algorithm_rows]
        minimums = [row["Minimum time (seconds)"] for row in algorithm_rows]
        maximums = [row["Maximum time (seconds)"] for row in algorithm_rows]
        axis.plot(sizes_kib, medians, marker="o", label=algorithm)
        for size, minimum, maximum in zip(sizes_kib, minimums, maximums):
            axis.vlines(size, minimum, maximum, alpha=0.55, linewidth=1.2)

    axis.set_xscale("log")
    axis.set_yscale("log")
    axis.set_xticks([size / 1024 for size in INPUT_SIZES])
    axis.set_xticklabels([f"{size / 1024:g}" for size in INPUT_SIZES])
    axis.set_xlabel("Input size (KiB; binary units)")
    axis.set_ylabel("Execution time (seconds)")
    axis.set_title("Hash execution time by input size (median and min–max range)")
    axis.grid(True, which="both", linestyle=":", alpha=0.45)
    axis.legend(title="Algorithm")
    figure.tight_layout()
    figure.savefig(path, dpi=180)
    plt.close(figure)


def analyze_benchmarks(input_csv: str | Path, output_dir: str | Path) -> dict:
    """Generate descriptive, inferential, and plot outputs from a raw CSV."""
    input_path = Path(input_csv)
    output_path = Path(output_dir)
    groups, source_sha256, row_count = _load_benchmarks(input_path)
    output_path.mkdir(parents=True, exist_ok=True)

    descriptive_rows = []
    for algorithm, _ in ALGORITHMS:
        for input_size in INPUT_SIZES:
            descriptive_rows.append(
                calculate_descriptive_row(
                    algorithm, input_size, groups[(algorithm, input_size)]
                )
            )

    anova_rows = []
    algorithm_summaries = []
    for algorithm, _ in ALGORITHMS:
        algorithm_groups = [groups[(algorithm, size)] for size in INPUT_SIZES]
        anova_row, algorithm_summary = _analyze_algorithm(
            algorithm, INPUT_SIZES, algorithm_groups
        )
        anova_rows.append(anova_row)
        algorithm_summaries.append(algorithm_summary)

    descriptive_path = output_path / "hashing_descriptive_statistics.csv"
    anova_path = output_path / "hashing_anova_results.csv"
    summary_path = output_path / "hashing_analysis_summary.json"
    plot_path = output_path / "hashing_execution_time.png"
    _write_csv(descriptive_path, DESCRIPTIVE_FIELDS, descriptive_rows)
    _write_csv(anova_path, ANOVA_FIELDS, anova_rows)
    _write_plot(plot_path, descriptive_rows)

    summary = {
        "analysis": "Hash execution time by input size",
        "source_csv": str(input_path),
        "source_csv_sha256": source_sha256,
        "source_observation_count": row_count,
        "configuration_count": len(ALGORITHMS) * len(INPUT_SIZES),
        "input_sizes": [
            {"bytes": size, "kib": size / 1024, "mib": size / MIB_BYTES}
            for size in INPUT_SIZES
        ],
        "algorithms_analyzed_separately": [name for name, _ in ALGORITHMS],
        "significance_level": ALPHA,
        "descriptive_statistics": descriptive_rows,
        "anova_results_by_algorithm": algorithm_summaries,
        "analysis_method": {
            "descriptive_standard_deviation": "sample standard deviation (n - 1)",
            "throughput": "input size in MiB divided by mean execution time in seconds",
            "outlier_policy": "No observations were removed, transformed, or winsorized.",
            "anova_scope": "Separate one-way ANOVA for each algorithm; input size is the five-level factor.",
            "anova_interpretation_limit": "A significant ANOVA indicates that at least one group mean differs; it does not identify which groups differ.",
            "normality_test": "Shapiro-Wilk test on within-group centered residuals.",
            "variance_test": "Median-centered Levene test.",
            "plot": "Median execution time with full observed minimum-to-maximum range; logarithmic axes.",
        },
        "limitations": [
            "The 30 timings in each configuration reuse one deterministic input and are sequential repeated measurements, not independent input samples.",
            "Independence and temporal autocorrelation cannot be checked from the available CSV; classic ANOVA, Welch ANOVA, Kruskal-Wallis, and Tukey HSD all rely on independent observations.",
            "The repeated 0-to-255 byte pattern controls content across algorithms but represents only one highly regular input pattern.",
            "Algorithms and sizes are processed in a fixed order, so CPU load, frequency scaling, and thermal drift may confound comparisons.",
            "The alpha threshold is applied separately to three algorithm-level ANOVAs; no cross-algorithm multiplicity correction is applied.",
            "Statistical assumption tests diagnose distribution and variance, but do not repair dependence or other benchmark-design limitations.",
        ],
        "runtime": {
            "python_version": sys.version,
            "scipy_version": scipy.__version__,
            "matplotlib_version": matplotlib.__version__,
            "numpy_version": numpy.__version__,
        },
        "generated_files": {
            "descriptive_statistics_csv": str(descriptive_path),
            "anova_results_csv": str(anova_path),
            "summary_json": str(summary_path),
            "execution_time_plot": str(plot_path),
        },
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8"
    )
    return summary["generated_files"]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze hashing benchmark observations without changing the source CSV."
    )
    parser.add_argument(
        "--input-csv",
        type=Path,
        default=Path("results/hashing/baseline/hashing_benchmarks.csv"),
        help="raw benchmark CSV (default: results/hashing/baseline/hashing_benchmarks.csv)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/hashing/analysis/new_run"),
        help="directory for analysis outputs (default: results/hashing/analysis/new_run)",
    )
    args = parser.parse_args()

    generated_files = analyze_benchmarks(args.input_csv, args.output_dir)
    for output_name, output_path in generated_files.items():
        print(f"{output_name}: {output_path}")


if __name__ == "__main__":
    main()
