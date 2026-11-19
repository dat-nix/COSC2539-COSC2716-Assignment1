"""Analyze matched-block hashing verification timings and outcomes."""

import csv
import hashlib
import hmac
import json
import math
import statistics
import sys
from pathlib import Path

import numpy as np
import scipy
from scipy import stats

from hashing.experiment_runner import ALGORITHMS
from hashing.tampering_performance_runner import (
    METADATA_NAME,
    RAW_FIELDS,
    RAW_CSV_NAME,
    SCENARIOS,
    VALID_SCENARIO,
    TAMPERED_TRUSTED_SCENARIO,
    TAMPERED_RECOMPUTED_SCENARIO,
)


ALPHA = 0.05
PERMUTATIONS = 9_999
MIB_BYTES = 1024 * 1024
DESCRIPTIVE_NAME = "hashing_tampering_performance_descriptive.csv"
PAIRED_NAME = "hashing_tampering_performance_paired_tests.csv"
SUMMARY_NAME = "hashing_tampering_performance_summary.json"

COMPARISONS = (
    (
        "trusted_tamper_vs_valid",
        TAMPERED_TRUSTED_SCENARIO,
        VALID_SCENARIO,
    ),
    (
        "attacker_recomputed_vs_valid",
        TAMPERED_RECOMPUTED_SCENARIO,
        VALID_SCENARIO,
    ),
    (
        "trusted_rejection_vs_attacker_recomputed",
        TAMPERED_TRUSTED_SCENARIO,
        TAMPERED_RECOMPUTED_SCENARIO,
    ),
)

DESCRIPTIVE_FIELDS = (
    "Algorithm",
    "Input size in bytes",
    "Scenario",
    "Observations",
    "Mean time (seconds)",
    "Median time (seconds)",
    "Standard deviation (seconds)",
    "Minimum time (seconds)",
    "Maximum time (seconds)",
    "Mean throughput (MiB/s)",
    "Verification passed count",
    "Tampering detected count",
)
PAIRED_FIELDS = (
    "Comparison",
    "Algorithm",
    "Input size in bytes",
    "Comparison scenario",
    "Baseline scenario",
    "Paired blocks",
    "Mean baseline time (seconds)",
    "Mean comparison time (seconds)",
    "Mean paired difference (seconds; comparison minus baseline)",
    "Median paired difference (seconds)",
    "Mean absolute paired difference (seconds)",
    "Mean percentage difference of means",
    "Mean paired percentage difference",
    "Median paired percentage difference",
    "Mean absolute paired percentage difference",
    "Paired difference Shapiro-Wilk statistic",
    "Paired difference Shapiro-Wilk p-value",
    "Paired difference skewness",
    "Paired difference lag-1 correlation by block",
    "Paired difference block-trend Spearman rho",
    "Paired difference block-trend Spearman p-value",
    "Statistical test",
    "Test statistic (absolute mean difference in seconds)",
    "Permutation count",
    "Permutation seed",
    "Raw p-value",
    "Holm adjusted p-value across all comparisons",
)


def _finite_or_none(value: float | None) -> float | None:
    """Return a finite numeric diagnostic, or ``None`` when it is undefined."""
    if value is None:
        return None
    numeric_value = float(value)
    return numeric_value if math.isfinite(numeric_value) else None


def _holm_adjust(p_values: list[float]) -> list[float]:
    """Return Holm step-down adjusted p-values in the original order."""
    count = len(p_values)
    order = sorted(range(count), key=p_values.__getitem__)
    adjusted = [0.0] * count
    running_max = 0.0
    for rank, index in enumerate(order):
        candidate = min(1.0, (count - rank) * p_values[index])
        running_max = max(running_max, candidate)
        adjusted[index] = running_max
    return adjusted


def _analysis_seed(seed: int, *parts: object) -> int:
    material = ":".join([str(seed), *(str(part) for part in parts)]).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def _parse_bool(value: str, row_number: int, field: str) -> bool:
    lowered = value.strip().lower()
    if lowered not in {"true", "false"}:
        raise ValueError(f"Invalid boolean {field} on CSV row {row_number}")
    return lowered == "true"


def _load_observations(
    input_csv: str | Path,
    metadata_path: str | Path | None = None,
    minimum_blocks: int = 30,
) -> tuple[list[dict], dict, str]:
    """Load and validate every raw row and its complete matched-block design."""
    raw_path = Path(input_csv)
    metadata_file = Path(metadata_path) if metadata_path else raw_path.with_name(METADATA_NAME)
    metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
    raw_bytes = raw_path.read_bytes()
    algorithms = tuple(name for name, _ in ALGORITHMS)
    input_sizes = tuple(int(size) for size in metadata["input_sizes_bytes"])
    block_count = int(metadata["block_count"])
    if block_count < minimum_blocks:
        raise ValueError(
            f"Expected at least {minimum_blocks} measured blocks; found {block_count}"
        )
    if not input_sizes or len(set(input_sizes)) != len(input_sizes) or any(
        size <= 0 for size in input_sizes
    ):
        raise ValueError("Metadata must list unique positive input sizes")
    if tuple(metadata.get("algorithms", ())) != algorithms:
        raise ValueError("Metadata algorithms do not match the supported hashing algorithms")
    if tuple(metadata.get("scenarios", ())) != SCENARIOS:
        raise ValueError("Metadata scenarios do not match the tampering experiment")

    records = []
    with raw_path.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        if tuple(reader.fieldnames or ()) != RAW_FIELDS:
            raise ValueError(f"Unexpected tampering-performance CSV columns in {raw_path}")
        for row_number, row in enumerate(reader, start=2):
            try:
                record = {
                    "Algorithm": row["Algorithm"],
                    "Input size in bytes": int(row["Input size in bytes"]),
                    "Scenario": row["Scenario"],
                    "Block ID": int(row["Block ID"]),
                    "Randomized position within block": int(
                        row["Randomized position within block"]
                    ),
                    "Repetition number": int(row["Repetition number"]),
                    "Execution time in seconds": float(row["Execution time in seconds"]),
                    "Measurement start monotonic seconds": float(
                        row["Measurement start monotonic seconds"]
                    ),
                    "Measurement end monotonic seconds": float(
                        row["Measurement end monotonic seconds"]
                    ),
                    "Input identifier": row["Input identifier"],
                    "Original input identifier": row["Original input identifier"],
                    "Modified input identifier": row["Modified input identifier"],
                    "Data state": row["Data state"],
                    "Digest trust basis": row["Digest trust basis"],
                    "Trusted original digest": row["Trusted original digest"],
                    "Comparison digest": row["Comparison digest"],
                    "Computed digest": row["Computed digest"],
                    "Verification passed": _parse_bool(
                        row["Verification passed"], row_number, "Verification passed"
                    ),
                    "Tampering detected": _parse_bool(
                        row["Tampering detected"], row_number, "Tampering detected"
                    ),
                }
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(f"Invalid value on CSV row {row_number}") from error

            if record["Algorithm"] not in algorithms:
                raise ValueError(f"Unknown algorithm on CSV row {row_number}")
            if record["Input size in bytes"] not in input_sizes:
                raise ValueError(f"Unexpected input size on CSV row {row_number}")
            if record["Scenario"] not in SCENARIOS:
                raise ValueError(f"Unknown verification scenario on CSV row {row_number}")
            if record["Block ID"] not in range(1, block_count + 1):
                raise ValueError(f"Invalid block ID on CSV row {row_number}")
            if record["Repetition number"] != record["Block ID"]:
                raise ValueError(f"Repetition does not match block on CSV row {row_number}")
            if not 1 <= record["Randomized position within block"] <= len(algorithms) * len(input_sizes) * len(SCENARIOS):
                raise ValueError(f"Invalid randomized position on CSV row {row_number}")
            for field in (
                "Execution time in seconds",
                "Measurement start monotonic seconds",
                "Measurement end monotonic seconds",
            ):
                if not math.isfinite(record[field]):
                    raise ValueError(f"Non-finite {field} on CSV row {row_number}")
            if record["Execution time in seconds"] <= 0:
                raise ValueError(f"Non-positive execution time on CSV row {row_number}")
            start = record["Measurement start monotonic seconds"]
            end = record["Measurement end monotonic seconds"]
            if end <= start or not math.isclose(
                end - start,
                record["Execution time in seconds"],
                rel_tol=1e-6,
                abs_tol=1e-12,
            ):
                raise ValueError(f"Invalid timing boundaries on CSV row {row_number}")

            for field in (
                "Trusted original digest",
                "Comparison digest",
                "Computed digest",
            ):
                digest = record[field]
                if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
                    raise ValueError(f"Invalid hexadecimal {field} on CSV row {row_number}")

            scenario = record["Scenario"]
            if scenario == VALID_SCENARIO:
                expected_state, expected_trust = "original", "trusted_original"
            elif scenario == TAMPERED_TRUSTED_SCENARIO:
                expected_state, expected_trust = "modified", "trusted_original"
            else:
                expected_state, expected_trust = "modified", "attacker_recomputed_unkeyed"
            if record["Data state"] != expected_state:
                raise ValueError(f"Data state does not match scenario on row {row_number}")
            if record["Digest trust basis"] != expected_trust:
                raise ValueError(f"Digest trust basis does not match scenario on row {row_number}")
            expected_identifier = (
                record["Original input identifier"]
                if expected_state == "original"
                else record["Modified input identifier"]
            )
            if record["Input identifier"] != expected_identifier:
                raise ValueError(f"Input identifier does not match data state on row {row_number}")
            expected_passed = hmac.compare_digest(
                record["Computed digest"], record["Comparison digest"]
            )
            if record["Verification passed"] != expected_passed:
                raise ValueError(f"Verification outcome does not match digests on row {row_number}")
            expected_detected = expected_state == "modified" and not expected_passed
            if record["Tampering detected"] != expected_detected:
                raise ValueError(f"Tampering outcome does not match verification on row {row_number}")
            if scenario in (VALID_SCENARIO, TAMPERED_TRUSTED_SCENARIO) and not hmac.compare_digest(
                record["Comparison digest"], record["Trusted original digest"]
            ):
                raise ValueError(f"Trusted comparison digest mismatch on CSV row {row_number}")
            records.append(record)

    expected = {
        (algorithm, size, scenario, block)
        for algorithm in algorithms
        for size in input_sizes
        for scenario in SCENARIOS
        for block in range(1, block_count + 1)
    }
    observed = [
        (
            row["Algorithm"],
            row["Input size in bytes"],
            row["Scenario"],
            row["Block ID"],
        )
        for row in records
    ]
    if len(records) != len(expected) or set(observed) != expected:
        raise ValueError(
            "CSV must contain exactly one observation for every algorithm, size, "
            "scenario, and block"
        )
    if len(set(observed)) != len(observed):
        raise ValueError("Duplicate algorithm-size-scenario-block observation")

    conditions_per_block = len(algorithms) * len(input_sizes) * len(SCENARIOS)
    for block_id in range(1, block_count + 1):
        block_rows = [row for row in records if row["Block ID"] == block_id]
        positions = [row["Randomized position within block"] for row in block_rows]
        if sorted(positions) != list(range(1, conditions_per_block + 1)):
            raise ValueError(f"Block {block_id} lacks a complete randomized condition order")

    for block_id in range(1, block_count + 1):
        for size in input_sizes:
            matching = [
                row
                for row in records
                if row["Block ID"] == block_id and row["Input size in bytes"] == size
            ]
            for field in ("Original input identifier", "Modified input identifier"):
                if len({row[field] for row in matching}) != 1:
                    raise ValueError(f"Algorithms or scenarios do not share {field}")
            for algorithm in algorithms:
                scenario_rows = [
                    row
                    for row in matching
                    if row["Algorithm"] == algorithm
                ]
                if len({row["Trusted original digest"] for row in scenario_rows}) != 1:
                    raise ValueError("Trusted digest changed within a matched block and size")

    if len(records) != int(metadata.get("measured_observations", -1)):
        raise ValueError("Metadata measured-observation count does not match the raw CSV")
    return records, metadata, hashlib.sha256(raw_bytes).hexdigest()


def _descriptive_row(algorithm: str, size_bytes: int, scenario: str, rows: list[dict]) -> dict:
    times = [row["Execution time in seconds"] for row in rows]
    mean_time = statistics.mean(times)
    return {
        "Algorithm": algorithm,
        "Input size in bytes": size_bytes,
        "Scenario": scenario,
        "Observations": len(rows),
        "Mean time (seconds)": mean_time,
        "Median time (seconds)": statistics.median(times),
        "Standard deviation (seconds)": statistics.stdev(times),
        "Minimum time (seconds)": min(times),
        "Maximum time (seconds)": max(times),
        "Mean throughput (MiB/s)": (size_bytes / MIB_BYTES) / mean_time,
        "Verification passed count": sum(row["Verification passed"] for row in rows),
        "Tampering detected count": sum(row["Tampering detected"] for row in rows),
    }


def _paired_randomization_test(
    differences: np.ndarray,
    seed: int,
    permutation_count: int,
) -> tuple[float, float]:
    """Monte Carlo paired sign-flip test of a zero mean under randomized labels."""
    if permutation_count <= 0:
        raise ValueError("permutation_count must be positive")
    observed = float(np.mean(differences))
    rng = np.random.default_rng(seed)
    signs = rng.choice(np.asarray([-1.0, 1.0]), size=(permutation_count, len(differences)))
    permuted_means = np.mean(signs * differences[None, :], axis=1)
    exceedances = int(np.count_nonzero(np.abs(permuted_means) >= abs(observed)))
    return observed, (exceedances + 1) / (permutation_count + 1)


def _paired_difference_row(
    algorithm: str,
    size_bytes: int,
    comparison_name: str,
    comparison_scenario: str,
    baseline_scenario: str,
    records_by_condition: dict,
    analysis_seed: int,
    permutation_count: int,
) -> dict:
    block_ids = sorted(
        block_id
        for (name, size, scenario, block_id) in records_by_condition
        if name == algorithm and size == size_bytes and scenario == comparison_scenario
    )
    comparison_rows = [
        records_by_condition[(algorithm, size_bytes, comparison_scenario, block_id)]
        for block_id in block_ids
    ]
    baseline_rows = [
        records_by_condition[(algorithm, size_bytes, baseline_scenario, block_id)]
        for block_id in block_ids
    ]
    comparison_times = np.asarray(
        [row["Execution time in seconds"] for row in comparison_rows], dtype=float
    )
    baseline_times = np.asarray(
        [row["Execution time in seconds"] for row in baseline_rows], dtype=float
    )
    differences = comparison_times - baseline_times
    percentages = differences / baseline_times * 100.0
    seed = _analysis_seed(analysis_seed, algorithm, size_bytes, comparison_name)
    observed_mean, p_value = _paired_randomization_test(
        differences, seed, permutation_count
    )

    shapiro_result = stats.shapiro(differences)
    skewness = _finite_or_none(stats.skew(differences, bias=False))
    lag1 = (
        float(np.corrcoef(differences[:-1], differences[1:])[0, 1])
        if len(differences) > 2
        and np.std(differences[:-1]) > 0
        and np.std(differences[1:]) > 0
        else None
    )
    block_trend = stats.spearmanr(block_ids, differences)
    trend_rho = _finite_or_none(block_trend.statistic)
    trend_p = _finite_or_none(block_trend.pvalue)
    mean_baseline = float(np.mean(baseline_times))
    mean_comparison = float(np.mean(comparison_times))
    return {
        "Comparison": comparison_name,
        "Algorithm": algorithm,
        "Input size in bytes": size_bytes,
        "Comparison scenario": comparison_scenario,
        "Baseline scenario": baseline_scenario,
        "Paired blocks": len(block_ids),
        "Mean baseline time (seconds)": mean_baseline,
        "Mean comparison time (seconds)": mean_comparison,
        "Mean paired difference (seconds; comparison minus baseline)": observed_mean,
        "Median paired difference (seconds)": float(np.median(differences)),
        "Mean absolute paired difference (seconds)": float(np.mean(np.abs(differences))),
        "Mean percentage difference of means": (
            (mean_comparison - mean_baseline) / mean_baseline * 100.0
        ),
        "Mean paired percentage difference": float(np.mean(percentages)),
        "Median paired percentage difference": float(np.median(percentages)),
        "Mean absolute paired percentage difference": float(np.mean(np.abs(percentages))),
        "Paired difference Shapiro-Wilk statistic": float(shapiro_result.statistic),
        "Paired difference Shapiro-Wilk p-value": float(shapiro_result.pvalue),
        "Paired difference skewness": skewness,
        "Paired difference lag-1 correlation by block": _finite_or_none(lag1),
        "Paired difference block-trend Spearman rho": trend_rho,
        "Paired difference block-trend Spearman p-value": trend_p,
        "Statistical test": "Paired within-block sign-flip randomization test of mean difference",
        "Test statistic (absolute mean difference in seconds)": abs(observed_mean),
        "Permutation count": permutation_count,
        "Permutation seed": seed,
        "Raw p-value": p_value,
        "Holm adjusted p-value across all comparisons": None,
        "_raw_p_value": p_value,
    }


def _write_csv(path: Path, fields: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("x", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def analyze_tampering_performance(
    input_csv: str | Path,
    output_dir: str | Path,
    seed: int = 55,
    permutation_count: int = PERMUTATIONS,
    minimum_blocks: int = 30,
    metadata_path: str | Path | None = None,
) -> dict:
    """Analyze verification timings as matched within-block comparisons."""
    if not 0 < ALPHA < 1:
        raise ValueError("alpha must be between zero and one")
    if permutation_count <= 0:
        raise ValueError("permutation_count must be positive")
    records, metadata, source_hash = _load_observations(
        input_csv, metadata_path=metadata_path, minimum_blocks=minimum_blocks
    )
    input_sizes = tuple(int(size) for size in metadata["input_sizes_bytes"])
    block_count = int(metadata["block_count"])
    output_path = Path(output_dir)
    outputs = {
        "descriptive_csv": output_path / DESCRIPTIVE_NAME,
        "paired_tests_csv": output_path / PAIRED_NAME,
        "summary_json": output_path / SUMMARY_NAME,
    }
    collisions = [path for path in outputs.values() if path.exists()]
    if collisions:
        raise FileExistsError(f"Analysis output already exists: {collisions[0]}")
    output_path.mkdir(parents=True, exist_ok=True)

    descriptive_rows = []
    outcome_summary = {}
    for algorithm, _ in ALGORITHMS:
        outcome_summary[algorithm] = {}
        for size_bytes in input_sizes:
            for scenario in SCENARIOS:
                group = [
                    row
                    for row in records
                    if row["Algorithm"] == algorithm
                    and row["Input size in bytes"] == size_bytes
                    and row["Scenario"] == scenario
                ]
                descriptive_rows.append(
                    _descriptive_row(algorithm, size_bytes, scenario, group)
                )
                passed = sum(row["Verification passed"] for row in group)
                detected = sum(row["Tampering detected"] for row in group)
                outcome_summary[algorithm].setdefault(str(size_bytes), {})[scenario] = {
                    "observations": len(group),
                    "verification_passed": passed,
                    "verification_rejected": len(group) - passed,
                    "tampering_detected": detected,
                    "verification_pass_rate": passed / len(group),
                    "tampering_detection_rate": detected / len(group),
                }

    records_by_condition = {
        (
            row["Algorithm"],
            row["Input size in bytes"],
            row["Scenario"],
            row["Block ID"],
        ): row
        for row in records
    }
    paired_rows = []
    for algorithm, _ in ALGORITHMS:
        for size_bytes in input_sizes:
            for comparison_name, comparison_scenario, baseline_scenario in COMPARISONS:
                paired_rows.append(
                    _paired_difference_row(
                        algorithm,
                        size_bytes,
                        comparison_name,
                        comparison_scenario,
                        baseline_scenario,
                        records_by_condition,
                        seed,
                        permutation_count,
                    )
                )
    adjusted = _holm_adjust([row["_raw_p_value"] for row in paired_rows])
    for row, adjusted_p in zip(paired_rows, adjusted):
        row["Holm adjusted p-value across all comparisons"] = adjusted_p
        row.pop("_raw_p_value")

    summary = {
        "analysis": "Matched-block hashing tampering-verification performance",
        "source_csv": str(input_csv),
        "source_csv_sha256": source_hash,
        "metadata_source": str(metadata_path or Path(input_csv).with_name(METADATA_NAME)),
        "observation_count": len(records),
        "block_count": block_count,
        "input_sizes_bytes": list(input_sizes),
        "algorithms_analyzed_separately": [name for name, _ in ALGORITHMS],
        "scenarios": list(SCENARIOS),
        "timed_operation": metadata["timed_operation"],
        "tampering_outcomes_separate_from_performance": outcome_summary,
        "paired_analysis": {
            "method": "Monte Carlo paired sign-flip randomization test of mean within-block time differences",
            "null_hypothesis": "Under the randomized scenario order, the paired scenario labels have no effect on verification time.",
            "alternative_hypothesis": "The paired scenario labels affect mean verification time.",
            "alpha": ALPHA,
            "permutation_count_per_comparison": permutation_count,
            "analysis_seed": seed,
            "multiple_testing": "Holm correction across all algorithm-size-scenario comparisons.",
            "comparisons": paired_rows,
            "diagnostics": (
                "Paired-difference Shapiro-Wilk, skewness, lag-1 correlation, and block trend are reported. "
                "The randomization test does not assume normally distributed differences; it relies on "
                "within-block randomized scenario order and no consequential carry-over between conditions."
            ),
        },
        "practical_interpretation": (
            "Absolute time differences and percentage differences relative to matched baseline times are reported. "
            "No application-specific minimum practically meaningful time difference was supplied; statistical "
            "significance alone must not be treated as practical importance."
        ),
        "limitations": [
            "Each block uses one input and its one-byte modification; blocks are sequential measurements in one process, so temporal dependence and carry-over cannot be ruled out.",
            "The attacker-recomputed digest scenario demonstrates that an unkeyed digest supplied by an attacker does not authenticate modified data; its passing verification is not successful tampering detection.",
            "The timed operation includes the hash call and hmac.compare_digest only; input preparation, reference-digest generation, formatting, and file I/O are excluded.",
            "The paired sign-flip test relies on the randomized within-block condition order and a sharp no-effect randomization null; inter-block environmental drift may still limit inference.",
            "The data measure local Python hashlib and digest-comparison execution time, not network or storage costs.",
        ],
        "outlier_policy": "All validated raw observations are retained; none are automatically removed.",
        "runtime": {
            "python_version": sys.version,
            "numpy_version": np.__version__,
            "scipy_version": scipy.__version__,
        },
        "generated_files": {key: str(value) for key, value in outputs.items()},
    }

    _write_csv(outputs["descriptive_csv"], DESCRIPTIVE_FIELDS, descriptive_rows)
    _write_csv(outputs["paired_tests_csv"], PAIRED_FIELDS, paired_rows)
    with outputs["summary_json"].open("x", encoding="utf-8") as summary_file:
        json.dump(summary, summary_file, indent=2, allow_nan=False)
        summary_file.write("\n")
    return summary["generated_files"]
