"""Validation and statistical analyses for symmetric RQ1, RQ2, and RQ3."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import scipy
from scipy import stats

from symmetric.adversarial_runner import (
    AUTHENTICATION_TAMPERED,
    CIPHERTEXT_TAMPERED,
    MALFORMED,
    NONCE_IV_TAMPERED,
    RQ2_CSV_NAME,
    RQ2_FIELDS,
    RQ3_CSV_NAME,
    RQ3_FIELDS,
    SCENARIOS,
    VALID,
    WRONG_KEY,
)
from symmetric.experiment_runner import RAW_CSV_NAME as RQ1_CSV_NAME, RAW_FIELDS as RQ1_FIELDS
from symmetric.experiment_utils import INPUT_SIZES, MIB_BYTES, write_csv, write_json
from symmetric.repeated_measures import analyze_matrix
from symmetric.schemes import SCHEMES


ALPHA = 0.05
DEFAULT_PERMUTATIONS = 9_999
DEFAULT_ANALYSIS_SEED = 20261119
RQ1_DESCRIPTIVE = "symmetric_rq1_descriptive.csv"
RQ1_ANOVA = "symmetric_rq1_repeated_measures_anova.csv"
RQ1_FRIEDMAN = "symmetric_rq1_friedman.csv"
RQ1_SUMMARY = "symmetric_rq1_summary.json"
RQ1_PLOT = "symmetric_rq1_execution_time.png"
RQ2_CASES = "symmetric_rq2_case_validation.csv"
RQ2_SUMMARY_CSV = "symmetric_rq2_summary.csv"
RQ2_SUMMARY_JSON = "symmetric_rq2_summary.json"
RQ3_DESCRIPTIVE = "symmetric_rq3_descriptive.csv"
RQ3_TESTS = "symmetric_rq3_paired_tests.csv"
RQ3_DIAGNOSTICS = "symmetric_rq3_diagnostics.csv"
RQ3_PREDECESSORS = "symmetric_rq3_predecessor_diagnostics.csv"
RQ3_SUMMARY = "symmetric_rq3_summary.json"
RQ3_PLOT = "symmetric_rq3_execution_time.png"

RQ1_DESCRIPTIVE_FIELDS = (
    "Algorithm", "Operation", "Input size in bytes", "Input size", "n",
    "Mean seconds", "Median seconds", "Standard deviation seconds",
    "Minimum seconds", "Maximum seconds", "Throughput MiB/s",
)
RQ1_ANOVA_FIELDS = (
    "Algorithm", "Operation", "Test", "Blocks", "Input size levels",
    "Null hypothesis", "Alternative hypothesis", "F statistic",
    "Uncorrected numerator df", "Uncorrected denominator df",
    "Uncorrected p-value", "Sphericity correction used", "Primary numerator df",
    "Primary denominator df", "Primary p-value",
    "Holm adjusted primary p-value across six tests", "Partial eta squared",
    "Mauchly W", "Mauchly chi-square", "Mauchly df", "Mauchly p-value",
    "Greenhouse-Geisser epsilon", "GG corrected numerator df",
    "GG corrected denominator df", "GG corrected p-value",
    "Residual Shapiro-Wilk statistic", "Residual Shapiro-Wilk p-value",
    "Minimum difference-score Shapiro-Wilk p-value", "Difference-score Shapiro test count",
    "Position residual Spearman rho", "Position residual Spearman p-value",
    "Block residual Spearman rho", "Block residual Spearman p-value",
    "Maximum absolute within-size lag-1 correlation", "Interpretation",
)
RQ1_FRIEDMAN_FIELDS = (
    "Algorithm", "Operation", "Test", "Blocks", "Input size levels",
    "Chi-square statistic", "Degrees of freedom", "Raw p-value",
    "Holm adjusted p-value across six Friedman tests", "Kendall W", "Interpretation",
)
RQ2_SUMMARY_FIELDS = (
    "Algorithm", "Scenario", "Cases", "Expected accepted", "Observed accepted",
    "Observed rejected", "Plaintext released", "Cases matching expectation",
)
RQ3_DESCRIPTIVE_FIELDS = (
    "Algorithm", "Input size in bytes", "Scenario", "n", "Accepted count",
    "Plaintext released count", "Mean seconds", "Median seconds",
    "Standard deviation seconds", "Minimum seconds", "Maximum seconds",
)
RQ3_TEST_FIELDS = (
    "Algorithm", "Input size in bytes", "Invalid scenario", "Matched blocks",
    "Valid mean seconds", "Invalid mean seconds", "Mean paired difference seconds",
    "Median paired difference seconds", "Difference standard deviation seconds",
    "Mean matched percentage difference", "Median matched percentage difference",
    "Difference relative to valid mean percent", "Randomization test statistic absolute mean difference",
    "Monte Carlo raw p-value", "Holm adjusted p-value across 75 comparisons",
    "Number of sign permutations", "Analysis seed", "Null hypothesis",
    "Interpretation", "Inference qualification",
)
RQ3_DIAGNOSTIC_FIELDS = (
    "Algorithm", "Input size in bytes", "Invalid scenario", "Difference Shapiro-Wilk statistic",
    "Difference Shapiro-Wilk p-value", "Difference vs block Spearman rho",
    "Difference vs block Spearman p-value", "Lag-1 difference correlation",
    "Difference vs position-difference Spearman rho",
    "Difference vs position-difference Spearman p-value",
    "Blocks with valid position before invalid", "Block count",
)
RQ3_PREDECESSOR_FIELDS = (
    "Algorithm", "Input size in bytes", "Current scenario", "Previous algorithm",
    "Previous input size in bytes", "Previous scenario", "Observations", "Mean seconds", "Median seconds",
)


def holm_adjust(p_values: list[float]) -> list[float]:
    """Holm step-down p-value adjustment, preserving original order."""
    if any(not math.isfinite(p) or p < 0 or p > 1 for p in p_values):
        raise ValueError("p-values must be finite and within [0, 1]")
    order = sorted(range(len(p_values)), key=p_values.__getitem__)
    adjusted = [0.0] * len(order)
    running = 0.0
    for rank, index in enumerate(order):
        running = max(running, min(1.0, (len(order) - rank) * p_values[index]))
        adjusted[index] = running
    return adjusted


def _read_csv(path: str | Path, expected_fields: tuple[str, ...]) -> tuple[list[dict], str]:
    raw = Path(path).read_bytes()
    with Path(path).open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != expected_fields:
            raise ValueError(f"unexpected CSV schema in {path}")
        rows = list(reader)
    return rows, hashlib.sha256(raw).hexdigest()


def _read_metadata(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _prepare_analysis_dir(output_dir: str | Path, names: tuple[str, ...]) -> Path:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    existing = [name for name in names if (target / name).exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite analysis files: {', '.join(existing)}")
    return target


def _as_bool(value: str, field: str) -> bool:
    if value == "True":
        return True
    if value == "False":
        return False
    raise ValueError(f"{field} must be True or False, got {value!r}")


def _holm_rows(rows: list[dict], source: str, destination: str) -> None:
    values = [float(row[source]) for row in rows]
    for row, adjusted in zip(rows, holm_adjust(values)):
        row[destination] = adjusted


def _software_versions() -> dict:
    import cryptography
    import matplotlib as mpl

    return {
        "python": sys.version,
        "platform": platform.platform(),
        "numpy": np.__version__,
        "scipy": scipy.__version__,
        "matplotlib": mpl.__version__,
        "cryptography": cryptography.__version__,
    }


def _validate_rq1(rows: list[dict], metadata: dict) -> tuple[list[int], list[int], list[str], list[str]]:
    sizes = [int(value) for value in metadata["input_sizes_bytes"]]
    blocks = int(metadata["block_count"])
    algorithms = [scheme.name for scheme in SCHEMES]
    operations = ["encrypt", "decrypt"]
    expected = {
        (algorithm, operation, size, block)
        for algorithm in algorithms
        for operation in operations
        for size in sizes
        for block in range(1, blocks + 1)
    }
    seen = set()
    ids: dict[tuple[int, int], set[str]] = {}
    by_block: dict[int, list[dict]] = {}
    for row in rows:
        algorithm = row["Algorithm"]
        operation = row["Operation"]
        size = int(row["Input size in bytes"])
        block = int(row["Block ID"])
        position = int(row["Randomized position within block"])
        repetition = int(row["Repetition number"])
        elapsed = float(row["Execution time in seconds"])
        start = float(row["Measurement start monotonic seconds"])
        end = float(row["Measurement end monotonic seconds"])
        key = (algorithm, operation, size, block)
        if key not in expected or key in seen:
            raise ValueError(f"unexpected or duplicate RQ1 observation {key}")
        if elapsed <= 0 or not all(map(math.isfinite, (elapsed, start, end))):
            raise ValueError("RQ1 timings must be finite and positive")
        if not math.isclose(end - start, elapsed, rel_tol=1e-6, abs_tol=1e-12):
            raise ValueError(f"RQ1 timing boundaries do not match on {key}")
        if repetition != block:
            raise ValueError("RQ1 repetition number must match its block")
        if not _as_bool(row["Accepted"], "Accepted"):
            raise ValueError("RQ1 operation unexpectedly failed")
        if _as_bool(row["Plaintext released"], "Plaintext released") != (operation == "decrypt"):
            raise ValueError("RQ1 plaintext release flag does not match operation")
        seen.add(key)
        ids.setdefault((block, size), set()).add(row["Input identifier"])
        by_block.setdefault(block, []).append(row)
    if seen != expected:
        raise ValueError(f"RQ1 observations incomplete: expected {len(expected)}, got {len(seen)}")
    condition_count = len(algorithms) * len(operations) * len(sizes)
    for block, block_rows in by_block.items():
        positions = {int(row["Randomized position within block"]) for row in block_rows}
        if positions != set(range(1, condition_count + 1)):
            raise ValueError(f"RQ1 block {block} has missing or duplicate positions")
        ordered = sorted(block_rows, key=lambda row: int(row["Randomized position within block"]))
        for index, row in enumerate(ordered):
            previous = "" if index == 0 else "|".join(
                (ordered[index - 1]["Algorithm"], ordered[index - 1]["Input size in bytes"], ordered[index - 1]["Operation"])
            )
            if row["Previous condition ID"] != previous:
                raise ValueError(f"incorrect previous-condition chain in RQ1 block {block}")
    if any(len(value) != 1 for value in ids.values()):
        raise ValueError("RQ1 algorithms did not share one input buffer per block and size")
    return sizes, list(range(1, blocks + 1)), algorithms, operations


def analyze_rq1(
    input_csv: str | Path,
    metadata_path: str | Path,
    output_dir: str | Path,
    *,
    alpha: float = ALPHA,
) -> dict[str, Path]:
    """Analyze each scheme-operation separately with RM-ANOVA and Friedman."""
    if not 0 < alpha < 1:
        raise ValueError("alpha must lie between zero and one")
    rows, raw_sha256 = _read_csv(input_csv, RQ1_FIELDS)
    metadata = _read_metadata(metadata_path)
    sizes, blocks, algorithms, operations = _validate_rq1(rows, metadata)
    if len(rows) != len(algorithms) * len(operations) * len(sizes) * len(blocks):
        raise ValueError("wrong RQ1 observation count")
    target = _prepare_analysis_dir(
        output_dir,
        (RQ1_DESCRIPTIVE, RQ1_ANOVA, RQ1_FRIEDMAN, RQ1_SUMMARY, RQ1_PLOT, "analysis.log"),
    )

    lookup = {
        (row["Algorithm"], row["Operation"], int(row["Input size in bytes"]), int(row["Block ID"])): row
        for row in rows
    }
    descriptive = []
    for algorithm in algorithms:
        for operation in operations:
            for size in sizes:
                values = np.asarray([
                    float(lookup[(algorithm, operation, size, block)]["Execution time in seconds"])
                    for block in blocks
                ])
                mean = float(values.mean())
                descriptive.append({
                    "Algorithm": algorithm,
                    "Operation": operation,
                    "Input size in bytes": size,
                    "Input size": _format_size(size),
                    "n": len(values),
                    "Mean seconds": mean,
                    "Median seconds": float(np.median(values)),
                    "Standard deviation seconds": float(values.std(ddof=1)),
                    "Minimum seconds": float(values.min()),
                    "Maximum seconds": float(values.max()),
                    "Throughput MiB/s": size / MIB_BYTES / mean,
                })
    write_csv(target / RQ1_DESCRIPTIVE, RQ1_DESCRIPTIVE_FIELDS, descriptive)

    anova_rows = []
    friedman_rows = []
    diag_by_group = {}
    for algorithm in algorithms:
        for operation in operations:
            matrix = np.asarray([
                [float(lookup[(algorithm, operation, size, block)]["Execution time in seconds"]) for size in sizes]
                for block in blocks
            ])
            result = analyze_matrix(matrix, alpha)
            group_rows = [
                lookup[(algorithm, operation, size, block)]
                for block in blocks
                for size in sizes
            ]
            log_residuals = np.asarray([
                math.log(float(row["Execution time in seconds"]))
                - float(np.mean([math.log(float(lookup[(algorithm, operation, int(row["Input size in bytes"]), b)]["Execution time in seconds"])) for b in blocks]))
                for row in group_rows
            ])
            positions = np.asarray([int(row["Randomized position within block"]) for row in group_rows])
            block_ids = np.asarray([int(row["Block ID"]) for row in group_rows])
            position_corr = _spearman(positions, log_residuals)
            block_corr = _spearman(block_ids, log_residuals)
            lag_values = []
            for size in sizes:
                series = np.asarray([
                    math.log(float(lookup[(algorithm, operation, size, block)]["Execution time in seconds"]))
                    for block in blocks
                ])
                residual = series - series.mean()
                if len(residual) > 2 and np.ptp(residual[:-1]) and np.ptp(residual[1:]):
                    lag_values.append(float(np.corrcoef(residual[:-1], residual[1:])[0, 1]))
            diagnostics = {
                "position_residual_spearman_rho": position_corr[0],
                "position_residual_spearman_p_value": position_corr[1],
                "block_residual_spearman_rho": block_corr[0],
                "block_residual_spearman_p_value": block_corr[1],
                "maximum_absolute_within_size_lag1_correlation": max(map(abs, lag_values), default=None),
            }
            diag_by_group[(algorithm, operation)] = diagnostics
            p = result["primary_p_value"]
            significant = p < alpha
            anova_rows.append({
                "Algorithm": algorithm,
                "Operation": operation,
                "Test": "One-factor repeated-measures ANOVA",
                "Blocks": len(blocks),
                "Input size levels": len(sizes),
                "Null hypothesis": "Mean execution time is equal across the five input sizes.",
                "Alternative hypothesis": "At least one input-size mean differs.",
                "F statistic": result["f_statistic"],
                "Uncorrected numerator df": result["uncorrected_df_numerator"],
                "Uncorrected denominator df": result["uncorrected_df_denominator"],
                "Uncorrected p-value": result["uncorrected_p_value"],
                "Sphericity correction used": result["correction_used"],
                "Primary numerator df": result["primary_df_numerator"],
                "Primary denominator df": result["primary_df_denominator"],
                "Primary p-value": p,
                "Holm adjusted primary p-value across six tests": None,
                "Partial eta squared": result["partial_eta_squared"],
                "Mauchly W": result["mauchly_w"],
                "Mauchly chi-square": result["mauchly_chi_square"],
                "Mauchly df": result["mauchly_df"],
                "Mauchly p-value": result["mauchly_p_value"],
                "Greenhouse-Geisser epsilon": result["greenhouse_geisser_epsilon"],
                "GG corrected numerator df": result["greenhouse_geisser_df_numerator"],
                "GG corrected denominator df": result["greenhouse_geisser_df_denominator"],
                "GG corrected p-value": result["greenhouse_geisser_p_value"],
                "Residual Shapiro-Wilk statistic": result["residual_shapiro_statistic"],
                "Residual Shapiro-Wilk p-value": result["residual_shapiro_p_value"],
                "Minimum difference-score Shapiro-Wilk p-value": result["difference_score_shapiro_min_p_value"],
                "Difference-score Shapiro test count": result["difference_score_shapiro_test_count"],
                "Position residual Spearman rho": diagnostics["position_residual_spearman_rho"],
                "Position residual Spearman p-value": diagnostics["position_residual_spearman_p_value"],
                "Block residual Spearman rho": diagnostics["block_residual_spearman_rho"],
                "Block residual Spearman p-value": diagnostics["block_residual_spearman_p_value"],
                "Maximum absolute within-size lag-1 correlation": diagnostics["maximum_absolute_within_size_lag1_correlation"],
                "Interpretation": "At least one mean differs" if significant else "No omnibus mean difference detected; this is not evidence of equivalence",
            })
            friedman = stats.friedmanchisquare(*matrix.T)
            n, k = matrix.shape
            rank_w = float(friedman.statistic / (n * (k - 1)))
            friedman_rows.append({
                "Algorithm": algorithm,
                "Operation": operation,
                "Test": "Friedman repeated-block rank test (supplementary)",
                "Blocks": n,
                "Input size levels": k,
                "Chi-square statistic": float(friedman.statistic),
                "Degrees of freedom": k - 1,
                "Raw p-value": float(friedman.pvalue),
                "Holm adjusted p-value across six Friedman tests": None,
                "Kendall W": rank_w,
                "Interpretation": "At least one input-size rank distribution differs" if friedman.pvalue < alpha else "No rank difference detected; this is not evidence of equivalence",
            })

    _holm_rows(anova_rows, "Primary p-value", "Holm adjusted primary p-value across six tests")
    _holm_rows(friedman_rows, "Raw p-value", "Holm adjusted p-value across six Friedman tests")
    for row in anova_rows:
        row["Interpretation"] = (
            "At least one mean differs after Holm adjustment"
            if row["Holm adjusted primary p-value across six tests"] < alpha
            else "No omnibus mean difference detected after Holm adjustment; not evidence of equivalence"
        )
    for row in friedman_rows:
        row["Interpretation"] = (
            "At least one repeated-block rank distribution differs after Holm adjustment"
            if row["Holm adjusted p-value across six Friedman tests"] < alpha
            else "No rank difference detected after Holm adjustment; not evidence of equivalence"
        )
    write_csv(target / RQ1_ANOVA, RQ1_ANOVA_FIELDS, anova_rows)
    write_csv(target / RQ1_FRIEDMAN, RQ1_FRIEDMAN_FIELDS, friedman_rows)
    _plot_rq1(descriptive, target / RQ1_PLOT, sizes)

    summary = {
        "research_question": "How does input data size affect the execution time of selected cryptographic algorithms?",
        "raw_csv": str(Path(input_csv)),
        "raw_csv_sha256": raw_sha256,
        "metadata_file": str(Path(metadata_path)),
        "alpha": alpha,
        "primary_method": "Conventional one-factor repeated-measures ANOVA; blocks are subjects and input size is the five-level within-subject factor.",
        "holm_family": "Six Greenhouse-Geisser/uncorrected primary ANOVA p-values, one per algorithm-operation combination.",
        "supplementary_method": "Friedman repeated-block rank test, separately per algorithm-operation; Holm across its six tests. It tests within-block ranks, not arithmetic means.",
        "limitations": [
            "Repeated-measures ANOVA assumes independent blocks, approximately normal model residuals, and sphericity unless corrected.",
            "Greenhouse-Geisser corrects the F reference degrees of freedom for sphericity, not nonnormality or temporal dependence.",
            "The blocks are sequential measurements on one machine; position randomization does not guarantee block independence or absence of carry-over.",
            "The same deterministic pseudo-random payload is reused across the three algorithms within each block and size; results generalize to these payloads and this environment only.",
            "No observations are removed and omnibus tests do not identify which input-size pairs differ.",
        ],
        "anova_results": anova_rows,
        "friedman_results": friedman_rows,
        "analysis_software": _software_versions(),
        "created_utc": datetime.now(timezone.utc).isoformat(),
    }
    write_json(target / RQ1_SUMMARY, _json_safe(summary))
    (target / "analysis.log").write_text(
        f"Analyzed {len(rows)} RQ1 observations; raw SHA-256 {raw_sha256}\n", encoding="utf-8"
    )
    return {
        "descriptive": target / RQ1_DESCRIPTIVE,
        "anova": target / RQ1_ANOVA,
        "friedman": target / RQ1_FRIEDMAN,
        "summary": target / RQ1_SUMMARY,
        "plot": target / RQ1_PLOT,
    }


def _validate_rq2(rows: list[dict], metadata: dict) -> tuple[list[int], list[str]]:
    sizes = [int(value) for value in metadata["input_sizes_bytes"]]
    algorithms = [scheme.name for scheme in SCHEMES]
    expected = {(a, size, scenario) for a in algorithms for size in sizes for scenario in SCENARIOS}
    seen = set()
    for row in rows:
        key = (row["Algorithm"], int(row["Input size in bytes"]), row["Scenario"])
        if key not in expected or key in seen:
            raise ValueError(f"unexpected or duplicate RQ2 functional case {key}")
        seen.add(key)
        actual = _as_bool(row["Accepted"], "Accepted")
        released = _as_bool(row["Plaintext released"], "Plaintext released")
        authenticated = _as_bool(row["Authentication succeeded"], "Authentication succeeded")
        matches = _as_bool(row["Outcome matched expectation"], "Outcome matched expectation")
        expected_accept = row["Scenario"] == VALID
        if _as_bool(row["Expected accepted"], "Expected accepted") != expected_accept:
            raise ValueError(f"RQ2 expected-outcome field is inconsistent for {key}")
        if actual != expected_accept or released != expected_accept or authenticated != expected_accept or not matches:
            raise ValueError(f"RQ2 invalid outcome or plaintext release for {key}")
        if row["Failure stage"] != row["Expected failure stage"]:
            raise ValueError(f"RQ2 failure stage mismatch for {key}")
    if seen != expected:
        raise ValueError(f"RQ2 cases incomplete: expected {len(expected)}, got {len(seen)}")
    return sizes, algorithms


def analyze_rq2(
    input_csv: str | Path,
    metadata_path: str | Path,
    output_dir: str | Path,
) -> dict[str, Path]:
    rows, raw_sha256 = _read_csv(input_csv, RQ2_FIELDS)
    metadata = _read_metadata(metadata_path)
    sizes, algorithms = _validate_rq2(rows, metadata)
    target = _prepare_analysis_dir(output_dir, (RQ2_CASES, RQ2_SUMMARY_CSV, RQ2_SUMMARY_JSON, "analysis.log"))
    write_csv(target / RQ2_CASES, RQ2_FIELDS, rows)
    summary_rows = []
    for algorithm in algorithms:
        for scenario in SCENARIOS:
            group = [row for row in rows if row["Algorithm"] == algorithm and row["Scenario"] == scenario]
            summary_rows.append({
                "Algorithm": algorithm,
                "Scenario": scenario,
                "Cases": len(group),
                "Expected accepted": sum(_as_bool(row["Expected accepted"], "Expected accepted") for row in group),
                "Observed accepted": sum(_as_bool(row["Accepted"], "Accepted") for row in group),
                "Observed rejected": sum(not _as_bool(row["Accepted"], "Accepted") for row in group),
                "Plaintext released": sum(_as_bool(row["Plaintext released"], "Plaintext released") for row in group),
                "Cases matching expectation": sum(_as_bool(row["Outcome matched expectation"], "Outcome matched expectation") for row in group),
            })
    write_csv(target / RQ2_SUMMARY_CSV, RQ2_SUMMARY_FIELDS, summary_rows)
    summary = {
        "research_question": "How do selected cryptographic schemes respond to tampered data and invalid ciphertext?",
        "raw_csv": str(Path(input_csv)),
        "raw_csv_sha256": raw_sha256,
        "case_count": len(rows),
        "all_cases_match_expectation": all(_as_bool(row["Outcome matched expectation"], "Outcome matched expectation") for row in rows),
        "invalid_cases_releasing_plaintext": sum(
            _as_bool(row["Plaintext released"], "Plaintext released")
            for row in rows if row["Scenario"] != VALID
        ),
        "scenario_summary": summary_rows,
        "interpretation": "These are controlled functional examples, not attack probabilities or security proofs. AEAD rejects modified nonce/ciphertext/tag at authentication. CBC-HMAC authenticates IV and ciphertext before decryption; malformed envelope fields fail validation. All public invalid-message errors are normalized.",
        "limitations": ["Only the listed mutations, keys, payloads, software, and environment were tested."],
        "analysis_software": _software_versions(),
    }
    write_json(target / RQ2_SUMMARY_JSON, summary)
    (target / "analysis.log").write_text(
        f"Validated {len(rows)} RQ2 functional cases; raw SHA-256 {raw_sha256}\n", encoding="utf-8"
    )
    return {"cases": target / RQ2_CASES, "summary_csv": target / RQ2_SUMMARY_CSV, "summary": target / RQ2_SUMMARY_JSON}


def _validate_rq3(rows: list[dict], metadata: dict) -> tuple[list[int], list[int], list[str]]:
    sizes = [int(value) for value in metadata["input_sizes_bytes"]]
    blocks = int(metadata["block_count"])
    algorithms = [scheme.name for scheme in SCHEMES]
    expected = {
        (algorithm, size, scenario, block)
        for algorithm in algorithms
        for size in sizes
        for scenario in SCENARIOS
        for block in range(1, blocks + 1)
    }
    seen = set()
    by_block: dict[int, list[dict]] = {}
    ids: dict[tuple[int, int], set[str]] = {}
    for row in rows:
        algorithm, size, scenario, block = row["Algorithm"], int(row["Input size in bytes"]), row["Scenario"], int(row["Block ID"])
        key = (algorithm, size, scenario, block)
        if key not in expected or key in seen:
            raise ValueError(f"unexpected or duplicate RQ3 observation {key}")
        elapsed = float(row["Total attempted decryption time in seconds"])
        start = float(row["Measurement start monotonic seconds"])
        end = float(row["Measurement end monotonic seconds"])
        if elapsed <= 0 or not all(map(math.isfinite, (elapsed, start, end))):
            raise ValueError("RQ3 timings must be finite and positive")
        if not math.isclose(end - start, elapsed, rel_tol=1e-6, abs_tol=1e-12):
            raise ValueError(f"RQ3 timing boundaries do not match for {key}")
        if int(row["Repetition number"]) != block:
            raise ValueError("RQ3 repetition number must match the block ID")
        accepted = _as_bool(row["Accepted"], "Accepted")
        authenticated = _as_bool(row["Authentication succeeded"], "Authentication succeeded")
        released = _as_bool(row["Plaintext released"], "Plaintext released")
        valid = scenario == VALID
        if accepted != valid or authenticated != valid or released != valid:
            raise ValueError(f"RQ3 acceptance/plaintext outcome invalid for {key}")
        expected_failure = "" if valid else ("envelope_validation" if scenario == MALFORMED else "authentication")
        if row["Failure category"] != expected_failure:
            raise ValueError(f"wrong RQ3 failure category for {key}")
        seen.add(key)
        by_block.setdefault(block, []).append(row)
        ids.setdefault((block, size), set()).add(row["Input identifier"])
    if seen != expected:
        raise ValueError(f"RQ3 observations incomplete: expected {len(expected)}, got {len(seen)}")
    per_block = len(algorithms) * len(sizes) * len(SCENARIOS)
    for block, block_rows in by_block.items():
        positions = {int(row["Randomized position within block"]) for row in block_rows}
        if positions != set(range(1, per_block + 1)):
            raise ValueError(f"RQ3 block {block} has missing or duplicate positions")
        ordered = sorted(block_rows, key=lambda row: int(row["Randomized position within block"]))
        for index, row in enumerate(ordered):
            if index == 0:
                expected_previous = ""
            else:
                prior = ordered[index - 1]
                expected_previous = "|".join((prior["Algorithm"], prior["Input size in bytes"], prior["Scenario"]))
            if row["Previous condition ID"] != expected_previous:
                raise ValueError(f"bad previous-condition chain in RQ3 block {block}")
            expected_previous_fields = ("", "", "") if index == 0 else (
                ordered[index - 1]["Algorithm"],
                ordered[index - 1]["Input size in bytes"],
                ordered[index - 1]["Scenario"],
            )
            actual_previous_fields = (
                row["Previous algorithm"],
                row["Previous input size in bytes"],
                row["Previous scenario"],
            )
            if actual_previous_fields != expected_previous_fields:
                raise ValueError(f"bad previous-condition fields in RQ3 block {block}")
    if any(len(value) != 1 for value in ids.values()):
        raise ValueError("RQ3 algorithms did not share one payload per block and size")
    return sizes, list(range(1, blocks + 1)), algorithms


def _sign_flip_p(differences: np.ndarray, permutations: int, rng: np.random.Generator) -> float:
    signs = rng.choice(np.asarray([-1.0, 1.0]), size=(permutations, len(differences)))
    observed = abs(float(differences.mean()))
    simulated = np.abs((signs * differences).mean(axis=1))
    return float((1 + np.count_nonzero(simulated >= observed - 1e-15)) / (permutations + 1))


def analyze_rq3(
    input_csv: str | Path,
    metadata_path: str | Path,
    output_dir: str | Path,
    *,
    permutations: int = DEFAULT_PERMUTATIONS,
    seed: int = DEFAULT_ANALYSIS_SEED,
) -> dict[str, Path]:
    """Run paired conditional label-swap tests; results are exploratory."""
    if permutations <= 0:
        raise ValueError("permutations must be positive")
    rows, raw_sha256 = _read_csv(input_csv, RQ3_FIELDS)
    metadata = _read_metadata(metadata_path)
    sizes, blocks, algorithms = _validate_rq3(rows, metadata)
    target = _prepare_analysis_dir(
        output_dir,
        (RQ3_DESCRIPTIVE, RQ3_TESTS, RQ3_DIAGNOSTICS, RQ3_PREDECESSORS, RQ3_SUMMARY, RQ3_PLOT, "analysis.log"),
    )
    lookup = {
        (row["Algorithm"], int(row["Input size in bytes"]), row["Scenario"], int(row["Block ID"])): row
        for row in rows
    }

    descriptive = []
    for algorithm in algorithms:
        for size in sizes:
            for scenario in SCENARIOS:
                group = [lookup[(algorithm, size, scenario, block)] for block in blocks]
                values = np.asarray([float(row["Total attempted decryption time in seconds"]) for row in group])
                descriptive.append({
                    "Algorithm": algorithm,
                    "Input size in bytes": size,
                    "Scenario": scenario,
                    "n": len(values),
                    "Accepted count": sum(_as_bool(row["Accepted"], "Accepted") for row in group),
                    "Plaintext released count": sum(_as_bool(row["Plaintext released"], "Plaintext released") for row in group),
                    "Mean seconds": float(values.mean()),
                    "Median seconds": float(np.median(values)),
                    "Standard deviation seconds": float(values.std(ddof=1)),
                    "Minimum seconds": float(values.min()),
                    "Maximum seconds": float(values.max()),
                })
    write_csv(target / RQ3_DESCRIPTIVE, RQ3_DESCRIPTIVE_FIELDS, descriptive)

    rng = np.random.default_rng(seed)
    test_rows = []
    diagnostic_rows = []
    for algorithm in algorithms:
        for size in sizes:
            valid_rows = [lookup[(algorithm, size, VALID, block)] for block in blocks]
            valid_values = np.asarray([float(row["Total attempted decryption time in seconds"]) for row in valid_rows])
            for scenario in SCENARIOS:
                if scenario == VALID:
                    continue
                invalid_rows = [lookup[(algorithm, size, scenario, block)] for block in blocks]
                invalid_values = np.asarray([float(row["Total attempted decryption time in seconds"]) for row in invalid_rows])
                differences = invalid_values - valid_values
                matched_percentages = differences / valid_values * 100.0
                p_value = _sign_flip_p(differences, permutations, rng)
                test_rows.append({
                    "Algorithm": algorithm,
                    "Input size in bytes": size,
                    "Invalid scenario": scenario,
                    "Matched blocks": len(blocks),
                    "Valid mean seconds": float(valid_values.mean()),
                    "Invalid mean seconds": float(invalid_values.mean()),
                    "Mean paired difference seconds": float(differences.mean()),
                    "Median paired difference seconds": float(np.median(differences)),
                    "Difference standard deviation seconds": float(differences.std(ddof=1)),
                    "Mean matched percentage difference": float(matched_percentages.mean()),
                    "Median matched percentage difference": float(np.median(matched_percentages)),
                    "Difference relative to valid mean percent": float(100 * differences.mean() / valid_values.mean()),
                    "Randomization test statistic absolute mean difference": abs(float(differences.mean())),
                    "Monte Carlo raw p-value": p_value,
                    "Holm adjusted p-value across 75 comparisons": None,
                    "Number of sign permutations": permutations,
                    "Analysis seed": seed,
                    "Null hypothesis": "Sharp null: swapping valid and this invalid condition between the two assigned within-block positions changes no decryption time for any block.",
                    "Interpretation": "Difference detected" if p_value < ALPHA else "No difference detected; not evidence of equivalence",
                    "Inference qualification": "Conditional/exploratory; relies on randomized schedule approximation and no consequential carry-over/interference.",
                })
                block_array = np.asarray(blocks, dtype=float)
                block_test = _spearman(block_array, differences)
                delta_position = np.asarray([
                    int(invalid_rows[index]["Randomized position within block"])
                    - int(valid_rows[index]["Randomized position within block"])
                    for index in range(len(blocks))
                ], dtype=float)
                position_test = _spearman(delta_position, differences)
                shapiro = stats.shapiro(differences) if np.ptp(differences) else None
                lag = _lag1(differences)
                diagnostic_rows.append({
                    "Algorithm": algorithm,
                    "Input size in bytes": size,
                    "Invalid scenario": scenario,
                    "Difference Shapiro-Wilk statistic": float(shapiro.statistic) if shapiro else None,
                    "Difference Shapiro-Wilk p-value": float(shapiro.pvalue) if shapiro else None,
                    "Difference vs block Spearman rho": block_test[0],
                    "Difference vs block Spearman p-value": block_test[1],
                    "Lag-1 difference correlation": lag,
                    "Difference vs position-difference Spearman rho": position_test[0],
                    "Difference vs position-difference Spearman p-value": position_test[1],
                    "Blocks with valid position before invalid": sum(delta < 0 for delta in delta_position),
                    "Block count": len(blocks),
                })
    if len(test_rows) != 75:
        raise ValueError(f"expected a Holm family of 75 comparisons, got {len(test_rows)}")
    _holm_rows(test_rows, "Monte Carlo raw p-value", "Holm adjusted p-value across 75 comparisons")
    for row in test_rows:
        row["Interpretation"] = (
            "Paired timing difference detected after Holm adjustment"
            if row["Holm adjusted p-value across 75 comparisons"] < ALPHA
            else "No adjusted difference detected; this is not evidence of equivalence"
        )
    write_csv(target / RQ3_TESTS, RQ3_TEST_FIELDS, test_rows)
    write_csv(target / RQ3_DIAGNOSTICS, RQ3_DIAGNOSTIC_FIELDS, diagnostic_rows)

    predecessor_groups: dict[tuple[str, int, str, str, str, str], list[float]] = {}
    for row in rows:
        previous_algorithm = row["Previous algorithm"] or "first_in_block"
        previous_size = row["Previous input size in bytes"] or ""
        previous_scenario = row["Previous scenario"] or "first_in_block"
        group_key = (
            row["Algorithm"], int(row["Input size in bytes"]), row["Scenario"],
            previous_algorithm, previous_size, previous_scenario,
        )
        predecessor_groups.setdefault(group_key, []).append(float(row["Total attempted decryption time in seconds"]))
    predecessor_rows = [
        {
            "Algorithm": key[0], "Input size in bytes": key[1], "Current scenario": key[2],
            "Previous algorithm": key[3], "Previous input size in bytes": key[4],
            "Previous scenario": key[5], "Observations": len(values),
            "Mean seconds": float(np.mean(values)), "Median seconds": float(np.median(values)),
        }
        for key, values in sorted(predecessor_groups.items())
    ]
    write_csv(target / RQ3_PREDECESSORS, RQ3_PREDECESSOR_FIELDS, predecessor_rows)
    _plot_rq3(descriptive, target / RQ3_PLOT, sizes)

    summary = {
        "research_question": "How do integrity verification and rejection of invalid inputs affect the processing time of selected cryptographic schemes under adversarial conditions?",
        "raw_csv": str(Path(input_csv)),
        "raw_csv_sha256": raw_sha256,
        "measurement_scope": "Complete decryption attempt including envelope validation, authentication, decrypt, and CBC unpadding. This does not isolate authentication overhead or include attacker-side mutation/key-generation costs.",
        "paired_comparisons": len(test_rows),
        "holm_family": "All 75 invalid-versus-valid contrasts (3 algorithms × 5 sizes × 5 invalid scenarios).",
        "test": "Monte Carlo conditional within-block label-swap/sign-flip randomization test on the mean paired time difference; two-sided; plus-one p-value correction.",
        "null_hypothesis": "For each contrast, the sharp null states that swapping the two scenario labels across their randomized positions would not change any block's measured decryption time.",
        "randomization_assumptions": [
            "Within each complete block, the condition-order PRNG shuffle approximates a uniform random permutation; pair-label swaps are considered conditionally exchangeable under the sharp null.",
            "No consequential carry-over or interference between adjacent decryption conditions.",
            "Blocks provide independent assignment draws; sequential blocks on one machine may be temporally dependent.",
        ],
        "diagnostic_summary": {
            "comparison_count": len(diagnostic_rows),
            "shapiro_rejections_nominal": sum(row["Difference Shapiro-Wilk p-value"] is not None and row["Difference Shapiro-Wilk p-value"] < ALPHA for row in diagnostic_rows),
            "block_trend_nominal_rejections": sum(row["Difference vs block Spearman p-value"] is not None and row["Difference vs block Spearman p-value"] < ALPHA for row in diagnostic_rows),
            "position_delta_nominal_rejections": sum(row["Difference vs position-difference Spearman p-value"] is not None and row["Difference vs position-difference Spearman p-value"] < ALPHA for row in diagnostic_rows),
            "maximum_absolute_lag1_correlation": max((abs(row["Lag-1 difference correlation"]) for row in diagnostic_rows if row["Lag-1 difference correlation"] is not None), default=None),
            "interpretation": "These are exploratory diagnostics and cannot prove independence or rule out carry-over. Shapiro-Wilk is descriptive and does not determine validity of the design-based label-swap test.",
        },
        "results": test_rows,
        "predecessor_diagnostics_file": RQ3_PREDECESSORS,
        "limitations": [
            "Non-significant tests do not establish equivalence; no application-specific equivalence margin was specified.",
            "Holm-adjusted differences concern complete decryption attempts, not isolated authentication cost.",
            "Timing is machine-, library-, workload-, and system-state-specific; one machine and sequential blocks limit generalization.",
            "A nominal position/predecessor association cannot prove or fully model carry-over.",
            "No observations or outliers are removed.",
        ],
        "analysis_parameters": {"alpha": ALPHA, "permutations": permutations, "seed": seed, "software": _software_versions()},
    }
    write_json(target / RQ3_SUMMARY, _json_safe(summary))
    (target / "analysis.log").write_text(
        f"Analyzed {len(rows)} RQ3 observations and {len(test_rows)} paired contrasts; raw SHA-256 {raw_sha256}\n",
        encoding="utf-8",
    )
    return {
        "descriptive": target / RQ3_DESCRIPTIVE,
        "paired_tests": target / RQ3_TESTS,
        "diagnostics": target / RQ3_DIAGNOSTICS,
        "predecessors": target / RQ3_PREDECESSORS,
        "summary": target / RQ3_SUMMARY,
        "plot": target / RQ3_PLOT,
    }


def _format_size(size: int) -> str:
    if size % MIB_BYTES == 0:
        return f"{size // MIB_BYTES} MiB"
    if size % 1024 == 0:
        return f"{size // 1024} KiB"
    return f"{size} bytes"


def _spearman(x: np.ndarray, y: np.ndarray) -> tuple[float | None, float | None]:
    if len(x) < 3 or np.ptp(x) == 0 or np.ptp(y) == 0:
        return None, None
    result = stats.spearmanr(x, y)
    return float(result.statistic), float(result.pvalue)


def _lag1(values: np.ndarray) -> float | None:
    if len(values) < 4 or np.ptp(values[:-1]) == 0 or np.ptp(values[1:]) == 0:
        return None
    return float(np.corrcoef(values[:-1], values[1:])[0, 1])


def _json_safe(value):
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value) if np.isfinite(value) else None
    if isinstance(value, np.bool_):
        return bool(value)
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def _plot_rq1(rows: list[dict], path: Path, sizes: list[int]) -> None:
    figure, axes = plt.subplots(1, 2, figsize=(13, 5), sharey=False)
    for axis, operation in zip(axes, ("encrypt", "decrypt")):
        for scheme in SCHEMES:
            group = [row for row in rows if row["Algorithm"] == scheme.name and row["Operation"] == operation]
            group.sort(key=lambda row: int(row["Input size in bytes"]))
            axis.plot(
                [int(row["Input size in bytes"]) for row in group],
                [float(row["Mean seconds"]) for row in group],
                marker="o", label=scheme.name,
            )
        axis.set_xscale("log", base=2)
        axis.set_yscale("log")
        axis.set_xticks(sizes, [_format_size(size) for size in sizes], rotation=30)
        axis.set_title(f"{operation.title()} mean time")
        axis.set_xlabel("Payload size")
        axis.set_ylabel("Time (seconds; log scale)")
        axis.grid(True, which="both", alpha=0.25)
        axis.legend(fontsize=8)
    figure.tight_layout()
    figure.savefig(path, dpi=160)
    plt.close(figure)


def _plot_rq3(rows: list[dict], path: Path, sizes: list[int]) -> None:
    figure, axes = plt.subplots(1, 3, figsize=(17, 5), sharey=False)
    for axis, scheme in zip(axes, SCHEMES):
        for scenario in SCENARIOS:
            group = [row for row in rows if row["Algorithm"] == scheme.name and row["Scenario"] == scenario]
            group.sort(key=lambda row: int(row["Input size in bytes"]))
            axis.plot(
                [int(row["Input size in bytes"]) for row in group],
                [float(row["Mean seconds"]) for row in group],
                marker="o", label=scenario,
            )
        axis.set_xscale("log", base=2)
        axis.set_yscale("log")
        axis.set_xticks(sizes, [_format_size(size) for size in sizes], rotation=35)
        axis.set_title(scheme.name)
        axis.set_xlabel("Payload size")
        axis.grid(True, which="both", alpha=0.25)
    axes[0].set_ylabel("Mean complete decryption time (seconds; log scale)")
    handles, labels = axes[0].get_legend_handles_labels()
    figure.legend(
        handles,
        labels,
        loc="upper center",
        bbox_to_anchor=(0.5, 0.99),
        ncol=3,
        fontsize=7,
    )
    figure.tight_layout(rect=(0, 0, 1, 0.86))
    figure.savefig(path, dpi=160)
    plt.close(figure)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="research_question", required=True)
    for rq in ("rq1", "rq2", "rq3"):
        sub = subparsers.add_parser(rq)
        sub.add_argument("--input-csv", type=Path, required=True)
        sub.add_argument("--metadata", type=Path, required=True)
        sub.add_argument("--output-dir", type=Path, required=True)
        if rq == "rq1":
            sub.add_argument("--alpha", type=float, default=ALPHA)
        if rq == "rq3":
            sub.add_argument("--permutations", type=int, default=DEFAULT_PERMUTATIONS)
            sub.add_argument("--seed", type=int, default=DEFAULT_ANALYSIS_SEED)
    args = parser.parse_args()
    if args.research_question == "rq1":
        outputs = analyze_rq1(args.input_csv, args.metadata, args.output_dir, alpha=args.alpha)
    elif args.research_question == "rq2":
        outputs = analyze_rq2(args.input_csv, args.metadata, args.output_dir)
    else:
        outputs = analyze_rq3(
            args.input_csv, args.metadata, args.output_dir,
            permutations=args.permutations, seed=args.seed,
        )
    for label, path in outputs.items():
        print(f"{label}: {path}")


if __name__ == "__main__":
    main()
