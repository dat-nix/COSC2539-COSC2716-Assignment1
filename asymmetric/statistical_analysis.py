"""Block-aware analyses for RQ1, RQ2, and RQ3 hybrid-encryption data."""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import platform
import sys
from bisect import bisect_left, bisect_right
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import scipy
import statsmodels
import statsmodels.formula.api as smf
import cryptography
from scipy import stats

from asymmetric.adversarial_runner import (
    CIPHERTEXT_TAMPERED,
    KEY_TAMPERED,
    MALFORMED,
    OUTCOME_FIELDS,
    RQ2_CSV_NAME,
    RQ2_METADATA_NAME,
    RQ3_CSV_NAME,
    RQ3_FIELDS,
    RQ3_METADATA_NAME,
    TAG_TAMPERED,
    VALID,
    rq3_conditions,
)
from asymmetric.experiment_runner import RAW_FIELDS as RQ1_FIELDS
from asymmetric.experiment_utils import INPUT_SIZES, write_csv, write_json
from asymmetric.repeated_measures import (
    build_repeated_measures_matrix,
    repeated_measures_anova,
)
from asymmetric.schemes import SCHEMES


ALPHA = 0.05
ANALYSIS_SEED = 20261118
BOOTSTRAP_REPLICATES = 10_000
RQ1_DESCRIPTIVE = "asymmetric_rq1_descriptive.csv"
RQ1_ANOVA = "asymmetric_rq1_repeated_measures_anova.csv"
RQ1_MODEL = "asymmetric_rq1_model.csv"
RQ1_PAIRWISE = "asymmetric_rq1_pairwise.csv"
RQ1_SUMMARY = "asymmetric_rq1_summary.json"
RQ1_PLOT = "asymmetric_rq1_execution_time.png"
RQ2_SUMMARY_CSV = "asymmetric_rq2_summary.csv"
RQ2_VALIDATION_CSV = "asymmetric_rq2_case_validation.csv"
RQ2_SUMMARY_JSON = "asymmetric_rq2_summary.json"
RQ3_DESCRIPTIVE = "asymmetric_rq3_descriptive.csv"
RQ3_TESTS = "asymmetric_rq3_paired_tests.csv"
RQ3_DIAGNOSTICS = "asymmetric_rq3_diagnostics.csv"
RQ3_SUMMARY = "asymmetric_rq3_summary.json"
RQ3_PLOT = "asymmetric_rq3_execution_time.png"


def holm_adjust(p_values: list[float]) -> list[float]:
    """Holm step-down adjusted p-values, returned in original order."""
    if any(not math.isfinite(value) or value < 0 or value > 1 for value in p_values):
        raise ValueError("p-values must be finite and lie in [0, 1]")
    order = sorted(range(len(p_values)), key=p_values.__getitem__)
    adjusted = [0.0] * len(p_values)
    running = 0.0
    for rank, index in enumerate(order):
        running = max(running, min(1.0, (len(order) - rank) * p_values[index]))
        adjusted[index] = running
    return adjusted


def exact_paired_sign_flip_p(differences: list[float] | np.ndarray) -> float:
    """Exact two-sided conditional sign-swap p-value via meet-in-the-middle.

    This is a randomization test only when signs correspond to independently
    randomized pair-label orientations under the stated sharp null.
    """
    values = np.asarray(differences, dtype=float)
    if values.ndim != 1 or not len(values) or not np.isfinite(values).all():
        raise ValueError("differences must be a non-empty finite vector")
    split = len(values) // 2

    def signed_sums(part: np.ndarray) -> list[float]:
        sums = [0.0]
        for value in part:
            value = float(value)
            sums = [current - value for current in sums] + [current + value for current in sums]
        return sums

    left = signed_sums(values[:split])
    right = sorted(signed_sums(values[split:]))
    observed = abs(float(values.sum()))
    tolerance = 1e-12 * max(1.0, observed, float(np.abs(values).sum()))
    if observed <= tolerance:
        return 1.0
    tail_count = 0
    for subtotal in left:
        lower = -observed + tolerance - subtotal
        upper = observed - tolerance - subtotal
        tail_count += bisect_right(right, lower) + len(right) - bisect_left(right, upper)
    total = len(left) * len(right)
    return min(1.0, tail_count / total)


def _read_csv(path: str | Path, expected_fields: tuple[str, ...]) -> list[dict[str, str]]:
    with Path(path).open(newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if tuple(reader.fieldnames or ()) != expected_fields:
            raise ValueError(f"unexpected CSV schema in {path}")
        return list(reader)


def _read_metadata(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _check_outputs(output_dir: str | Path, names: tuple[str, ...]) -> Path:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    existing = [name for name in names if (target / name).exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite analysis outputs: {', '.join(existing)}")
    return target


def _number(row: dict, field: str, *, integer: bool = False):
    try:
        value = int(row[field]) if integer else float(row[field])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"invalid {field!r} value: {row.get(field)!r}") from error
    if not math.isfinite(float(value)):
        raise ValueError(f"non-finite {field!r} value")
    return value


def _json_safe(value):
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value) if np.isfinite(value) else None
    if isinstance(value, np.bool_):
        return bool(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _write_analysis_metadata(summary: dict) -> None:
    summary["analysis_environment"] = {
        "python": sys.version,
        "platform": platform.platform(),
        "numpy": np.__version__,
        "scipy": scipy.__version__,
        "statsmodels": statsmodels.__version__,
        "pandas": pd.__version__,
        "matplotlib": matplotlib.__version__,
        "cryptography": cryptography.__version__,
    }


def _validate_previous_chain(rows: list[dict[str, str]], block_field: str = "Block ID") -> None:
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        grouped.setdefault(row[block_field], []).append(row)
    for block, block_rows in grouped.items():
        ordered = sorted(block_rows, key=lambda row: _number(row, "Randomized position within block", integer=True))
        for index, row in enumerate(ordered):
            expected = "" if index == 0 else "|".join(
                str(ordered[index - 1][field])
                for field in (
                    "Scheme",
                    "Input size in bytes",
                    "Operation" if "Operation" in ordered[index - 1] else "Scenario",
                )
            )
            if row.get("Previous condition ID", "") != expected:
                raise ValueError(f"incorrect previous-condition chain in block {block}")


def _validate_rq1(rows: list[dict[str, str]], metadata: dict) -> tuple[list[int], list[str], list[str]]:
    sizes = [int(value) for value in metadata["input_sizes_bytes"]]
    expected_blocks = int(metadata["block_count"])
    schemes = [scheme.name for scheme in SCHEMES]
    operations = ["encrypt", "decrypt"]
    expected = {
        (str(block), scheme, size, operation)
        for block in range(1, expected_blocks + 1)
        for scheme in schemes
        for size in sizes
        for operation in operations
    }
    seen = set()
    positions: dict[str, set[int]] = {}
    input_ids: dict[tuple[str, int], set[str]] = {}
    for row in rows:
        block = str(_number(row, "Block ID", integer=True))
        scheme, size, operation = row["Scheme"], _number(row, "Input size in bytes", integer=True), row["Operation"]
        key = (block, scheme, size, operation)
        if key not in expected or key in seen:
            raise ValueError(f"unexpected or duplicate RQ1 observation: {key}")
        seen.add(key)
        positions.setdefault(block, set()).add(_number(row, "Randomized position within block", integer=True))
        input_ids.setdefault((block, size), set()).add(row["Input identifier"])
        if _number(row, "Execution time in seconds") <= 0:
            raise ValueError("RQ1 execution times must be positive")
    if seen != expected:
        raise ValueError("RQ1 CSV is missing one or more block/scheme/size/operation observations")
    condition_count = len(schemes) * len(sizes) * len(operations)
    if any(pos != set(range(1, condition_count + 1)) for pos in positions.values()):
        raise ValueError("RQ1 randomized positions are incomplete or duplicated")
    if any(len(identifiers) != 1 for identifiers in input_ids.values()):
        raise ValueError("algorithms did not share the same RQ1 input per block and size")
    _validate_previous_chain(rows)
    return sizes, schemes, operations


def _block_ols_fit(data: pd.DataFrame, formula: str):
    """Position-adjusted block fixed-effects OLS with CR1 block covariance."""
    return smf.ols(formula, data=data).fit(
        cov_type="cluster",
        cov_kwds={"groups": data["block_factor"], "use_correction": True},
        use_t=True,
    )


def _block_wald_f(result, terms: tuple[str, ...], cluster_count: int) -> dict:
    names = list(result.model.exog_names)
    indices = []
    for term in terms:
        if ":" in term and term.startswith("C("):
            factor, effect = term.split(":", 1)
            matched = [
                index for index, name in enumerate(names)
                if name.startswith(factor + "[") and name.endswith(":" + effect)
            ]
        else:
            matched = [
                index for index, name in enumerate(names)
                if name == term or name.startswith(term + "[") or name.startswith(term + ":")
            ]
        if not matched:
            raise ValueError(f"model does not contain requested term {term!r}")
        indices.extend(matched)
    params = np.asarray(result.params, dtype=float)[indices]
    covariance = np.asarray(result.cov_params(), dtype=float)[np.ix_(indices, indices)]
    statistic_chi2 = float(params @ np.linalg.pinv(covariance) @ params)
    numerator_df = len(indices)
    statistic_f = statistic_chi2 / numerator_df
    denominator_df = cluster_count - 1
    return {
        "wald_chi_square": statistic_chi2,
        "f_statistic": statistic_f,
        "numerator_df": numerator_df,
        "denominator_df": denominator_df,
        "p_value": float(stats.f.sf(statistic_f, numerator_df, denominator_df)),
    }


def _term_test(result, term: str, cluster_count: int) -> dict | None:
    try:
        return _block_wald_f(result, (term,), cluster_count)
    except (KeyError, ValueError):
        return None


def _holm_family(rows: list[dict], p_field: str, adjusted_field: str) -> None:
    indices = [i for i, row in enumerate(rows) if row.get(p_field) is not None]
    adjusted = holm_adjust([float(rows[i][p_field]) for i in indices])
    for index, value in zip(indices, adjusted):
        rows[index][adjusted_field] = value


def _block_pair_diagnostics(group: pd.DataFrame, adjusted_time: np.ndarray, sizes: list[int]) -> dict:
    size_order = sorted(sizes)
    matrix = group.assign(adjusted_time=adjusted_time).pivot(
        index="block_id", columns="size_bytes", values="adjusted_time"
    ).sort_index()
    trend_ps, serial_ps, difference_normality_ps = [], [], []
    block_ids = np.asarray([int(value) for value in matrix.index], dtype=float)
    for left, right in itertools.combinations(size_order, 2):
        differences = (matrix[left] - matrix[right]).to_numpy(dtype=float)
        if len(differences) >= 3 and np.ptp(differences) > 0:
            difference_normality_ps.append(float(stats.shapiro(differences).pvalue))
        if len(differences) >= 4 and np.ptp(differences) > 0:
            trend_ps.append(float(stats.linregress(block_ids, differences).pvalue))
            if np.ptp(differences[:-1]) > 0 and np.ptp(differences[1:]) > 0:
                serial_ps.append(float(stats.pearsonr(differences[:-1], differences[1:]).pvalue))
    return {
        "difference_score_shapiro_min_p": min(difference_normality_ps, default=None),
        "block_difference_linear_trend_min_holm_p": min(holm_adjust(trend_ps), default=None),
        "block_difference_lag1_min_holm_p": min(holm_adjust(serial_ps), default=None),
    }


def _diagnostic_block_model(data: pd.DataFrame, base_formula: str, block_count: int) -> dict:
    diagnostics = {}
    base = _block_ols_fit(data, base_formula)
    residuals = np.asarray(base.resid, dtype=float)
    diagnostics["residual_shapiro_wilk"] = (
        {"statistic": float(stats.shapiro(residuals).statistic), "p_value": float(stats.shapiro(residuals).pvalue)}
        if len(residuals) >= 3 and np.ptp(residuals) > 0 else None
    )
    position = _term_test(base, "position_centered", block_count)
    diagnostics["position_term_test"] = position

    interaction_formula = base_formula.replace(
        "C(size_factor) +", "C(size_factor) * position_centered +"
    )
    interaction = _block_ols_fit(data, interaction_formula)
    interaction_test = _term_test(interaction, "C(size_factor):position_centered", block_count)
    diagnostics["size_by_position_test"] = interaction_test

    quadratic_formula = base_formula + " + I(position_centered ** 2)"
    quadratic = _block_ols_fit(data, quadratic_formula)
    diagnostics["quadratic_position_test"] = _term_test(
        quadratic, "I(position_centered ** 2)", block_count
    )
    return diagnostics


def _previous_fields_rq1(frame: pd.DataFrame) -> pd.DataFrame:
    previous = frame["Previous condition ID"].fillna("").str.split("|", regex=False)
    frame = frame.copy()
    frame["previous_scheme"] = previous.map(lambda parts: parts[0] if len(parts) == 3 else "BLOCK_START")
    frame["previous_size"] = previous.map(
        lambda parts: int(parts[1]) if len(parts) == 3 else 0
    )
    frame["previous_operation"] = previous.map(
        lambda parts: parts[2] if len(parts) == 3 else "BLOCK_START"
    )
    frame["previous_same_scheme"] = (frame["previous_scheme"] == frame["Scheme"]).astype(float)
    frame["previous_same_operation"] = (frame["previous_operation"] == frame["Operation"]).astype(float)
    frame["previous_log_size"] = np.where(
        frame["previous_size"] > 0,
        np.log2(np.maximum(frame["previous_size"], 1)),
        0.0,
    )
    return frame


def _adjusted_pairwise(result, data: pd.DataFrame, sizes: list[int], blocks: int) -> list[dict]:
    names = list(result.model.exog_names)
    covariance = np.asarray(result.cov_params(), dtype=float)
    parameters = np.asarray(result.params, dtype=float)

    def size_vector(size: int) -> np.ndarray:
        vector = np.zeros(len(names), dtype=float)
        coefficient_name = f"C(size_factor)[T.{size}]"
        if coefficient_name in names:
            vector[names.index(coefficient_name)] = 1.0
        return vector

    rows = []
    for left, right in itertools.combinations(sorted(sizes), 2):
        contrast = size_vector(left) - size_vector(right)
        difference = float(contrast @ parameters)
        standard_error = float(np.sqrt(max(0.0, contrast @ covariance @ contrast)))
        statistic = difference / standard_error if standard_error else 0.0
        p_value = float(2 * stats.t.sf(abs(statistic), blocks - 1))
        critical = float(stats.t.ppf(1 - ALPHA / 2, blocks - 1))
        rows.append({
            "Input size 1 bytes": left,
            "Input size 2 bytes": right,
            "Adjusted mean difference seconds (size 1 - size 2)": difference,
            "Robust standard error": standard_error,
            "t statistic": statistic,
            "Degrees of freedom": blocks - 1,
            "Raw p-value": p_value,
            "95% CI lower seconds": difference - critical * standard_error,
            "95% CI upper seconds": difference + critical * standard_error,
            "Holm adjusted p-value within scheme-operation": None,
        })
    adjusted = holm_adjust([row["Raw p-value"] for row in rows])
    for row, value in zip(rows, adjusted):
        row["Holm adjusted p-value within scheme-operation"] = value
    return rows


def analyze_rq1(
    input_csv: str | Path,
    metadata_json: str | Path,
    output_dir: str | Path,
) -> dict[str, Path]:
    """Analyze RQ1 with a position-adjusted, block-clustered marginal model."""
    raw = _read_csv(input_csv, RQ1_FIELDS)
    metadata = _read_metadata(metadata_json)
    sizes, schemes, operations = _validate_rq1(raw, metadata)
    target = _check_outputs(
        output_dir,
        (RQ1_DESCRIPTIVE, RQ1_ANOVA, RQ1_MODEL, RQ1_PAIRWISE, RQ1_SUMMARY, RQ1_PLOT),
    )

    frame = pd.DataFrame(raw)
    frame["time_seconds"] = frame["Execution time in seconds"].astype(float)
    frame["size_bytes"] = frame["Input size in bytes"].astype(int)
    frame["block_id"] = frame["Block ID"].astype(int)
    frame["block_factor"] = frame["block_id"].astype(str)
    frame["size_factor"] = frame["size_bytes"].astype(str)
    frame["position"] = frame["Randomized position within block"].astype(float)
    conditions_per_block = len(schemes) * len(sizes) * len(operations)
    frame["position_centered"] = frame["position"] - (conditions_per_block + 1) / 2
    frame = _previous_fields_rq1(frame)

    descriptive_rows = []
    anova_rows = []
    model_rows = []
    pairwise_rows = []
    plot, axes = plt.subplots(3, 2, figsize=(12, 12), sharex=True)
    all_group_models = []

    for scheme_index, scheme in enumerate(schemes):
        for operation_index, operation in enumerate(operations):
            group = frame[(frame["Scheme"] == scheme) & (frame["Operation"] == operation)].copy()
            group_count = group["block_id"].nunique()
            group_records = [
                {
                    "Block ID": int(row["Block ID"]),
                    "Input size in bytes": int(row["Input size in bytes"]),
                    "Execution time in seconds": float(row["Execution time in seconds"]),
                }
                for row in raw
                if row["Scheme"] == scheme and row["Operation"] == operation
            ]
            rm_matrix = build_repeated_measures_matrix(
                group_records, sizes, sorted(group["block_id"].unique())
            )
            rm_result = repeated_measures_anova(rm_matrix, alpha=ALPHA)
            anova_rows.append({
                "Scheme": scheme,
                "Operation": operation,
                "Test": "Conventional one-factor repeated-measures ANOVA",
                "Within-subject factor": "Input size",
                "Subject": "Experimental block",
                "Subjects": rm_result["subject_count"],
                "Input size levels": rm_result["factor_level_count"],
                "Alpha": ALPHA,
                "Null hypothesis": "Mean execution times are equal across the five input sizes.",
                "Alternative hypothesis": "At least one input-size mean differs.",
                "F statistic": rm_result["f_statistic"],
                "Input-size sum of squares": rm_result["ss_input_size"],
                "Error sum of squares": rm_result["ss_error"],
                "Uncorrected numerator df": rm_result["uncorrected_df_numerator"],
                "Uncorrected denominator df": rm_result["uncorrected_df_denominator"],
                "Uncorrected p-value": rm_result["uncorrected_p_value"],
                "Mauchly W": rm_result["mauchly_w"],
                "Mauchly chi-square": rm_result["mauchly_chi_square"],
                "Mauchly df": rm_result["mauchly_df"],
                "Mauchly p-value": rm_result["mauchly_p_value"],
                "Sphericity rejected": rm_result["sphericity_rejected"],
                "Greenhouse-Geisser epsilon": rm_result["greenhouse_geisser_epsilon"],
                "Greenhouse-Geisser numerator df": rm_result["greenhouse_geisser_df_numerator"],
                "Greenhouse-Geisser denominator df": rm_result["greenhouse_geisser_df_denominator"],
                "Greenhouse-Geisser p-value": rm_result["greenhouse_geisser_p_value"],
                "Correction used": rm_result["correction_used"],
                "Primary numerator df": rm_result["primary_df_numerator"],
                "Primary denominator df": rm_result["primary_df_denominator"],
                "Primary p-value": rm_result["primary_p_value"],
                "Holm adjusted primary p-value across six tests": None,
                "Partial eta-squared": rm_result["partial_eta_squared"],
                "Residual Shapiro-Wilk statistic": rm_result["residual_shapiro_statistic"],
                "Residual Shapiro-Wilk p-value": rm_result["residual_shapiro_p_value"],
                "Minimum pairwise difference-score Shapiro-Wilk p-value": rm_result["difference_score_shapiro_min_p_value"],
                "Difference-score normality tests": rm_result["difference_score_shapiro_test_count"],
                "Residual variance max/min ratio": rm_result["residual_variance_max_min_ratio"],
                "Independence note": "Blocks are sequential observations; randomization does not prove block independence or absence of carry-over.",
                "Interpretation": "A significant omnibus result means at least one input-size mean differs; it does not identify which pairs differ.",
            })
            group_formula = "time_seconds ~ C(size_factor) + C(block_factor) + position_centered"
            result = _block_ols_fit(group, group_formula)
            omnibus = _block_wald_f(result, ("C(size_factor)",), group_count)
            diagnostics = _diagnostic_block_model(group, group_formula, group_count)

            previous_formula = group_formula + " + previous_same_scheme + previous_same_operation + previous_log_size"
            previous_result = _block_ols_fit(group, previous_formula)
            previous_test = _block_wald_f(
                previous_result,
                ("previous_same_scheme", "previous_same_operation", "previous_log_size"),
                group_count,
            )
            diagnostics["previous_condition_joint_test"] = previous_test
            position_coef = float(result.params.iloc[result.model.exog_names.index("position_centered")])
            adjusted = group["time_seconds"].to_numpy() - position_coef * group["position_centered"].to_numpy()
            diagnostics.update(_block_pair_diagnostics(group, adjusted, sizes))

            residual_variances = {}
            for size in sizes:
                size_mask = group["size_bytes"].to_numpy() == size
                residual_variances[size] = float(np.var(np.asarray(result.resid)[size_mask], ddof=1))
            positive_variances = [value for value in residual_variances.values() if value > 0]
            diagnostics["residual_variance_max_min_ratio"] = (
                max(positive_variances) / min(positive_variances) if positive_variances else None
            )
            group["log_time_seconds"] = np.log(group["time_seconds"])
            log_result = _block_ols_fit(
                group,
                "log_time_seconds ~ C(size_factor) + C(block_factor) + position_centered",
            )
            log_omnibus = _block_wald_f(log_result, ("C(size_factor)",), group_count)
            flags = []
            if diagnostics.get("size_by_position_test") and diagnostics["size_by_position_test"]["p_value"] < ALPHA:
                flags.append("position_effect_varies_by_input_size")
            if diagnostics.get("quadratic_position_test") and diagnostics["quadratic_position_test"]["p_value"] < ALPHA:
                flags.append("nonlinear_position_trend")
            if previous_test["p_value"] < ALPHA:
                flags.append("previous_condition_association")
            if diagnostics.get("block_difference_linear_trend_min_holm_p") is not None and diagnostics["block_difference_linear_trend_min_holm_p"] < ALPHA:
                flags.append("block_order_trend")
            if diagnostics.get("block_difference_lag1_min_holm_p") is not None and diagnostics["block_difference_lag1_min_holm_p"] < ALPHA:
                flags.append("serial_dependence_between_blocks")

            row = {
                "Scheme": scheme,
                "Operation": operation,
                "Blocks": group_count,
                "Input size levels": len(sizes),
                "Model": "Position-adjusted block-fixed-effects OLS; complementary sensitivity analysis, not conventional one-way RM-ANOVA",
                "Estimation and covariance": "OLS with CR1 cluster-robust sandwich covariance clustered by block; t/F reference uses blocks - 1 degrees of freedom",
                "Test": "position-adjusted joint cluster-robust Wald F test of input-size coefficients",
                "Alpha": ALPHA,
                "Null hypothesis": "Adjusted mean execution time is equal across all five input sizes, conditional on block and position.",
                "Alternative hypothesis": "At least one adjusted input-size mean differs.",
                "F statistic": omnibus["f_statistic"],
                "Wald chi-square": omnibus["wald_chi_square"],
                "Numerator df": omnibus["numerator_df"],
                "Denominator df": omnibus["denominator_df"],
                "Reference distribution": "Approximate F(4, blocks - 1), using the CR1 cluster-robust Wald statistic divided by 4",
                "Raw p-value": omnibus["p_value"],
                "Log-time sensitivity Wald F": log_omnibus["f_statistic"],
                "Log-time sensitivity p-value": log_omnibus["p_value"],
                "Holm adjusted p-value across six scheme-operation tests": None,
                "Sphericity assumption": "not required by cluster-robust block inference",
                "Mauchly test": "not applicable",
                "Greenhouse-Geisser epsilon": None,
                "Greenhouse-Geisser correction": "not applicable; the primary model uses a block-clustered sandwich covariance that does not assume sphericity",
                "Position slope test p-value": diagnostics.get("position_term_test", {}).get("p_value"),
                "Size-by-position test p-value": diagnostics.get("size_by_position_test", {}).get("p_value"),
                "Quadratic-position test p-value": diagnostics.get("quadratic_position_test", {}).get("p_value"),
                "Previous-condition joint test p-value": previous_test["p_value"],
                "Residual Shapiro-Wilk p-value": (diagnostics.get("residual_shapiro_wilk") or {}).get("p_value"),
                "Difference-score Shapiro-Wilk minimum p-value": diagnostics.get("difference_score_shapiro_min_p"),
                "Residual variance max/min ratio": diagnostics.get("residual_variance_max_min_ratio"),
                "Block difference trend minimum Holm p-value": diagnostics.get("block_difference_linear_trend_min_holm_p"),
                "Block difference lag-1 minimum Holm p-value": diagnostics.get("block_difference_lag1_min_holm_p"),
                "Diagnostic flags": ";".join(flags),
                "Inference status": (
                    "downgraded: diagnostic signal"
                    if flags
                    else "conditional: no diagnostic flag; independent blocks and no carry-over are not proven"
                ),
                "Pairwise status": "pending omnibus Holm adjustment",
            }
            model_rows.append(row)
            all_group_models.append((result, group, scheme, operation, flags))

            for size in sizes:
                values = group.loc[group["size_bytes"] == size, "time_seconds"].to_numpy()
                mean_time = float(np.mean(values))
                descriptive_rows.append({
                    "Scheme": scheme,
                    "Operation": operation,
                    "Input size in bytes": size,
                    "Input size KiB": size / 1024,
                    "Blocks": len(values),
                    "Mean seconds": mean_time,
                    "Median seconds": float(np.median(values)),
                    "Standard deviation seconds": float(np.std(values, ddof=1)),
                    "Minimum seconds": float(np.min(values)),
                    "Maximum seconds": float(np.max(values)),
                    "Throughput MiB per second": (size / (1024 * 1024)) / mean_time,
                })
            ax = axes[scheme_index, operation_index]
            for size in sizes:
                values = group.loc[group["size_bytes"] == size, "time_seconds"].to_numpy()
                ax.scatter([size / 1024] * len(values), values, alpha=0.25, s=12)
            means = [group.loc[group["size_bytes"] == size, "time_seconds"].mean() for size in sizes]
            ax.plot([size / 1024 for size in sizes], means, marker="o", label=scheme)
            ax.set_xscale("log")
            ax.set_yscale("log")
            ax.set_title(f"{scheme} — {operation}")
            ax.set_ylabel("Execution time (seconds)")
            ax.set_xlabel("Input size (KiB)")
            ax.grid(True, alpha=0.25)

    anova_adjusted = holm_adjust([float(row["Primary p-value"]) for row in anova_rows])
    for row, adjusted_p in zip(anova_rows, anova_adjusted):
        row["Holm adjusted primary p-value across six tests"] = adjusted_p

    model_adjusted = holm_adjust([float(row["Raw p-value"]) for row in model_rows])
    for row, adjusted_p in zip(model_rows, model_adjusted):
        row["Holm adjusted p-value across six scheme-operation tests"] = adjusted_p

    for result, group, scheme, operation, flags in all_group_models:
        model_row = next(row for row in model_rows if row["Scheme"] == scheme and row["Operation"] == operation)
        if model_row["Holm adjusted p-value across six scheme-operation tests"] < ALPHA and not flags:
            for pair in _adjusted_pairwise(result, group, sizes, group["block_id"].nunique()):
                pair.update({"Scheme": scheme, "Operation": operation, "Status": "performed after significant omnibus and no diagnostic flags"})
                pairwise_rows.append(pair)
            model_row["Pairwise status"] = "performed; Holm adjustment across ten size pairs within this scheme-operation"
        else:
            status = "omitted: diagnostic flag" if flags else "omitted: omnibus not significant after Holm correction"
            model_row["Pairwise status"] = status

    axes[2, 0].legend(loc="best", fontsize="small")
    plot.tight_layout()
    plot_path = target / RQ1_PLOT
    plot.savefig(plot_path, dpi=160)
    plt.close(plot)

    write_csv(target / RQ1_DESCRIPTIVE, tuple(descriptive_rows[0]), descriptive_rows)
    write_csv(target / RQ1_ANOVA, tuple(anova_rows[0]), anova_rows)
    write_csv(target / RQ1_MODEL, tuple(model_rows[0]), model_rows)
    pair_fields = tuple(pairwise_rows[0]) if pairwise_rows else (
        "Scheme", "Operation", "Input size 1 bytes", "Input size 2 bytes", "Status"
    )
    write_csv(target / RQ1_PAIRWISE, pair_fields, pairwise_rows)
    summary = {
        "research_question": "How does input size affect hybrid encryption and decryption execution time?",
        "primary_model": "Conventional one-factor repeated-measures ANOVA, separately by scheme and operation, with block as subject and input size as the five-level within-subject factor.",
        "repeated_measures_anova": anova_rows,
        "complementary_position_adjusted_ols": model_rows,
        "multiple_testing": "Holm correction across six repeated-measures ANOVA primary p-values; the complementary OLS analysis also Holm-adjusts its six omnibus tests. Its ten pairwise contrasts are Holm-adjusted within each scheme-operation only after a significant adjusted OLS omnibus and when diagnostics permit.",
        "interpretation_limit": "A significant omnibus ANOVA establishes only that at least one input-size mean differs; it does not identify pairs.",
        "sphericity": "Mauchly's approximate test is applied to the within-subject contrast covariance. If it rejects at alpha=0.05, Greenhouse-Geisser epsilon corrects both degrees of freedom and the primary p-value. The F statistic and partial eta-squared are unchanged by the correction.",
        "diagnostic_caveat": "Residual and paired difference-score normality are diagnostics. Blocks are sequential, so independence and absence of carry-over are not proven; diagnostic flags downgrade interpretation.",
        "raw_csv_sha256": hashlib.sha256(Path(input_csv).read_bytes()).hexdigest(),
    }
    _write_analysis_metadata(summary)
    write_json(target / RQ1_SUMMARY, _json_safe(summary))
    return {
        "descriptive": target / RQ1_DESCRIPTIVE,
        "repeated_measures_anova": target / RQ1_ANOVA,
        "model": target / RQ1_MODEL,
        "pairwise": target / RQ1_PAIRWISE,
        "summary": target / RQ1_SUMMARY,
        "plot": plot_path,
    }


def _truth(value: str, field: str) -> bool:
    if value == "True":
        return True
    if value == "False":
        return False
    raise ValueError(f"invalid boolean value for {field}: {value!r}")


def analyze_rq2(
    input_csv: str | Path,
    metadata_json: str | Path,
    output_dir: str | Path,
) -> dict[str, Path]:
    """Summarize measured acceptance and rejection behavior without timing claims."""
    rows = _read_csv(input_csv, OUTCOME_FIELDS)
    metadata = _read_metadata(metadata_json)
    target = _check_outputs(
        output_dir, (RQ2_SUMMARY_CSV, RQ2_VALIDATION_CSV, RQ2_SUMMARY_JSON)
    )
    seen = set()
    grouped: dict[tuple[str, int, str], list[dict[str, str]]] = {}
    for row in rows:
        scheme = row["Scheme"]
        size = _number(row, "Input size in bytes", integer=True)
        scenario = row["Scenario"]
        key = (scheme, size, scenario)
        if key in seen:
            raise ValueError(f"duplicate RQ2 functional case: {key}")
        seen.add(key)
        accepted = _truth(row["Accepted"], "Accepted")
        released = _truth(row["Plaintext released"], "Plaintext released")
        if scenario == VALID:
            if not accepted or not released or row["Failure stage"]:
                raise ValueError(f"valid RQ2 case failed: {key}")
        elif accepted or released:
            raise ValueError(f"invalid RQ2 case accepted data or released plaintext: {key}")
        grouped.setdefault(key, []).append(row)

    expected_sizes = [int(value) for value in metadata["input_sizes_bytes"]]
    expected = set()
    for scheme in (item.name for item in SCHEMES):
        for size in expected_sizes:
            expected.update({
                (scheme, size, VALID),
                (scheme, size, CIPHERTEXT_TAMPERED),
                (scheme, size, TAG_TAMPERED),
                (scheme, size, "malformed_common_envelope_field"),
            })
            if scheme.startswith("RSA-"):
                expected.add((scheme, size, "wrapped_key_tampered"))
            else:
                expected.add((scheme, size, "valid_replacement_public_key"))
                expected.add((scheme, size, "malformed_public_key"))
    if seen != expected:
        raise ValueError("RQ2 outcome matrix is incomplete or contains unexpected cases")

    expected_scenarios = {
        VALID: (True, "accepted", {""}),
        CIPHERTEXT_TAMPERED: (False, "aes_gcm_authentication", {"aes_gcm_authentication"}),
        TAG_TAMPERED: (False, "aes_gcm_authentication", {"aes_gcm_authentication"}),
        "malformed_common_envelope_field": (False, "envelope_validation", {"envelope_validation"}),
        "wrapped_key_tampered": (
            False,
            "rsa_oaep_unwrap|aes_gcm_authentication",
            {"rsa_oaep_unwrap", "aes_gcm_authentication"},
        ),
        "valid_replacement_public_key": (
            False,
            "aes_gcm_authentication",
            {"aes_gcm_authentication"},
        ),
        "malformed_public_key": (False, "public_key_parse", {"public_key_parse"}),
    }
    validation_rows = []
    for key in sorted(grouped):
        scheme, size, scenario = key
        row = grouped[key][0]
        expected_accepted, expected_stage, allowed_stages = expected_scenarios[scenario]
        observed_accepted = _truth(row["Accepted"], "Accepted")
        expected_released = expected_accepted
        observed_released = _truth(row["Plaintext released"], "Plaintext released")
        observed_stage = row["Failure stage"]
        stage_matches = observed_stage in allowed_stages
        validation_rows.append({
            "Scheme": scheme,
            "Input size in bytes": size,
            "Scenario": scenario,
            "Scenario detail": row["Scenario detail"],
            "Expected accepted": expected_accepted,
            "Observed accepted": observed_accepted,
            "Acceptance matches expectation": observed_accepted == expected_accepted,
            "Expected failure stage": expected_stage,
            "Observed failure stage": observed_stage or "accepted",
            "Failure stage matches expectation": stage_matches,
            "Observed exception category": row["Exception category"],
            "Expected plaintext released": expected_released,
            "Observed plaintext released": observed_released,
            "Plaintext-release expectation met": observed_released == expected_released,
            "Observed session key unwrapped": row["Session key unwrapped"],
            "Observed key agreement completed": row["Key agreement completed"],
            "Observed HKDF completed": row["HKDF completed"],
            "Observed AES-GCM verification reached": row["AES-GCM verification reached"],
            "Case matches expected behavior": (
                observed_accepted == expected_accepted
                and observed_released == expected_released
                and stage_matches
            ),
        })

    summary_rows = []
    stage_counts = {}
    for key in sorted(grouped):
        scheme, size, scenario = key
        case_rows = grouped[key]
        failure_counts: dict[str, int] = {}
        for row in case_rows:
            stage = row["Failure stage"] or "accepted"
            failure_counts[stage] = failure_counts.get(stage, 0) + 1
        summary_rows.append({
            "Scheme": scheme,
            "Input size in bytes": size,
            "Scenario": scenario,
            "Cases": len(case_rows),
            "Accepted count": sum(_truth(row["Accepted"], "Accepted") for row in case_rows),
            "Rejected count": sum(not _truth(row["Accepted"], "Accepted") for row in case_rows),
            "Plaintext released count": sum(_truth(row["Plaintext released"], "Plaintext released") for row in case_rows),
            "Failure stage counts": json.dumps(failure_counts, sort_keys=True),
        })
        stage_counts[f"{scheme}|{size}|{scenario}"] = failure_counts

    write_csv(target / RQ2_SUMMARY_CSV, tuple(summary_rows[0]), summary_rows)
    write_csv(target / RQ2_VALIDATION_CSV, tuple(validation_rows[0]), validation_rows)
    summary = {
        "research_question": "How do the schemes respond to modified or malformed envelopes?",
        "outcome_count": len(rows),
        "expected_vs_observed_case_count": len(validation_rows),
        "all_cases_match_expected_behavior": all(
            row["Case matches expected behavior"] for row in validation_rows
        ),
        "results_are_functional_observations_not_timing_or_population_probabilities": True,
        "plaintext_release_invariant": "All invalid cases were rejected without returning plaintext; valid cases released the original plaintext.",
        "failure_stage_counts": stage_counts,
        "raw_csv_sha256": hashlib.sha256(Path(input_csv).read_bytes()).hexdigest(),
        "note": "No sender authentication is provided; successful decryption does not identify who created the envelope.",
    }
    _write_analysis_metadata(summary)
    write_json(target / RQ2_SUMMARY_JSON, _json_safe(summary))
    return {
        "summary_csv": target / RQ2_SUMMARY_CSV,
        "case_validation_csv": target / RQ2_VALIDATION_CSV,
        "summary_json": target / RQ2_SUMMARY_JSON,
    }


def _ols_cluster_test(result, terms: tuple[str, ...], block_count: int) -> dict:
    names = list(result.model.exog_names)
    indices = []
    for term in terms:
        if ":" in term and term.startswith("C("):
            factor, effect = term.split(":", 1)
            matches = [
                index for index, name in enumerate(names)
                if name.startswith(factor + "[") and name.endswith(":" + effect)
            ]
        else:
            matches = [
                index for index, name in enumerate(names)
                if name == term or name.startswith(term + "[") or name.startswith(term + ":")
            ]
        indices.extend(matches)
    if not indices:
        return {"statistic": None, "df_num": 0, "df_den": block_count - 1, "p_value": None}
    params = np.asarray(result.params, dtype=float)[indices]
    covariance = np.asarray(result.cov_params(), dtype=float)[np.ix_(indices, indices)]
    wald = float(params @ np.linalg.pinv(covariance) @ params)
    df_num = len(indices)
    statistic = wald / df_num
    return {
        "statistic": statistic,
        "wald_chi_square": wald,
        "df_num": df_num,
        "df_den": block_count - 1,
        "p_value": float(stats.f.sf(statistic, df_num, block_count - 1)),
    }


def _rq3_design_diagnostics(frame: pd.DataFrame) -> dict:
    blocks = frame["block_id"].nunique()
    frame = frame.copy()
    frame["condition_factor"] = (
        frame["scheme"].astype(str) + "|" + frame["size_factor"].astype(str)
        + "|" + frame["scenario"].astype(str)
    )
    frame["previous_scheme_factor"] = frame["previous_scheme"].replace("", "BLOCK_START")
    frame["previous_scenario_factor"] = frame["previous_scenario"].replace("", "BLOCK_START")
    frame["previous_size_factor"] = frame["previous_size_factor"].replace("", "BLOCK_START")
    frame["previous_same_scheme"] = (frame["previous_scheme_factor"] == frame["scheme"]).astype(float)
    frame["previous_same_scenario"] = (frame["previous_scenario_factor"] == frame["scenario"]).astype(float)
    frame["previous_same_size"] = (frame["previous_size_factor"] == frame["size_factor"]).astype(float)

    trend_fit = smf.ols(
        "time_seconds ~ C(condition_factor) + position_centered", data=frame
    ).fit()
    trend_cluster = trend_fit.get_robustcov_results(
        cov_type="cluster", groups=frame["block_factor"], use_correction=True, use_t=True
    )
    pos_idx = trend_cluster.model.exog_names.index("position_centered")
    position_p = float(trend_cluster.pvalues[pos_idx])
    trend_frame = frame.copy()
    trend_frame["condition_scheme"] = trend_frame["scheme"]
    trend_frame["condition_size"] = trend_frame["size_factor"]
    trend_frame["condition_scenario"] = trend_frame["scenario"]
    interaction_fit = smf.ols(
        "time_seconds ~ C(scheme) + C(size_factor) + C(scenario) + position_centered "
        "+ C(scheme):position_centered + C(size_factor):position_centered "
        "+ C(scenario):position_centered + C(block_factor)",
        data=trend_frame,
    ).fit(cov_type="cluster", cov_kwds={"groups": frame["block_factor"], "use_correction": True}, use_t=True)
    interaction_test = _ols_cluster_test(
        interaction_fit,
        ("C(scheme):position_centered", "C(size_factor):position_centered", "C(scenario):position_centered"),
        blocks,
    )
    quadratic_fit = smf.ols(
        "time_seconds ~ C(condition_factor) + position_centered + I(position_centered ** 2)",
        data=frame,
    ).fit(cov_type="cluster", cov_kwds={"groups": frame["block_factor"], "use_correction": True}, use_t=True)
    quadratic_test = _ols_cluster_test(quadratic_fit, ("I(position_centered ** 2)",), blocks)

    block_diagnostic_fit = smf.ols(
        "time_seconds ~ C(condition_factor) + position_centered", data=frame
    ).fit()
    residuals = pd.Series(block_diagnostic_fit.resid, index=frame.index)
    block_means = frame.assign(model_residual=residuals).groupby("block_id")["model_residual"].mean().sort_index()
    block_ids = block_means.index.to_numpy(dtype=float)
    trend_p = float(stats.linregress(block_ids, block_means.to_numpy()).pvalue) if len(block_means) >= 3 else None
    if len(block_means) >= 4 and np.ptp(block_means.to_numpy()[:-1]) > 0 and np.ptp(block_means.to_numpy()[1:]) > 0:
        lag1 = stats.pearsonr(block_means.to_numpy()[:-1], block_means.to_numpy()[1:])
        lag1_r, lag1_p = float(lag1.statistic), float(lag1.pvalue)
    else:
        lag1_r, lag1_p = None, None

    previous_fit = smf.ols(
        "time_seconds ~ C(condition_factor) + C(block_factor) + position_centered "
        "+ previous_same_scheme + previous_same_size + previous_same_scenario",
        data=frame,
    ).fit(cov_type="cluster", cov_kwds={"groups": frame["block_factor"], "use_correction": True}, use_t=True)
    previous_test = _ols_cluster_test(
        previous_fit,
        ("previous_same_scheme", "previous_same_size", "previous_same_scenario"),
        blocks,
    )
    return {
        "position_linear_slope_seconds_per_position": float(trend_cluster.params[pos_idx]),
        "position_linear_slope_p_value": position_p,
        "position_by_condition_family_test": interaction_test,
        "quadratic_position_test": quadratic_test,
        "block_residual_mean_linear_trend_p_value": trend_p,
        "block_residual_mean_lag1_correlation": lag1_r,
        "block_residual_mean_lag1_p_value": lag1_p,
        "previous_condition_joint_test": previous_test,
        "block_count": blocks,
        "independence_note": "Thirty sequential blocks cannot establish independence; these are diagnostics, not proof.",
    }


def _validate_rq3(rows: list[dict[str, str]], metadata: dict) -> tuple[list[int], list[str]]:
    sizes = [int(value) for value in metadata["input_sizes_bytes"]]
    blocks = int(metadata["block_count"])
    schemes = [scheme.name for scheme in SCHEMES]
    expected_conditions = set(rq3_conditions(tuple(sizes)))
    seen = set()
    positions: dict[str, set[int]] = {}
    input_ids: dict[tuple[str, int], set[str]] = {}
    for row in rows:
        block = str(_number(row, "Block ID", integer=True))
        condition = (
            row["Scheme"],
            _number(row, "Input size in bytes", integer=True),
            row["Scenario"],
        )
        key = (block, *condition)
        if block not in {str(i) for i in range(1, blocks + 1)} or condition not in expected_conditions or key in seen:
            raise ValueError(f"unexpected or duplicate RQ3 observation: {key}")
        seen.add(key)
        positions.setdefault(block, set()).add(_number(row, "Randomized position within block", integer=True))
        input_ids.setdefault((block, condition[1]), set()).add(row["Input identifier"])
        time_value = _number(row, "Total attempted decryption time in seconds")
        if time_value <= 0:
            raise ValueError("RQ3 attempted-decryption times must be positive")
        accepted = _truth(row["Accepted"], "Accepted")
        released = _truth(row["Plaintext released"], "Plaintext released")
        if condition[2] == VALID:
            if not accepted or not released:
                raise ValueError(f"valid RQ3 observation failed: {key}")
        elif accepted or released:
            raise ValueError(f"invalid RQ3 observation released plaintext: {key}")
        if condition[2] in (CIPHERTEXT_TAMPERED, TAG_TAMPERED) and not _truth(row["AES-GCM verification reached"], "AES-GCM verification reached"):
            raise ValueError(f"GCM was not reached for {condition[2]}: {key}")
        if condition[2] in (CIPHERTEXT_TAMPERED, TAG_TAMPERED) and row["Failure stage"] != "aes_gcm_authentication":
            raise ValueError(f"unexpected ciphertext/tag tampering failure stage: {key}")
        if row["Scenario"] == KEY_TAMPERED:
            if row["Scheme"].startswith("RSA-"):
                if row["Failure stage"] not in ("rsa_oaep_unwrap", "aes_gcm_authentication"):
                    raise ValueError(f"unexpected RSA wrapped-key failure stage: {key}")
            else:
                if not _truth(row["Key agreement completed"], "Key agreement completed") or not _truth(row["HKDF completed"], "HKDF completed") or not _truth(row["AES-GCM verification reached"], "AES-GCM verification reached"):
                    raise ValueError(f"valid replacement public key did not reach GCM: {key}")
                if row["Failure stage"] != "aes_gcm_authentication":
                    raise ValueError(f"replacement public key did not fail at GCM: {key}")
        if condition[2] == MALFORMED:
            if _truth(row["AES-GCM verification reached"], "AES-GCM verification reached"):
                raise ValueError(f"malformed input unexpectedly reached AES-GCM: {key}")
            if row["Scheme"].startswith("RSA-"):
                if row["Failure stage"] != "envelope_validation" or _truth(row["Session key unwrapped"], "Session key unwrapped"):
                    raise ValueError(f"malformed RSA envelope failed at an unexpected stage: {key}")
            elif row["Failure stage"] != "public_key_parse":
                raise ValueError(f"malformed DH public key failed at an unexpected stage: {key}")
    if len(seen) != blocks * len(expected_conditions):
        raise ValueError("RQ3 CSV is incomplete")
    condition_count = len(expected_conditions)
    if any(position_set != set(range(1, condition_count + 1)) for position_set in positions.values()):
        raise ValueError("RQ3 block positions are incomplete or duplicated")
    if any(len(ids) != 1 for ids in input_ids.values()):
        raise ValueError("RQ3 algorithms/scenarios did not share one input per block and size")
    _validate_previous_chain(rows)
    return sizes, schemes


def _bootstrap_mean_ci(values: np.ndarray, rng: np.random.Generator) -> tuple[float, float]:
    sample_indices = rng.integers(0, len(values), size=(BOOTSTRAP_REPLICATES, len(values)))
    bootstrap_means = values[sample_indices].mean(axis=1)
    low, high = np.quantile(bootstrap_means, [0.025, 0.975])
    return float(low), float(high)


def analyze_rq3(
    input_csv: str | Path,
    metadata_json: str | Path,
    output_dir: str | Path,
    *,
    analysis_seed: int = ANALYSIS_SEED,
) -> dict[str, Path]:
    """Analyze matched RQ3 decryption attempts and conditional label swaps."""
    raw = _read_csv(input_csv, RQ3_FIELDS)
    metadata = _read_metadata(metadata_json)
    sizes, schemes = _validate_rq3(raw, metadata)
    target = _check_outputs(output_dir, (RQ3_DESCRIPTIVE, RQ3_TESTS, RQ3_DIAGNOSTICS, RQ3_SUMMARY, RQ3_PLOT))

    frame = pd.DataFrame(raw)
    frame["time_seconds"] = frame["Total attempted decryption time in seconds"].astype(float)
    frame["size_bytes"] = frame["Input size in bytes"].astype(int)
    frame["size_factor"] = frame["size_bytes"].astype(str)
    frame["block_id"] = frame["Block ID"].astype(int)
    frame["block_factor"] = frame["block_id"].astype(str)
    frame["position"] = frame["Randomized position within block"].astype(float)
    condition_count = len(rq3_conditions(tuple(sizes)))
    frame["position_centered"] = frame["position"] - (condition_count + 1) / 2
    frame["previous_scheme"] = frame["Previous scheme"].replace("", "BLOCK_START")
    frame["previous_scenario"] = frame["Previous scenario"].replace("", "BLOCK_START")
    frame["previous_size_factor"] = frame["Previous input size in bytes"].replace("", "BLOCK_START").astype(str)
    frame["scheme"] = frame["Scheme"]
    frame["scenario"] = frame["Scenario"]

    diagnostics = _rq3_design_diagnostics(frame)
    diagnostic_flags = []
    if metadata.get("random_seed_source") != "os_entropy":
        diagnostic_flags.append("randomization_seed_was_explicit_not_randomly_drawn")
    if diagnostics["previous_condition_joint_test"]["p_value"] is not None and diagnostics["previous_condition_joint_test"]["p_value"] < ALPHA:
        diagnostic_flags.append("previous_condition_association_detected")
    if diagnostics["block_residual_mean_linear_trend_p_value"] is not None and diagnostics["block_residual_mean_linear_trend_p_value"] < ALPHA:
        diagnostic_flags.append("block_level_temporal_trend_detected")
    if diagnostics["block_residual_mean_lag1_p_value"] is not None and diagnostics["block_residual_mean_lag1_p_value"] < ALPHA:
        diagnostic_flags.append("block_level_lag1_dependence_detected")
    if diagnostics["position_by_condition_family_test"]["p_value"] is not None and diagnostics["position_by_condition_family_test"]["p_value"] < ALPHA:
        diagnostic_flags.append("position_effect_varies_across_condition_families")
    if diagnostics["quadratic_position_test"]["p_value"] is not None and diagnostics["quadratic_position_test"]["p_value"] < ALPHA:
        diagnostic_flags.append("nonlinear_within_block_position_trend_detected")

    randomization_eligible = (
        metadata.get("random_seed_source") == "os_entropy"
        and "one Python random.Random shuffle per block" in metadata.get("randomization", "")
        and len(metadata.get("block_randomization_seeds", [])) == int(metadata.get("block_count", 0))
        and len(set(metadata.get("block_randomization_seeds", []))) == int(metadata.get("block_count", 0))
        and int(metadata.get("block_count", 0)) == frame["block_id"].nunique()
    )
    inference_status = (
        "downgraded/conditional-exploratory: diagnostic or assignment issue"
        if diagnostic_flags
        else "conditional/exploratory: no diagnostic flag; PRNG uniformity, independence, and no carry-over are not proven"
    )

    descriptive_rows = []
    grouped = frame.groupby(["scheme", "size_bytes", "scenario"], sort=False)
    for (scheme, size, scenario), group in grouped:
        values = group["time_seconds"].to_numpy(dtype=float)
        stage_counts = group["Failure stage"].replace("", "accepted").value_counts().to_dict()
        descriptive_rows.append({
            "Scheme": scheme,
            "Input size in bytes": int(size),
            "Scenario": scenario,
            "Observations": len(values),
            "Mean attempted-decryption seconds": float(np.mean(values)),
            "Median attempted-decryption seconds": float(np.median(values)),
            "Standard deviation seconds": float(np.std(values, ddof=1)) if len(values) > 1 else None,
            "Minimum seconds": float(np.min(values)),
            "Maximum seconds": float(np.max(values)),
            "Accepted count": int(group["Accepted"].map(lambda value: _truth(value, "Accepted")).sum()),
            "Plaintext released count": int(group["Plaintext released"].map(lambda value: _truth(value, "Plaintext released")).sum()),
            "Failure stage counts": json.dumps(stage_counts, sort_keys=True),
        })

    block_count = frame["block_id"].nunique()
    valid_lookup = {
        (row["scheme"], int(row["size_bytes"]), int(row["block_id"])): float(row["time_seconds"])
        for _, row in frame[frame["scenario"] == VALID].iterrows()
    }
    paired_rows = []
    planned = []
    for scheme in schemes:
        for size in sizes:
            valid_times = np.asarray([
                valid_lookup[(scheme, size, block)] for block in range(1, block_count + 1)
            ], dtype=float)
            for scenario in (CIPHERTEXT_TAMPERED, TAG_TAMPERED, KEY_TAMPERED, MALFORMED):
                invalid_group = frame[
                    (frame["scheme"] == scheme)
                    & (frame["size_bytes"] == size)
                    & (frame["scenario"] == scenario)
                ].sort_values("block_id")
                invalid_times = invalid_group["time_seconds"].to_numpy(dtype=float)
                differences = invalid_times - valid_times
                percentages = differences / valid_times * 100.0
                p_value = exact_paired_sign_flip_p(differences) if randomization_eligible else None
                row = {
                    "Scheme": scheme,
                    "Input size in bytes": size,
                    "Invalid scenario": scenario,
                    "Matched blocks": block_count,
                    "Mean valid seconds": float(np.mean(valid_times)),
                    "Mean invalid seconds": float(np.mean(invalid_times)),
                    "Mean paired difference seconds (invalid - valid)": float(np.mean(differences)),
                    "Median paired difference seconds": float(np.median(differences)),
                    "SD paired difference seconds": float(np.std(differences, ddof=1)) if block_count > 1 else None,
                    "Mean paired percentage difference": float(np.mean(percentages)),
                    "Median paired percentage difference": float(np.median(percentages)),
                    "95% block-bootstrap CI lower seconds": None,
                    "95% block-bootstrap CI upper seconds": None,
                    "Randomization p-value (sharp null)": p_value,
                    "Holm adjusted p-value across 60 planned contrasts": None,
                    "Randomization test status": (
                        "conditional/exploratory; diagnostic flags prevent stronger interpretation"
                        if randomization_eligible and diagnostic_flags
                        else "conditional/exploratory under the recorded OS-entropy schedule and uniform-shuffle idealization"
                        if randomization_eligible
                        else "not computed: assignment seed/mechanism not eligible"
                    ),
                    "Inference status": inference_status,
                    "Diagnostic flags": ";".join(diagnostic_flags),
                    "Null hypothesis": "Swapping valid and this invalid condition between their two assigned positions changes no block-position outcome (sharp null).",
                    "Interpretation warning": "A non-significant result is not evidence of equivalence; no practical equivalence margin was supplied.",
                }
                if not diagnostic_flags and block_count >= 10:
                    rng = np.random.default_rng(derived_seed(analysis_seed, scheme, size, scenario))
                    low, high = _bootstrap_mean_ci(differences, rng)
                    row["95% block-bootstrap CI lower seconds"] = low
                    row["95% block-bootstrap CI upper seconds"] = high
                paired_rows.append(row)
                planned.append(row)

    if randomization_eligible:
        p_values = [float(row["Randomization p-value (sharp null)"]) for row in paired_rows]
        adjusted = holm_adjust(p_values)
        for row, value in zip(paired_rows, adjusted):
            row["Holm adjusted p-value across 60 planned contrasts"] = value

    diagnostics_rows = [
        {"Diagnostic": key, "Result": json.dumps(_json_safe(value), sort_keys=True)}
        for key, value in diagnostics.items()
    ]
    diagnostics_rows.extend([
        {"Diagnostic": "randomization_test_eligible", "Result": str(randomization_eligible)},
        {"Diagnostic": "inference_status", "Result": inference_status},
        {"Diagnostic": "diagnostic_flags", "Result": json.dumps(diagnostic_flags)},
    ])

    plot, axis = plt.subplots(figsize=(12, 6))
    scenarios = [VALID, CIPHERTEXT_TAMPERED, TAG_TAMPERED, KEY_TAMPERED, MALFORMED]
    for scheme in schemes:
        for scenario in scenarios:
            means = []
            for size in sorted(sizes):
                values = frame.loc[
                    (frame["scheme"] == scheme)
                    & (frame["size_bytes"] == size)
                    & (frame["scenario"] == scenario),
                    "time_seconds",
                ].to_numpy(dtype=float)
                means.append(float(np.mean(values)))
            axis.plot([size / 1024 for size in sorted(sizes)], means, marker="o", label=f"{scheme} — {scenario}")
    axis.set_xscale("log")
    axis.set_yscale("log")
    axis.set_xlabel("Input size (KiB)")
    axis.set_ylabel("Total attempted decryption time (seconds)")
    axis.set_title("RQ3 valid and invalid decryption attempts")
    axis.grid(True, alpha=0.25)
    axis.legend(fontsize="x-small", ncol=2)
    plot.tight_layout()
    plot_path = target / RQ3_PLOT
    plot.savefig(plot_path, dpi=160)
    plt.close(plot)

    write_csv(target / RQ3_DESCRIPTIVE, tuple(descriptive_rows[0]), descriptive_rows)
    write_csv(target / RQ3_TESTS, tuple(paired_rows[0]), paired_rows)
    write_csv(target / RQ3_DIAGNOSTICS, tuple(diagnostics_rows[0]), diagnostics_rows)
    summary = {
        "research_question": "Are there processing-time differences between valid and invalid envelope decryption?",
        "planned_contrast_count": len(paired_rows),
        "planned_holm_family": f"All four invalid scenarios versus valid for each scheme and input size ({len(paired_rows)} planned contrasts; 60 with the five configured sizes).",
        "randomization_mechanism": metadata.get("randomization"),
        "randomization_seed_source": metadata.get("random_seed_source"),
        "randomization_test": {
            "method": "exhaustive enumeration of the paired label-swap/sign-flip reference distribution; conditional/exploratory, not unqualified exact design-based inference",
            "exchangeable_labels": "For each fixed scheme/size pair, valid and one invalid condition occupy two positions from a uniformly shuffled complete block; conditional on those positions and the other labels, orientation is equiprobable.",
            "sharp_null": "Swapping the valid and invalid labels changes no outcome at either assigned position in any block.",
            "assumptions": [
                "Each block uses an independently shuffled complete condition list.",
                "The recorded seed was drawn from OS entropy; explicit fixed seeds are not eligible for design-based inference. Python's finite-state PRNG is treated as approximating a uniform shuffle, not as literal equal probability over every possible permutation.",
                "No carry-over or interference changes later timings when two labels are swapped.",
            ],
            "eligible": randomization_eligible,
            "interpretation_status": inference_status,
        },
        "design_diagnostics": diagnostics,
        "diagnostic_flags": diagnostic_flags,
        "limitations": [
            "A non-significant test does not establish equal timings or equivalence.",
            "An application-specific equivalence margin was not supplied.",
            "Failure-stage timings are reported separately; early parse/OAEP/key-agreement failures are not pooled as one invalid class.",
            "No sender authentication or end-to-end network cost is measured.",
        ],
        "analysis_seed": analysis_seed,
        "bootstrap_replicates": BOOTSTRAP_REPLICATES,
        "raw_csv_sha256": hashlib.sha256(Path(input_csv).read_bytes()).hexdigest(),
    }
    _write_analysis_metadata(summary)
    write_json(target / RQ3_SUMMARY, _json_safe(summary))
    return {"descriptive": target / RQ3_DESCRIPTIVE, "paired_tests": target / RQ3_TESTS, "diagnostics": target / RQ3_DIAGNOSTICS, "summary": target / RQ3_SUMMARY, "plot": plot_path}


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze asymmetric hybrid-encryption experiments.")
    subparsers = parser.add_subparsers(dest="research_question", required=True)
    defaults = {
        "rq1": ("asymmetric_rq1_benchmarks.csv", "asymmetric_rq1_metadata.json"),
        "rq2": (RQ2_CSV_NAME, RQ2_METADATA_NAME),
        "rq3": (RQ3_CSV_NAME, RQ3_METADATA_NAME),
    }
    for name, (csv_name, metadata_name) in defaults.items():
        subparser = subparsers.add_parser(name)
        subparser.add_argument("--input-csv", type=Path, required=True)
        subparser.add_argument("--metadata", type=Path, default=None)
        subparser.add_argument("--output-dir", type=Path, required=True)
        if name == "rq3":
            subparser.add_argument("--analysis-seed", type=int, default=ANALYSIS_SEED)
        subparser.set_defaults(metadata_name=metadata_name)
    args = parser.parse_args()
    metadata = args.metadata or (args.input_csv.parent / args.metadata_name)
    if args.research_question == "rq1":
        outputs = analyze_rq1(args.input_csv, metadata, args.output_dir)
    elif args.research_question == "rq2":
        outputs = analyze_rq2(args.input_csv, metadata, args.output_dir)
    else:
        outputs = analyze_rq3(
            args.input_csv, metadata, args.output_dir, analysis_seed=args.analysis_seed
        )
    for name, path in outputs.items():
        print(f"{name}: {path}")


if __name__ == "__main__":
    main()

