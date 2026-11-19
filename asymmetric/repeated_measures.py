"""Conventional one-factor repeated-measures ANOVA for RQ1."""

from __future__ import annotations

import math

import numpy as np
from scipy import stats
from scipy.linalg import helmert


def build_repeated_measures_matrix(
    rows: list[dict], input_sizes: list[int] | tuple[int, ...], block_ids: list[int] | tuple[int, ...]
) -> np.ndarray:
    """Build a complete subject-by-size matrix and reject missing/duplicate cells."""
    sizes = tuple(int(size) for size in input_sizes)
    blocks = tuple(int(block) for block in block_ids)
    if len(sizes) < 2 or len(set(sizes)) != len(sizes):
        raise ValueError("input_sizes must contain at least two unique levels")
    if not blocks or len(set(blocks)) != len(blocks):
        raise ValueError("block_ids must contain unique subjects")

    values: dict[tuple[int, int], float] = {}
    for row in rows:
        key = (int(row["Block ID"]), int(row["Input size in bytes"]))
        if key[0] not in blocks or key[1] not in sizes:
            raise ValueError(f"unexpected repeated-measures observation: {key}")
        if key in values:
            raise ValueError(f"duplicate repeated-measures observation: {key}")
        value = float(row["Execution time in seconds"])
        if not math.isfinite(value):
            raise ValueError(f"non-finite execution time for {key}")
        values[key] = value

    expected = {(block, size) for block in blocks for size in sizes}
    if set(values) != expected:
        missing = sorted(expected - set(values))
        raise ValueError(f"missing repeated-measures observations: {missing[:5]}")
    return np.asarray([[values[(block, size)] for size in sizes] for block in blocks])


def _mauchly_sphericity(matrix: np.ndarray) -> dict:
    """Calculate Mauchly's approximate test and Greenhouse-Geisser epsilon."""
    subject_count, level_count = matrix.shape
    dimension = level_count - 1
    contrast_scores = matrix @ helmert(level_count, full=False).T
    covariance = np.atleast_2d(np.cov(contrast_scores, rowvar=False, ddof=1))
    eigenvalues = np.maximum(np.linalg.eigvalsh(covariance), 0.0)
    trace = float(eigenvalues.sum())
    squared_trace = float(np.square(eigenvalues).sum())
    if trace <= 0.0 or squared_trace <= 0.0:
        raise ValueError("Mauchly's test is undefined when contrast variance is zero")

    epsilon = trace**2 / (dimension * squared_trace)
    epsilon = min(1.0, max(1.0 / dimension, float(epsilon)))

    sign, log_determinant = np.linalg.slogdet(covariance)
    if sign <= 0 or not math.isfinite(float(log_determinant)):
        log_w = math.log(np.finfo(float).tiny)
    else:
        log_w = float(log_determinant - dimension * math.log(trace / dimension))
        log_w = min(0.0, max(math.log(np.finfo(float).tiny), log_w))
    mauchly_w = math.exp(log_w)
    correction = 1.0 - (
        2 * dimension**2 + dimension + 2
    ) / (6 * dimension * (subject_count - 1))
    if correction <= 0:
        raise ValueError("too few subjects for the Mauchly approximation")
    chi_square = max(0.0, -(subject_count - 1) * correction * log_w)
    mauchly_df = dimension * (dimension + 1) / 2 - 1
    p_value = float(stats.chi2.sf(chi_square, mauchly_df))
    return {
        "mauchly_w": mauchly_w,
        "mauchly_chi_square": chi_square,
        "mauchly_df": mauchly_df,
        "mauchly_p_value": p_value,
        "greenhouse_geisser_epsilon": epsilon,
    }


def repeated_measures_anova(matrix: np.ndarray, alpha: float = 0.05) -> dict:
    """Run a conventional one-factor RM-ANOVA with subjects as repeated blocks.

    Greenhouse-Geisser adjusts both numerator and denominator degrees of freedom
    only when Mauchly's approximate sphericity test rejects at ``alpha``.
    """
    values = np.asarray(matrix, dtype=float)
    if values.ndim != 2 or values.shape[0] < 3 or values.shape[1] < 3:
        raise ValueError("matrix must have at least three subjects and three factor levels")
    if not np.isfinite(values).all():
        raise ValueError("matrix must contain only finite execution times")
    if not 0 < alpha < 1:
        raise ValueError("alpha must lie between zero and one")

    subject_count, level_count = values.shape
    grand_mean = float(values.mean())
    level_means = values.mean(axis=0)
    subject_means = values.mean(axis=1)
    residuals = (
        values
        - level_means[np.newaxis, :]
        - subject_means[:, np.newaxis]
        + grand_mean
    )
    ss_factor = subject_count * float(np.square(level_means - grand_mean).sum())
    ss_error = float(np.square(residuals).sum())
    df_factor = level_count - 1
    df_error = (subject_count - 1) * df_factor
    if ss_error <= 0.0:
        raise ValueError("RM-ANOVA is undefined because within-subject residual variance is zero")

    f_statistic = (ss_factor / df_factor) / (ss_error / df_error)
    uncorrected_p = float(stats.f.sf(f_statistic, df_factor, df_error))
    partial_eta_squared = ss_factor / (ss_factor + ss_error) if ss_factor + ss_error else 0.0

    sphericity = _mauchly_sphericity(values)
    epsilon = sphericity["greenhouse_geisser_epsilon"]
    gg_df_factor = epsilon * df_factor
    gg_df_error = epsilon * df_error
    gg_p = float(stats.f.sf(f_statistic, gg_df_factor, gg_df_error))
    corrected = sphericity["mauchly_p_value"] < alpha

    residual_shapiro = (
        stats.shapiro(residuals.ravel())
        if residuals.size >= 3 and np.ptp(residuals) > 0
        else None
    )
    difference_p_values = []
    for left in range(level_count - 1):
        for right in range(left + 1, level_count):
            differences = values[:, left] - values[:, right]
            if len(differences) >= 3 and np.ptp(differences) > 0:
                difference_p_values.append(float(stats.shapiro(differences).pvalue))

    residual_variances = np.var(residuals, axis=0, ddof=1)
    positive_variances = residual_variances[residual_variances > 0]
    variance_ratio = (
        float(positive_variances.max() / positive_variances.min())
        if len(positive_variances)
        else None
    )
    return {
        "subject_count": subject_count,
        "factor_level_count": level_count,
        "ss_input_size": ss_factor,
        "ss_error": ss_error,
        "f_statistic": float(f_statistic),
        "uncorrected_df_numerator": df_factor,
        "uncorrected_df_denominator": df_error,
        "uncorrected_p_value": uncorrected_p,
        "partial_eta_squared": partial_eta_squared,
        **sphericity,
        "greenhouse_geisser_df_numerator": gg_df_factor,
        "greenhouse_geisser_df_denominator": gg_df_error,
        "greenhouse_geisser_p_value": gg_p,
        "sphericity_rejected": corrected,
        "correction_used": "Greenhouse-Geisser" if corrected else "None",
        "primary_df_numerator": gg_df_factor if corrected else df_factor,
        "primary_df_denominator": gg_df_error if corrected else df_error,
        "primary_p_value": gg_p if corrected else uncorrected_p,
        "residual_shapiro_statistic": (
            float(residual_shapiro.statistic) if residual_shapiro else None
        ),
        "residual_shapiro_p_value": float(residual_shapiro.pvalue) if residual_shapiro else None,
        "difference_score_shapiro_min_p_value": (
            min(difference_p_values) if difference_p_values else None
        ),
        "difference_score_shapiro_test_count": len(difference_p_values),
        "residual_variance_max_min_ratio": variance_ratio,
    }
