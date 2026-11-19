"""One-factor repeated-measures ANOVA calculations for symmetric RQ1."""

from __future__ import annotations

import math

import numpy as np
from scipy import stats
from scipy.linalg import helmert


def analyze_matrix(matrix: np.ndarray, alpha: float = 0.05) -> dict:
    """Return classical RM-ANOVA, Mauchly/GG, and diagnostic quantities."""
    values = np.asarray(matrix, dtype=float)
    if values.ndim != 2 or values.shape[0] < 3 or values.shape[1] < 3:
        raise ValueError("matrix needs at least three blocks and three factor levels")
    if not np.isfinite(values).all() or not 0 < alpha < 1:
        raise ValueError("matrix must be finite and alpha must lie between zero and one")

    subjects, levels = values.shape
    grand = float(values.mean())
    means = values.mean(axis=0)
    subject_means = values.mean(axis=1)
    residuals = values - means[None, :] - subject_means[:, None] + grand
    ss_factor = subjects * float(np.square(means - grand).sum())
    ss_error = float(np.square(residuals).sum())
    df_factor = levels - 1
    df_error = (subjects - 1) * df_factor
    if ss_error <= 0:
        raise ValueError("ANOVA undefined because repeated-measures error variance is zero")
    f_value = (ss_factor / df_factor) / (ss_error / df_error)
    raw_p = float(stats.f.sf(f_value, df_factor, df_error))
    eta_p = ss_factor / (ss_factor + ss_error)

    contrast = values @ helmert(levels, full=False).T
    covariance = np.atleast_2d(np.cov(contrast, rowvar=False, ddof=1))
    eigenvalues = np.maximum(np.linalg.eigvalsh(covariance), 0.0)
    dimension = levels - 1
    trace = float(eigenvalues.sum())
    square_trace = float(np.square(eigenvalues).sum())
    if trace <= 0 or square_trace <= 0:
        raise ValueError("sphericity diagnostics undefined for zero contrast variance")
    epsilon = min(1.0, max(1.0 / dimension, trace**2 / (dimension * square_trace)))
    sign, log_det = np.linalg.slogdet(covariance)
    if sign <= 0 or not math.isfinite(float(log_det)):
        log_w = math.log(np.finfo(float).tiny)
    else:
        log_w = min(0.0, max(math.log(np.finfo(float).tiny), float(log_det - dimension * math.log(trace / dimension))))
    w = math.exp(log_w)
    correction = 1 - (2 * dimension**2 + dimension + 2) / (6 * dimension * (subjects - 1))
    if correction <= 0:
        raise ValueError("too few blocks for Mauchly's approximation")
    chi2 = max(0.0, -(subjects - 1) * correction * log_w)
    mauchly_df = dimension * (dimension + 1) / 2 - 1
    mauchly_p = float(stats.chi2.sf(chi2, mauchly_df))
    gg_df_factor = epsilon * df_factor
    gg_df_error = epsilon * df_error
    gg_p = float(stats.f.sf(f_value, gg_df_factor, gg_df_error))
    rejected = mauchly_p < alpha

    residual_shapiro = stats.shapiro(residuals.ravel()) if np.ptp(residuals) else None
    difference_p = [
        float(stats.shapiro(values[:, left] - values[:, right]).pvalue)
        for left in range(levels)
        for right in range(left + 1, levels)
        if np.ptp(values[:, left] - values[:, right]) > 0
    ]
    return {
        "blocks": subjects,
        "input_size_levels": levels,
        "ss_input_size": ss_factor,
        "ss_error": ss_error,
        "f_statistic": float(f_value),
        "uncorrected_df_numerator": df_factor,
        "uncorrected_df_denominator": df_error,
        "uncorrected_p_value": raw_p,
        "partial_eta_squared": eta_p,
        "mauchly_w": w,
        "mauchly_chi_square": chi2,
        "mauchly_df": mauchly_df,
        "mauchly_p_value": mauchly_p,
        "greenhouse_geisser_epsilon": epsilon,
        "greenhouse_geisser_df_numerator": gg_df_factor,
        "greenhouse_geisser_df_denominator": gg_df_error,
        "greenhouse_geisser_p_value": gg_p,
        "correction_used": "Greenhouse-Geisser" if rejected else "None",
        "primary_df_numerator": gg_df_factor if rejected else df_factor,
        "primary_df_denominator": gg_df_error if rejected else df_error,
        "primary_p_value": gg_p if rejected else raw_p,
        "sphericity_rejected": rejected,
        "residual_shapiro_statistic": float(residual_shapiro.statistic) if residual_shapiro else None,
        "residual_shapiro_p_value": float(residual_shapiro.pvalue) if residual_shapiro else None,
        "difference_score_shapiro_min_p_value": min(difference_p) if difference_p else None,
        "difference_score_shapiro_test_count": len(difference_p),
    }
