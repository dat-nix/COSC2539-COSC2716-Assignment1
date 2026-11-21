"""Matched descriptive magnitude analysis for the existing RQ3 datasets.

This module performs no inferential tests. It recomputes descriptive metrics from
the authoritative raw observations and copies existing p-values into the output
for context. Output is created in a new directory and is never overwritten.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence


BLOCKS = tuple(range(1, 31))
SIZES = (1024, 10_240, 102_400, 1_048_576, 10_485_760)
SIZE_LABELS = {
    1024: "1 KiB",
    10_240: "10 KiB",
    102_400: "100 KiB",
    1_048_576: "1 MiB",
    10_485_760: "10 MiB",
}
ALPHA = 0.05
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = PROJECT_ROOT / "results/rq3_timing_magnitude_analysis_run_20261121_01"

HASH_VALID = "valid_data_trusted_digest"
HASH_INVALID = (
    "modified_data_checked_against_trusted_digest",
    "modified_data_with_recomputed_unkeyed_digest",
)
SYM_VALID = "valid"
SYM_INVALID = (
    "ciphertext_tampered",
    "authentication_data_tampered",
    "nonce_or_iv_tampered",
    "wrong_key",
    "malformed_envelope",
)
HYBRID_VALID = "valid"
HYBRID_INVALID = (
    "ciphertext_tampered",
    "tag_tampered",
    "key_material_tampered",
    "malformed_envelope_or_public_key",
)


@dataclass(frozen=True)
class CategorySpec:
    category: str
    entity_column: str
    time_column: str
    valid_scenario: str
    invalid_scenarios: tuple[str, ...]
    expected_entities: tuple[str, ...]
    raw_path: str
    paired_path: str
    paired_family_size: int
    raw_row_count: int
    conditions_per_block: int
    raw_test_p_column: str
    holm_test_p_column: str
    test_entity_column: str
    test_baseline_column: str | None = None
    test_comparison_column: str | None = None


SPECS = (
    CategorySpec(
        category="Hashing",
        entity_column="Algorithm",
        time_column="Execution time in seconds",
        valid_scenario=HASH_VALID,
        invalid_scenarios=HASH_INVALID,
        expected_entities=("SHA-256", "SHA3-256", "BLAKE2b-256"),
        raw_path="results/hashing/rq3/tampering_performance/hashing_tampering_performance.csv",
        paired_path="results/hashing/rq3/tampering_performance/hashing_tampering_performance_paired_tests.csv",
        paired_family_size=45,
        raw_row_count=1350,
        conditions_per_block=45,
        raw_test_p_column="Raw p-value",
        holm_test_p_column="Holm adjusted p-value across all comparisons",
        test_entity_column="Algorithm",
        test_baseline_column="Baseline scenario",
        test_comparison_column="Comparison scenario",
    ),
    CategorySpec(
        category="Symmetric",
        entity_column="Algorithm",
        time_column="Total attempted decryption time in seconds",
        valid_scenario=SYM_VALID,
        invalid_scenarios=SYM_INVALID,
        expected_entities=("AES-256-GCM", "ChaCha20-Poly1305", "AES-256-CBC+HMAC-SHA256"),
        raw_path="results/symmetric/rq3/runs/run_20261119_02/symmetric_rq3_verification.csv",
        paired_path="results/symmetric/rq3/analysis/run_20261119_03/symmetric_rq3_paired_tests.csv",
        paired_family_size=75,
        raw_row_count=2700,
        conditions_per_block=90,
        raw_test_p_column="Monte Carlo raw p-value",
        holm_test_p_column="Holm adjusted p-value across 75 comparisons",
        test_entity_column="Algorithm",
    ),
    CategorySpec(
        category="Hybrid",
        entity_column="Scheme",
        time_column="Total attempted decryption time in seconds",
        valid_scenario=HYBRID_VALID,
        invalid_scenarios=HYBRID_INVALID,
        expected_entities=(
            "RSA-OAEP-SHA256+AES-256-GCM",
            "ECDH-P256-HKDF-SHA256+AES-256-GCM",
            "X25519-HKDF-SHA256+AES-256-GCM",
        ),
        raw_path="results/asymmetric/rq3/runs/run_20261119_01/asymmetric_rq3_verification.csv",
        paired_path="results/asymmetric/rq3/analysis/run_20261119_01/asymmetric_rq3_paired_tests.csv",
        paired_family_size=60,
        raw_row_count=2250,
        conditions_per_block=75,
        raw_test_p_column="Randomization p-value (sharp null)",
        holm_test_p_column="Holm adjusted p-value across 60 planned contrasts",
        test_entity_column="Scheme",
    ),
)


CSV_FIELDS = (
    "category",
    "algorithm_or_scheme",
    "input_size_bytes",
    "input_size_label",
    "time_unit",
    "valid_scenario",
    "comparison_scenario",
    "valid_observations",
    "invalid_observations",
    "matched_pairs",
    "valid_mean_seconds",
    "valid_median_seconds",
    "valid_sample_sd_seconds",
    "invalid_mean_seconds",
    "invalid_median_seconds",
    "invalid_sample_sd_seconds",
    "mean_paired_difference_seconds_invalid_minus_valid",
    "median_paired_difference_seconds_invalid_minus_valid",
    "mean_paired_percentage_difference_invalid_over_valid_percent",
    "median_paired_percentage_difference_invalid_over_valid_percent",
    "mean_paired_time_ratio_invalid_over_valid",
    "median_paired_time_ratio_invalid_over_valid",
    "ratio_of_aggregate_means_invalid_over_valid",
    "valid_outcome_summary_json",
    "comparison_outcome_summary_json",
    "comparison_failure_stage_counts_json",
    "existing_test_comparison",
    "existing_test_raw_p_value",
    "existing_test_holm_adjusted_p_value",
    "existing_test_family_size",
    "existing_test_method",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_csv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            raise ValueError(f"CSV has no header: {path}")
        return list(reader.fieldnames), list(reader)


def parse_bool(value: str, *, field: str, row_number: int) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    raise ValueError(f"invalid Boolean {field} on CSV row {row_number}: {value!r}")


def parse_optional_bool(value: str, *, field: str, row_number: int) -> bool | None:
    if value.strip() == "":
        return None
    return parse_bool(value, field=field, row_number=row_number)


def condition_index(
    rows: Sequence[Mapping[str, str]],
    *,
    entity_column: str,
    scenario_column: str = "Scenario",
) -> dict[tuple[int, str, int, str], Mapping[str, str]]:
    """Index one row per (block, entity, size, scenario), rejecting duplicates."""
    result: dict[tuple[int, str, int, str], Mapping[str, str]] = {}
    for row_number, row in enumerate(rows, start=2):
        try:
            key = (
                int(row["Block ID"]),
                row[entity_column],
                int(row["Input size in bytes"]),
                row[scenario_column],
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"invalid condition key on CSV row {row_number}") from error
        if key in result:
            raise ValueError(f"duplicate experimental condition {key}")
        result[key] = row
    return result


def missing_and_extra_keys(
    observed: Iterable[tuple[int, str, int, str]],
    expected: Iterable[tuple[int, str, int, str]],
) -> tuple[list[tuple[int, str, int, str]], list[tuple[int, str, int, str]]]:
    observed_set, expected_set = set(observed), set(expected)
    return sorted(expected_set - observed_set), sorted(observed_set - expected_set)


def paired_metrics(valid_times: Sequence[float], invalid_times: Sequence[float]) -> dict[str, float]:
    """Compute paired magnitude metrics with direction invalid minus valid."""
    if len(valid_times) != len(invalid_times) or not valid_times:
        raise ValueError("paired time vectors must be non-empty and equal in length")
    if any(not math.isfinite(value) for value in (*valid_times, *invalid_times)):
        raise ValueError("paired times must be finite")
    if any(value <= 0 for value in valid_times):
        raise ValueError("percentage and ratio metrics require strictly positive valid times")
    if any(value <= 0 for value in invalid_times):
        raise ValueError("execution times must be strictly positive")

    differences = [invalid - valid for valid, invalid in zip(valid_times, invalid_times)]
    percentages = [100.0 * difference / valid for valid, difference in zip(valid_times, differences)]
    ratios = [invalid / valid for valid, invalid in zip(valid_times, invalid_times)]
    valid_mean = statistics.mean(valid_times)
    invalid_mean = statistics.mean(invalid_times)
    return {
        "valid_mean": valid_mean,
        "valid_median": statistics.median(valid_times),
        "valid_sample_sd": statistics.stdev(valid_times),
        "invalid_mean": invalid_mean,
        "invalid_median": statistics.median(invalid_times),
        "invalid_sample_sd": statistics.stdev(invalid_times),
        "mean_difference": statistics.mean(differences),
        "median_difference": statistics.median(differences),
        "mean_percentage_difference": statistics.mean(percentages),
        "median_percentage_difference": statistics.median(percentages),
        "mean_paired_ratio": statistics.mean(ratios),
        "median_paired_ratio": statistics.median(ratios),
        "ratio_aggregate_means": invalid_mean / valid_mean,
    }


def _required_columns(spec: CategorySpec) -> set[str]:
    common = {
        spec.entity_column,
        "Input size in bytes",
        "Scenario",
        "Block ID",
        "Randomized position within block",
        "Repetition number",
        spec.time_column,
    }
    if spec.category == "Hashing":
        common |= {
            "Input identifier",
            "Original input identifier",
            "Modified input identifier",
            "Verification passed",
            "Tampering detected",
        }
    elif spec.category == "Symmetric":
        common |= {
            "Input identifier",
            "Accepted",
            "Authentication succeeded",
            "Plaintext released",
            "Failure category",
        }
    else:
        common |= {
            "Input identifier",
            "Accepted",
            "Failure stage",
            "Session key unwrapped",
            "Key agreement completed",
            "HKDF completed",
            "AES-GCM verification reached",
            "Plaintext released",
        }
    return common


def _validate_inputs(spec: CategorySpec, rows: Sequence[Mapping[str, str]]) -> dict:
    if len(rows) != spec.raw_row_count:
        raise ValueError(f"{spec.category}: expected {spec.raw_row_count} raw rows, got {len(rows)}")
    entities = set(spec.expected_entities)
    scenarios = {spec.valid_scenario, *spec.invalid_scenarios}
    expected = set(itertools.product(BLOCKS, spec.expected_entities, SIZES, sorted(scenarios)))
    index = condition_index(rows, entity_column=spec.entity_column)
    missing, extra = missing_and_extra_keys(index, expected)
    if missing or extra:
        raise ValueError(
            f"{spec.category}: incomplete or unexpected conditions; "
            f"missing={missing[:5]}, extra={extra[:5]}"
        )

    position_counts: Counter[int] = Counter()
    positions_by_block: dict[int, set[int]] = defaultdict(set)
    entity_coverage: set[str] = set()
    scenario_coverage: set[str] = set()
    size_coverage: set[int] = set()
    for row_number, row in enumerate(rows, start=2):
        entity = row[spec.entity_column]
        scenario = row["Scenario"]
        block = int(row["Block ID"])
        size = int(row["Input size in bytes"])
        position = int(row["Randomized position within block"])
        repetition = int(row["Repetition number"])
        timing = float(row[spec.time_column])
        if entity not in entities or scenario not in scenarios or size not in SIZES or block not in BLOCKS:
            raise ValueError(f"unexpected category label on {spec.category} CSV row {row_number}")
        # These runners record the block index in the repetition field; each
        # block-condition key is still unique and contributes one observation.
        if repetition != block:
            raise ValueError(
                f"repetition number does not match block ID on {spec.category} CSV row {row_number}"
            )
        if not math.isfinite(timing) or timing <= 0:
            raise ValueError(f"non-positive or non-finite timing on {spec.category} CSV row {row_number}")
        if position < 1 or position > spec.conditions_per_block:
            raise ValueError(f"randomized position outside block on {spec.category} CSV row {row_number}")
        if position in positions_by_block[block]:
            raise ValueError(f"duplicate randomized position {position} in {spec.category} block {block}")
        positions_by_block[block].add(position)
        position_counts[position] += 1
        entity_coverage.add(entity)
        scenario_coverage.add(scenario)
        size_coverage.add(size)

    for block in BLOCKS:
        expected_positions = set(range(1, spec.conditions_per_block + 1))
        if positions_by_block[block] != expected_positions:
            raise ValueError(f"incomplete randomized positions in {spec.category} block {block}")

    input_id_checks = _validate_input_identifiers(spec, rows)
    outcome_summary = _validate_outcomes(spec, rows)
    stage_counts = _failure_stage_counts(spec, rows)
    return {
        "raw_row_count": len(rows),
        "blocks": list(BLOCKS),
        "block_count": len(BLOCKS),
        "conditions_per_block": spec.conditions_per_block,
        "expected_condition_count": len(expected),
        "unique_condition_count": len(index),
        "duplicate_condition_count": 0,
        "missing_condition_count": 0,
        "extra_condition_count": 0,
        "algorithm_or_scheme_coverage": sorted(entity_coverage),
        "input_sizes_bytes": sorted(size_coverage),
        "scenario_coverage": sorted(scenario_coverage),
        "randomized_positions_complete_per_block": True,
        "input_identifier_validation": input_id_checks,
        "outcome_validation": outcome_summary,
        "failure_stage_counts_by_entity_scenario": stage_counts,
    }


def _validate_input_identifiers(spec: CategorySpec, rows: Sequence[Mapping[str, str]]) -> dict:
    by_block_size: dict[tuple[int, int], list[Mapping[str, str]]] = defaultdict(list)
    for row in rows:
        by_block_size[(int(row["Block ID"]), int(row["Input size in bytes"]))].append(row)

    mismatch_count = 0
    checked_group_count = 0
    for group in by_block_size.values():
        checked_group_count += 1
        if spec.category == "Hashing":
            original_ids = {row["Original input identifier"] for row in group}
            modified_ids = {row["Modified input identifier"] for row in group}
            if len(original_ids) != 1 or len(modified_ids) != 1:
                mismatch_count += 1
                continue
            original_id = next(iter(original_ids))
            modified_id = next(iter(modified_ids))
            for row in group:
                expected_id = original_id if row["Scenario"] == HASH_VALID else modified_id
                if row["Input identifier"] != expected_id:
                    mismatch_count += 1
        else:
            if len({row["Input identifier"] for row in group}) != 1:
                mismatch_count += 1
    if mismatch_count:
        raise ValueError(f"{spec.category}: input identifiers differ across matched algorithms/scenarios")
    return {
        "matched_block_size_groups_checked": checked_group_count,
        "input_identifier_mismatch_groups": mismatch_count,
        "shared_input_identity_across_algorithms_verified": True,
    }


def _validate_outcomes(spec: CategorySpec, rows: Sequence[Mapping[str, str]]) -> dict:
    counts: dict[str, dict[str, int]] = {}
    for scenario in sorted({spec.valid_scenario, *spec.invalid_scenarios}):
        selected = [row for row in rows if row["Scenario"] == scenario]
        if spec.category == "Hashing":
            for row_number, row in enumerate(selected, start=2):
                passed = parse_bool(row["Verification passed"], field="Verification passed", row_number=row_number)
                detected = parse_bool(row["Tampering detected"], field="Tampering detected", row_number=row_number)
                expected_passed = scenario != "modified_data_checked_against_trusted_digest"
                expected_detected = scenario == "modified_data_checked_against_trusted_digest"
                if passed != expected_passed or detected != expected_detected:
                    raise ValueError(f"Hashing outcome mismatch for scenario {scenario}")
            counts[scenario] = {
                "observations": len(selected),
                "verification_passed": sum(parse_bool(row["Verification passed"], field="Verification passed", row_number=2) for row in selected),
                "tampering_detected": sum(parse_bool(row["Tampering detected"], field="Tampering detected", row_number=2) for row in selected),
            }
        elif spec.category == "Symmetric":
            expected_valid = scenario == SYM_VALID
            for row in selected:
                row_number = 2
                accepted = parse_bool(row["Accepted"], field="Accepted", row_number=row_number)
                authenticated = parse_bool(row["Authentication succeeded"], field="Authentication succeeded", row_number=row_number)
                released = parse_bool(row["Plaintext released"], field="Plaintext released", row_number=row_number)
                expected_stage = "" if expected_valid else ("envelope_validation" if scenario == "malformed_envelope" else "authentication")
                if (accepted, authenticated, released) != (expected_valid, expected_valid, expected_valid):
                    raise ValueError(f"Symmetric acceptance/authentication/plaintext outcome mismatch for {scenario}")
                if row["Failure category"] != expected_stage:
                    raise ValueError(f"Symmetric failure category mismatch for {scenario}: {row['Failure category']!r}")
            counts[scenario] = {
                "observations": len(selected),
                "accepted": sum(row["Accepted"].strip().lower() == "true" for row in selected),
                "authentication_succeeded": sum(row["Authentication succeeded"].strip().lower() == "true" for row in selected),
                "plaintext_released": sum(row["Plaintext released"].strip().lower() == "true" for row in selected),
            }
        else:
            for row in selected:
                valid = scenario == HYBRID_VALID
                accepted = parse_bool(row["Accepted"], field="Accepted", row_number=2)
                released = parse_bool(row["Plaintext released"], field="Plaintext released", row_number=2)
                if accepted != valid or released != valid:
                    raise ValueError(f"Hybrid acceptance/plaintext outcome mismatch for {scenario}")
                scheme = row["Scheme"]
                if valid:
                    expected_stage = ""
                elif scenario in {"ciphertext_tampered", "tag_tampered"}:
                    expected_stage = "aes_gcm_authentication"
                elif scenario == "key_material_tampered":
                    expected_stage = "rsa_oaep_unwrap" if scheme.startswith("RSA-") else "aes_gcm_authentication"
                else:
                    expected_stage = "envelope_validation" if scheme.startswith("RSA-") else "public_key_parse"
                if row["Failure stage"] != expected_stage:
                    raise ValueError(f"Hybrid failure stage mismatch for {scheme} {scenario}: {row['Failure stage']!r}")

                unwrapped = parse_optional_bool(row["Session key unwrapped"], field="Session key unwrapped", row_number=2)
                agreement = parse_optional_bool(row["Key agreement completed"], field="Key agreement completed", row_number=2)
                hkdf = parse_optional_bool(row["HKDF completed"], field="HKDF completed", row_number=2)
                gcm_reached = parse_bool(row["AES-GCM verification reached"], field="AES-GCM verification reached", row_number=2)
                if scheme.startswith("RSA-"):
                    expected_unwrapped = valid or scenario in {"ciphertext_tampered", "tag_tampered"}
                    if unwrapped != expected_unwrapped or agreement is not None or hkdf is not None:
                        raise ValueError(f"Hybrid RSA key-processing flags mismatch for {scenario}")
                    expected_gcm = expected_unwrapped and scenario != "malformed_envelope_or_public_key"
                else:
                    if unwrapped is not None:
                        raise ValueError(f"unexpected RSA key unwrap flag for {scheme}")
                    expected_agreement = valid or scenario in {"ciphertext_tampered", "tag_tampered", "key_material_tampered"}
                    if agreement != expected_agreement or hkdf != expected_agreement:
                        raise ValueError(f"Hybrid agreement/HKDF flags mismatch for {scheme} {scenario}")
                    expected_gcm = expected_agreement
                if gcm_reached != expected_gcm:
                    raise ValueError(f"Hybrid GCM-reached flag mismatch for {scheme} {scenario}")
            counts[scenario] = {
                "observations": len(selected),
                "accepted": sum(row["Accepted"].strip().lower() == "true" for row in selected),
                "plaintext_released": sum(row["Plaintext released"].strip().lower() == "true" for row in selected),
            }
    result = {
        "scenario_outcomes": counts,
    }
    if "Plaintext released" in rows[0]:
        result["invalid_observations_releasing_plaintext"] = sum(
            parse_bool(row["Plaintext released"], field="Plaintext released", row_number=2)
            for row in rows
            if row["Scenario"] != spec.valid_scenario
        )
    return result


def _failure_stage_counts(spec: CategorySpec, rows: Sequence[Mapping[str, str]]) -> dict:
    stage_column = "Failure category" if spec.category == "Symmetric" else "Failure stage"
    if stage_column not in rows[0]:
        return {}
    counts: dict[str, dict[str, int]] = {}
    for entity in spec.expected_entities:
        for scenario in spec.invalid_scenarios:
            group = [row for row in rows if row[spec.entity_column] == entity and row["Scenario"] == scenario]
            counts[f"{entity}|{scenario}"] = dict(sorted(Counter(row[stage_column] or "none" for row in group).items()))
    return counts


def _float(row: Mapping[str, str], column: str, *, source: str) -> float:
    try:
        value = float(row[column])
    except (KeyError, ValueError) as error:
        raise ValueError(f"missing or invalid {column!r} in {source}") from error
    if not math.isfinite(value):
        raise ValueError(f"non-finite {column!r} in {source}")
    return value


def _index_existing_tests(
    spec: CategorySpec, rows: Sequence[Mapping[str, str]], expected_comparison_keys: set[tuple[str, int, str]]
) -> tuple[dict[tuple[str, int, str], Mapping[str, str]], dict]:
    if len(rows) != spec.paired_family_size:
        raise ValueError(f"{spec.category}: expected {spec.paired_family_size} existing paired-test rows, got {len(rows)}")
    index: dict[tuple[str, int, str], Mapping[str, str]] = {}
    non_valid_hash_rows = 0
    for row in rows:
        entity = row[spec.test_entity_column]
        size = int(row["Input size in bytes"])
        scenario = row["Invalid scenario"] if spec.category != "Hashing" else row[spec.test_comparison_column]
        if spec.category == "Hashing":
            if row[spec.test_baseline_column] != HASH_VALID:
                if row["Comparison"] == "trusted_rejection_vs_attacker_recomputed":
                    non_valid_hash_rows += 1
                    continue
                raise ValueError("unexpected Hashing paired-test baseline")
            if scenario not in HASH_INVALID:
                raise ValueError(f"unexpected Hashing valid-baseline comparison scenario: {scenario}")
        key = (entity, size, scenario)
        if key in index:
            raise ValueError(f"duplicate existing paired-test row {key} for {spec.category}")
        index[key] = row
        if int(row["Paired blocks"] if spec.category == "Hashing" else row["Matched blocks"]) != len(BLOCKS):
            raise ValueError(f"existing paired test does not have 30 matched blocks: {spec.category} {key}")
        for p_column in (spec.raw_test_p_column, spec.holm_test_p_column):
            p_value = _float(row, p_column, source=f"{spec.category} paired tests")
            if not 0.0 <= p_value <= 1.0:
                raise ValueError(f"p-value outside [0,1] in {spec.category}: {key}")

    if set(index) != expected_comparison_keys:
        missing = sorted(expected_comparison_keys - set(index))
        extra = sorted(set(index) - expected_comparison_keys)
        raise ValueError(f"{spec.category}: paired-test coverage mismatch; missing={missing[:5]}, extra={extra[:5]}")
    if spec.category == "Hashing" and non_valid_hash_rows != 15:
        raise ValueError(f"Hashing: expected 15 trusted-tamper-versus-recomputed comparisons, got {non_valid_hash_rows}")

    adjusted_column = spec.holm_test_p_column
    significant = sum(_float(row, adjusted_column, source=spec.category) < ALPHA for row in rows)
    return index, {
        "existing_paired_test_rows": len(rows),
        "valid_versus_invalid_rows_joined": len(index),
        "non_valid_hash_contrasts_excluded_from_magnitude_csv": non_valid_hash_rows,
        "holm_family_size": spec.paired_family_size,
        "holm_significant_count_at_alpha_0_05": significant,
        "holm_significant_fraction": f"{significant}/{spec.paired_family_size}",
        "p_values_recalculated": False,
    }


def _check_existing_descriptives(
    spec: CategorySpec,
    existing: Mapping[str, str],
    metrics: Mapping[str, float],
) -> None:
    if spec.category == "Hashing":
        columns = {
            "Mean baseline time (seconds)": metrics["valid_mean"],
            "Mean comparison time (seconds)": metrics["invalid_mean"],
            "Mean paired difference (seconds; comparison minus baseline)": metrics["mean_difference"],
            "Median paired difference (seconds)": metrics["median_difference"],
            "Mean paired percentage difference": metrics["mean_percentage_difference"],
            "Median paired percentage difference": metrics["median_percentage_difference"],
        }
    else:
        columns = {
            "Valid mean seconds" if spec.category == "Symmetric" else "Mean valid seconds": metrics["valid_mean"],
            "Invalid mean seconds" if spec.category == "Symmetric" else "Mean invalid seconds": metrics["invalid_mean"],
            "Mean paired difference seconds" if spec.category == "Symmetric" else "Mean paired difference seconds (invalid - valid)": metrics["mean_difference"],
            "Median paired difference seconds": metrics["median_difference"],
            "Mean matched percentage difference" if spec.category == "Symmetric" else "Mean paired percentage difference": metrics["mean_percentage_difference"],
            "Median matched percentage difference" if spec.category == "Symmetric" else "Median paired percentage difference": metrics["median_percentage_difference"],
        }
    for column, calculated in columns.items():
        observed = _float(existing, column, source=f"{spec.category} existing paired output")
        if not math.isclose(calculated, observed, rel_tol=1e-8, abs_tol=1e-12):
            raise ValueError(
                f"{spec.category}: recomputed descriptive value differs from existing output "
                f"for {column}: calculated={calculated!r}, existing={observed!r}"
            )


def _outcome_summary(spec: CategorySpec, group: Sequence[Mapping[str, str]]) -> dict:
    if spec.category == "Hashing":
        return {
            "verification_passed": sum(row["Verification passed"].strip().lower() == "true" for row in group),
            "tampering_detected": sum(row["Tampering detected"].strip().lower() == "true" for row in group),
        }
    if spec.category == "Symmetric":
        return {
            "accepted": sum(row["Accepted"].strip().lower() == "true" for row in group),
            "authentication_succeeded": sum(row["Authentication succeeded"].strip().lower() == "true" for row in group),
            "plaintext_released": sum(row["Plaintext released"].strip().lower() == "true" for row in group),
        }
    return {
        "accepted": sum(row["Accepted"].strip().lower() == "true" for row in group),
        "plaintext_released": sum(row["Plaintext released"].strip().lower() == "true" for row in group),
    }


def _stage_summary(spec: CategorySpec, group: Sequence[Mapping[str, str]]) -> dict:
    column = "Failure category" if spec.category == "Symmetric" else "Failure stage"
    if column not in group[0]:
        return {}
    return dict(sorted(Counter(row[column] or "none" for row in group).items()))


def _analysis_rows(
    spec: CategorySpec,
    raw_rows: Sequence[Mapping[str, str]],
    condition_rows: Mapping[tuple[int, str, int, str], Mapping[str, str]],
    test_rows: Mapping[tuple[str, int, str], Mapping[str, str]],
) -> list[dict]:
    output: list[dict] = []
    for entity in spec.expected_entities:
        for size in SIZES:
            valid_group = [
                condition_rows[(block, entity, size, spec.valid_scenario)]
                for block in BLOCKS
            ]
            valid_times = [float(row[spec.time_column]) for row in valid_group]
            valid_summary = {
                "observations": len(valid_group),
                **_outcome_summary(spec, valid_group),
            }
            for scenario in spec.invalid_scenarios:
                invalid_group = [condition_rows[(block, entity, size, scenario)] for block in BLOCKS]
                invalid_times = [float(row[spec.time_column]) for row in invalid_group]
                metrics = paired_metrics(valid_times, invalid_times)
                existing = test_rows[(entity, size, scenario)]
                _check_existing_descriptives(spec, existing, metrics)
                if spec.category == "Hashing":
                    method = existing["Statistical test"]
                    test_comparison = existing["Comparison"]
                elif spec.category == "Symmetric":
                    method = "Conditional within-block label-swap randomization test (existing output)"
                    test_comparison = f"{scenario}_vs_valid"
                else:
                    method = "Conditional within-block label-swap randomization test (existing output)"
                    test_comparison = f"{scenario}_vs_valid"

                output.append({
                    "category": spec.category,
                    "algorithm_or_scheme": entity,
                    "input_size_bytes": size,
                    "input_size_label": SIZE_LABELS[size],
                    "time_unit": "seconds",
                    "valid_scenario": spec.valid_scenario,
                    "comparison_scenario": scenario,
                    "valid_observations": len(valid_times),
                    "invalid_observations": len(invalid_times),
                    "matched_pairs": len(valid_times),
                    "valid_mean_seconds": metrics["valid_mean"],
                    "valid_median_seconds": metrics["valid_median"],
                    "valid_sample_sd_seconds": metrics["valid_sample_sd"],
                    "invalid_mean_seconds": metrics["invalid_mean"],
                    "invalid_median_seconds": metrics["invalid_median"],
                    "invalid_sample_sd_seconds": metrics["invalid_sample_sd"],
                    "mean_paired_difference_seconds_invalid_minus_valid": metrics["mean_difference"],
                    "median_paired_difference_seconds_invalid_minus_valid": metrics["median_difference"],
                    "mean_paired_percentage_difference_invalid_over_valid_percent": metrics["mean_percentage_difference"],
                    "median_paired_percentage_difference_invalid_over_valid_percent": metrics["median_percentage_difference"],
                    "mean_paired_time_ratio_invalid_over_valid": metrics["mean_paired_ratio"],
                    "median_paired_time_ratio_invalid_over_valid": metrics["median_paired_ratio"],
                    "ratio_of_aggregate_means_invalid_over_valid": metrics["ratio_aggregate_means"],
                    "valid_outcome_summary_json": json.dumps(valid_summary, sort_keys=True, separators=(",", ":")),
                    "comparison_outcome_summary_json": json.dumps(_outcome_summary(spec, invalid_group), sort_keys=True, separators=(",", ":")),
                    "comparison_failure_stage_counts_json": json.dumps(_stage_summary(spec, invalid_group), sort_keys=True, separators=(",", ":")),
                    "existing_test_comparison": test_comparison,
                    "existing_test_raw_p_value": _float(existing, spec.raw_test_p_column, source=f"{spec.category} paired tests"),
                    "existing_test_holm_adjusted_p_value": _float(existing, spec.holm_test_p_column, source=f"{spec.category} paired tests"),
                    "existing_test_family_size": spec.paired_family_size,
                    "existing_test_method": method,
                })
    return output


def _load_category(root: Path, spec: CategorySpec) -> tuple[list[dict[str, str]], list[dict[str, str]], dict, dict]:
    raw_path = root / spec.raw_path
    paired_path = root / spec.paired_path
    if not raw_path.is_file():
        raise FileNotFoundError(f"required authoritative raw file is missing: {raw_path}")
    if not paired_path.is_file():
        raise FileNotFoundError(f"required existing paired-test file is missing: {paired_path}")
    raw_fields, raw_rows = read_csv(raw_path)
    missing_columns = _required_columns(spec) - set(raw_fields)
    if missing_columns:
        raise ValueError(f"{spec.category} raw CSV missing columns: {sorted(missing_columns)}")
    paired_fields, paired_rows = read_csv(paired_path)
    needed = {
        spec.test_entity_column,
        "Input size in bytes",
        spec.raw_test_p_column,
        spec.holm_test_p_column,
        "Matched blocks" if spec.category != "Hashing" else "Paired blocks",
    }
    if spec.category == "Hashing":
        needed |= {"Comparison", spec.test_baseline_column, spec.test_comparison_column, "Statistical test"}
    else:
        needed.add("Invalid scenario")
    missing_test_columns = needed - set(paired_fields)
    if missing_test_columns:
        raise ValueError(f"{spec.category} paired-test CSV missing columns: {sorted(missing_test_columns)}")
    raw_validation = _validate_inputs(spec, raw_rows)
    return raw_rows, paired_rows, raw_validation, {
        "raw_path": spec.raw_path,
        "raw_sha256": sha256_file(raw_path),
        "raw_row_count": len(raw_rows),
        "paired_test_path": spec.paired_path,
        "paired_test_sha256": sha256_file(paired_path),
        "paired_test_row_count": len(paired_rows),
    }


def _verify_run_linkage(root: Path, file_inventory: Mapping[str, dict]) -> dict:
    checks: dict[str, dict] = {}
    for category, summary_path, raw_key in (
        ("Symmetric", "results/symmetric/rq3/analysis/run_20261119_03/symmetric_rq3_summary.json", "Symmetric"),
        ("Hybrid", "results/asymmetric/rq3/analysis/run_20261119_01/asymmetric_rq3_summary.json", "Hybrid"),
    ):
        path = root / summary_path
        if not path.is_file():
            raise FileNotFoundError(f"required linkage summary missing: {path}")
        summary = json.loads(path.read_text(encoding="utf-8"))
        raw_hash_key = "raw_csv_sha256"
        expected_hash = file_inventory[raw_key]["raw_sha256"]
        observed_hash = summary.get(raw_hash_key)
        observed_path = summary.get("raw_csv")
        if observed_hash != expected_hash:
            raise ValueError(f"{category} existing analysis summary raw hash does not match selected raw CSV")
        if observed_path is not None and observed_path != file_inventory[raw_key]["raw_path"]:
            raise ValueError(f"{category} existing analysis summary references a different raw path")
        checks[category] = {
            "summary_path": summary_path,
            "summary_raw_path": observed_path,
            "summary_records_raw_path": observed_path is not None,
            "summary_raw_sha256": observed_hash,
            "matches_selected_authoritative_raw": observed_hash == expected_hash,
        }
    return checks


def analyze(root: Path, output_dir: Path) -> tuple[list[dict], dict]:
    """Validate and analyze authoritative inputs, then write new outputs."""
    root = root.resolve()
    output_dir = (root / output_dir).resolve() if not output_dir.is_absolute() else output_dir.resolve()
    try:
        output_dir.relative_to(root)
    except ValueError as error:
        raise ValueError("output directory must be inside the project root") from error
    if output_dir.exists():
        raise FileExistsError(f"refusing to overwrite existing output directory: {output_dir}")

    loaded: dict[str, tuple[list[dict[str, str]], list[dict[str, str]], dict, dict]] = {}
    file_inventory: dict[str, dict] = {}
    for spec in SPECS:
        raw_rows, paired_rows, raw_validation, file_info = _load_category(root, spec)
        loaded[spec.category] = raw_rows, paired_rows, raw_validation, file_info
        file_inventory[spec.category] = file_info

    linkage = _verify_run_linkage(root, file_inventory)
    outputs: list[dict] = []
    categories_validation: dict[str, dict] = {}
    for spec in SPECS:
        raw_rows, existing_rows, raw_validation, _ = loaded[spec.category]
        conditions = condition_index(raw_rows, entity_column=spec.entity_column)
        expected_keys = {
            (entity, size, scenario)
            for entity in spec.expected_entities
            for size in SIZES
            for scenario in spec.invalid_scenarios
        }
        existing_index, inferential_validation = _index_existing_tests(spec, existing_rows, expected_keys)
        category_rows = _analysis_rows(spec, raw_rows, conditions, existing_index)
        outputs.extend(category_rows)
        categories_validation[spec.category] = {
            **raw_validation,
            "magnitude_comparison_rows": len(category_rows),
            "matched_pairs_per_comparison": {"minimum": 30, "maximum": 30, "expected": 30},
            "existing_inferential_output": inferential_validation,
        }

    expected_total = 30 + 75 + 60
    if len(outputs) != expected_total:
        raise ValueError(f"expected {expected_total} valid-versus-invalid magnitude rows, got {len(outputs)}")

    output_dir.mkdir(parents=True, exist_ok=False)
    csv_path = output_dir / "rq3_valid_invalid_timing_magnitude.csv"
    json_path = output_dir / "rq3_valid_invalid_timing_validation.json"
    with csv_path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(outputs)

    validation = {
        "analysis": "Descriptive matched magnitude analysis of existing RQ3 valid-versus-specified-invalid processing timings",
        "script": "analysis/rq3_timing_magnitude_analysis.py",
        "input_files": file_inventory,
        "run_linkage_checks": linkage,
        "design_validation": categories_validation,
        "output": {
            "csv_path": str(csv_path.relative_to(root)),
            "validation_json_path": str(json_path.relative_to(root)),
            "csv_sha256": sha256_file(csv_path),
            "row_count": len(outputs),
            "rows_by_category": dict(Counter(row["category"] for row in outputs)),
        },
        "formulas": {
            "paired_direction": "invalid - valid",
            "paired_difference": "invalid_time_i - valid_time_i",
            "paired_percentage_difference": "100 * (invalid_time_i - valid_time_i) / valid_time_i",
            "paired_time_ratio": "invalid_time_i / valid_time_i",
            "aggregate_mean_ratio": "mean(invalid_time) / mean(valid_time); distinct from mean of paired ratios",
            "descriptive_sd": "sample standard deviation (ddof=1)",
            "undefined_denominator_handling": "No timing rows are dropped. Non-positive valid or invalid times cause validation to stop before outputs are written.",
        },
        "inferential_results": {
            "new_significance_tests_run": False,
            "existing_raw_and_holm_adjusted_p_values": "Copied from the specified existing paired-test CSVs without recalculation.",
        },
        "limitations": [
            "The same valid observation is reused in several scenario contrasts for each algorithm/scheme and size; those planned contrasts are correlated. Holm adjustment addresses multiplicity but does not make the contrasts independent.",
            "The output describes complete timed workflows, not isolated primitive or authentication costs.",
            "Hashing's attacker-recomputed-digest scenario is a modified-data verification path that passes; attacker-side digest generation was outside the timer.",
            "Existing dependence and assignment caveats remain applicable; no new inferential conclusion is made here.",
        ],
    }
    with json_path.open("x", encoding="utf-8") as stream:
        json.dump(validation, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return outputs, validation


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT, help="new output directory; existing paths are never overwritten")
    args = parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    rows, validation = analyze(root, args.output_dir)
    print(f"Validated and wrote {len(rows)} matched descriptive contrasts.")
    print(f"Magnitude CSV: {validation['output']['csv_path']}")
    print(f"Validation JSON: {validation['output']['validation_json_path']}")
    for category, summary in validation["design_validation"].items():
        print(
            f"{category}: {summary['raw_row_count']} raw rows; "
            f"{summary['unique_condition_count']} unique conditions; "
            f"{summary['magnitude_comparison_rows']} magnitude rows; "
            f"{summary['existing_inferential_output']['holm_significant_fraction']} Holm-significant existing tests"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
