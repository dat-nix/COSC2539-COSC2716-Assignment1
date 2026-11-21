"""Matched descriptive comparisons for the authoritative RQ1 benchmark data.

This analysis is descriptive only. It matches observations within block, input
size, and operation, and never performs inferential statistical tests.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import math
import statistics
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


INPUT_SIZES = (1024, 10_240, 102_400, 1_048_576, 10_485_760)
BLOCK_IDS = tuple(range(1, 31))
MIB_BYTES = 1024 * 1024

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "results" / "rq1_matched_comparisons"


@dataclass(frozen=True)
class DatasetSpec:
    category: str
    path: Path
    algorithm_column: str
    algorithms: tuple[str, ...]
    operations: tuple[str, ...]
    operation_column: str | None

    @property
    def expected_rows(self) -> int:
        return len(BLOCK_IDS) * len(INPUT_SIZES) * len(self.algorithms) * len(self.operations)

    @property
    def conditions_per_block(self) -> int:
        return len(INPUT_SIZES) * len(self.algorithms) * len(self.operations)


DEFAULT_SPECS = (
    DatasetSpec(
        category="Hashing",
        path=PROJECT_ROOT
        / "results/hashing/rq1/randomized_block/hashing_randomized_block_benchmarks.csv",
        algorithm_column="Algorithm",
        algorithms=("SHA-256", "SHA3-256", "BLAKE2b-256"),
        operations=("digest",),
        operation_column=None,
    ),
    DatasetSpec(
        category="Symmetric",
        path=PROJECT_ROOT
        / "results/symmetric/rq1/runs/run_20261119_01/symmetric_rq1_benchmarks.csv",
        algorithm_column="Algorithm",
        algorithms=(
            "AES-256-GCM",
            "ChaCha20-Poly1305",
            "AES-256-CBC+HMAC-SHA256",
        ),
        operations=("encrypt", "decrypt"),
        operation_column="Operation",
    ),
    DatasetSpec(
        category="Hybrid",
        path=PROJECT_ROOT
        / "results/asymmetric/rq1/runs/run_20261119_01/asymmetric_rq1_benchmarks.csv",
        algorithm_column="Scheme",
        algorithms=(
            "RSA-OAEP-SHA256+AES-256-GCM",
            "ECDH-P256-HKDF-SHA256+AES-256-GCM",
            "X25519-HKDF-SHA256+AES-256-GCM",
        ),
        operations=("encrypt", "decrypt"),
        operation_column="Operation",
    ),
)

DESCRIPTIVE_FIELDS = (
    "Category",
    "Algorithm or scheme",
    "Operation",
    "Input size (bytes)",
    "Input size label",
    "Matched blocks",
    "Mean execution time (seconds)",
    "Median execution time (seconds)",
    "Sample standard deviation (seconds)",
    "Minimum execution time (seconds)",
    "Maximum execution time (seconds)",
    "Effective payload throughput from mean time (MiB/s)",
)

PAIRWISE_FIELDS = (
    "Category",
    "Operation",
    "Input size (bytes)",
    "Input size label",
    "Algorithm A",
    "Algorithm B",
    "Contrast direction",
    "Matched blocks",
    "Mean paired time difference A-B (seconds)",
    "Median paired time difference A-B (seconds)",
    "Mean paired time ratio A/B",
    "Median paired time ratio A/B",
    "Mean paired percentage difference (%, 100*(A-B)/B)",
    "Median paired percentage difference (%, 100*(A-B)/B)",
)


def size_label(size_bytes: int) -> str:
    labels = {
        1024: "1 KiB",
        10_240: "10 KiB",
        102_400: "100 KiB",
        1_048_576: "1 MiB",
        10_485_760: "10 MiB",
    }
    return labels[size_bytes]


def _read_rows(spec: DatasetSpec) -> tuple[list[dict], str, tuple[str, ...]]:
    raw_bytes = spec.path.read_bytes()
    with spec.path.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        fieldnames = tuple(reader.fieldnames or ())
        required = {
            spec.algorithm_column,
            "Input size in bytes",
            "Block ID",
            "Randomized position within block",
            "Repetition number",
            "Execution time in seconds",
            "Input identifier",
        }
        if spec.operation_column:
            required.add(spec.operation_column)
        missing_fields = sorted(required - set(fieldnames))
        if missing_fields:
            raise ValueError(f"{spec.category}: missing CSV columns: {missing_fields}")

        rows = []
        for line_number, raw in enumerate(reader, start=2):
            try:
                algorithm = raw[spec.algorithm_column]
                operation = raw[spec.operation_column] if spec.operation_column else "digest"
                row = {
                    "algorithm": algorithm,
                    "operation": operation,
                    "size": int(raw["Input size in bytes"]),
                    "block": int(raw["Block ID"]),
                    "position": int(raw["Randomized position within block"]),
                    "repetition": int(raw["Repetition number"]),
                    "seconds": float(raw["Execution time in seconds"]),
                    "input_identifier": raw["Input identifier"],
                }
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError(
                    f"{spec.category}: invalid value on CSV row {line_number}"
                ) from error
            if not math.isfinite(row["seconds"]) or row["seconds"] <= 0:
                raise ValueError(
                    f"{spec.category}: execution time must be finite and positive "
                    f"on CSV row {line_number}"
                )
            rows.append(row)

    return rows, hashlib.sha256(raw_bytes).hexdigest(), fieldnames


def validate_rows(spec: DatasetSpec, rows: list[dict]) -> dict:
    """Validate the complete block layout and shared input identifiers."""
    expected = {
        (block, size, operation, algorithm)
        for block in BLOCK_IDS
        for size in INPUT_SIZES
        for operation in spec.operations
        for algorithm in spec.algorithms
    }
    keys = [
        (row["block"], row["size"], row["operation"], row["algorithm"])
        for row in rows
    ]
    duplicates = len(keys) - len(set(keys))
    actual = set(keys)
    missing = expected - actual
    unexpected = actual - expected
    if duplicates or missing or unexpected or len(rows) != spec.expected_rows:
        raise ValueError(
            f"{spec.category}: incomplete/duplicate design; rows={len(rows)} "
            f"expected={spec.expected_rows}, duplicate_keys={duplicates}, "
            f"missing={len(missing)}, unexpected={len(unexpected)}"
        )

    position_rows: dict[int, list[int]] = {block: [] for block in BLOCK_IDS}
    repetition_errors = []
    identifiers: dict[tuple[int, int], set[str]] = {}
    for row in rows:
        block = row["block"]
        position_rows[block].append(row["position"])
        if row["repetition"] != block:
            repetition_errors.append((block, row["repetition"]))
        if not row["input_identifier"]:
            raise ValueError(f"{spec.category}: empty input identifier")
        identifiers.setdefault((block, row["size"]), set()).add(row["input_identifier"])

    expected_positions = list(range(1, spec.conditions_per_block + 1))
    for block, positions in position_rows.items():
        if sorted(positions) != expected_positions:
            raise ValueError(
                f"{spec.category}: block {block} does not have each randomized "
                "position exactly once"
            )
    if repetition_errors:
        raise ValueError(f"{spec.category}: repetition number differs from block ID")
    nonshared = {key: values for key, values in identifiers.items() if len(values) != 1}
    if nonshared:
        example = next(iter(nonshared.items()))
        raise ValueError(
            f"{spec.category}: algorithms/operations do not share one input ID "
            f"for block-size {example[0]}"
        )

    return {
        "raw_rows": len(rows),
        "expected_raw_rows": spec.expected_rows,
        "block_count": len(BLOCK_IDS),
        "conditions_per_block": spec.conditions_per_block,
        "algorithm_or_scheme_count": len(spec.algorithms),
        "algorithms_or_schemes": list(spec.algorithms),
        "input_sizes_bytes": list(INPUT_SIZES),
        "operations": list(spec.operations),
        "unique_condition_keys": len(actual),
        "duplicate_condition_keys": duplicates,
        "missing_condition_keys": len(missing),
        "unexpected_condition_keys": len(unexpected),
        "input_identifiers_shared_per_block_size": True,
        "block_size_input_identifier_groups": len(identifiers),
        "all_block_positions_present_once": True,
        "repetition_number_matches_block_id": True,
    }


def _summarize_times(times: list[float]) -> dict:
    mean = statistics.fmean(times)
    return {
        "n": len(times),
        "mean": mean,
        "median": statistics.median(times),
        "stdev": statistics.stdev(times),
        "minimum": min(times),
        "maximum": max(times),
    }


def _paired_metrics(times_a: Iterable[float], times_b: Iterable[float]) -> dict:
    """Summarize block-paired A/B values; array order must use the same blocks."""
    a_values = tuple(times_a)
    b_values = tuple(times_b)
    if len(a_values) != len(b_values) or not a_values:
        raise ValueError("paired time series must have equal, non-zero lengths")
    if any(not math.isfinite(value) or value <= 0 for value in (*a_values, *b_values)):
        raise ValueError("paired execution times must be finite and positive")
    differences = [a - b for a, b in zip(a_values, b_values, strict=True)]
    ratios = [a / b for a, b in zip(a_values, b_values, strict=True)]
    percentages = [100.0 * (a - b) / b for a, b in zip(a_values, b_values, strict=True)]
    return {
        "matched_blocks": len(a_values),
        "mean_difference": statistics.fmean(differences),
        "median_difference": statistics.median(differences),
        "mean_ratio": statistics.fmean(ratios),
        "median_ratio": statistics.median(ratios),
        "mean_percentage_difference": statistics.fmean(percentages),
        "median_percentage_difference": statistics.median(percentages),
    }


def analyze_rows(spec: DatasetSpec, rows: list[dict]) -> tuple[list[dict], list[dict]]:
    """Return per-cell summaries and all three matched pair contrasts per cell."""
    validate_rows(spec, rows)
    lookup = {
        (row["block"], row["size"], row["operation"], row["algorithm"]): row
        for row in rows
    }
    descriptive = []
    pairwise = []
    for operation in spec.operations:
        for size in INPUT_SIZES:
            for algorithm in spec.algorithms:
                times = [
                    lookup[(block, size, operation, algorithm)]["seconds"]
                    for block in BLOCK_IDS
                ]
                summary = _summarize_times(times)
                descriptive.append(
                    {
                        "Category": spec.category,
                        "Algorithm or scheme": algorithm,
                        "Operation": operation,
                        "Input size (bytes)": size,
                        "Input size label": size_label(size),
                        "Matched blocks": summary["n"],
                        "Mean execution time (seconds)": summary["mean"],
                        "Median execution time (seconds)": summary["median"],
                        "Sample standard deviation (seconds)": summary["stdev"],
                        "Minimum execution time (seconds)": summary["minimum"],
                        "Maximum execution time (seconds)": summary["maximum"],
                        "Effective payload throughput from mean time (MiB/s)": (
                            (size / MIB_BYTES) / summary["mean"]
                        ),
                    }
                )
            for algorithm_a, algorithm_b in itertools.combinations(spec.algorithms, 2):
                times_a = [
                    lookup[(block, size, operation, algorithm_a)]["seconds"]
                    for block in BLOCK_IDS
                ]
                times_b = [
                    lookup[(block, size, operation, algorithm_b)]["seconds"]
                    for block in BLOCK_IDS
                ]
                metrics = _paired_metrics(times_a, times_b)
                pairwise.append(
                    {
                        "Category": spec.category,
                        "Operation": operation,
                        "Input size (bytes)": size,
                        "Input size label": size_label(size),
                        "Algorithm A": algorithm_a,
                        "Algorithm B": algorithm_b,
                        "Contrast direction": f"{algorithm_a} − {algorithm_b}",
                        "Matched blocks": metrics["matched_blocks"],
                        "Mean paired time difference A-B (seconds)": metrics["mean_difference"],
                        "Median paired time difference A-B (seconds)": metrics["median_difference"],
                        "Mean paired time ratio A/B": metrics["mean_ratio"],
                        "Median paired time ratio A/B": metrics["median_ratio"],
                        "Mean paired percentage difference (%, 100*(A-B)/B)": metrics[
                            "mean_percentage_difference"
                        ],
                        "Median paired percentage difference (%, 100*(A-B)/B)": metrics[
                            "median_percentage_difference"
                        ],
                    }
                )
    return descriptive, pairwise


def _write_csv(path: Path, fields: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("x", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _format_metadata(spec: DatasetSpec, source_sha256: str, fieldnames: tuple[str, ...], validation: dict) -> dict:
    try:
        source_path = str(spec.path.resolve().relative_to(PROJECT_ROOT))
    except ValueError:
        source_path = str(spec.path.resolve())
    return {
        "category": spec.category,
        "source_csv": source_path,
        "source_csv_sha256": source_sha256,
        "source_csv_columns": list(fieldnames),
        "condition_key": (
            ["Block ID", "Input size in bytes", spec.algorithm_column]
            if spec.operation_column is None
            else [
                "Block ID",
                "Input size in bytes",
                spec.operation_column,
                spec.algorithm_column,
            ]
        ),
        "pairing_key": (
            ["Block ID", "Input size in bytes"]
            if spec.operation_column is None
            else ["Block ID", "Input size in bytes", spec.operation_column]
        ),
        "block_pair_count_per_pairwise_row": len(BLOCK_IDS),
        "validation": validation,
    }


def run_analysis(output_dir: str | Path = DEFAULT_OUTPUT_DIR, specs=DEFAULT_SPECS) -> dict:
    output_path = Path(output_dir)
    output_files = {
        "descriptive": output_path / "rq1_matched_descriptive.csv",
        "pairwise": output_path / "rq1_matched_pairwise.csv",
        "validation": output_path / "rq1_matched_validation.json",
    }
    existing = [str(path) for path in output_files.values() if path.exists()]
    if existing:
        raise FileExistsError("Refusing to overwrite existing output(s): " + ", ".join(existing))

    combined_descriptive = []
    combined_pairwise = []
    dataset_summaries = {}
    for spec in specs:
        rows, source_sha256, fieldnames = _read_rows(spec)
        validation = validate_rows(spec, rows)
        descriptive, pairwise = analyze_rows(spec, rows)
        combined_descriptive.extend(descriptive)
        combined_pairwise.extend(pairwise)
        dataset_summary = _format_metadata(
            spec, source_sha256, fieldnames, validation
        )
        dataset_summary["descriptive_output_rows"] = len(descriptive)
        dataset_summary["expected_descriptive_output_rows"] = (
            len(spec.algorithms) * len(spec.operations) * len(INPUT_SIZES)
        )
        dataset_summary["pairwise_output_rows"] = len(pairwise)
        dataset_summary["expected_pairwise_output_rows"] = (
            math.comb(len(spec.algorithms), 2)
            * len(spec.operations)
            * len(INPUT_SIZES)
        )
        dataset_summary["paired_observation_pairs_per_contrast"] = len(BLOCK_IDS)
        dataset_summaries[spec.category] = dataset_summary

    expected_descriptive_rows = sum(
        len(spec.algorithms) * len(spec.operations) * len(INPUT_SIZES) for spec in specs
    )
    expected_pairwise_rows = sum(
        math.comb(len(spec.algorithms), 2) * len(spec.operations) * len(INPUT_SIZES)
        for spec in specs
    )
    if len(combined_descriptive) != expected_descriptive_rows:
        raise RuntimeError("unexpected descriptive output row count")
    if len(combined_pairwise) != expected_pairwise_rows:
        raise RuntimeError("unexpected pairwise output row count")

    output_path.mkdir(parents=True, exist_ok=True)
    _write_csv(output_files["descriptive"], DESCRIPTIVE_FIELDS, combined_descriptive)
    _write_csv(output_files["pairwise"], PAIRWISE_FIELDS, combined_pairwise)
    validation_summary = {
        "analysis": "RQ1 matched comparative descriptive analysis",
        "inferential_tests_performed": False,
        "method": (
            "Descriptive summaries per algorithm/scheme, operation, and size; all "
            "pairwise contrasts calculated from observations matched by block, size, "
            "and operation. No between-algorithm inferential tests were run."
        ),
        "size_units": "bytes; throughput uses binary MiB (1,048,576 bytes)",
        "pairwise_definitions": {
            "difference": "A - B for each matched block, then summarized across blocks",
            "ratio": "A / B within each matched block, then summarized across blocks",
            "percentage_difference": "100 * (A - B) / B within each matched block, then summarized across blocks",
            "interpretation": "negative A-B means A took less time; ratios below 1 mean A took less time than B",
        },
        "output_row_counts": {
            "descriptive_rows": len(combined_descriptive),
            "expected_descriptive_rows": expected_descriptive_rows,
            "pairwise_rows": len(combined_pairwise),
            "expected_pairwise_rows": expected_pairwise_rows,
        },
        "datasets": dataset_summaries,
        "outputs": {key: path.name for key, path in output_files.items()},
    }
    with output_files["validation"].open("x", encoding="utf-8") as summary_file:
        summary_file.write(json.dumps(validation_summary, indent=2) + "\n")
    return output_files


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate matched descriptive comparisons from authoritative RQ1 CSVs."
    )
    parser.add_argument(
        "--hashing-csv", type=Path, default=DEFAULT_SPECS[0].path,
        help="Randomized-block Hashing RQ1 raw CSV (legacy baseline is not used).",
    )
    parser.add_argument(
        "--symmetric-csv", type=Path, default=DEFAULT_SPECS[1].path,
        help="Authoritative Symmetric RQ1 raw CSV.",
    )
    parser.add_argument(
        "--hybrid-csv", type=Path, default=DEFAULT_SPECS[2].path,
        help="Authoritative Hybrid RQ1 raw CSV.",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
        help="New output directory; existing output filenames are never overwritten.",
    )
    args = parser.parse_args()
    specs = tuple(
        DatasetSpec(**{**spec.__dict__, "path": path})
        for spec, path in zip(
            DEFAULT_SPECS,
            (args.hashing_csv, args.symmetric_csv, args.hybrid_csv),
            strict=True,
        )
    )
    outputs = run_analysis(args.output_dir, specs)
    for label, path in outputs.items():
        print(f"{label.title()} output: {path}")


if __name__ == "__main__":
    main()
