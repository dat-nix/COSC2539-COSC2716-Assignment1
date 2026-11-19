"""Measure hashing and digest-comparison time in tampering scenarios."""

import argparse
import csv
import hashlib
import hmac
import json
import platform
import random
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from hashing.experiment_runner import ALGORITHMS, INPUT_SIZES, WARMUP_ITERATIONS


BLOCK_COUNT = 30
DEFAULT_RANDOM_SEED = 20261118
RAW_CSV_NAME = "hashing_tampering_performance.csv"
METADATA_NAME = "hashing_tampering_performance_metadata.json"

VALID_SCENARIO = "valid_data_trusted_digest"
TAMPERED_TRUSTED_SCENARIO = "modified_data_checked_against_trusted_digest"
TAMPERED_RECOMPUTED_SCENARIO = "modified_data_with_recomputed_unkeyed_digest"
SCENARIOS = (
    VALID_SCENARIO,
    TAMPERED_TRUSTED_SCENARIO,
    TAMPERED_RECOMPUTED_SCENARIO,
)

RAW_FIELDS = (
    "Algorithm",
    "Input size in bytes",
    "Scenario",
    "Block ID",
    "Randomized position within block",
    "Repetition number",
    "Execution time in seconds",
    "Measurement start monotonic seconds",
    "Measurement end monotonic seconds",
    "Input identifier",
    "Original input identifier",
    "Modified input identifier",
    "Data state",
    "Digest trust basis",
    "Trusted original digest",
    "Comparison digest",
    "Computed digest",
    "Verification passed",
    "Tampering detected",
)


def conditions(input_sizes: tuple[int, ...] = INPUT_SIZES) -> tuple[tuple[str, int, str], ...]:
    """Return each algorithm, size, and verification-scenario condition once."""
    return tuple(
        (algorithm_name, size_bytes, scenario)
        for algorithm_name, _ in ALGORITHMS
        for size_bytes in input_sizes
        for scenario in SCENARIOS
    )


def _derived_seed(seed: int, *parts: object) -> int:
    material = ":".join([str(seed), *(str(part) for part in parts)]).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def build_block_orders(
    seed: int,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
    block_count: int = BLOCK_COUNT,
) -> list[list[tuple[str, int, str]]]:
    """Randomize all conditions independently within every complete block."""
    if block_count <= 0:
        raise ValueError("block_count must be positive")
    base_conditions = conditions(input_sizes)
    orders = []
    for block_id in range(1, block_count + 1):
        order = list(base_conditions)
        random.Random(_derived_seed(seed, "block-order", block_id)).shuffle(order)
        orders.append(order)
    return orders


def build_warmup_order(
    seed: int,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
    warmup_iterations: int = WARMUP_ITERATIONS,
) -> list[tuple[str, int, str]]:
    """Shuffle every warm-up call separately across all conditions."""
    if warmup_iterations < 0:
        raise ValueError("warmup_iterations must not be negative")
    warmups = [
        condition
        for condition in conditions(input_sizes)
        for _ in range(warmup_iterations)
    ]
    random.Random(_derived_seed(seed, "warmup-order")).shuffle(warmups)
    return warmups


def prepare_block_inputs(
    seed: int,
    block_id: int,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
) -> dict[int, dict[str, bytes | str]]:
    """Prepare shared original/modified byte buffers and identifiers per size."""
    prepared = {}
    for size_bytes in input_sizes:
        input_seed = _derived_seed(seed, "input", block_id, size_bytes)
        original_data = random.Random(input_seed).randbytes(size_bytes)
        modified_buffer = bytearray(original_data)
        modified_buffer[0] ^= 1
        modified_data = bytes(modified_buffer)
        prepared[size_bytes] = {
            "original_data": original_data,
            "modified_data": modified_data,
            "original_identifier": (
                f"block-{block_id:02d}-size-{size_bytes}-sha256-"
                f"{hashlib.sha256(original_data).hexdigest()}"
            ),
            "modified_identifier": (
                f"block-{block_id:02d}-size-{size_bytes}-sha256-"
                f"{hashlib.sha256(modified_data).hexdigest()}"
            ),
        }
    return prepared


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def output_paths(output_dir: str | Path) -> tuple[Path, Path]:
    root = Path(output_dir)
    return root / RAW_CSV_NAME, root / METADATA_NAME


def run_tampering_performance_experiment(
    output_dir: str | Path,
    seed: int = DEFAULT_RANDOM_SEED,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
    block_count: int = BLOCK_COUNT,
    warmup_iterations: int = WARMUP_ITERATIONS,
) -> tuple[Path, Path]:
    """Run the matched-block verification experiment and save raw timings.

    Only a hash call and ``hmac.compare_digest`` are inside each timed interval.
    Existing files at either output path are never overwritten.
    """
    if not input_sizes or any(size <= 0 for size in input_sizes):
        raise ValueError("input sizes must be non-empty and positive")
    if len(set(input_sizes)) != len(input_sizes):
        raise ValueError("input sizes must be unique")
    if block_count <= 0:
        raise ValueError("block_count must be positive")
    if warmup_iterations < 0:
        raise ValueError("warmup_iterations must not be negative")

    output_path = Path(output_dir)
    raw_csv_path, metadata_path = output_paths(output_path)
    if raw_csv_path.exists() or metadata_path.exists():
        raise FileExistsError(
            f"Tampering-performance outputs already exist in {output_path}; "
            "choose a new output directory"
        )
    output_path.mkdir(parents=True, exist_ok=True)
    utc_started = _utc_now()
    algorithm_functions = dict(ALGORITHMS)
    compare_digests = hmac.compare_digest

    warmup_inputs = prepare_block_inputs(seed, 0, input_sizes)
    warmup_references = {}
    for algorithm_name, digest_function in ALGORITHMS:
        for size_bytes in input_sizes:
            original_data = warmup_inputs[size_bytes]["original_data"]
            modified_data = warmup_inputs[size_bytes]["modified_data"]
            warmup_references[(algorithm_name, size_bytes)] = (
                digest_function(original_data),
                digest_function(modified_data),
            )

    for algorithm_name, size_bytes, scenario in build_warmup_order(
        seed, input_sizes, warmup_iterations
    ):
        original_data = warmup_inputs[size_bytes]["original_data"]
        modified_data = warmup_inputs[size_bytes]["modified_data"]
        trusted_digest, modified_digest = warmup_references[(algorithm_name, size_bytes)]
        if scenario == VALID_SCENARIO:
            payload, reference = original_data, trusted_digest
        elif scenario == TAMPERED_TRUSTED_SCENARIO:
            payload, reference = modified_data, trusted_digest
        else:
            payload, reference = modified_data, modified_digest
        hmac.compare_digest(algorithm_functions[algorithm_name](payload), reference)

    orders = build_block_orders(seed, input_sizes, block_count)
    rows = []
    for block_id, order in enumerate(orders, start=1):
        # Input buffers and both reference digests are prepared before timing.
        block_inputs = prepare_block_inputs(seed, block_id, input_sizes)
        trusted_digests = {}
        modified_digests = {}
        for algorithm_name, digest_function in ALGORITHMS:
            for size_bytes in input_sizes:
                input_data = block_inputs[size_bytes]
                trusted_digests[(algorithm_name, size_bytes)] = digest_function(
                    input_data["original_data"]
                )
                modified_digests[(algorithm_name, size_bytes)] = digest_function(
                    input_data["modified_data"]
                )

        for position, (algorithm_name, size_bytes, scenario) in enumerate(order, start=1):
            input_data = block_inputs[size_bytes]
            trusted_digest = trusted_digests[(algorithm_name, size_bytes)]
            modified_digest = modified_digests[(algorithm_name, size_bytes)]
            if scenario == VALID_SCENARIO:
                payload = input_data["original_data"]
                comparison_digest = trusted_digest
                data_state = "original"
                digest_trust_basis = "trusted_original"
                input_identifier = input_data["original_identifier"]
            elif scenario == TAMPERED_TRUSTED_SCENARIO:
                payload = input_data["modified_data"]
                comparison_digest = trusted_digest
                data_state = "modified"
                digest_trust_basis = "trusted_original"
                input_identifier = input_data["modified_identifier"]
            else:
                payload = input_data["modified_data"]
                comparison_digest = modified_digest
                data_state = "modified"
                digest_trust_basis = "attacker_recomputed_unkeyed"
                input_identifier = input_data["modified_identifier"]
            digest_function = algorithm_functions[algorithm_name]

            # Only hashing and digest comparison are measured.
            start_time = time.perf_counter()
            computed_digest = digest_function(payload)
            verification_passed = compare_digests(computed_digest, comparison_digest)
            end_time = time.perf_counter()

            was_modified = data_state == "modified"
            rows.append(
                {
                    "Algorithm": algorithm_name,
                    "Input size in bytes": size_bytes,
                    "Scenario": scenario,
                    "Block ID": block_id,
                    "Randomized position within block": position,
                    "Repetition number": block_id,
                    "Execution time in seconds": end_time - start_time,
                    "Measurement start monotonic seconds": start_time,
                    "Measurement end monotonic seconds": end_time,
                    "Input identifier": input_identifier,
                    "Original input identifier": input_data["original_identifier"],
                    "Modified input identifier": input_data["modified_identifier"],
                    "Data state": data_state,
                    "Digest trust basis": digest_trust_basis,
                    "Trusted original digest": trusted_digest.hex(),
                    "Comparison digest": comparison_digest.hex(),
                    "Computed digest": computed_digest.hex(),
                    "Verification passed": verification_passed,
                    "Tampering detected": was_modified and not verification_passed,
                }
            )

    with raw_csv_path.open("x", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=RAW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    perf_counter_info = time.get_clock_info("perf_counter")
    metadata = {
        "design": "randomized complete-block tampering-verification performance experiment",
        "random_seed": seed,
        "block_count": block_count,
        "conditions_per_block": len(conditions(input_sizes)),
        "measured_observations": len(rows),
        "measured_repetitions_per_configuration": block_count,
        "warmup_calls_per_configuration": warmup_iterations,
        "warmup_order": "all individual warm-up calls shuffled with a derived seed",
        "block_order": "all algorithm-size-scenario conditions shuffled independently within each block",
        "input_sizes_bytes": list(input_sizes),
        "algorithms": [name for name, _ in ALGORITHMS],
        "scenarios": list(SCENARIOS),
        "input_generation": "random.Random(derived_seed).randbytes(size_bytes), prepared before timing",
        "input_modification": "flip bit 0 of byte 0; modified buffer prepared before timing",
        "shared_data": "one original and one modified buffer per block and size, shared across algorithms",
        "reference_digests": "trusted original and attacker-recomputed digests prepared outside timing",
        "timed_operation": "digest_function(payload) followed by hmac.compare_digest(computed_digest, comparison_digest)",
        "timing_clock": "time.perf_counter(); monotonic start/end recorded per measured verification",
        "digest_formatting_and_csv_io": "performed outside timed interval",
        "utc_started": utc_started,
        "utc_finished": _utc_now(),
        "python_version": sys.version,
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "openssl_version": ssl.OPENSSL_VERSION,
        "perf_counter": {
            "implementation": perf_counter_info.implementation,
            "resolution": perf_counter_info.resolution,
            "monotonic": perf_counter_info.monotonic,
            "adjustable": perf_counter_info.adjustable,
        },
        "raw_csv": str(raw_csv_path),
    }
    with metadata_path.open("x", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, indent=2)
        metadata_file.write("\n")
    return raw_csv_path, metadata_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure hashing and digest-comparison time in tampering scenarios."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/hashing/rq3/tampering_performance/runs/new_run"),
        help="separate output directory (default: results/hashing/rq3/tampering_performance/runs/new_run)",
    )
    parser.add_argument(
        "--seed", type=int, default=DEFAULT_RANDOM_SEED, help="reproducible input/order seed"
    )
    args = parser.parse_args()
    raw_path, metadata_path = run_tampering_performance_experiment(
        args.output_dir, seed=args.seed
    )
    print(f"Raw verification timings: {raw_path}")
    print(f"Environment metadata: {metadata_path}")


if __name__ == "__main__":
    main()
