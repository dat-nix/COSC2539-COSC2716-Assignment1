"""Run reproducible hashing timing and tampering experiments."""

import argparse
import csv
import json
import platform
import sys
import time
from pathlib import Path
from typing import Callable

from hashing import blake2b_256, sha256, sha3_256


INPUT_SIZES = (1_024, 10_240, 102_400, 1_048_576, 10_485_760)
WARMUP_ITERATIONS = 5
MEASURED_ITERATIONS = 30
ALGORITHMS: tuple[tuple[str, Callable[[bytes], bytes]], ...] = (
    ("SHA-256", sha256),
    ("SHA3-256", sha3_256),
    ("BLAKE2b-256", blake2b_256),
)

BENCHMARK_FIELDS = (
    "Algorithm",
    "Input size in bytes",
    "Repetition number",
    "Execution time in seconds",
    "Digest",
)
TAMPERING_FIELDS = (
    "Algorithm",
    "Input size in bytes",
    "Scenario",
    "Verification passed",
    "Tampering detected",
    "Computed digest",
    "Trusted original digest",
    "Accompanying digest",
)


def generate_input(size_bytes: int) -> bytes:
    """Create deterministic input with exactly *size_bytes* bytes."""
    if size_bytes < 0:
        raise ValueError("size_bytes must not be negative")

    pattern = bytes(range(256))
    full_patterns, remaining_bytes = divmod(size_bytes, len(pattern))
    return pattern * full_patterns + pattern[:remaining_bytes]


def _write_csv(path: Path, fieldnames: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_benchmarks(
    output_dir: str | Path,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
    warmup_iterations: int = WARMUP_ITERATIONS,
    measured_iterations: int = MEASURED_ITERATIONS,
) -> Path:
    """Measure each algorithm and write every observation to a raw CSV."""
    if any(size <= 0 for size in input_sizes):
        raise ValueError("input sizes must be positive")
    if warmup_iterations < 0:
        raise ValueError("warmup_iterations must not be negative")
    if measured_iterations <= 0:
        raise ValueError("measured_iterations must be positive")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    rows = []

    for size_bytes in input_sizes:
        data = generate_input(size_bytes)
        for algorithm_name, digest_function in ALGORITHMS:
            for _ in range(warmup_iterations):
                digest_function(data)

            for repetition in range(1, measured_iterations + 1):
                start_time = time.perf_counter()
                digest = digest_function(data)
                elapsed_seconds = time.perf_counter() - start_time
                rows.append(
                    {
                        "Algorithm": algorithm_name,
                        "Input size in bytes": size_bytes,
                        "Repetition number": repetition,
                        "Execution time in seconds": elapsed_seconds,
                        "Digest": digest.hex(),
                    }
                )

    csv_path = output_path / "hashing_benchmarks.csv"
    _write_csv(csv_path, BENCHMARK_FIELDS, rows)
    return csv_path


def run_tampering_experiments(
    output_dir: str | Path,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
) -> Path:
    """Compare modified input with a trusted or attacker-recomputed digest."""
    if any(size <= 0 for size in input_sizes):
        raise ValueError("input sizes must be positive")

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    rows = []

    for size_bytes in input_sizes:
        original_data = generate_input(size_bytes)
        modified_data = bytearray(original_data)
        modified_data[0] ^= 1
        modified_data = bytes(modified_data)

        for algorithm_name, digest_function in ALGORITHMS:
            trusted_digest = digest_function(original_data).hex()
            modified_digest = digest_function(modified_data).hex()
            scenarios = (
                ("modified_data_checked_against_trusted_digest", trusted_digest),
                ("modified_data_with_recomputed_unkeyed_digest", modified_digest),
            )

            for scenario, accompanying_digest in scenarios:
                verification_passed = modified_digest == accompanying_digest
                rows.append(
                    {
                        "Algorithm": algorithm_name,
                        "Input size in bytes": size_bytes,
                        "Scenario": scenario,
                        "Verification passed": verification_passed,
                        "Tampering detected": not verification_passed,
                        "Computed digest": modified_digest,
                        "Trusted original digest": trusted_digest,
                        "Accompanying digest": accompanying_digest,
                    }
                )

    csv_path = output_path / "hashing_tampering.csv"
    _write_csv(csv_path, TAMPERING_FIELDS, rows)
    return csv_path


def _write_metadata(output_dir: Path) -> Path:
    metadata = {
        "python_version": sys.version,
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "input_sizes_bytes": list(INPUT_SIZES),
        "warmup_iterations": WARMUP_ITERATIONS,
        "measured_iterations": MEASURED_ITERATIONS,
        "algorithms": [name for name, _ in ALGORITHMS],
        "input_generation": "repeating bytes 0 through 255",
    }
    metadata_path = output_dir / "hashing_metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata_path


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark hashing algorithms and run basic tampering checks."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/hashing/rq1/runs/new_run"),
        help="directory for CSV results and metadata (default: results/hashing/rq1/runs/new_run)",
    )
    args = parser.parse_args()

    benchmark_path = run_benchmarks(args.output_dir)
    tampering_path = run_tampering_experiments(args.output_dir)
    metadata_path = _write_metadata(args.output_dir)
    print(f"Benchmark observations: {benchmark_path}")
    print(f"Tampering results: {tampering_path}")
    print(f"Environment metadata: {metadata_path}")


if __name__ == "__main__":
    main()
