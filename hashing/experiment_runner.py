"""Run the report's Hashing RQ1, RQ2, and RQ3 experiments."""

import argparse
import csv
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
    """Create the fixed repeated-byte pattern used by the Hashing RQ2 checks."""
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run a Hashing experiment used by the final research report."
    )
    subparsers = parser.add_subparsers(dest="experiment", required=True)

    rq1 = subparsers.add_parser("rq1", help="randomized-block digest benchmark")
    rq1.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/hashing/rq1/randomized_block/runs/new_run"),
    )
    rq1.add_argument("--seed", type=int, default=20261118)

    rq2 = subparsers.add_parser("rq2", help="functional tampering checks")
    rq2.add_argument(
        "--output-dir", type=Path, default=Path("results/hashing/rq2/runs/new_run")
    )

    rq3 = subparsers.add_parser("rq3", help="tampering-verification timing experiment")
    rq3.add_argument(
        "--output-dir",
        type=Path,
        default=Path("results/hashing/rq3/tampering_performance/runs/new_run"),
    )
    rq3.add_argument("--seed", type=int, default=20261118)

    args = parser.parse_args()
    if args.experiment == "rq1":
        from hashing.randomized_block_runner import run_randomized_block_experiment

        paths = run_randomized_block_experiment(args.output_dir, args.seed)
        for path in paths:
            print(path)
    elif args.experiment == "rq2":
        print(run_tampering_experiments(args.output_dir))
    else:
        from hashing.tampering_performance_runner import (
            run_tampering_performance_experiment,
        )

        paths = run_tampering_performance_experiment(args.output_dir, args.seed)
        for path in paths:
            print(path)


if __name__ == "__main__":
    main()
