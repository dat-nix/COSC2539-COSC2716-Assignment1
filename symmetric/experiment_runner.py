"""Randomized complete-block RQ1 performance benchmark."""

from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path

from symmetric.experiment_utils import (
    INPUT_SIZES,
    MEASURED_BLOCKS,
    WARMUP_ITERATIONS,
    choose_seed,
    default_run_dir,
    derived_seed,
    environment_metadata,
    input_identifier,
    make_input,
    prepare_output_dir,
    utc_now,
    write_csv,
    write_json,
)
from symmetric.schemes import SCHEMES


RAW_CSV_NAME = "symmetric_rq1_benchmarks.csv"
METADATA_NAME = "symmetric_rq1_metadata.json"
LOG_NAME = "execution.log"
RAW_FIELDS = (
    "Algorithm",
    "Operation",
    "Input size in bytes",
    "Block ID",
    "Randomized position within block",
    "Repetition number",
    "Input identifier",
    "Envelope identifier",
    "Previous condition ID",
    "Measurement start UTC",
    "Measurement start monotonic seconds",
    "Measurement end monotonic seconds",
    "Execution time in seconds",
    "Accepted",
    "Plaintext released",
)


def conditions(input_sizes: tuple[int, ...] = INPUT_SIZES) -> tuple[tuple[str, int, str], ...]:
    return tuple(
        (scheme.name, size, operation)
        for scheme in SCHEMES
        for size in input_sizes
        for operation in ("encrypt", "decrypt")
    )


def block_orders(
    seed: int,
    blocks: int = MEASURED_BLOCKS,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
) -> list[list[tuple[str, int, str]]]:
    if blocks <= 0 or not input_sizes or len(set(input_sizes)) != len(input_sizes):
        raise ValueError("blocks and unique input sizes must be positive")
    base = list(conditions(input_sizes))
    orders = []
    for block in range(1, blocks + 1):
        order = base.copy()
        random.Random(derived_seed(seed, "rq1-measured-order", block)).shuffle(order)
        orders.append(order)
    return orders


def _condition_id(condition: tuple[str, int, str]) -> str:
    return "|".join(map(str, condition))


def run_rq1(
    output_dir: str | Path | None = None,
    *,
    seed: int | None = None,
    blocks: int = MEASURED_BLOCKS,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
) -> tuple[Path, Path]:
    """Run RQ1 explicitly; input and envelope preparation are outside timers."""
    if blocks <= 0 or not input_sizes or any(size <= 0 for size in input_sizes):
        raise ValueError("blocks and input sizes must be positive")
    if len(set(input_sizes)) != len(input_sizes):
        raise ValueError("input_sizes must not contain duplicates")
    seed_value, seed_source = choose_seed(seed)
    target = prepare_output_dir(
        output_dir or default_run_dir("rq1"), (RAW_CSV_NAME, METADATA_NAME, LOG_NAME)
    )
    keys = {scheme.name: scheme.generate_key() for scheme in SCHEMES}
    scheme_by_name = {scheme.name: scheme for scheme in SCHEMES}
    all_conditions = conditions(input_sizes)
    orders = block_orders(seed_value, blocks, input_sizes)
    rows = []

    for block_id, order in enumerate(orders, start=1):
        payloads = {
            size: make_input(size, derived_seed(seed_value, "rq1-input", block_id, size))
            for size in input_sizes
        }
        identifiers = {size: input_identifier(payload) for size, payload in payloads.items()}
        # Prepare valid decrypt envelopes before either warm-up or measurement.
        envelopes = {
            (scheme.name, size): scheme.encrypt(payloads[size], keys[scheme.name])
            for scheme in SCHEMES
            for size in input_sizes
        }

        warmups = list(all_conditions) * WARMUP_ITERATIONS
        random.Random(derived_seed(seed_value, "rq1-warmup-order", block_id)).shuffle(warmups)
        for algorithm, size, operation in warmups:
            scheme = scheme_by_name[algorithm]
            if operation == "encrypt":
                scheme.encrypt(payloads[size], keys[algorithm])
            else:
                if scheme.decrypt(envelopes[(algorithm, size)], keys[algorithm]) != payloads[size]:
                    raise RuntimeError("valid RQ1 decryption warm-up did not recover its input")

        previous = ""
        for position, condition in enumerate(order, start=1):
            algorithm, size, operation = condition
            scheme = scheme_by_name[algorithm]
            start_utc = utc_now()
            start = time.perf_counter()
            if operation == "encrypt":
                result = scheme.encrypt(payloads[size], keys[algorithm])
            else:
                result = scheme.decrypt(envelopes[(algorithm, size)], keys[algorithm])
            end = time.perf_counter()
            elapsed = end - start

            if operation == "decrypt" and result != payloads[size]:
                raise RuntimeError("decryption did not recover the input bytes")
            envelope_id = (
                f"{block_id}:{algorithm}:{size}"
                if operation == "decrypt"
                else ""
            )
            rows.append(
                {
                    "Algorithm": algorithm,
                    "Operation": operation,
                    "Input size in bytes": size,
                    "Block ID": block_id,
                    "Randomized position within block": position,
                    "Repetition number": block_id,
                    "Input identifier": identifiers[size],
                    "Envelope identifier": envelope_id,
                    "Previous condition ID": previous,
                    "Measurement start UTC": start_utc,
                    "Measurement start monotonic seconds": start,
                    "Measurement end monotonic seconds": end,
                    "Execution time in seconds": elapsed,
                    "Accepted": True,
                    "Plaintext released": operation == "decrypt",
                }
            )
            previous = _condition_id(condition)

    expected_count = blocks * len(all_conditions)
    if len(rows) != expected_count:
        raise RuntimeError(f"expected {expected_count} observations, generated {len(rows)}")
    raw_path = target / RAW_CSV_NAME
    metadata_path = target / METADATA_NAME
    write_csv(raw_path, RAW_FIELDS, rows)
    write_json(
        metadata_path,
        {
            "experiment": "symmetric RQ1 randomized complete-block benchmark",
            "status": "complete",
            "random_seed": seed_value,
            "random_seed_source": seed_source,
            "seed_note": "Scheduling and deterministic payload generation only; cryptographic keys and nonces use OS/library CSPRNGs.",
            "block_count": blocks,
            "conditions_per_block": len(all_conditions),
            "expected_measured_observations": expected_count,
            "measured_observations": len(rows),
            "warmup_iterations_per_condition": WARMUP_ITERATIONS,
            "warmups_in_raw_csv": False,
            "input_sizes_bytes": list(input_sizes),
            "algorithms": [scheme.name for scheme in SCHEMES],
            "operations": ["encrypt", "decrypt"],
            "input_generation": "random.Random(seed).randbytes; generated per block and size outside timed regions; common bytes shared across algorithms",
            "randomization": "independently derived pseudo-random permutation of all conditions within each measured block; warm-up calls separately shuffled per block",
            "timing": "time.perf_counter surrounds only the scheme encrypt/decrypt call; payload generation, key generation, valid envelope preparation, result checks, and CSV/metadata writing are excluded",
            "encryption_timing_includes": "fresh nonce/IV generation, encryption, padding where applicable, tag/MAC generation, and in-memory envelope construction",
            "decryption_timing_includes": "envelope validation, authentication verification, decryption, and unpadding where applicable",
            "key_material_written": False,
            "environment": environment_metadata(),
            "created_utc": utc_now(),
        },
    )
    (target / LOG_NAME).write_text(
        f"Completed at {utc_now()}\nMeasured observations: {len(rows)}\n", encoding="utf-8"
    )
    return raw_path, metadata_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run symmetric RQ1, RQ2, or RQ3.")
    parser.add_argument("experiment", choices=("rq1", "rq2", "rq3"))
    parser.add_argument("--output-dir", type=Path, default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--blocks", type=int, default=MEASURED_BLOCKS)
    args = parser.parse_args()

    if args.experiment == "rq1":
        paths = run_rq1(args.output_dir, seed=args.seed, blocks=args.blocks)
    else:
        from symmetric.adversarial_runner import run_rq2, run_rq3

        if args.experiment == "rq2":
            paths = run_rq2(args.output_dir, seed=args.seed)
        else:
            paths = run_rq3(args.output_dir, seed=args.seed, blocks=args.blocks)
    print(f"Raw observations: {paths[0]}")
    print(f"Metadata: {paths[1]}")


if __name__ == "__main__":
    main()
