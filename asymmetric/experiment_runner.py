"""RQ1 randomized-block benchmark for asymmetric hybrid encryption."""

from __future__ import annotations

import argparse
import random
import time
from datetime import datetime, timezone
from pathlib import Path

from asymmetric.experiment_utils import (
    DEFAULT_RSA_KEY_SIZE,
    INPUT_SIZES,
    MEASURED_BLOCKS,
    WARMUP_ITERATIONS,
    block_randomization_seeds,
    choose_seed,
    derived_seed,
    environment_metadata,
    input_identifier,
    make_input,
    prepare_output_dir,
    public_key_fingerprints,
    seed_metadata,
    utc_now,
    write_csv,
    write_json,
)
from asymmetric.schemes import SCHEMES, generate_recipient_keypairs


RAW_CSV_NAME = "asymmetric_rq1_benchmarks.csv"
METADATA_NAME = "asymmetric_rq1_metadata.json"
RAW_FIELDS = (
    "Scheme",
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
    "Failure stage",
    "Exception category",
    "Internal exception type",
    "Session key unwrapped",
    "Key agreement completed",
    "HKDF completed",
    "AES-GCM verification reached",
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
    randomization_seeds: list[int] | None = None,
) -> list[list[tuple[str, int, str]]]:
    if blocks <= 0:
        raise ValueError("blocks must be positive")
    if randomization_seeds is not None and len(randomization_seeds) != blocks:
        raise ValueError("randomization_seeds must contain one seed per block")
    base = list(conditions(input_sizes))
    orders = []
    for block_id in range(1, blocks + 1):
        order = base.copy()
        block_seed = (
            randomization_seeds[block_id - 1]
            if randomization_seeds is not None
            else derived_seed(seed, "rq1-block", block_id)
        )
        random.Random(block_seed).shuffle(order)
        orders.append(order)
    return orders


def _condition_id(condition: tuple[str, int, str]) -> str:
    scheme, size, operation = condition
    return f"{scheme}|{size}|{operation}"


def _outcome_fields(outcome) -> dict:
    return {
        "Accepted": outcome.accepted,
        "Failure stage": outcome.failure_stage or "",
        "Exception category": outcome.exception_category or "",
        "Internal exception type": outcome.internal_exception_type or "",
        "Session key unwrapped": outcome.session_key_unwrapped,
        "Key agreement completed": outcome.key_agreement_completed,
        "HKDF completed": outcome.hkdf_completed,
        "AES-GCM verification reached": outcome.aes_gcm_verification_reached,
        "Plaintext released": outcome.plaintext_released,
    }


def _make_envelope(scheme, plaintext: bytes, public_key):
    return scheme.encrypt(plaintext, public_key)


def run_rq1(
    output_dir: str | Path,
    *,
    seed: int | None = None,
    blocks: int = MEASURED_BLOCKS,
    input_sizes: tuple[int, ...] = INPUT_SIZES,
    rsa_key_size: int = DEFAULT_RSA_KEY_SIZE,
) -> tuple[Path, Path]:
    """Run RQ1; this function is called only by an explicit CLI/user request."""
    if blocks <= 0 or not input_sizes or any(size <= 0 for size in input_sizes):
        raise ValueError("blocks and input sizes must be positive")
    if len(set(input_sizes)) != len(input_sizes):
        raise ValueError("input_sizes must not contain duplicates")

    seed_value, seed_source = choose_seed(seed)
    target = prepare_output_dir(output_dir, (RAW_CSV_NAME, METADATA_NAME))
    keypairs = generate_recipient_keypairs(rsa_key_size)
    scheme_by_name = {scheme.name: scheme for scheme in SCHEMES}
    block_seeds = block_randomization_seeds(seed_value, seed_source, blocks)
    rng_orders = block_orders(seed_value, blocks, input_sizes, block_seeds)

    # Warm-ups are prepared and shuffled before the measured blocks.
    warmup_data = {
        size: make_input(size, derived_seed(seed_value, "rq1-warmup-input", size))
        for size in input_sizes
    }
    warmup_envelopes = {
        (scheme.name, size): _make_envelope(
            scheme, warmup_data[size], keypairs[scheme.name][1]
        )
        for scheme in SCHEMES
        for size in input_sizes
    }
    warmup_conditions = [
        condition
        for condition in conditions(input_sizes)
        for _ in range(WARMUP_ITERATIONS)
    ]
    random.Random(derived_seed(seed_value, "rq1-warmup-order")).shuffle(warmup_conditions)
    for scheme_name, size, operation in warmup_conditions:
        scheme = scheme_by_name[scheme_name]
        private_key, public_key = keypairs[scheme_name]
        if operation == "encrypt":
            scheme.encrypt(warmup_data[size], public_key)
        else:
            warmup_result = scheme.attempt_decrypt(
                warmup_envelopes[(scheme_name, size)], private_key
            )
            if not warmup_result.accepted:
                raise RuntimeError("valid RQ1 decryption warm-up failed")

    rows = []
    for block_id, order in enumerate(rng_orders, start=1):
        buffers = {
            size: make_input(size, derived_seed(seed_value, "rq1-input", block_id, size))
            for size in input_sizes
        }
        identifiers = {size: input_identifier(data) for size, data in buffers.items()}
        decrypt_envelopes = {
            (scheme.name, size): scheme.encrypt(buffers[size], keypairs[scheme.name][1])
            for scheme in SCHEMES
            for size in input_sizes
        }

        previous = ""
        for position, condition in enumerate(order, start=1):
            scheme_name, size, operation = condition
            scheme = scheme_by_name[scheme_name]
            private_key, public_key = keypairs[scheme_name]
            start_utc = datetime.now(timezone.utc).isoformat()
            start = time.perf_counter()
            if operation == "encrypt":
                result = scheme.encrypt(buffers[size], public_key)
                outcome = None
            else:
                outcome = scheme.attempt_decrypt(
                    decrypt_envelopes[(scheme_name, size)], private_key
                )
                result = None
            end = time.perf_counter()

            if operation == "decrypt":
                if not outcome.accepted or outcome.plaintext != buffers[size]:
                    raise RuntimeError("valid RQ1 decryption failed or returned wrong plaintext")
                outcome.plaintext = None  # Do not retain or write plaintext.
            elif result is None:
                raise RuntimeError("RQ1 encryption returned no envelope")

            row = {
                "Scheme": scheme_name,
                "Operation": operation,
                "Input size in bytes": size,
                "Block ID": block_id,
                "Randomized position within block": position,
                "Repetition number": block_id,
                "Input identifier": identifiers[size],
                "Envelope identifier": (
                    f"{block_id}:{scheme_name}:{size}:decrypt" if operation == "decrypt" else ""
                ),
                "Previous condition ID": previous,
                "Measurement start UTC": start_utc,
                "Measurement start monotonic seconds": start,
                "Measurement end monotonic seconds": end,
                "Execution time in seconds": end - start,
                **(_outcome_fields(outcome) if outcome else {
                    "Accepted": "",
                    "Failure stage": "",
                    "Exception category": "",
                    "Internal exception type": "",
                    "Session key unwrapped": "",
                    "Key agreement completed": "",
                    "HKDF completed": "",
                    "AES-GCM verification reached": "",
                    "Plaintext released": "",
                }),
            }
            rows.append(row)
            previous = _condition_id(condition)

    csv_path = target / RAW_CSV_NAME
    metadata_path = target / METADATA_NAME
    write_csv(csv_path, RAW_FIELDS, rows)
    metadata = {
        "experiment": "RQ1 asymmetric-based hybrid encryption randomized complete blocks",
        **seed_metadata(seed_value, seed_source),
        "randomization": "one Python random.Random shuffle per block, with an independently drawn 256-bit OS seed for each block when the root seed source is OS entropy",
        "block_randomization_seeds": block_seeds,
        "block_count": blocks,
        "conditions_per_block": len(conditions(input_sizes)),
        "expected_measured_observations": blocks * len(conditions(input_sizes)),
        "warmup_iterations_per_condition": WARMUP_ITERATIONS,
        "input_sizes_bytes": list(input_sizes),
        "operations": ["encrypt", "decrypt"],
        "rsa_key_size_bits": rsa_key_size,
        "recipient_public_key_sha256_fingerprints": public_key_fingerprints(keypairs),
        "timing": "time.perf_counter around the scheme operation only",
        "environment": environment_metadata(),
        "created_utc": utc_now(),
    }
    write_json(metadata_path, metadata)
    return csv_path, metadata_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the RQ1 hybrid-encryption benchmark.")
    parser.add_argument("--output-dir", type=Path, default=Path("results/asymmetric/rq1/runs/run_1"))
    parser.add_argument("--seed", type=int, default=None, help="explicit seed (marks randomization as non-confirmatory)")
    parser.add_argument("--blocks", type=int, default=MEASURED_BLOCKS)
    parser.add_argument("--rsa-key-size", type=int, default=DEFAULT_RSA_KEY_SIZE)
    args = parser.parse_args()
    csv_path, metadata_path = run_rq1(
        args.output_dir, seed=args.seed, blocks=args.blocks, rsa_key_size=args.rsa_key_size
    )
    print(csv_path)
    print(metadata_path)


if __name__ == "__main__":
    main()
