"""Run a reproducible randomized complete-block hashing experiment."""

import csv
import hashlib
import json
import platform
import random
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from hashing.experiment_runner import (
    ALGORITHMS,
    INPUT_SIZES,
    MEASURED_ITERATIONS,
    WARMUP_ITERATIONS,
)


BLOCK_COUNT = 30
DEFAULT_RANDOM_SEED = 20261118
RAW_CSV_NAME = "hashing_randomized_block_benchmarks.csv"
METADATA_NAME = "hashing_randomized_block_metadata.json"
RAW_FIELDS = (
    "Algorithm",
    "Input size in bytes",
    "Block ID",
    "Randomized position within block",
    "Repetition number",
    "Execution time in seconds",
    "Input identifier",
    "Measurement start monotonic seconds",
    "Measurement end monotonic seconds",
    "Digest",
)


def conditions() -> tuple[tuple[str, int], ...]:
    """Return the 15 unique algorithm and input-size conditions."""
    return tuple(
        (algorithm_name, size_bytes)
        for algorithm_name, _ in ALGORITHMS
        for size_bytes in INPUT_SIZES
    )


def _derived_seed(seed: int, *parts: object) -> int:
    material = ":".join([str(seed), *(str(part) for part in parts)]).encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:8], "big")


def build_block_orders(seed: int, block_count: int = BLOCK_COUNT) -> list[list[tuple[str, int]]]:
    """Create an independently shuffled, reproducible condition order per block."""
    if block_count <= 0:
        raise ValueError("block_count must be positive")

    base_conditions = conditions()
    orders = []
    for block_id in range(1, block_count + 1):
        order = list(base_conditions)
        random.Random(_derived_seed(seed, "block-order", block_id)).shuffle(order)
        orders.append(order)
    return orders


def build_warmup_order(seed: int) -> list[tuple[str, int, int]]:
    """Shuffle all five warm-up calls for every condition as individual calls."""
    warmups = [
        (algorithm_name, size_bytes, warmup_number)
        for algorithm_name, size_bytes in conditions()
        for warmup_number in range(1, WARMUP_ITERATIONS + 1)
    ]
    random.Random(_derived_seed(seed, "warmup-order")).shuffle(warmups)
    return warmups


def _prepare_inputs(seed: int, block_id: int) -> tuple[dict[int, bytes], dict[int, str]]:
    """Generate one buffer per size and its ID, before any timed hash calls."""
    buffers = {}
    identifiers = {}
    for size_bytes in INPUT_SIZES:
        input_seed = _derived_seed(seed, "input", block_id, size_bytes)
        data = random.Random(input_seed).randbytes(size_bytes)
        buffers[size_bytes] = data
        identifiers[size_bytes] = (
            f"block-{block_id:02d}-size-{size_bytes}-sha256-"
            f"{hashlib.sha256(data).hexdigest()}"
        )
    return buffers, identifiers


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def output_paths(output_dir: str | Path) -> tuple[Path, Path]:
    output_path = Path(output_dir)
    return output_path / RAW_CSV_NAME, output_path / METADATA_NAME


def run_randomized_block_experiment(
    output_dir: str | Path,
    seed: int = DEFAULT_RANDOM_SEED,
) -> tuple[Path, Path]:
    """Run 30 complete blocks and write raw observations plus metadata.

    Existing outputs with the target filenames are never overwritten.
    """
    output_path = Path(output_dir)
    raw_csv_path, metadata_path = output_paths(output_path)
    if raw_csv_path.exists() or metadata_path.exists():
        raise FileExistsError(
            f"Randomized-block outputs already exist in {output_path}; choose a new directory"
        )

    output_path.mkdir(parents=True, exist_ok=True)
    started_at = _utc_now()
    algorithm_functions = dict(ALGORITHMS)
    warmup_buffers, _ = _prepare_inputs(seed, 0)

    # Warm-up call order is randomized across all 75 individual calls.
    for algorithm_name, size_bytes, _ in build_warmup_order(seed):
        algorithm_functions[algorithm_name](warmup_buffers[size_bytes])

    orders = build_block_orders(seed)
    rows = []
    for block_id, order in enumerate(orders, start=1):
        # Each size's buffer is shared by the three algorithms in this block.
        buffers, identifiers = _prepare_inputs(seed, block_id)
        for position, (algorithm_name, size_bytes) in enumerate(order, start=1):
            start_time = time.perf_counter()
            digest = algorithm_functions[algorithm_name](buffers[size_bytes])
            end_time = time.perf_counter()
            rows.append(
                {
                    "Algorithm": algorithm_name,
                    "Input size in bytes": size_bytes,
                    "Block ID": block_id,
                    "Randomized position within block": position,
                    "Repetition number": block_id,
                    "Execution time in seconds": end_time - start_time,
                    "Input identifier": identifiers[size_bytes],
                    "Measurement start monotonic seconds": start_time,
                    "Measurement end monotonic seconds": end_time,
                    "Digest": digest.hex(),
                }
            )

    with raw_csv_path.open("x", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=RAW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)

    metadata = {
        "design": "randomized complete-block hashing experiment",
        "random_seed": seed,
        "block_count": BLOCK_COUNT,
        "conditions_per_block": len(conditions()),
        "measured_observations": len(rows),
        "warmup_calls_per_condition": WARMUP_ITERATIONS,
        "warmup_call_order": "all individual warm-up calls shuffled using a derived seed",
        "block_order": "15 conditions independently shuffled within each block using derived seeds",
        "input_generation": "random.Random(derived_seed).randbytes(size_bytes); generated before each block's timed calls",
        "input_identity": "SHA-256 of the prepared input bytes; identical among the three algorithms within a block and size",
        "input_sizes_bytes": list(INPUT_SIZES),
        "algorithms": [name for name, _ in ALGORITHMS],
        "timing_clock": "time.perf_counter(); start and end recorded per measured call",
        "utc_started": started_at,
        "utc_finished": _utc_now(),
        "python_version": sys.version,
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "raw_csv": str(raw_csv_path),
    }
    with metadata_path.open("x", encoding="utf-8") as metadata_file:
        json.dump(metadata, metadata_file, indent=2)
        metadata_file.write("\n")
    return raw_csv_path, metadata_path
