"""Non-cryptographic scheduling, input generation, and output helpers."""

from __future__ import annotations

import csv
import hashlib
import importlib.metadata
import json
import os
import platform
import random
import secrets
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path


INPUT_SIZES = (1_024, 10_240, 102_400, 1_048_576, 10_485_760)
WARMUP_ITERATIONS = 5
MEASURED_BLOCKS = 30
MIB_BYTES = 1024 * 1024


def choose_seed(seed: int | None) -> tuple[int, str]:
    return (secrets.randbits(256), "os_entropy") if seed is None else (seed, "explicit")


def derived_seed(seed: int, *labels: object) -> int:
    payload = ":".join((str(seed), *(str(label) for label in labels))).encode()
    return int.from_bytes(hashlib.sha256(payload).digest(), "big")


def make_input(size_bytes: int, seed: int) -> bytes:
    """Generate reproducible pseudo-random test payloads (never crypto keys)."""
    if size_bytes <= 0:
        raise ValueError("input size must be positive")
    return random.Random(seed).randbytes(size_bytes)


def input_identifier(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def environment_metadata() -> dict:
    versions = {}
    for name in ("cryptography", "numpy", "scipy", "matplotlib"):
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    return {
        "python": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor(),
        "machine_architecture": platform.machine(),
        "logical_cpu_count": os.cpu_count(),
        "openssl": ssl.OPENSSL_VERSION,
        "packages": versions,
    }


def write_csv(path: Path, fieldnames: tuple[str, ...], rows: list[dict]) -> None:
    with path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def default_run_dir(rq: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("run_%Y%m%d_%H%M%S_utc")
    return Path("results") / "symmetric" / rq / "runs" / stamp


def prepare_output_dir(output_dir: str | Path, expected_names: tuple[str, ...]) -> Path:
    target = Path(output_dir)
    target.mkdir(parents=True, exist_ok=True)
    existing = [name for name in expected_names if (target / name).exists()]
    if existing:
        raise FileExistsError(f"refusing to overwrite outputs: {', '.join(existing)}")
    return target
