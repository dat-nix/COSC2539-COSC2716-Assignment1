import hashlib
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from hashing.experiment_runner import ALGORITHMS, INPUT_SIZES
from hashing.randomized_block_runner import (
    BLOCK_COUNT,
    METADATA_NAME,
    RAW_CSV_NAME,
    build_block_orders,
    build_warmup_order,
    conditions,
    output_paths,
    run_randomized_block_experiment,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_BENCHMARK = PROJECT_ROOT / "results" / "hashing_benchmarks.csv"


class RandomizedBlockRunnerTests(unittest.TestCase):
    def test_each_of_30_blocks_contains_15_unique_conditions(self):
        expected = set(conditions())
        orders = build_block_orders(seed=12345)
        self.assertEqual(len(orders), BLOCK_COUNT)
        for order in orders:
            self.assertEqual(len(order), 15)
            self.assertEqual(len(set(order)), 15)
            self.assertEqual(set(order), expected)

    def test_schedule_is_reproducible_for_a_fixed_seed(self):
        self.assertEqual(build_block_orders(8675309), build_block_orders(8675309))
        self.assertEqual(build_warmup_order(8675309), build_warmup_order(8675309))
        self.assertNotEqual(build_block_orders(8675309), build_block_orders(8675310))

    def test_all_sizes_algorithms_and_warmup_counts_are_present(self):
        order = build_warmup_order(seed=17)
        self.assertEqual(len(order), len(ALGORITHMS) * len(INPUT_SIZES) * 5)
        counts = Counter((algorithm, size) for algorithm, size, _ in order)
        self.assertEqual(set(counts), set(conditions()))
        self.assertEqual(set(counts.values()), {5})
        self.assertEqual({size for _, size in conditions()}, set(INPUT_SIZES))
        self.assertEqual({name for name, _ in conditions()}, {name for name, _ in ALGORITHMS})

    def test_outputs_are_separate_from_original_and_existing_outputs_are_protected(self):
        original_before = hashlib.sha256(ORIGINAL_BENCHMARK.read_bytes()).hexdigest()
        raw_path, metadata_path = output_paths(PROJECT_ROOT / "results" / "randomized_block")
        self.assertEqual(raw_path.name, RAW_CSV_NAME)
        self.assertEqual(metadata_path.name, METADATA_NAME)
        self.assertNotEqual(raw_path.resolve(), ORIGINAL_BENCHMARK.resolve())

        with tempfile.TemporaryDirectory() as temporary_dir:
            target = Path(temporary_dir)
            existing_raw = target / RAW_CSV_NAME
            existing_raw.write_bytes(b"keep this file")
            with self.assertRaises(FileExistsError):
                run_randomized_block_experiment(target, seed=5)
            self.assertEqual(existing_raw.read_bytes(), b"keep this file")

        original_after = hashlib.sha256(ORIGINAL_BENCHMARK.read_bytes()).hexdigest()
        self.assertEqual(original_before, original_after)


if __name__ == "__main__":
    unittest.main()
