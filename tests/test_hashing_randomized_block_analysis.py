import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from hashing.randomized_block_analysis import (
    DESCRIPTIVE_FIELDS,
    MODEL_FIELDS,
    PAIRWISE_FIELDS,
    analyze_randomized_blocks,
)
from hashing.randomized_block_runner import (
    BLOCK_COUNT,
    RAW_FIELDS,
    build_block_orders,
    conditions,
)
from hashing.experiment_runner import ALGORITHMS, INPUT_SIZES


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_BENCHMARK = (
    PROJECT_ROOT / "results" / "hashing" / "rq1" / "baseline" / "hashing_benchmarks.csv"
)


def _write_synthetic_fixture(path: Path) -> None:
    """Write a temporary unit-test fixture; it is never experimental output."""
    rows = []
    for block_id, order in enumerate(build_block_orders(seed=9001), start=1):
        position_by_condition = {condition: position for position, condition in enumerate(order, 1)}
        for algorithm_index, (algorithm, _) in enumerate(ALGORITHMS):
            for size_index, size in enumerate(INPUT_SIZES):
                condition = (algorithm, size)
                position = position_by_condition[condition]
                noise_index = (block_id * 7 + size_index * 11 + algorithm_index * 5) % 13
                noise = (noise_index - 6) * 0.00001
                seconds = (
                    0.01
                    + algorithm_index * 0.003
                    + size_index * 0.0008
                    + block_id * 0.00003
                    + noise
                )
                start = block_id * 1.0 + position * 0.01
                input_identifier = f"test-block-{block_id}-size-{size}"
                rows.append(
                    {
                        "Algorithm": algorithm,
                        "Input size in bytes": size,
                        "Block ID": block_id,
                        "Randomized position within block": position,
                        "Repetition number": block_id,
                        "Execution time in seconds": seconds,
                        "Input identifier": input_identifier,
                        "Measurement start monotonic seconds": start,
                        "Measurement end monotonic seconds": start + seconds,
                        "Digest": hashlib.sha256(
                            f"{algorithm}:{input_identifier}".encode()
                        ).hexdigest(),
                    }
                )
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=RAW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


class RandomizedBlockAnalysisTests(unittest.TestCase):
    def test_block_model_detects_known_size_effect_after_accounting_for_blocks(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            input_path = root / "test_fixture.csv"
            output_dir = root / "analysis"
            _write_synthetic_fixture(input_path)
            files = analyze_randomized_blocks(
                input_path,
                output_dir,
                seed=71,
                permutation_count=199,
            )

            summary = json.loads(Path(files["summary_json"]).read_text(encoding="utf-8"))
            self.assertEqual(summary["observation_count"], BLOCK_COUNT * len(conditions()))
            self.assertEqual(len(summary["model_results_by_algorithm"]), 3)
            for result in summary["model_results_by_algorithm"]:
                self.assertGreater(result["input_size_test"]["partial_eta_squared"], 0.9)
                self.assertEqual(result["design_based_sensitivity"]["permutations"], 199)

    def test_analysis_output_structure_and_original_data_preservation(self):
        original_before = hashlib.sha256(ORIGINAL_BENCHMARK.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            input_path = root / "synthetic_fixture.csv"
            _write_synthetic_fixture(input_path)
            files = analyze_randomized_blocks(
                input_path,
                root / "analysis",
                seed=3,
                permutation_count=99,
            )

            with Path(files["descriptive_csv"]).open(newline="", encoding="utf-8") as csv_file:
                descriptive_reader = csv.DictReader(csv_file)
                descriptive_rows = list(descriptive_reader)
                self.assertEqual(tuple(descriptive_reader.fieldnames), DESCRIPTIVE_FIELDS)
            with Path(files["model_csv"]).open(newline="", encoding="utf-8") as csv_file:
                model_reader = csv.DictReader(csv_file)
                model_rows = list(model_reader)
                self.assertEqual(tuple(model_reader.fieldnames), MODEL_FIELDS)
            with Path(files["pairwise_csv"]).open(newline="", encoding="utf-8") as csv_file:
                pairwise_reader = csv.DictReader(csv_file)
                list(pairwise_reader)
                self.assertEqual(tuple(pairwise_reader.fieldnames), PAIRWISE_FIELDS)

            summary_path = Path(files["summary_json"])
            plot_path = Path(files["diagnostic_qq_plot"])
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(len(descriptive_rows), 15)
            self.assertEqual(len(model_rows), 3)
            self.assertTrue(plot_path.is_file())
            self.assertEqual(plot_path.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(summary["source_observation_count"] if "source_observation_count" in summary else summary["observation_count"], 450)

        original_after = hashlib.sha256(ORIGINAL_BENCHMARK.read_bytes()).hexdigest()
        self.assertEqual(original_before, original_after)


if __name__ == "__main__":
    unittest.main()
