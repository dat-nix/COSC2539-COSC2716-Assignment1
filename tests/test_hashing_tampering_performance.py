import csv
import hashlib
import hmac
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from hashing import blake2b_256, sha256, sha3_256
from hashing.experiment_runner import ALGORITHMS
from hashing.tampering_performance_analysis import (
    DESCRIPTIVE_FIELDS,
    PAIRED_FIELDS,
    _load_observations,
    analyze_tampering_performance,
)
from hashing.tampering_performance_runner import (
    BLOCK_COUNT,
    RAW_FIELDS,
    SCENARIOS,
    TAMPERED_RECOMPUTED_SCENARIO,
    TAMPERED_TRUSTED_SCENARIO,
    VALID_SCENARIO,
    build_block_orders,
    build_warmup_order,
    conditions,
    output_paths,
    prepare_block_inputs,
    run_tampering_performance_experiment,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRESERVED_FILES = (
    PROJECT_ROOT / "results" / "hashing" / "baseline" / "hashing_benchmarks.csv",
    PROJECT_ROOT / "results" / "hashing" / "baseline" / "hashing_tampering.csv",
    PROJECT_ROOT / "results" / "hashing" / "randomized_block" / "hashing_randomized_block_benchmarks.csv",
    PROJECT_ROOT / "results" / "hashing" / "randomized_block" / "hashing_randomized_block_summary.json",
    PROJECT_ROOT
    / "results"
    / "hashing"
    / "randomized_block"
    / "repeated_measures"
    / "hashing_repeated_measures_summary.json",
    PROJECT_ROOT
    / "results"
    / "hashing"
    / "tampering_performance"
    / "hashing_tampering_performance.csv",
)


def _checksums(paths):
    return {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


class TamperingPerformanceTests(unittest.TestCase):
    def test_hash_and_compare_correctness_for_all_algorithms(self):
        original = b"trusted sample data"
        modified = bytearray(original)
        modified[0] ^= 1
        modified = bytes(modified)
        for _, digest_function in ALGORITHMS:
            trusted = digest_function(original)
            recomputed = digest_function(modified)
            self.assertTrue(hmac.compare_digest(digest_function(original), trusted))
            self.assertFalse(hmac.compare_digest(digest_function(modified), trusted))
            self.assertTrue(hmac.compare_digest(digest_function(modified), recomputed))

        self.assertEqual(sha256(original), sha256(original))
        self.assertEqual(sha3_256(original), sha3_256(original))
        self.assertEqual(blake2b_256(original), blake2b_256(original))

    def test_block_schedules_are_complete_randomized_and_reproducible(self):
        schedule = conditions((64, 128))
        self.assertEqual(len(schedule), 3 * 2 * 3)
        self.assertEqual(len(set(schedule)), len(schedule))
        orders = build_block_orders(seed=71, input_sizes=(64, 128), block_count=4)
        self.assertEqual(len(orders), 4)
        for order in orders:
            self.assertEqual(len(order), len(schedule))
            self.assertEqual(set(order), set(schedule))
        self.assertEqual(
            build_block_orders(71, (64, 128), 4),
            build_block_orders(71, (64, 128), 4),
        )
        self.assertNotEqual(
            build_block_orders(71, (64, 128), 4),
            build_block_orders(72, (64, 128), 4),
        )

        warmups = build_warmup_order(71, (64, 128), warmup_iterations=2)
        self.assertEqual(Counter(warmups), Counter({condition: 2 for condition in schedule}))

    def test_modified_input_is_shared_across_algorithms_by_block_and_size(self):
        inputs = prepare_block_inputs(seed=91, block_id=3, input_sizes=(64, 128))
        self.assertEqual(set(inputs), {64, 128})
        for size_bytes, row in inputs.items():
            original = row["original_data"]
            modified = row["modified_data"]
            self.assertEqual(len(original), size_bytes)
            self.assertEqual(len(modified), size_bytes)
            differences = [index for index, pair in enumerate(zip(original, modified)) if pair[0] != pair[1]]
            self.assertEqual(differences, [0])
            self.assertNotEqual(row["original_identifier"], row["modified_identifier"])

        algorithm_outputs = {
            name: (function(inputs[64]["original_data"]), function(inputs[64]["modified_data"]))
            for name, function in ALGORITHMS
        }
        self.assertEqual(len(algorithm_outputs), 3)

    def test_raw_timing_records_cover_complete_blocks_and_correct_outcomes(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            raw_path, metadata_path = run_tampering_performance_experiment(
                temporary_dir,
                seed=17,
                input_sizes=(64, 128),
                block_count=3,
                warmup_iterations=1,
            )
            with raw_path.open(newline="", encoding="utf-8") as csv_file:
                reader = csv.DictReader(csv_file)
                rows = list(reader)
                self.assertEqual(tuple(reader.fieldnames), RAW_FIELDS)
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

            self.assertEqual(len(rows), 3 * 2 * 3 * 3)
            self.assertEqual(metadata["measured_observations"], len(rows))
            self.assertEqual(metadata["block_count"], 3)
            for block_id in range(1, 4):
                block_rows = [row for row in rows if int(row["Block ID"]) == block_id]
                self.assertEqual(len(block_rows), 18)
                self.assertEqual(
                    sorted(int(row["Randomized position within block"]) for row in block_rows),
                    list(range(1, 19)),
                )
            for scenario in SCENARIOS:
                scenario_rows = [row for row in rows if row["Scenario"] == scenario]
                self.assertEqual(len(scenario_rows), 18)
                self.assertTrue(all(float(row["Execution time in seconds"]) > 0 for row in scenario_rows))
                for row in scenario_rows:
                    start = float(row["Measurement start monotonic seconds"])
                    end = float(row["Measurement end monotonic seconds"])
                    elapsed = float(row["Execution time in seconds"])
                    self.assertAlmostEqual(end - start, elapsed, delta=1e-10)

            for row in rows:
                if row["Scenario"] == VALID_SCENARIO:
                    self.assertEqual(row["Data state"], "original")
                    self.assertEqual(row["Verification passed"], "True")
                    self.assertEqual(row["Tampering detected"], "False")
                elif row["Scenario"] == TAMPERED_TRUSTED_SCENARIO:
                    self.assertEqual(row["Data state"], "modified")
                    self.assertEqual(row["Verification passed"], "False")
                    self.assertEqual(row["Tampering detected"], "True")
                else:
                    self.assertEqual(row["Scenario"], TAMPERED_RECOMPUTED_SCENARIO)
                    self.assertEqual(row["Digest trust basis"], "attacker_recomputed_unkeyed")
                    self.assertEqual(row["Verification passed"], "True")
                    self.assertEqual(row["Tampering detected"], "False")

    def test_analysis_outputs_matched_statistics_and_preserves_existing_results(self):
        checksums_before = _checksums(PRESERVED_FILES)
        with tempfile.TemporaryDirectory() as temporary_dir:
            raw_path, _ = run_tampering_performance_experiment(
                temporary_dir,
                seed=29,
                input_sizes=(64, 128),
                block_count=3,
                warmup_iterations=1,
            )
            output_dir = Path(temporary_dir) / "analysis"
            outputs = analyze_tampering_performance(
                raw_path,
                output_dir,
                seed=31,
                permutation_count=99,
                minimum_blocks=3,
            )
            with Path(outputs["descriptive_csv"]).open(
                newline="", encoding="utf-8"
            ) as csv_file:
                reader = csv.DictReader(csv_file)
                descriptive_rows = list(reader)
                self.assertEqual(tuple(reader.fieldnames), DESCRIPTIVE_FIELDS)
            with Path(outputs["paired_tests_csv"]).open(
                newline="", encoding="utf-8"
            ) as csv_file:
                reader = csv.DictReader(csv_file)
                paired_rows = list(reader)
                self.assertEqual(tuple(reader.fieldnames), PAIRED_FIELDS)

            summary = json.loads(Path(outputs["summary_json"]).read_text(encoding="utf-8"))
            self.assertEqual(summary["observation_count"], 3 * 2 * 3 * 3)
            self.assertEqual(len(descriptive_rows), 3 * 2 * 3)
            self.assertEqual(len(paired_rows), 3 * 2 * 3)
            self.assertTrue(
                all(int(row["Paired blocks"]) == 3 for row in paired_rows)
            )
            self.assertTrue(
                all(
                    0 <= float(row["Holm adjusted p-value across all comparisons"]) <= 1
                    for row in paired_rows
                )
            )
            for algorithm, _ in ALGORITHMS:
                by_scenario = summary["tampering_outcomes_separate_from_performance"][algorithm]["64"]
                self.assertEqual(by_scenario[VALID_SCENARIO]["verification_pass_rate"], 1.0)
                self.assertEqual(by_scenario[TAMPERED_TRUSTED_SCENARIO]["tampering_detection_rate"], 1.0)
                self.assertEqual(by_scenario[TAMPERED_RECOMPUTED_SCENARIO]["verification_pass_rate"], 1.0)

        self.assertEqual(_checksums(PRESERVED_FILES), checksums_before)

    def test_analysis_rejects_missing_raw_observations(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            raw_path, metadata_path = run_tampering_performance_experiment(
                temporary_dir,
                seed=43,
                input_sizes=(64,),
                block_count=3,
                warmup_iterations=0,
            )
            with raw_path.open(newline="", encoding="utf-8") as csv_file:
                reader = csv.DictReader(csv_file)
                rows = list(reader)
                fieldnames = reader.fieldnames
            broken_path = Path(temporary_dir) / "missing.csv"
            with broken_path.open("w", newline="", encoding="utf-8") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows[:-1])
            with self.assertRaisesRegex(ValueError, "exactly one observation"):
                _load_observations(
                    broken_path,
                    metadata_path=metadata_path,
                    minimum_blocks=3,
                )


if __name__ == "__main__":
    unittest.main()
