import csv
import json
import itertools
import math
import tempfile
import unittest
from pathlib import Path

from rq1_matched_comparative_analysis import (
    DEFAULT_SPECS,
    DESCRIPTIVE_FIELDS,
    INPUT_SIZES,
    PAIRWISE_FIELDS,
    _paired_metrics,
    _read_rows,
    analyze_rows,
    run_analysis,
    validate_rows,
)


class MatchedComparativeAnalysisTests(unittest.TestCase):
    def test_authoritative_datasets_have_complete_matched_comparisons(self):
        descriptive_count = 0
        pairwise_count = 0
        raw_counts = {}
        for spec in DEFAULT_SPECS:
            rows, _, _ = _read_rows(spec)
            validation = validate_rows(spec, rows)
            descriptive, pairwise = analyze_rows(spec, rows)
            raw_counts[spec.category] = validation["raw_rows"]
            self.assertEqual(validation["duplicate_condition_keys"], 0)
            self.assertEqual(validation["missing_condition_keys"], 0)
            self.assertTrue(validation["input_identifiers_shared_per_block_size"])
            self.assertEqual(
                {row["Input size (bytes)"] for row in descriptive}, set(INPUT_SIZES)
            )
            self.assertTrue(all(row["Matched blocks"] == 30 for row in descriptive))
            self.assertTrue(all(row["Matched blocks"] == 30 for row in pairwise))
            self.assertEqual(
                len(pairwise),
                math.comb(len(spec.algorithms), 2)
                * len(spec.operations)
                * len(INPUT_SIZES),
            )
            observed_pairs = {
                (row["Operation"], row["Input size (bytes)"], row["Algorithm A"], row["Algorithm B"])
                for row in pairwise
            }
            expected_pairs = {
                (operation, size, algorithm_a, algorithm_b)
                for operation in spec.operations
                for size in INPUT_SIZES
                for algorithm_a, algorithm_b in itertools.combinations(spec.algorithms, 2)
            }
            self.assertEqual(observed_pairs, expected_pairs)
            descriptive_count += len(descriptive)
            pairwise_count += len(pairwise)

        self.assertEqual(raw_counts, {"Hashing": 450, "Symmetric": 900, "Hybrid": 900})
        self.assertEqual(descriptive_count, 75)
        self.assertEqual(pairwise_count, 75)

    def test_pairwise_metrics_are_computed_from_matched_values(self):
        result = _paired_metrics([1.0, 2.0, 3.0], [2.0, 2.0, 6.0])
        self.assertEqual(result["matched_blocks"], 3)
        self.assertAlmostEqual(result["mean_difference"], -4.0 / 3.0)
        self.assertAlmostEqual(result["median_difference"], -1.0)
        self.assertAlmostEqual(result["mean_ratio"], 2.0 / 3.0)
        self.assertAlmostEqual(result["median_ratio"], 0.5)
        self.assertAlmostEqual(result["mean_percentage_difference"], -100.0 / 3.0)
        self.assertAlmostEqual(result["median_percentage_difference"], -50.0)

    def test_validation_rejects_missing_duplicate_or_mismatched_inputs(self):
        spec = DEFAULT_SPECS[0]
        rows, _, _ = _read_rows(spec)
        with self.assertRaisesRegex(ValueError, "incomplete/duplicate design"):
            validate_rows(spec, rows[:-1])
        with self.assertRaisesRegex(ValueError, "incomplete/duplicate design"):
            validate_rows(spec, rows + [rows[0]])

        mismatched = [dict(row) for row in rows]
        mismatched[0]["input_identifier"] += "-different"
        with self.assertRaisesRegex(ValueError, "do not share one input ID"):
            validate_rows(spec, mismatched)

    def test_analysis_outputs_have_documented_schema_and_no_inference(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            output_dir = Path(temporary_dir) / "analysis"
            outputs = run_analysis(output_dir)
            with outputs["descriptive"].open(newline="", encoding="utf-8") as source:
                descriptive_reader = csv.DictReader(source)
                descriptive = list(descriptive_reader)
                self.assertEqual(tuple(descriptive_reader.fieldnames), DESCRIPTIVE_FIELDS)
            with outputs["pairwise"].open(newline="", encoding="utf-8") as source:
                pairwise_reader = csv.DictReader(source)
                pairwise = list(pairwise_reader)
                self.assertEqual(tuple(pairwise_reader.fieldnames), PAIRWISE_FIELDS)
            validation = json.loads(outputs["validation"].read_text(encoding="utf-8"))

            self.assertEqual(len(descriptive), 75)
            self.assertEqual(len(pairwise), 75)
            self.assertFalse(validation["inferential_tests_performed"])
            self.assertEqual(validation["output_row_counts"]["pairwise_rows"], 75)
            self.assertEqual(
                {
                    category: dataset["pairwise_output_rows"]
                    for category, dataset in validation["datasets"].items()
                },
                {"Hashing": 15, "Symmetric": 30, "Hybrid": 30},
            )
            numeric_pairwise_columns = (
                "Mean paired time difference A-B (seconds)",
                "Median paired time difference A-B (seconds)",
                "Mean paired time ratio A/B",
                "Median paired time ratio A/B",
                "Mean paired percentage difference (%, 100*(A-B)/B)",
                "Median paired percentage difference (%, 100*(A-B)/B)",
            )
            for row in pairwise:
                for column in numeric_pairwise_columns:
                    self.assertTrue(math.isfinite(float(row[column])))
                self.assertGreater(float(row["Mean paired time ratio A/B"]), 0.0)
            for row in descriptive:
                mean = float(row["Mean execution time (seconds)"])
                size = int(row["Input size (bytes)"])
                throughput = float(
                    row["Effective payload throughput from mean time (MiB/s)"]
                )
                self.assertTrue(math.isfinite(throughput))
                self.assertAlmostEqual(throughput, size / (1024 * 1024) / mean)
            self.assertTrue(all(int(row["Matched blocks"]) == 30 for row in pairwise))


if __name__ == "__main__":
    unittest.main()
