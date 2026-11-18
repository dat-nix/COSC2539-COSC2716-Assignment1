import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from hashing.statistical_analysis import (
    ANOVA_FIELDS,
    DESCRIPTIVE_FIELDS,
    _analyze_algorithm,
    analyze_benchmarks,
    calculate_descriptive_row,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_CSV = PROJECT_ROOT / "results" / "hashing_benchmarks.csv"


class HashingStatisticalAnalysisTests(unittest.TestCase):
    def test_descriptive_statistics_and_throughput(self):
        row = calculate_descriptive_row(
            "SHA-256", 1_048_576, [1.0, 2.0, 3.0]
        )
        self.assertEqual(row["Observations"], 3)
        self.assertEqual(row["Mean time (seconds)"], 2.0)
        self.assertEqual(row["Median time (seconds)"], 2.0)
        self.assertEqual(row["Standard deviation (seconds)"], 1.0)
        self.assertEqual(row["Minimum time (seconds)"], 1.0)
        self.assertEqual(row["Maximum time (seconds)"], 3.0)
        self.assertEqual(row["Throughput (MiB/s)"], 0.5)

    def test_one_way_anova_calculation_and_interpretation(self):
        # Small deterministic unit-test values, not benchmark observations.
        row, _ = _analyze_algorithm(
            "SHA-256",
            (1_024, 2_048, 3_072),
            [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0], [7.0, 8.0, 9.0]],
        )
        self.assertEqual(row["F-statistic"], 27.0)
        self.assertAlmostEqual(row["p-value"], 0.001)
        self.assertIn("at least one input-size group mean differs", row["ANOVA interpretation"])
        self.assertIn("does not identify which groups differ", row["ANOVA interpretation"])

    def test_analysis_outputs_and_preserves_source_csv(self):
        source_before = hashlib.sha256(BENCHMARK_CSV.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as temporary_dir:
            generated = analyze_benchmarks(BENCHMARK_CSV, temporary_dir)

            descriptive_path = Path(generated["descriptive_statistics_csv"])
            anova_path = Path(generated["anova_results_csv"])
            summary_path = Path(generated["summary_json"])
            plot_path = Path(generated["execution_time_plot"])

            with descriptive_path.open(newline="", encoding="utf-8") as csv_file:
                descriptive_reader = csv.DictReader(csv_file)
                descriptive_rows = list(descriptive_reader)
                self.assertEqual(tuple(descriptive_reader.fieldnames), DESCRIPTIVE_FIELDS)
            with anova_path.open(newline="", encoding="utf-8") as csv_file:
                anova_reader = csv.DictReader(csv_file)
                anova_rows = list(anova_reader)
                self.assertEqual(tuple(anova_reader.fieldnames), ANOVA_FIELDS)

            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(len(descriptive_rows), 15)
            self.assertEqual(len(anova_rows), 3)
            self.assertEqual(summary["source_observation_count"], 450)
            self.assertEqual(
                summary["analysis_method"]["outlier_policy"],
                "No observations were removed, transformed, or winsorized.",
            )
            self.assertTrue(plot_path.is_file())
            self.assertGreater(plot_path.stat().st_size, 0)
            self.assertEqual(plot_path.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")

        source_after = hashlib.sha256(BENCHMARK_CSV.read_bytes()).hexdigest()
        self.assertEqual(source_before, source_after)


if __name__ == "__main__":
    unittest.main()
