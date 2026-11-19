import csv
import json
import math
import tempfile
import unittest
from pathlib import Path

import numpy as np

from symmetric.adversarial_runner import (
    MALFORMED,
    RQ3_FIELDS,
    SCENARIOS,
    VALID,
    rq3_block_orders,
)
from symmetric.experiment_runner import RAW_FIELDS as RQ1_FIELDS, block_orders
from symmetric.experiment_utils import INPUT_SIZES, write_csv, write_json
from symmetric.repeated_measures import analyze_matrix
from symmetric.schemes import SCHEMES
from symmetric.statistical_analysis import (
    RQ1_ANOVA_FIELDS,
    RQ1_DESCRIPTIVE_FIELDS,
    RQ1_FRIEDMAN_FIELDS,
    RQ3_TEST_FIELDS,
    analyze_rq1,
    analyze_rq2,
    analyze_rq3,
    holm_adjust,
)


class SymmetricStatisticalAnalysisTests(unittest.TestCase):
    def test_holm_step_down_adjustment_preserves_order(self):
        self.assertEqual(holm_adjust([0.01, 0.04, 0.03]), [0.03, 0.06, 0.06])

    def test_repeated_measures_anova_calculates_f_degrees_effect_and_gg(self):
        rng = np.random.default_rng(481)
        matrix = (
            rng.normal(0, 0.2, size=(30, 1))
            + np.arange(5)[None, :] * 0.15
            + rng.normal(0, 0.03, size=(30, 5))
        )
        result = analyze_matrix(matrix)
        grand = matrix.mean()
        means = matrix.mean(axis=0)
        block_means = matrix.mean(axis=1)
        residuals = matrix - means[None, :] - block_means[:, None] + grand
        ss_factor = matrix.shape[0] * np.square(means - grand).sum()
        ss_error = np.square(residuals).sum()
        expected_f = (ss_factor / 4) / (ss_error / 116)
        self.assertEqual(result["uncorrected_df_numerator"], 4)
        self.assertEqual(result["uncorrected_df_denominator"], 116)
        self.assertAlmostEqual(result["f_statistic"], expected_f)
        self.assertAlmostEqual(result["partial_eta_squared"], ss_factor / (ss_factor + ss_error))
        self.assertGreaterEqual(result["greenhouse_geisser_epsilon"], 0.25)
        self.assertLessEqual(result["greenhouse_geisser_epsilon"], 1.0)
        self.assertAlmostEqual(
            result["greenhouse_geisser_df_numerator"],
            4 * result["greenhouse_geisser_epsilon"],
        )
        self.assertAlmostEqual(
            result["greenhouse_geisser_df_denominator"],
            116 * result["greenhouse_geisser_epsilon"],
        )

    def test_gg_correction_is_selected_when_mauchly_sphericity_is_rejected(self):
        rng = np.random.default_rng(920)
        scales = np.asarray([0.03, 0.08, 0.2, 0.8, 2.0])
        matrix = (
            rng.normal(size=(30, 1)) * 0.1
            + np.arange(5)[None, :] * 0.1
            + rng.normal(size=(30, 5)) * scales
        )
        result = analyze_matrix(matrix)
        self.assertLess(result["mauchly_p_value"], 0.05)
        self.assertEqual(result["correction_used"], "Greenhouse-Geisser")
        self.assertEqual(result["primary_p_value"], result["greenhouse_geisser_p_value"])
        self.assertEqual(
            result["primary_df_numerator"],
            4 * result["greenhouse_geisser_epsilon"],
        )
        self.assertEqual(
            result["primary_df_denominator"],
            116 * result["greenhouse_geisser_epsilon"],
        )

    def _synthetic_rq1(self, root: Path):
        raw_path = root / "synthetic_rq1.csv"
        metadata_path = root / "synthetic_rq1.json"
        rows = []
        orders = block_orders(383, blocks=30)
        for block_id, order in enumerate(orders, start=1):
            previous = ""
            payload_ids = {size: f"input-{block_id}-{size}" for size in INPUT_SIZES}
            for position, (algorithm, size, operation) in enumerate(order, start=1):
                algorithm_index = [scheme.name for scheme in SCHEMES].index(algorithm)
                op_offset = 0.00003 if operation == "decrypt" else 0.0
                size_index = INPUT_SIZES.index(size)
                elapsed = (
                    0.0002 + size / 100_000_000 + algorithm_index * 0.00002
                    + op_offset + (block_id % 7) * 0.000001
                    + math.sin(block_id * position + size_index) * 0.0000004
                )
                start = block_id * 1000.0 + position
                end = start + elapsed
                rows.append({
                    "Algorithm": algorithm,
                    "Operation": operation,
                    "Input size in bytes": size,
                    "Block ID": block_id,
                    "Randomized position within block": position,
                    "Repetition number": block_id,
                    "Input identifier": payload_ids[size],
                    "Envelope identifier": f"{block_id}:{algorithm}:{size}" if operation == "decrypt" else "",
                    "Previous condition ID": previous,
                    "Measurement start UTC": f"2026-01-01T00:{block_id:02d}:{position:02d}+00:00",
                    "Measurement start monotonic seconds": start,
                    "Measurement end monotonic seconds": end,
                    "Execution time in seconds": elapsed,
                    "Accepted": True,
                    "Plaintext released": operation == "decrypt",
                })
                previous = f"{algorithm}|{size}|{operation}"
        write_csv(raw_path, RQ1_FIELDS, rows)
        write_json(metadata_path, {
            "block_count": 30,
            "input_sizes_bytes": list(INPUT_SIZES),
            "expected_measured_observations": 900,
        })
        return raw_path, metadata_path

    def test_rq1_analysis_outputs_six_rm_anovas_and_six_friedman_tests(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw, metadata = self._synthetic_rq1(root)
            outputs = analyze_rq1(raw, metadata, root / "analysis")
            with outputs["anova"].open(newline="", encoding="utf-8") as source:
                anova_rows = list(csv.DictReader(source))
            with outputs["friedman"].open(newline="", encoding="utf-8") as source:
                friedman_rows = list(csv.DictReader(source))
            with outputs["descriptive"].open(newline="", encoding="utf-8") as source:
                descriptive_rows = list(csv.DictReader(source))
            summary = json.loads(outputs["summary"].read_text(encoding="utf-8"))
            self.assertEqual(tuple(anova_rows[0]), RQ1_ANOVA_FIELDS)
            self.assertEqual(tuple(friedman_rows[0]), RQ1_FRIEDMAN_FIELDS)
            self.assertEqual(tuple(descriptive_rows[0]), RQ1_DESCRIPTIVE_FIELDS)
            self.assertEqual(len(anova_rows), 6)
            self.assertEqual(len(friedman_rows), 6)
            self.assertEqual(len(descriptive_rows), 30)
            self.assertEqual(
                summary["research_question"],
                "How does input data size affect the execution time of selected cryptographic algorithms?",
            )
            self.assertTrue(all(row["Test"] == "One-factor repeated-measures ANOVA" for row in anova_rows))
            self.assertEqual(
                [float(row["Holm adjusted primary p-value across six tests"]) for row in anova_rows],
                holm_adjust([float(row["Primary p-value"]) for row in anova_rows]),
            )
            self.assertEqual(summary["raw_csv_sha256"], __import__("hashlib").sha256(raw.read_bytes()).hexdigest())
            self.assertTrue(outputs["plot"].is_file())

    def test_rq1_analysis_rejects_missing_and_duplicate_cells(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw, metadata = self._synthetic_rq1(root)
            with raw.open(newline="", encoding="utf-8") as source:
                rows = list(csv.DictReader(source))
            for name, altered in (("missing", rows[:-1]), ("duplicate", rows + [rows[0]])):
                candidate = root / f"{name}.csv"
                write_csv(candidate, RQ1_FIELDS, altered)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    analyze_rq1(candidate, metadata, root / f"analysis-{name}")

    def _synthetic_rq3(self, root: Path):
        raw_path = root / "synthetic_rq3.csv"
        metadata_path = root / "synthetic_rq3.json"
        rows = []
        orders = rq3_block_orders(772, blocks=30)
        for block, order in enumerate(orders, start=1):
            previous = ("", "", "")
            for position, (algorithm, size, scenario) in enumerate(order, start=1):
                scheme_index = [scheme.name for scheme in SCHEMES].index(algorithm)
                scenario_index = SCENARIOS.index(scenario)
                elapsed = (
                    0.0003 + size / 100_000_000 + scheme_index * 0.00002
                    + scenario_index * 0.000003 + (block % 5) * 0.0000005
                    + position * 0.000000001
                )
                start = block * 10000.0 + position
                end = start + elapsed
                valid = scenario == VALID
                previous_id = "|".join(map(str, previous)) if previous[0] else ""
                rows.append({
                    "Algorithm": algorithm,
                    "Input size in bytes": size,
                    "Scenario": scenario,
                    "Block ID": block,
                    "Randomized position within block": position,
                    "Repetition number": block,
                    "Input identifier": f"input-{block}-{size}",
                    "Envelope identifier": f"{block}:{algorithm}:{size}",
                    "Previous condition ID": previous_id,
                    "Previous algorithm": previous[0],
                    "Previous input size in bytes": previous[1],
                    "Previous scenario": previous[2],
                    "Measurement start UTC": f"2026-01-01T00:{block:02d}:{position:02d}+00:00",
                    "Measurement start monotonic seconds": start,
                    "Measurement end monotonic seconds": end,
                    "Total attempted decryption time in seconds": elapsed,
                    "Accepted": valid,
                    "Authentication succeeded": valid,
                    "Plaintext released": valid,
                    "Failure category": "" if valid else ("envelope_validation" if scenario == MALFORMED else "authentication"),
                })
                previous = (algorithm, size, scenario)
        write_csv(raw_path, RQ3_FIELDS, rows)
        write_json(metadata_path, {
            "block_count": 30,
            "input_sizes_bytes": list(INPUT_SIZES),
            "expected_measured_observations": 2700,
        })
        return raw_path, metadata_path

    def test_rq3_analysis_has_75_matched_contrasts_and_correct_holm_family(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw, metadata = self._synthetic_rq3(root)
            outputs = analyze_rq3(raw, metadata, root / "analysis", permutations=199, seed=84)
            with outputs["paired_tests"].open(newline="", encoding="utf-8") as source:
                tests = list(csv.DictReader(source))
            summary = json.loads(outputs["summary"].read_text(encoding="utf-8"))
            self.assertEqual(tuple(tests[0]), RQ3_TEST_FIELDS)
            self.assertEqual(len(tests), 75)
            self.assertEqual(summary["paired_comparisons"], 75)
            self.assertEqual(
                summary["research_question"],
                "How do integrity verification and rejection of invalid inputs affect the processing time of selected cryptographic schemes under adversarial conditions?",
            )
            self.assertEqual(
                [float(row["Holm adjusted p-value across 75 comparisons"]) for row in tests],
                holm_adjust([float(row["Monte Carlo raw p-value"]) for row in tests]),
            )
            self.assertEqual({int(row["Matched blocks"]) for row in tests}, {30})
            self.assertTrue(outputs["plot"].is_file())

    def test_rq2_analysis_preserves_and_validates_every_functional_case(self):
        from symmetric.adversarial_runner import run_rq2

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw, metadata = run_rq2(root / "run", seed=10, input_sizes=(32,))
            outputs = analyze_rq2(raw, metadata, root / "analysis")
            with outputs["summary_csv"].open(newline="", encoding="utf-8") as source:
                summary_rows = list(csv.DictReader(source))
            summary = json.loads(outputs["summary"].read_text(encoding="utf-8"))
            self.assertEqual(len(summary_rows), 3 * len(SCENARIOS))
            self.assertEqual(
                summary["research_question"],
                "How do selected cryptographic schemes respond to tampered data and invalid ciphertext?",
            )
            self.assertTrue(summary["all_cases_match_expectation"])
            self.assertEqual(summary["invalid_cases_releasing_plaintext"], 0)


if __name__ == "__main__":
    unittest.main()
