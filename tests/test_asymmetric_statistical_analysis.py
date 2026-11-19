import csv
import hashlib
import json
import math
import tempfile
import unittest
from pathlib import Path

import numpy as np

from asymmetric.adversarial_runner import (
    CIPHERTEXT_TAMPERED,
    KEY_TAMPERED,
    MALFORMED,
    RQ3_FIELDS,
    TAG_TAMPERED,
    VALID,
    rq3_block_orders,
)
from asymmetric.experiment_runner import RAW_FIELDS, block_orders, conditions
from asymmetric.experiment_utils import INPUT_SIZES, write_csv, write_json
from asymmetric.repeated_measures import (
    build_repeated_measures_matrix,
    repeated_measures_anova,
)
from asymmetric.schemes import SCHEMES
from asymmetric.statistical_analysis import (
    analyze_rq1,
    analyze_rq2,
    analyze_rq3,
    exact_paired_sign_flip_p,
    holm_adjust,
)


class AsymmetricStatisticalAnalysisTests(unittest.TestCase):
    def test_holm_adjustment_is_monotone_and_preserves_input_order(self):
        self.assertEqual(holm_adjust([0.01, 0.04, 0.03]), [0.03, 0.06, 0.06])

    def test_exact_sign_flip_test_matches_small_known_distribution(self):
        self.assertEqual(exact_paired_sign_flip_p([1.0, 1.0, 1.0]), 0.25)
        self.assertEqual(exact_paired_sign_flip_p([0.0, 0.0, 0.0]), 1.0)

    def test_rm_anova_calculates_factor_f_and_expected_degrees_of_freedom(self):
        rng = np.random.default_rng(101)
        matrix = (
            np.arange(30)[:, None] * 0.2
            + np.arange(5)[None, :] * 0.5
            + rng.normal(size=(30, 5))
        )
        result = repeated_measures_anova(matrix)
        grand = matrix.mean()
        level_means = matrix.mean(axis=0)
        subject_means = matrix.mean(axis=1)
        residuals = matrix - level_means[None, :] - subject_means[:, None] + grand
        ss_factor = matrix.shape[0] * np.square(level_means - grand).sum()
        ss_error = np.square(residuals).sum()
        expected_f = (ss_factor / 4) / (ss_error / 116)

        self.assertEqual(result["uncorrected_df_numerator"], 4)
        self.assertEqual(result["uncorrected_df_denominator"], 116)
        self.assertAlmostEqual(result["f_statistic"], expected_f)
        self.assertAlmostEqual(
            result["partial_eta_squared"], ss_factor / (ss_factor + ss_error)
        )
        self.assertFalse(result["sphericity_rejected"])
        self.assertEqual(result["correction_used"], "None")
        self.assertEqual(result["primary_df_numerator"], 4)
        self.assertEqual(result["primary_df_denominator"], 116)

    def test_rm_anova_uses_greenhouse_geisser_when_sphericity_is_rejected(self):
        rng = np.random.default_rng(202)
        scales = np.asarray([0.1, 0.2, 0.5, 2.0, 5.0])
        matrix = (
            np.arange(30)[:, None] * 0.2
            + np.arange(5)[None, :] * 0.5
            + rng.normal(size=(30, 5)) * scales
        )
        result = repeated_measures_anova(matrix)

        self.assertLess(result["mauchly_p_value"], 0.05)
        self.assertLess(result["greenhouse_geisser_epsilon"], 1.0)
        self.assertEqual(result["correction_used"], "Greenhouse-Geisser")
        self.assertAlmostEqual(
            result["primary_df_numerator"],
            result["greenhouse_geisser_epsilon"] * result["uncorrected_df_numerator"],
        )
        self.assertAlmostEqual(
            result["primary_df_denominator"],
            result["greenhouse_geisser_epsilon"] * result["uncorrected_df_denominator"],
        )
        self.assertEqual(result["primary_p_value"], result["greenhouse_geisser_p_value"])

    def test_repeated_measures_matrix_rejects_missing_and_duplicate_cells(self):
        rows = [
            {"Block ID": block, "Input size in bytes": size, "Execution time in seconds": 1.0}
            for block in (1, 2, 3)
            for size in (10, 20, 30)
        ]
        matrix = build_repeated_measures_matrix(rows, (10, 20, 30), (1, 2, 3))
        self.assertEqual(matrix.shape, (3, 3))
        with self.assertRaisesRegex(ValueError, "missing repeated-measures"):
            build_repeated_measures_matrix(rows[:-1], (10, 20, 30), (1, 2, 3))
        with self.assertRaisesRegex(ValueError, "duplicate repeated-measures"):
            build_repeated_measures_matrix(rows + [rows[0]], (10, 20, 30), (1, 2, 3))

    def _synthetic_rq1(self, directory: Path):
        raw_path = directory / "synthetic_rq1.csv"
        metadata_path = directory / "synthetic_rq1.json"
        rows = []
        orders = block_orders(411, blocks=30)
        for block_id, order in enumerate(orders, start=1):
            previous = ""
            for position, (scheme, size, operation) in enumerate(order, start=1):
                size_index = INPUT_SIZES.index(size)
                scheme_index = [item.name for item in SCHEMES].index(scheme)
                noise = math.sin(block_id * position + scheme_index) * 1e-8
                value = (
                    0.001 + block_id * 0.000002 + position * 0.00000001
                    + scheme_index * 0.0001 + (0.00001 if operation == "decrypt" else 0)
                    + noise
                )
                row = {
                    "Scheme": scheme,
                    "Operation": operation,
                    "Input size in bytes": size,
                    "Block ID": block_id,
                    "Randomized position within block": position,
                    "Repetition number": block_id,
                    "Input identifier": f"block-{block_id}-size-{size}",
                    "Envelope identifier": f"{block_id}:{scheme}:{size}:decrypt" if operation == "decrypt" else "",
                    "Previous condition ID": previous,
                    "Measurement start UTC": f"2026-01-01T00:00:{block_id:02d}+00:00",
                    "Measurement start monotonic seconds": block_id * 1000 + position,
                    "Measurement end monotonic seconds": block_id * 1000 + position + value,
                    "Execution time in seconds": value,
                    "Accepted": True if operation == "decrypt" else "",
                    "Failure stage": "" if operation == "decrypt" else "",
                    "Exception category": "" if operation == "decrypt" else "",
                    "Internal exception type": "" if operation == "decrypt" else "",
                    "Internal exception type": "" if operation == "decrypt" else "",
                    "Session key unwrapped": True if operation == "decrypt" and scheme.startswith("RSA-") else (False if operation == "decrypt" and scheme.startswith("RSA-") else ""),
                    "Key agreement completed": True if operation == "decrypt" and not scheme.startswith("RSA-") else ("" if operation == "encrypt" else ""),
                    "HKDF completed": True if operation == "decrypt" and not scheme.startswith("RSA-") else ("" if operation == "encrypt" else ""),
                    "AES-GCM verification reached": True if operation == "decrypt" else "",
                    "Plaintext released": True if operation == "decrypt" else "",
                }
                rows.append(row)
                previous = f"{scheme}|{size}|{operation}"
        write_csv(raw_path, RAW_FIELDS, rows)
        write_json(metadata_path, {
            "block_count": 30,
            "input_sizes_bytes": list(INPUT_SIZES),
            "random_seed_source": "synthetic-test",
        })
        return raw_path, metadata_path

    def test_rq1_outputs_rm_anova_and_distinct_complementary_ols_model(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path, metadata_path = self._synthetic_rq1(root)
            outputs = analyze_rq1(raw_path, metadata_path, root / "analysis")
            with outputs["repeated_measures_anova"].open(newline="", encoding="utf-8") as source:
                anova_rows = list(csv.DictReader(source))
            with outputs["model"].open(newline="", encoding="utf-8") as source:
                model_rows = list(csv.DictReader(source))
            with outputs["descriptive"].open(newline="", encoding="utf-8") as source:
                descriptive = list(csv.DictReader(source))
            summary = json.loads(outputs["summary"].read_text(encoding="utf-8"))
            self.assertEqual(len(anova_rows), 6)
            self.assertEqual(len(model_rows), 6)
            self.assertEqual(len(descriptive), 30)
            self.assertTrue(all(row["Test"] == "Conventional one-factor repeated-measures ANOVA" for row in anova_rows))
            self.assertTrue(all(row["Model"].startswith("Position-adjusted block-fixed-effects OLS") for row in model_rows))
            self.assertTrue(all("not conventional one-way RM-ANOVA" in row["Model"] for row in model_rows))
            self.assertEqual(
                [float(row["Holm adjusted primary p-value across six tests"]) for row in anova_rows],
                holm_adjust([float(row["Primary p-value"]) for row in anova_rows]),
            )
            self.assertTrue(all(int(row["Denominator df"]) == 29 for row in model_rows))
            self.assertTrue(all(row["Mauchly test"] == "not applicable" for row in model_rows))
            self.assertEqual(summary["primary_model"].startswith("Conventional one-factor"), True)
            self.assertEqual(summary["raw_csv_sha256"], hashlib.sha256(raw_path.read_bytes()).hexdigest())

    def test_rq1_rejects_missing_or_duplicate_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path, metadata_path = self._synthetic_rq1(root)
            with raw_path.open(newline="", encoding="utf-8") as source:
                rows = list(csv.DictReader(source))
            fields = tuple(rows[0])
            for name, altered in (("missing", rows[:-1]), ("duplicate", rows + [rows[0]])):
                candidate = root / f"{name}.csv"
                write_csv(candidate, fields, altered)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    analyze_rq1(candidate, metadata_path, root / f"{name}-analysis")

    def _synthetic_rq3(self, directory: Path):
        raw_path = directory / "synthetic_rq3.csv"
        metadata_path = directory / "synthetic_rq3.json"
        size = 1024
        rows = []
        block_seeds = list(range(30))
        orders = rq3_block_orders(909, blocks=30, input_sizes=(size,), randomization_seeds=block_seeds)
        scenario_increase = {
            VALID: 0.0,
            CIPHERTEXT_TAMPERED: 0.00002,
            TAG_TAMPERED: 0.00003,
            KEY_TAMPERED: 0.00004,
            MALFORMED: 0.000005,
        }
        for block_id, order in enumerate(orders, start=1):
            previous = None
            for position, (scheme, input_size, scenario) in enumerate(order, start=1):
                value = 0.001 + block_id * 0.000001 + position * 0.00000001 + scenario_increase[scenario]
                if scenario == VALID:
                    accepted, released, stage = True, True, ""
                    unwrapped = True if scheme.startswith("RSA-") else ""
                    agreement = False if scheme.startswith("RSA-") else True
                    hkdf = False if scheme.startswith("RSA-") else True
                    gcm_reached = True
                elif scenario in (CIPHERTEXT_TAMPERED, TAG_TAMPERED):
                    accepted, released, stage = False, False, "aes_gcm_authentication"
                    unwrapped = True if scheme.startswith("RSA-") else ""
                    agreement = False if scheme.startswith("RSA-") else True
                    hkdf = False if scheme.startswith("RSA-") else True
                    gcm_reached = True
                elif scenario == KEY_TAMPERED and scheme.startswith("RSA-"):
                    accepted, released, stage = False, False, "rsa_oaep_unwrap"
                    unwrapped, agreement, hkdf, gcm_reached = False, "", "", False
                elif scenario == KEY_TAMPERED:
                    accepted, released, stage = False, False, "aes_gcm_authentication"
                    unwrapped, agreement, hkdf, gcm_reached = "", True, True, True
                elif scheme.startswith("RSA-"):
                    accepted, released, stage = False, False, "envelope_validation"
                    unwrapped, agreement, hkdf, gcm_reached = False, "", "", False
                else:
                    accepted, released, stage = False, False, "public_key_parse"
                    unwrapped, agreement, hkdf, gcm_reached = "", False, False, False
                prev = previous or ("", "", "")
                row = {
                    "Scheme": scheme,
                    "Input size in bytes": input_size,
                    "Scenario": scenario,
                    "Scenario detail": scenario,
                    "Input identifier": f"shared-block-{block_id}-size-{input_size}",
                    "Block ID": block_id,
                    "Randomized position within block": position,
                    "Repetition number": block_id,
                    "Previous condition ID": "|".join(map(str, prev)) if prev[0] else "",
                    "Previous scheme": prev[0],
                    "Previous input size in bytes": prev[1],
                    "Previous scenario": prev[2],
                    "Measurement start UTC": f"2026-01-01T00:00:{block_id:02d}+00:00",
                    "Measurement start monotonic seconds": block_id * 1000 + position,
                    "Measurement end monotonic seconds": block_id * 1000 + position + value,
                    "Total attempted decryption time in seconds": value,
                    "Accepted": accepted,
                    "Failure stage": stage,
                    "Exception category": "" if accepted else "synthetic_failure",
                    "Internal exception type": "" if accepted else "SyntheticFailure",
                    "Internal exception type": "" if accepted else "SyntheticFailure",
                    "Session key unwrapped": unwrapped,
                    "Key agreement completed": agreement,
                    "HKDF completed": hkdf,
                    "AES-GCM verification reached": gcm_reached,
                    "Plaintext released": released,
                }
                rows.append(row)
                previous = (scheme, input_size, scenario)
        write_csv(raw_path, RQ3_FIELDS, rows)
        write_json(metadata_path, {
            "block_count": 30,
            "input_sizes_bytes": [size],
            "random_seed_source": "os_entropy",
            "randomization": "one Python random.Random shuffle per block",
            "random_seed": 909,
            "block_randomization_seeds": block_seeds,
        })
        return raw_path, metadata_path

    def test_rq3_uses_all_matched_scenarios_and_downgrades_for_block_trend(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path, metadata_path = self._synthetic_rq3(root)
            outputs = analyze_rq3(raw_path, metadata_path, root / "analysis")
            with outputs["paired_tests"].open(newline="", encoding="utf-8") as source:
                tests = list(csv.DictReader(source))
            summary = json.loads(outputs["summary"].read_text(encoding="utf-8"))
            self.assertEqual(len(tests), 12)
            self.assertTrue(all(row["Randomization p-value (sharp null)"] != "" for row in tests))
            self.assertIn("block_level_temporal_trend_detected", summary["diagnostic_flags"])
            self.assertTrue(summary["randomization_test"]["interpretation_status"].startswith("downgraded"))

    def test_rq3_rejects_duplicate_condition_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path, metadata_path = self._synthetic_rq3(root)
            with raw_path.open(newline="", encoding="utf-8") as source:
                rows = list(csv.DictReader(source))
            duplicate_path = root / "duplicate.csv"
            write_csv(duplicate_path, RQ3_FIELDS, rows + [rows[0]])
            with self.assertRaises(ValueError):
                analyze_rq3(duplicate_path, metadata_path, root / "duplicate-analysis")

    def test_rq2_analysis_keeps_failure_stages_separate(self):
        from asymmetric.adversarial_runner import run_rq2

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw_path, metadata_path = run_rq2(
                root / "raw", seed=5, input_sizes=(32,), rsa_key_size=2048
            )
            outputs = analyze_rq2(raw_path, metadata_path, root / "analysis")
            with outputs["summary_csv"].open(newline="", encoding="utf-8") as source:
                summary_rows = list(csv.DictReader(source))
            self.assertEqual(len(summary_rows), 17)
            with outputs["case_validation_csv"].open(newline="", encoding="utf-8") as source:
                validations = list(csv.DictReader(source))
            self.assertEqual(len(validations), 17)
            self.assertTrue(all(row["Case matches expected behavior"] == "True" for row in validations))
            self.assertTrue(json.loads(Path(outputs["summary_json"]).read_text())["all_cases_match_expected_behavior"])
            stages = {row["Scenario"]: row["Failure stage counts"] for row in summary_rows}
            self.assertIn("rsa_oaep_unwrap", stages["wrapped_key_tampered"])
            self.assertIn("public_key_parse", stages["malformed_public_key"])


if __name__ == "__main__":
    unittest.main()
