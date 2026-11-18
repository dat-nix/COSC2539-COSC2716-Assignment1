import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np
from scipy.linalg import helmert

from hashing.experiment_runner import ALGORITHMS, INPUT_SIZES
from hashing.randomized_block_runner import BLOCK_COUNT, RAW_FIELDS, build_block_orders
from hashing.randomized_block_analysis import _restricted_permutation_test
from hashing.repeated_measures_analysis import (
    ANOVA_FIELDS,
    FRIEDMAN_FIELDS,
    POSTHOC_FIELDS,
    _build_matrix,
    _finalize_pairwise_rows,
    _friedman_test,
    _holm_adjust,
    _load_and_validate,
    _rank_sign_rows,
    _repeated_measures_anova,
    analyze_repeated_measures,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_RAW = PROJECT_ROOT / "results" / "hashing_benchmarks.csv"
RANDOMIZED_RAW = (
    PROJECT_ROOT
    / "results"
    / "randomized_block"
    / "hashing_randomized_block_benchmarks.csv"
)
EXPECTED_ORIGINAL_SHA256 = "f4ab011fedfb337cfe97d0192ab2caaa261c16310d534b208ffc39b6ce2b063c"
EXPECTED_RANDOMIZED_SHA256 = "a66103cbd5d37f9c1779f5bbebf6c599834522d967181d769b83aa80757fefd8"


def _fixture_rows() -> list[dict]:
    """Create temporary synthetic measurements for tests, never experiment data."""
    rows = []
    algorithm_names = [name for name, _ in ALGORITHMS]
    for block_id, order in enumerate(build_block_orders(seed=20261118), start=1):
        positions = {condition: position for position, condition in enumerate(order, start=1)}
        for algorithm_index, algorithm in enumerate(algorithm_names):
            for size_index, size in enumerate(INPUT_SIZES):
                condition = (algorithm, size)
                position = positions[condition]
                noise_index = (block_id * 7 + size_index * 11 + algorithm_index * 5) % 13
                noise = (noise_index - 6) * 0.000001
                seconds = (
                    0.01
                    + algorithm_index * 0.02
                    + size_index * 0.005
                    + block_id * 0.00003
                    + noise
                )
                input_identifier = f"synthetic-block-{block_id}-size-{size}"
                start = block_id * 100.0 + position
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
    return rows


def _write_rows(path: Path, rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=RAW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


class RepeatedMeasuresAnalysisTests(unittest.TestCase):
    def test_five_input_size_levels_and_complete_block_pairing(self):
        self.assertEqual(len(INPUT_SIZES), 5)
        self.assertEqual(
            INPUT_SIZES,
            (1024, 10 * 1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024),
        )
        rows = _fixture_rows()
        records, _ = _load_and_validate_from_rows_for_test(rows)
        self.assertEqual(len(records), 450)
        for algorithm, _ in ALGORITHMS:
            matrix, blocks = _build_matrix(records, algorithm)
            self.assertEqual(matrix.shape, (30, 5))
            self.assertEqual(blocks, tuple(range(1, 31)))

    def test_repeated_matrix_matches_block_and_size_cells(self):
        rows = _fixture_rows()
        records, _ = _load_and_validate_from_rows_for_test(rows)
        matrix, _ = _build_matrix(records, "SHA-256")
        lookup = {
            (row["Block ID"], row["Input size in bytes"]): row["Execution time in seconds"]
            for row in records
            if row["Algorithm"] == "SHA-256"
        }
        for block_index in range(30):
            for size_index, size in enumerate(INPUT_SIZES):
                self.assertEqual(matrix[block_index, size_index], lookup[(block_index + 1, size)])

    def test_validation_rejects_missing_and_duplicate_observations(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            rows = _fixture_rows()
            missing_path = root / "missing.csv"
            _write_rows(missing_path, rows[:-1])
            with self.assertRaisesRegex(ValueError, "exactly one observation"):
                _load_and_validate(missing_path)

            duplicate_path = root / "duplicate.csv"
            _write_rows(duplicate_path, rows + [rows[-1]])
            with self.assertRaisesRegex(ValueError, "exactly one observation"):
                _load_and_validate(duplicate_path)

    def test_holm_adjustment_uses_step_down_values(self):
        self.assertEqual(_holm_adjust([0.01, 0.04, 0.03]), [0.03, 0.06, 0.06])

    def test_repeated_measures_effect_size_and_sphericity_outputs(self):
        block_effects = np.arange(30, dtype=float)[:, None] * 0.001
        noise = np.fromfunction(
            lambda block, size: ((block + 1) * (size + 2)) % 11,
            (30, 5),
            dtype=float,
        )
        noise = noise - noise.mean(axis=1, keepdims=True)
        noise = noise - noise.mean(axis=0, keepdims=True) + noise.mean()
        size_effects = np.arange(5, dtype=float)[None, :] * 0.01
        matrix = 0.1 + block_effects + size_effects + noise * 0.0001
        result = _repeated_measures_anova(matrix)

        self.assertEqual(result["df_size"], 4)
        self.assertEqual(result["df_error"], 116)
        self.assertGreater(result["f_statistic"], 0)
        self.assertGreater(result["partial_eta_squared"], 0.9)
        self.assertAlmostEqual(
            result["partial_eta_squared"],
            result["ss_size"] / (result["ss_size"] + result["ss_error"]),
        )
        self.assertGreaterEqual(result["greenhouse_geisser_epsilon"], 0.25)
        self.assertLessEqual(result["greenhouse_geisser_epsilon"], 1.0)
        self.assertLessEqual(result["gg_df_size"], result["df_size"])
        self.assertLessEqual(result["gg_df_error"], result["df_error"])

    def test_sphericity_correction_is_only_selected_when_mauchly_rejects(self):
        contrast_basis = np.linalg.qr(
            np.column_stack(
                [
                    np.cos(2 * np.pi * (np.arange(30) + 0.5) * harmonic / 30)
                    for harmonic in range(1, 5)
                ]
            )
        )[0]
        equal_covariance_contrasts = contrast_basis * np.sqrt(15.0)
        matrix = equal_covariance_contrasts @ helmert(5, full=False)
        matrix += np.arange(30, dtype=float)[:, None] * 0.001
        result = _repeated_measures_anova(matrix)
        self.assertGreater(result["mauchly_p_value"], 0.05)
        self.assertEqual(result["sphericity_correction_used"], "None")
        self.assertEqual(result["primary_df_size"], result["df_size"])
        self.assertEqual(result["primary_p_value"], result["raw_p_value"])

    def test_friedman_kendall_w_and_paired_rank_posthoc(self):
        matrix = np.tile(np.arange(5, dtype=float), (30, 1))
        omnibus = _friedman_test(matrix)
        self.assertEqual(omnibus["degrees_of_freedom"], 4)
        self.assertAlmostEqual(omnibus["kendall_w"], 1.0)
        self.assertLess(omnibus["p_value"], 0.05)

        rows = _rank_sign_rows("SHA-256", matrix)
        self.assertEqual(len(rows), 10)
        _finalize_pairwise_rows(rows, 0.05)
        self.assertAlmostEqual(rows[0]["Probability size 1 has faster rank"], 1.0)
        self.assertAlmostEqual(rows[0]["Rank-direction effect (2p - 1)"], 1.0)
        self.assertLess(rows[0]["Holm adjusted p-value across all reported pairs"], 0.05)
        self.assertLessEqual(
            rows[0]["Bonferroni simultaneous CI low for probability"],
            rows[0]["Probability size 1 has faster rank"],
        )
        self.assertGreaterEqual(
            rows[0]["Bonferroni simultaneous CI high for probability"],
            rows[0]["Probability size 1 has faster rank"],
        )

    def test_existing_restricted_permutation_is_reproducible(self):
        matrix = np.tile(np.arange(5, dtype=float), (30, 1))
        first = _restricted_permutation_test(matrix, seed=314, permutation_count=99)
        second = _restricted_permutation_test(matrix, seed=314, permutation_count=99)
        self.assertEqual(first, second)

    def test_output_schema_and_original_raw_checksums_are_preserved(self):
        original_before = hashlib.sha256(ORIGINAL_RAW.read_bytes()).hexdigest()
        randomized_before = hashlib.sha256(RANDOMIZED_RAW.read_bytes()).hexdigest()
        self.assertEqual(original_before, EXPECTED_ORIGINAL_SHA256)
        self.assertEqual(randomized_before, EXPECTED_RANDOMIZED_SHA256)

        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            input_path = root / "synthetic_fixture.csv"
            _write_rows(input_path, _fixture_rows())
            files = analyze_repeated_measures(input_path, root / "analysis")

            with Path(files["repeated_measures_anova_csv"]).open(
                newline="", encoding="utf-8"
            ) as csv_file:
                reader = csv.DictReader(csv_file)
                anova_rows = list(reader)
                self.assertEqual(tuple(reader.fieldnames), ANOVA_FIELDS)
            with Path(files["friedman_csv"]).open(
                newline="", encoding="utf-8"
            ) as csv_file:
                reader = csv.DictReader(csv_file)
                friedman_rows = list(reader)
                self.assertEqual(tuple(reader.fieldnames), FRIEDMAN_FIELDS)
            with Path(files["posthoc_csv"]).open(
                newline="", encoding="utf-8"
            ) as csv_file:
                reader = csv.DictReader(csv_file)
                posthoc_rows = list(reader)
                self.assertEqual(tuple(reader.fieldnames), POSTHOC_FIELDS)

            summary = json.loads(Path(files["summary_json"]).read_text(encoding="utf-8"))
            self.assertEqual(len(anova_rows), 3)
            self.assertEqual(len(friedman_rows), 3)
            self.assertEqual(len(posthoc_rows), 30)
            self.assertEqual(summary["observation_count"], 450)
            self.assertFalse(summary["reproducibility"]["randomness_used"])
            self.assertTrue(Path(files["diagnostic_qq_plot"]).is_file())
            self.assertEqual(
                Path(files["diagnostic_qq_plot"]).read_bytes()[:8],
                b"\x89PNG\r\n\x1a\n",
            )

        self.assertEqual(hashlib.sha256(ORIGINAL_RAW.read_bytes()).hexdigest(), original_before)
        self.assertEqual(
            hashlib.sha256(RANDOMIZED_RAW.read_bytes()).hexdigest(), randomized_before
        )


def _load_and_validate_from_rows_for_test(rows: list[dict]) -> tuple[list[dict], str]:
    """Use the public CSV validator for an in-memory synthetic fixture."""
    with tempfile.TemporaryDirectory() as temporary_dir:
        path = Path(temporary_dir) / "fixture.csv"
        _write_rows(path, rows)
        return _load_and_validate(path)


if __name__ == "__main__":
    unittest.main()
