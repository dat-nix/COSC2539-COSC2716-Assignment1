import csv
import tempfile
import unittest
from pathlib import Path

from hashing.experiment_runner import (
    ALGORITHMS,
    INPUT_SIZES,
    TAMPERING_FIELDS,
    MEASURED_ITERATIONS,
    WARMUP_ITERATIONS,
    generate_input,
    run_tampering_experiments,
)


class HashingExperimentTests(unittest.TestCase):
    def test_default_run_configuration(self):
        self.assertEqual(WARMUP_ITERATIONS, 5)
        self.assertEqual(MEASURED_ITERATIONS, 30)
        self.assertEqual(len(INPUT_SIZES), 5)
        self.assertEqual(len(ALGORITHMS), 3)

    def test_all_configured_input_sizes_are_exact_and_deterministic(self):
        for size_bytes in INPUT_SIZES:
            with self.subTest(size_bytes=size_bytes):
                first = generate_input(size_bytes)
                second = generate_input(size_bytes)
                self.assertEqual(len(first), size_bytes)
                self.assertEqual(first, second)

    def test_tampering_csv_distinguishes_trusted_and_recomputed_digest(self):
        with tempfile.TemporaryDirectory() as temporary_dir:
            csv_path = run_tampering_experiments(temporary_dir, input_sizes=(1_024,))

            with csv_path.open(newline="", encoding="utf-8") as csv_file:
                reader = csv.DictReader(csv_file)
                rows = list(reader)

            self.assertEqual(tuple(reader.fieldnames), TAMPERING_FIELDS)
            self.assertEqual(len(rows), len(ALGORITHMS) * 2)
            trusted_scenario = "modified_data_checked_against_trusted_digest"
            recomputed_scenario = "modified_data_with_recomputed_unkeyed_digest"

            for algorithm_name, _ in ALGORITHMS:
                with self.subTest(algorithm=algorithm_name):
                    algorithm_rows = [
                        row for row in rows if row["Algorithm"] == algorithm_name
                    ]
                    by_scenario = {row["Scenario"]: row for row in algorithm_rows}
                    trusted_row = by_scenario[trusted_scenario]
                    recomputed_row = by_scenario[recomputed_scenario]

                    self.assertEqual(trusted_row["Verification passed"], "False")
                    self.assertEqual(trusted_row["Tampering detected"], "True")
                    self.assertNotEqual(
                        trusted_row["Computed digest"], trusted_row["Accompanying digest"]
                    )
                    self.assertEqual(
                        trusted_row["Trusted original digest"],
                        trusted_row["Accompanying digest"],
                    )
                    self.assertEqual(recomputed_row["Verification passed"], "True")
                    self.assertEqual(recomputed_row["Tampering detected"], "False")
                    self.assertEqual(
                        recomputed_row["Computed digest"],
                        recomputed_row["Accompanying digest"],
                    )
                    self.assertNotEqual(
                        recomputed_row["Trusted original digest"],
                        recomputed_row["Accompanying digest"],
                    )


if __name__ == "__main__":
    unittest.main()
