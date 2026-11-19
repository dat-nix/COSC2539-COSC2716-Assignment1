import csv
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from asymmetric.adversarial_runner import (
    MALFORMED,
    RQ2_CSV_NAME,
    RQ3_CSV_NAME,
    run_rq2,
    run_rq3,
    rq3_block_orders,
    rq3_conditions,
)
from asymmetric.experiment_runner import (
    RAW_CSV_NAME as RQ1_CSV_NAME,
    block_orders,
    conditions as rq1_conditions,
    run_rq1,
)
from asymmetric.experiment_utils import INPUT_SIZES


class AsymmetricExperimentTests(unittest.TestCase):
    def test_input_sizes_and_rq1_conditions_are_complete(self):
        self.assertEqual(INPUT_SIZES, (1024, 10240, 102400, 1048576, 10485760))
        self.assertEqual(len(rq1_conditions()), 30)
        self.assertEqual(len({condition[0] for condition in rq1_conditions()}), 3)
        self.assertEqual(len({condition[1] for condition in rq1_conditions()}), 5)
        self.assertEqual(len({condition[2] for condition in rq1_conditions()}), 2)

    def test_rq1_randomized_blocks_are_reproducible_and_complete(self):
        first = block_orders(12345, blocks=4)
        second = block_orders(12345, blocks=4)
        self.assertEqual(first, second)
        self.assertEqual(len(first), 4)
        expected = set(rq1_conditions())
        for order in first:
            self.assertEqual(len(order), 30)
            self.assertEqual(len(set(order)), 30)
            self.assertEqual(set(order), expected)

    def test_rq3_randomized_blocks_have_75_unique_conditions(self):
        self.assertEqual(len(rq3_conditions()), 75)
        orders = rq3_block_orders(9981, blocks=3)
        self.assertEqual(orders, rq3_block_orders(9981, blocks=3))
        expected = set(rq3_conditions())
        for order in orders:
            self.assertEqual(len(order), 75)
            self.assertEqual(len(set(order)), 75)
            self.assertEqual(set(order), expected)

    def test_small_rq1_runner_records_timing_and_does_not_write_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_path, metadata_path = run_rq1(
                directory, seed=7, blocks=1, input_sizes=(32,), rsa_key_size=2048
            )
            with raw_path.open(newline="", encoding="utf-8") as source:
                rows = list(csv.DictReader(source))
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(raw_path.name, RQ1_CSV_NAME)
            self.assertEqual(len(rows), 6)
            self.assertTrue(all(float(row["Execution time in seconds"]) > 0 for row in rows))
            self.assertEqual({int(row["Randomized position within block"]) for row in rows}, set(range(1, 7)))
            self.assertNotIn("private_key", json.dumps(metadata).lower())
            self.assertEqual(len({row["Input identifier"] for row in rows}), 1)

    def test_rq2_runner_records_rejections_without_plaintext(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_path, metadata_path = run_rq2(
                directory, seed=9, input_sizes=(32,), rsa_key_size=2048
            )
            with raw_path.open(newline="", encoding="utf-8") as source:
                rows = list(csv.DictReader(source))
            self.assertEqual(raw_path.name, RQ2_CSV_NAME)
            self.assertEqual(len(rows), 17)
            for row in rows:
                if row["Scenario"] == "valid":
                    self.assertEqual(row["Accepted"], "True")
                    self.assertEqual(row["Plaintext released"], "True")
                else:
                    self.assertEqual(row["Accepted"], "False")
                    self.assertEqual(row["Plaintext released"], "False")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(metadata["case_count"], 17)

    def test_small_rq3_runner_records_failure_stages_and_previous_conditions(self):
        with tempfile.TemporaryDirectory() as directory:
            raw_path, metadata_path = run_rq3(
                directory, seed=3, blocks=1, input_sizes=(32,), rsa_key_size=2048
            )
            with raw_path.open(newline="", encoding="utf-8") as source:
                rows = list(csv.DictReader(source))
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(raw_path.name, RQ3_CSV_NAME)
            self.assertEqual(len(rows), 15)
            self.assertTrue(all(float(row["Total attempted decryption time in seconds"]) > 0 for row in rows))
            self.assertEqual(sum(bool(row["Previous condition ID"]) for row in rows), 14)
            self.assertEqual(metadata["expected_measured_observations"], 15)
            malformed_rows = [row for row in rows if row["Scenario"] == MALFORMED]
            self.assertEqual(len(malformed_rows), 3)
            self.assertTrue(all(row["Plaintext released"] == "False" for row in malformed_rows))

    def test_asymmetric_runner_does_not_modify_existing_hashing_results(self):
        hashing_root = Path(__file__).resolve().parents[1] / "results" / "hashing"
        before = {
            path.relative_to(hashing_root): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in hashing_root.rglob("*")
            if path.is_file()
        }
        with tempfile.TemporaryDirectory() as directory:
            run_rq2(directory, seed=21, input_sizes=(16,), rsa_key_size=2048)
        after = {
            path.relative_to(hashing_root): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in hashing_root.rglob("*")
            if path.is_file()
        }
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
