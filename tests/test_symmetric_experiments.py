import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from symmetric.adversarial_runner import (
    MALFORMED,
    RQ2_CSV_NAME,
    RQ3_CSV_NAME,
    SCENARIOS,
    run_rq2,
    run_rq3,
    _timed_decrypt,
    rq3_block_orders,
    rq3_conditions,
)
from symmetric.experiment_runner import RAW_CSV_NAME, block_orders, conditions, run_rq1
from symmetric.experiment_utils import INPUT_SIZES
from symmetric.common import CiphertextEnvelope, InvalidCiphertextError
from symmetric.schemes import SCHEMES


class SymmetricExperimentRunnerTests(unittest.TestCase):
    def test_rq3_timer_stops_immediately_after_return_or_rejection(self):
        envelope = CiphertextEnvelope("test", b"data")
        success = mock.Mock()
        success.decrypt.return_value = b"plain"
        with mock.patch("symmetric.adversarial_runner.time.perf_counter", side_effect=(1.0, 1.25)):
            elapsed, start, end, plaintext, accepted, released, stage = _timed_decrypt(success, envelope, b"key")
        self.assertEqual(elapsed, 0.25)
        self.assertEqual((start, end), (1.0, 1.25))
        self.assertEqual(plaintext, b"plain")
        self.assertTrue(accepted and released)
        self.assertEqual(stage, "")

        failure = mock.Mock()
        failure.decrypt.side_effect = InvalidCiphertextError("authentication")
        with mock.patch("symmetric.adversarial_runner.time.perf_counter", side_effect=(3.0, 3.5)):
            elapsed, start, end, plaintext, accepted, released, stage = _timed_decrypt(failure, envelope, b"key")
        self.assertEqual(elapsed, 0.5)
        self.assertEqual((start, end), (3.0, 3.5))
        self.assertIsNone(plaintext)
        self.assertFalse(accepted or released)
        self.assertEqual(stage, "authentication")

    def test_rq1_and_rq3_condition_sets_are_complete_and_reproducible(self):
        self.assertEqual(INPUT_SIZES, (1024, 10240, 102400, 1048576, 10485760))
        expected_rq1 = set(conditions())
        self.assertEqual(len(expected_rq1), 30)
        self.assertEqual(len(block_orders(93, blocks=4)), 4)
        for order in block_orders(93, blocks=4):
            self.assertEqual(set(order), expected_rq1)
            self.assertEqual(len(order), len(set(order)))
        expected_rq3 = set(rq3_conditions())
        self.assertEqual(len(expected_rq3), 90)
        first = rq3_block_orders(733, blocks=3)
        self.assertEqual(first, rq3_block_orders(733, blocks=3))
        for order in first:
            self.assertEqual(set(order), expected_rq3)
            self.assertEqual(len(order), len(set(order)))

    def test_small_rq1_runner_has_same_input_id_and_excludes_warmups(self):
        with tempfile.TemporaryDirectory() as temporary:
            raw_path, metadata_path = run_rq1(
                Path(temporary) / "run", seed=18, blocks=2, input_sizes=(32, 64)
            )
            with raw_path.open(newline="", encoding="utf-8") as source:
                rows = list(csv.DictReader(source))
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(raw_path.name, RAW_CSV_NAME)
            self.assertEqual(len(rows), 2 * 3 * 2 * 2)
            self.assertFalse(metadata["warmups_in_raw_csv"])
            for block in (1, 2):
                for size in (32, 64):
                    group = [row for row in rows if int(row["Block ID"]) == block and int(row["Input size in bytes"]) == size]
                    self.assertEqual(len({row["Input identifier"] for row in group}), 1)
                    self.assertEqual(len({row["Algorithm"] for row in group}), 3)

    def test_rq2_runs_all_expected_cases_and_no_invalid_case_releases_plaintext(self):
        with tempfile.TemporaryDirectory() as temporary:
            raw_path, metadata_path = run_rq2(
                Path(temporary) / "run", seed=29, input_sizes=(32,)
            )
            with raw_path.open(newline="", encoding="utf-8") as source:
                rows = list(csv.DictReader(source))
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(raw_path.name, RQ2_CSV_NAME)
            self.assertEqual(len(rows), 3 * len(SCENARIOS))
            self.assertEqual(metadata["case_count"], len(rows))
            for row in rows:
                self.assertEqual(row["Outcome matched expectation"], "True")
                if row["Scenario"] == "valid":
                    self.assertEqual(row["Plaintext released"], "True")
                else:
                    self.assertEqual(row["Plaintext released"], "False")

    def test_rq3_measured_rows_are_complete_with_distinct_failure_stages(self):
        with tempfile.TemporaryDirectory() as temporary:
            raw_path, metadata_path = run_rq3(
                Path(temporary) / "run", seed=47, blocks=2, input_sizes=(32,)
            )
            with raw_path.open(newline="", encoding="utf-8") as source:
                rows = list(csv.DictReader(source))
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertEqual(raw_path.name, RQ3_CSV_NAME)
            self.assertEqual(len(rows), 2 * 3 * len(SCENARIOS))
            self.assertEqual(metadata["measured_observations"], len(rows))
            for block in (1, 2):
                block_rows = [row for row in rows if int(row["Block ID"]) == block]
                self.assertEqual({int(row["Randomized position within block"]) for row in block_rows}, set(range(1, 19)))
                for row in block_rows:
                    is_valid = row["Scenario"] == "valid"
                    self.assertEqual(row["Accepted"], str(is_valid))
                    self.assertEqual(row["Plaintext released"], str(is_valid))
                    if row["Scenario"] == MALFORMED:
                        self.assertEqual(row["Failure category"], "envelope_validation")


if __name__ == "__main__":
    unittest.main()
