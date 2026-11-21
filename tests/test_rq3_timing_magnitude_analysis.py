import unittest

from analysis.rq3_timing_magnitude_analysis import condition_index, missing_and_extra_keys, paired_metrics


class PairedMetricsTests(unittest.TestCase):
    def test_direction_and_ratios_are_invalid_minus_valid(self):
        result = paired_metrics([2.0, 4.0], [1.0, 6.0])
        self.assertEqual(result["mean_difference"], 0.5)
        self.assertEqual(result["median_difference"], 0.5)
        self.assertEqual(result["mean_percentage_difference"], 0.0)
        self.assertEqual(result["median_percentage_difference"], 0.0)
        self.assertEqual(result["mean_paired_ratio"], 1.0)
        self.assertEqual(result["median_paired_ratio"], 1.0)
        self.assertAlmostEqual(result["ratio_aggregate_means"], 7.0 / 6.0)

    def test_zero_denominator_is_rejected_without_dropping_pair(self):
        with self.assertRaisesRegex(ValueError, "strictly positive valid times"):
            paired_metrics([0.0, 1.0], [1.0, 2.0])

    def test_mismatched_pair_lengths_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "equal in length"):
            paired_metrics([1.0, 2.0], [1.0])

    def test_non_finite_time_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "finite"):
            paired_metrics([1.0, 2.0], [1.0, float("inf")])


class ConditionValidationTests(unittest.TestCase):
    def test_duplicate_matching_key_is_rejected(self):
        row = {
            "Block ID": "1",
            "Algorithm": "SHA-256",
            "Input size in bytes": "1024",
            "Scenario": "valid",
        }
        with self.assertRaisesRegex(ValueError, "duplicate experimental condition"):
            condition_index([row, row], entity_column="Algorithm")

    def test_missing_and_extra_keys_are_reported(self):
        expected = [(1, "SHA-256", 1024, "valid"), (2, "SHA-256", 1024, "valid")]
        observed = [(1, "SHA-256", 1024, "valid"), (3, "SHA-256", 1024, "valid")]
        missing, extra = missing_and_extra_keys(observed, expected)
        self.assertEqual(missing, [(2, "SHA-256", 1024, "valid")])
        self.assertEqual(extra, [(3, "SHA-256", 1024, "valid")])


if __name__ == "__main__":
    unittest.main()
