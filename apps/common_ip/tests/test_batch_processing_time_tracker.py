from __future__ import annotations

import logging
import unittest

from common_ip_correlator.services.batch_processing_time_tracker import (
    BatchProcessingTimeTracker,
)


class FakePerfCounter:
    def __init__(self, values: list[float]) -> None:
        self._values = list(values)

    def __call__(self) -> float:
        if not self._values:
            raise AssertionError("No more perf counter values available")
        return self._values.pop(0)


class BatchProcessingTimeTrackerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.logger = logging.getLogger("batch-processing-time-tracker-tests")
        self.logger.handlers = [logging.NullHandler()]
        self.logger.propagate = False

    def test_record_completed_attack_computes_batch_average(self) -> None:
        tracker = BatchProcessingTimeTracker(
            enabled=True,
            perf_counter_fn=FakePerfCounter([10.0, 10.005, 20.0, 20.015]),
        )

        first_start_time = tracker.start_attack()
        tracker.record_completed_attack(first_start_time)
        second_start_time = tracker.start_attack()
        tracker.record_completed_attack(second_start_time)

        self.assertEqual(tracker.processed_attack_count, 2)
        self.assertAlmostEqual(tracker.total_processing_time_seconds, 0.02)

        with self.assertLogs(
            "batch-processing-time-tracker-tests", level="INFO"
        ) as captured_logs:
            tracker.log_batch_average(self.logger)

        self.assertIn(
            "Average IP processing time for batch: average=10.000 ms processed=2",
            captured_logs.output[0],
        )

    def test_disabled_tracker_does_not_measure_or_log(self) -> None:
        tracker = BatchProcessingTimeTracker(enabled=False)

        start_time = tracker.start_attack()
        tracker.record_completed_attack(start_time)

        self.assertIsNone(start_time)
        self.assertEqual(tracker.processed_attack_count, 0)
        self.assertEqual(tracker.total_processing_time_seconds, 0.0)
