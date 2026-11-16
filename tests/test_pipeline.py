
import pytest

from event_analyzer.pipeline import (
    EventPipeline,
    PipelineExecutionError,
)


class FakeCollector:
    def __init__(self, events):
        self.events = events

    def collect(self, event_ids=None, max_events=100):
        return self.events


class FakeParser:
    def parse(self, raw_event):
        return {
            "event_id": 4625,
            "source_ip": "192.168.1.50",
            "timestamp": "2026-11-14T20:00:00+00:00",
            "username": "lab_user",
        }


class FakeDetector:
    def __init__(self, alerts):
        self.alerts = alerts

    def detect(self, events):
        return self.alerts


class FakeAlertManager:
    def __init__(self, new_alerts=None):
        self.new_alerts = new_alerts or []
        self.received_alerts = []

    def add_alerts(self, alerts):
        self.received_alerts = alerts
        return self.new_alerts


@pytest.fixture
def sample_alert():
    return {
        "rule_id": "WIN-AUTH-001",
        "severity": "High",
        "source_ip": "192.168.1.50",
        "event_id": 4625,
        "failed_attempts": 5,
        "record_ids": [1001, 1002, 1003, 1004, 1005],
    }


def test_pipeline_complete_execution(sample_alert):
    collector = FakeCollector(["xml1", "xml2"])
    parser = FakeParser()
    detector = FakeDetector([sample_alert])
    manager = FakeAlertManager([sample_alert])

    pipeline = EventPipeline(
        collector,
        parser,
        detector,
        manager,
    )

    result = pipeline.run()

    assert result["collected_events"] == 2
    assert result["parsed_events"] == 2
    assert result["detected_alerts"] == 1
    assert result["new_alerts"] == 1


def test_pipeline_handles_empty_collection():
    pipeline = EventPipeline(
        FakeCollector([]),
        FakeParser(),
        FakeDetector([]),
        FakeAlertManager(),
    )

    result = pipeline.run()

    assert result["collected_events"] == 0
    assert result["parsed_events"] == 0
    assert result["detected_alerts"] == 0
    assert result["new_alerts"] == 0


def test_pipeline_without_detected_alerts():
    pipeline = EventPipeline(
        FakeCollector(["xml1"]),
        FakeParser(),
        FakeDetector([]),
        FakeAlertManager(),
    )

    result = pipeline.run()

    assert result["detected_alerts"] == 0
    assert result["new_alerts"] == 0


def test_pipeline_passes_alerts_to_manager(sample_alert):
    manager = FakeAlertManager([sample_alert])

    pipeline = EventPipeline(
        FakeCollector(["xml1"]),
        FakeParser(),
        FakeDetector([sample_alert]),
        manager,
    )

    pipeline.run()

    assert manager.received_alerts == [sample_alert]


def test_pipeline_reports_only_new_alerts(sample_alert):
    pipeline = EventPipeline(
        FakeCollector(["xml1"]),
        FakeParser(),
        FakeDetector([sample_alert]),
        FakeAlertManager([]),
    )

    result = pipeline.run()

    assert result["detected_alerts"] == 1
    assert result["new_alerts"] == 0
    assert result["alerts"] == []


def test_pipeline_wraps_execution_errors():
    class BrokenCollector:
        def collect(self, event_ids=None, max_events=100):
            raise RuntimeError("Simulated collection failure")

    pipeline = EventPipeline(
        BrokenCollector(),
        FakeParser(),
        FakeDetector([]),
        FakeAlertManager(),
    )

    with pytest.raises(PipelineExecutionError):
        pipeline.run()
