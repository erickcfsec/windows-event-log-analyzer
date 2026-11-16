import pytest

from datetime import datetime, timedelta, timezone

from event_analyzer.detector import (
    BruteForceDetector,
    EventDetectionError,
)

def create_event(
    event_id=4625,
    source_ip="192.168.1.50",
    minutes_ago=0,
    username="lab_user",
    record_id=100,
):
    timestamp = (
        datetime.now(timezone.utc)
        - timedelta(minutes=minutes_ago)
    ).isoformat()

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "username": username,
        "record_id": record_id,
    }


def test_detector_initialization():
    detector = BruteForceDetector()

    assert detector.threshold == 5
    assert detector.window == timedelta(minutes=5)


def test_custom_detector_configuration():
    detector = BruteForceDetector(
        threshold=8,
        window_minutes=10,
    )

    assert detector.threshold == 8
    assert detector.window == timedelta(minutes=10)


def test_invalid_threshold():
    with pytest.raises(ValueError):
        BruteForceDetector(threshold=1)


def test_invalid_window():
    with pytest.raises(ValueError):
        BruteForceDetector(window_minutes=0)


def test_detect_possible_brute_force():
    events = [
        create_event(minutes_ago=i, record_id=i + 1)
        for i in range(5)
    ]

    alerts = BruteForceDetector().detect(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "WIN-AUTH-001"
    assert alerts[0]["severity"] == "High"
    assert alerts[0]["failed_attempts"] == 5
    assert alerts[0]["source_ip"] == "192.168.1.50"


def test_no_alert_below_threshold():
    events = [
        create_event(minutes_ago=i, record_id=i)
        for i in range(3)
    ]

    alerts = BruteForceDetector().detect(events)

    assert alerts == []


def test_no_alert_outside_time_window():
    events = [
        create_event(minutes_ago=15, record_id=1),
        create_event(minutes_ago=10, record_id=2),
        create_event(minutes_ago=8, record_id=3),
        create_event(minutes_ago=7, record_id=4),
        create_event(minutes_ago=0, record_id=5),
    ]

    alerts = BruteForceDetector().detect(events)

    assert alerts == []


def test_events_are_grouped_by_ip():
    events = [
        create_event(source_ip="192.168.1.50", record_id=1),
        create_event(source_ip="192.168.1.50", record_id=2),
        create_event(source_ip="192.168.1.50", record_id=3),
        create_event(source_ip="192.168.1.60", record_id=4),
        create_event(source_ip="192.168.1.60", record_id=5),
        create_event(source_ip="192.168.1.60", record_id=6),
    ]

    alerts = BruteForceDetector().detect(events)

    assert alerts == []


def test_non_4625_events_are_ignored():
    events = [
        create_event(event_id=4624, record_id=i)
        for i in range(5)
    ]

    alerts = BruteForceDetector().detect(events)

    assert alerts == []


def test_events_without_valid_ip_are_ignored():
    events = [
        create_event(source_ip="-", record_id=i)
        for i in range(5)
    ]

    alerts = BruteForceDetector().detect(events)

    assert alerts == []


def test_invalid_timestamp_is_ignored():
    events = [
        create_event(record_id=i)
        for i in range(4)
    ]

    events.append({
        "event_id": 4625,
        "timestamp": "invalid-date",
        "source_ip": "192.168.1.50",
        "username": "lab_user",
        "record_id": 5,
    })

    alerts = BruteForceDetector().detect(events)

    assert alerts == []


def test_invalid_events_input():
    with pytest.raises(EventDetectionError):
        BruteForceDetector().detect("invalid")


def test_alert_contains_evidence():
    events = [
        create_event(minutes_ago=i, record_id=i + 100)
        for i in range(5)
    ]

    alerts = BruteForceDetector().detect(events)

    alert = alerts[0]

    assert alert["usernames"] == ["lab_user"]
    assert len(alert["record_ids"]) == 5
    assert alert["event_id"] == 4625
    assert alert["recommendation"]


def test_only_one_alert_per_ip():
    events = [
        create_event(minutes_ago=i, record_id=i + 1)
        for i in range(10)
    ]

    alerts = BruteForceDetector().detect(events)

    assert len(alerts) == 1


def test_invalid_event_entry():
    with pytest.raises(EventDetectionError):
        BruteForceDetector().detect([123])
