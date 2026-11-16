
import pytest

from event_analyzer.collector import (
    EventLogCollector,
)


def test_collector_initialization():
    collector = EventLogCollector()

    assert collector.channel == "Security"
    assert collector.batch_size == 32


def test_collector_custom_configuration():
    collector = EventLogCollector(
        channel="System",
        batch_size=10
    )

    assert collector.channel == "System"
    assert collector.batch_size == 10


def test_invalid_channel():
    with pytest.raises(ValueError):
        EventLogCollector(channel="")


def test_invalid_batch_size():
    with pytest.raises(ValueError):
        EventLogCollector(batch_size=0)


def test_build_query_single_event_id():
    query = EventLogCollector._build_query([4625])

    assert query == "*[System[(EventID=4625)]]"


def test_build_query_multiple_event_ids():
    query = EventLogCollector._build_query(
        [4624, 4625, 4672]
    )

    assert query == (
        "*[System[(EventID=4624 or "
        "EventID=4625 or EventID=4672)]]"
    )


def test_build_query_removes_duplicates():
    query = EventLogCollector._build_query(
        [4625, 4624, 4625]
    )

    assert query == (
        "*[System[(EventID=4624 or EventID=4625)]]"
    )


def test_build_query_rejects_empty_list():
    with pytest.raises(ValueError):
        EventLogCollector._build_query([])


def test_build_query_rejects_invalid_event_id():
    with pytest.raises(ValueError):
        EventLogCollector._build_query([4625, -1])


def test_build_query_rejects_boolean_event_id():
    with pytest.raises(ValueError):
        EventLogCollector._build_query([True])


def test_collect_rejects_invalid_max_events():
    collector = EventLogCollector()

    with pytest.raises(ValueError):
        collector.collect(max_events=0)


def test_collect_rejects_boolean_max_events():
    collector = EventLogCollector()

    with pytest.raises(ValueError):
        collector.collect(max_events=True)
