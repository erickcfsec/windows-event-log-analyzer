
import json
import pytest

from event_analyzer.alert_manager import (
    AlertManager,
    AlertManagementError,
)


@pytest.fixture
def sample_alert():
    return {
        "rule_id": "WIN-AUTH-001",
        "severity": "High",
        "source_ip": "192.168.1.50",
        "event_id": 4625,
        "failed_attempts": 5,
        "first_seen": "2026-11-14T20:00:00+00:00",
        "last_seen": "2026-11-14T20:04:00+00:00",
        "usernames": ["lab_user"],
        "record_ids": [1001, 1002, 1003, 1004, 1005],
        "recommendation": "Investigate the source IP.",
    }


def test_manager_initialization(tmp_path):
    manager = AlertManager(
        storage_path=tmp_path / "alerts.json"
    )

    assert manager.storage_path.name == "alerts.json"


def test_load_empty_alerts(tmp_path):
    manager = AlertManager(
        storage_path=tmp_path / "alerts.json"
    )

    assert manager.load_alerts() == []


def test_add_alert(tmp_path, sample_alert):
    manager = AlertManager(
        storage_path=tmp_path / "alerts.json"
    )

    added = manager.add_alerts([sample_alert])

    assert len(added) == 1
    assert "alert_id" in added[0]


def test_alert_is_persisted(tmp_path, sample_alert):
    path = tmp_path / "alerts.json"

    manager = AlertManager(storage_path=path)
    manager.add_alerts([sample_alert])

    with path.open("r", encoding="utf-8") as file:
        stored = json.load(file)

    assert len(stored) == 1
    assert stored[0]["source_ip"] == "192.168.1.50"


def test_duplicate_alert_is_ignored(tmp_path, sample_alert):
    manager = AlertManager(
        storage_path=tmp_path / "alerts.json"
    )

    first = manager.add_alerts([sample_alert])
    second = manager.add_alerts([sample_alert])

    assert len(first) == 1
    assert second == []
    assert len(manager.load_alerts()) == 1


def test_multiple_alerts_are_stored(tmp_path, sample_alert):
    manager = AlertManager(
        storage_path=tmp_path / "alerts.json"
    )

    another_alert = {
        **sample_alert,
        "source_ip": "10.0.0.20",
        "record_ids": [2001, 2002, 2003, 2004, 2005],
    }

    added = manager.add_alerts([
        sample_alert,
        another_alert,
    ])

    assert len(added) == 2
    assert len(manager.load_alerts()) == 2


def test_invalid_alert_input(tmp_path):
    manager = AlertManager(
        storage_path=tmp_path / "alerts.json"
    )

    with pytest.raises(AlertManagementError):
        manager.add_alerts("invalid")


def test_invalid_alert_entry(tmp_path):
    manager = AlertManager(
        storage_path=tmp_path / "alerts.json"
    )

    with pytest.raises(AlertManagementError):
        manager.add_alerts([123])


def test_invalid_json_file(tmp_path):
    path = tmp_path / "alerts.json"
    path.write_text("{invalid json", encoding="utf-8")

    manager = AlertManager(storage_path=path)

    with pytest.raises(AlertManagementError):
        manager.load_alerts()
