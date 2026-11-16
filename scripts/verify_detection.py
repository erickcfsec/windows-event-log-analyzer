
from pathlib import Path
from event_analyzer.parser import EventParser
from event_analyzer.detector import BruteForceDetector
from event_analyzer.alert_manager import AlertManager
from event_analyzer.pipeline import EventPipeline


class SyntheticCollector:
    """Provides controlled synthetic Windows events."""

    def collect(self, event_ids=None, max_events=100):
        events = []

        for index in range(5):
            record_id = 1000 + index
            minute = f"0{index}"

            event_xml = f"""
            <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
                <System>
                    <Provider Name="Microsoft-Windows-Security-Auditing"/>
                    <EventID>4625</EventID>
                    <TimeCreated SystemTime="2026-11-14T20:{minute}:00.000Z"/>
                    <EventRecordID>{record_id}</EventRecordID>
                    <Computer>LAB-WINDOWS</Computer>
                </System>
                <EventData>
                    <Data Name="TargetUserName">lab_user</Data>
                    <Data Name="TargetDomainName">LAB</Data>
                    <Data Name="IpAddress">192.0.2.10</Data>
                    <Data Name="LogonType">3</Data>
                </EventData>
            </Event>
            """

            events.append(event_xml)

        return events[:max_events]


def main():
    storage_path = Path("data/synthetic_test_alerts.json")

    # Remove only the previous synthetic test output.
    storage_path.unlink(missing_ok=True)

    pipeline = EventPipeline(
        collector=SyntheticCollector(),
        parser=EventParser(),
        detector=BruteForceDetector(
            threshold=5,
            window_minutes=5,
        ),
        alert_manager=AlertManager(
            storage_path=storage_path,
        ),
    )

    print("\n========== FIRST EXECUTION ==========")

    first_result = pipeline.run(
        event_ids=[4625],
        max_events=100,
    )

    print(f"Collected: {first_result['collected_events']}")
    print(f"Parsed: {first_result['parsed_events']}")
    print(f"Detected: {first_result['detected_alerts']}")
    print(f"New alerts: {first_result['new_alerts']}")

    print("\n========== SECOND EXECUTION ==========")

    second_result = pipeline.run(
        event_ids=[4625],
        max_events=100,
    )

    print(f"Collected: {second_result['collected_events']}")
    print(f"Parsed: {second_result['parsed_events']}")
    print(f"Detected: {second_result['detected_alerts']}")
    print(f"New alerts: {second_result['new_alerts']}")

    print("\n========== PERSISTENCE CHECK ==========")

    saved_alerts = AlertManager(
        storage_path=storage_path
    ).load_alerts()

    print(f"Alerts saved in JSON: {len(saved_alerts)}")

    if saved_alerts:
        alert = saved_alerts[0]
        print(f"Source IP: {alert['source_ip']}")
        print(f"Failed attempts: {alert['failed_attempts']}")
        print(f"Severity: {alert['severity']}")
        print(f"Alert ID: {alert['alert_id']}")

    assert first_result["detected_alerts"] == 1
    assert first_result["new_alerts"] == 1
    assert second_result["detected_alerts"] == 1
    assert second_result["new_alerts"] == 0
    assert len(saved_alerts) == 1

    print("\n[OK] Detection and persistence validated.")


if __name__ == "__main__":
    main()
