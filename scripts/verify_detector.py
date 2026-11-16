
from datetime import datetime, timedelta, timezone
import sys

sys.path.insert(0, "src")

from event_analyzer.detector import BruteForceDetector


def create_simulated_event(minutes_ago, record_id):
    timestamp = (
        datetime.now(timezone.utc)
        - timedelta(minutes=minutes_ago)
    ).isoformat()

    return {
        "event_id": 4625,
        "timestamp": timestamp,
        "computer": "LAB-PC",
        "username": "lab_user",
        "source_ip": "192.168.1.50",
        "record_id": record_id,
    }


def main():
    print("Starting simulated detection test...")

    simulated_events = [
        create_simulated_event(4, 1001),
        create_simulated_event(3, 1002),
        create_simulated_event(2, 1003),
        create_simulated_event(1, 1004),
        create_simulated_event(0, 1005),
    ]

    detector = BruteForceDetector(
        threshold=5,
        window_minutes=5
    )

    alerts = detector.detect(simulated_events)

    print("Events analyzed:", len(simulated_events))
    print("Alerts generated:", len(alerts))

    for alert in alerts:
        print("\n========== SECURITY ALERT ==========")
        print("Rule:", alert["rule_id"])
        print("Name:", alert["alert_name"])
        print("Severity:", alert["severity"])
        print("Source IP:", alert["source_ip"])
        print("Failed attempts:", alert["failed_attempts"])
        print("Affected users:", alert["usernames"])
        print("Record IDs:", alert["record_ids"])
        print("Description:", alert["description"])
        print("Recommendation:", alert["recommendation"])


if __name__ == "__main__":
    main()
