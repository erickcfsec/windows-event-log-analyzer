
from datetime import datetime, timedelta, timezone
import ipaddress


class EventDetectionError(Exception):
    """Raised when event detection receives invalid input."""


class BruteForceDetector:
    """
    Detects possible brute-force activity based on
    repeated Windows Security Event ID 4625 events.
    """

    def __init__(self, threshold=5, window_minutes=5):
        if not isinstance(threshold, int) or isinstance(threshold, bool) or threshold < 2:
            raise ValueError("Threshold must be an integer greater than or equal to 2.")

        if not isinstance(window_minutes, int) or isinstance(window_minutes, bool) or window_minutes <= 0:
            raise ValueError("Window must be a positive integer.")

        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def _parse_timestamp(self, value):
        try:
            timestamp = datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )

            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)

            return timestamp.astimezone(timezone.utc)

        except (ValueError, TypeError, AttributeError):
            return None

    def detect(self, events):
        if not isinstance(events, list):
            raise EventDetectionError(
                "Events input must be a list."
            )

        grouped_events = {}

        for event in events:
            if not isinstance(event, dict):
                raise EventDetectionError(
                    "Every event must be a dictionary."
                )

            if event.get("event_id") != 4625:
                continue

            source_ip = event.get("source_ip")

            try:
                source_ip = str(ipaddress.ip_address(source_ip))
            except (ValueError, TypeError):
                continue

            timestamp = self._parse_timestamp(
                event.get("timestamp")
            )

            if timestamp is None:
                continue

            grouped_events.setdefault(source_ip, []).append(
                {
                    "timestamp": timestamp,
                    "username": event.get("username"),
                    "record_id": event.get("record_id"),
                }
            )

        alerts = []

        for source_ip, ip_events in grouped_events.items():
            ip_events.sort(key=lambda item: item["timestamp"])

            left = 0

            for right in range(len(ip_events)):
                while (
                    ip_events[right]["timestamp"]
                    - ip_events[left]["timestamp"]
                    > self.window
                ):
                    left += 1

                window_events = ip_events[left:right + 1]

                if len(window_events) >= self.threshold:
                    usernames = sorted({
                        item["username"]
                        for item in window_events
                        if isinstance(item["username"], str)
                    })

                    record_ids = [
                        item["record_id"]
                        for item in window_events
                        if item["record_id"] is not None
                    ]

                    alerts.append({
                        "rule_id": "WIN-AUTH-001",
                        "severity": "High",
                        "source_ip": source_ip,
                        "event_id": 4625,
                        "failed_attempts": len(window_events),
                        "first_seen": window_events[0]["timestamp"].isoformat(),
                        "last_seen": window_events[-1]["timestamp"].isoformat(),
                        "usernames": usernames,
                        "record_ids": record_ids,
                        "description": (
                            "Multiple failed Windows logon attempts "
                            "detected from the same source IP."
                        ),
                        "recommendation": (
                            "Investigate the source IP, validate the "
                            "target accounts and review related "
                            "authentication events."
                        ),
                    })

                    break

        return alerts
