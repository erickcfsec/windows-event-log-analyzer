
import hashlib
import json

from pathlib import Path


class AlertManagementError(Exception):
    """Raised when alert management fails."""


class AlertManager:
    """
    Manages alert storage and prevents duplicate alerts.
    """

    def __init__(self, storage_path="data/alerts.json"):
        self.storage_path = Path(storage_path)

    def _generate_alert_id(self, alert):
        """
        Generates a deterministic ID using alert evidence.
        """

        evidence = {
            "rule_id": alert.get("rule_id"),
            "source_ip": alert.get("source_ip"),
            "event_id": alert.get("event_id"),
            "record_ids": sorted(
                str(record_id)
                for record_id in alert.get("record_ids", [])
            ),
            "first_seen": alert.get("first_seen"),
            "last_seen": alert.get("last_seen"),
        }

        serialized = json.dumps(
            evidence,
            sort_keys=True,
            ensure_ascii=False,
        )

        return hashlib.sha256(
            serialized.encode("utf-8")
        ).hexdigest()

    def load_alerts(self):
        """
        Loads previously stored alerts.
        """

        if not self.storage_path.exists():
            return []

        try:
            with self.storage_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                alerts = json.load(file)

        except (OSError, json.JSONDecodeError) as error:
            raise AlertManagementError(
                f"Could not load alerts: {error}"
            ) from error

        if not isinstance(alerts, list):
            raise AlertManagementError(
                "Stored alerts must be a JSON list."
            )

        if not all(isinstance(alert, dict) for alert in alerts):
            raise AlertManagementError(
                "Every stored alert must be a JSON object."
            )

        return alerts

    def _save_alerts(self, alerts):
        """
        Saves alerts using a temporary file before replacement.
        """

        try:
            self.storage_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            temporary_path = self.storage_path.with_suffix(
                self.storage_path.suffix + ".tmp"
            )

            with temporary_path.open(
                "w",
                encoding="utf-8",
            ) as file:
                json.dump(
                    alerts,
                    file,
                    indent=4,
                    ensure_ascii=False,
                )

            temporary_path.replace(self.storage_path)

        except (OSError, TypeError, ValueError) as error:
            raise AlertManagementError(
                f"Could not save alerts: {error}"
            ) from error

    def add_alerts(self, new_alerts):
        """
        Stores new alerts and ignores duplicates.

        Returns only the alerts that were newly stored.
        """

        if not isinstance(new_alerts, list):
            raise AlertManagementError(
                "New alerts input must be a list."
            )

        if not all(isinstance(alert, dict) for alert in new_alerts):
            raise AlertManagementError(
                "Every alert must be a dictionary."
            )

        stored_alerts = self.load_alerts()

        known_ids = {
            alert.get("alert_id")
            for alert in stored_alerts
        }

        added_alerts = []

        for alert in new_alerts:
            alert_copy = dict(alert)

            alert_id = self._generate_alert_id(alert_copy)

            if alert_id in known_ids:
                continue

            alert_copy["alert_id"] = alert_id

            stored_alerts.append(alert_copy)
            added_alerts.append(alert_copy)

            known_ids.add(alert_id)

        if added_alerts:
            self._save_alerts(stored_alerts)

        return added_alerts
