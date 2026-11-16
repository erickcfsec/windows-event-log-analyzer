
"""
Windows Event Log Analyzer
Module: parser.py

Transforms raw Windows Event XML into structured dictionaries.
"""

import xml.etree.ElementTree as ET
from typing import Any


class EventParsingError(Exception):
    """Raised when a Windows event cannot be parsed."""


class EventParser:
    """Parses Windows Event XML into structured data."""

    @staticmethod
    def _find_child(element: ET.Element, tag: str):
        """
        Finds a direct child by its local tag name.
        This approach works with or without XML namespaces.
        """
        for child in element:
            local_name = child.tag.split("}")[-1]

            if local_name == tag:
                return child

        return None

    @staticmethod
    def _get_text(element: ET.Element, tag: str):
        """Returns the text of a direct child, or None."""
        child = EventParser._find_child(element, tag)

        if child is None:
            return None

        return child.text

    @staticmethod
    def _get_event_data(root: ET.Element) -> dict[str, str]:
        """
        Extracts named values from EventData.

        Example:
        <Data Name="TargetUserName">lab_user</Data>
        becomes:
        {"TargetUserName": "lab_user"}
        """
        event_data = EventParser._find_child(root, "EventData")

        if event_data is None:
            return {}

        result = {}

        for item in event_data:
            local_name = item.tag.split("}")[-1]

            if local_name != "Data":
                continue

            field_name = item.attrib.get("Name")

            if field_name:
                result[field_name] = item.text or ""

        return result

    @staticmethod
    def _to_integer(value: Any):
        """Converts a value to integer when possible."""
        if value is None or value == "":
            return None

        try:
            return int(value)
        except (ValueError, TypeError):
            return value

    def parse(self, event_xml: str) -> dict:
        """
        Parses one raw Windows event XML document.

        Returns a normalized dictionary containing system
        metadata and event-specific fields.
        """

        if not isinstance(event_xml, (str, bytes)):
            raise TypeError("event_xml must be a string or bytes.")

        try:
            root = ET.fromstring(event_xml)

        except ET.ParseError as exc:
            raise EventParsingError(
                f"Invalid Windows Event XML: {exc}"
            ) from exc

        system = self._find_child(root, "System")

        if system is None:
            raise EventParsingError(
                "Invalid Windows Event XML: missing System element."
            )

        event_id = self._to_integer(
            self._get_text(system, "EventID")
        )

        if event_id is None:
            raise EventParsingError(
                "Invalid Windows Event XML: missing EventID."
            )

        provider_element = self._find_child(system, "Provider")

        provider = (
            provider_element.attrib.get("Name")
            if provider_element is not None
            else None
        )

        time_element = self._find_child(system, "TimeCreated")

        timestamp = (
            time_element.attrib.get("SystemTime")
            if time_element is not None
            else None
        )

        event_record_id = self._to_integer(
            self._get_text(system, "EventRecordID")
        )

        computer = self._get_text(system, "Computer")

        event_data = self._get_event_data(root)

        # Normalize common authentication fields.
        parsed_event = {
            "event_id": event_id,
            "timestamp": timestamp,
            "computer": computer,
            "provider": provider,
            "record_id": event_record_id,
            "username": (
                event_data.get("TargetUserName")
                or event_data.get("SubjectUserName")
            ),
            "domain": (
                event_data.get("TargetDomainName")
                or event_data.get("SubjectDomainName")
            ),
            "source_ip": event_data.get("IpAddress"),
            "logon_type": self._to_integer(
                event_data.get("LogonType")
            ),
            "status": event_data.get("Status"),
            "sub_status": event_data.get("SubStatus"),
            "process_name": event_data.get("NewProcessName"),
            "process_command_line": event_data.get(
                "ProcessCommandLine"
            ),
            "event_data": event_data,
        }

        return parsed_event
