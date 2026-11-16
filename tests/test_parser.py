
import pytest

from event_analyzer.parser import (
    EventParser,
    EventParsingError,
)


SAMPLE_4625 = """
<Event>
    <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>4625</EventID>
        <TimeCreated SystemTime="2026-11-13T21:53:03Z"/>
        <EventRecordID>355768</EventRecordID>
        <Computer>LAB-PC</Computer>
    </System>
    <EventData>
        <Data Name="TargetUserName">lab_user</Data>
        <Data Name="TargetDomainName">LAB-PC</Data>
        <Data Name="IpAddress">192.168.1.50</Data>
        <Data Name="LogonType">3</Data>
        <Data Name="Status">0xC000006D</Data>
        <Data Name="SubStatus">0xC000006A</Data>
    </EventData>
</Event>
"""


def test_parse_event_id():
    result = EventParser().parse(SAMPLE_4625)

    assert result["event_id"] == 4625


def test_parse_system_metadata():
    result = EventParser().parse(SAMPLE_4625)

    assert result["computer"] == "LAB-PC"
    assert result["record_id"] == 355768
    assert result["provider"] == (
        "Microsoft-Windows-Security-Auditing"
    )


def test_parse_timestamp():
    result = EventParser().parse(SAMPLE_4625)

    assert result["timestamp"] == "2026-11-13T21:53:03Z"


def test_parse_authentication_fields():
    result = EventParser().parse(SAMPLE_4625)

    assert result["username"] == "lab_user"
    assert result["domain"] == "LAB-PC"
    assert result["source_ip"] == "192.168.1.50"
    assert result["logon_type"] == 3


def test_parse_status_codes():
    result = EventParser().parse(SAMPLE_4625)

    assert result["status"] == "0xC000006D"
    assert result["sub_status"] == "0xC000006A"


def test_preserve_original_event_data():
    result = EventParser().parse(SAMPLE_4625)

    assert result["event_data"]["TargetUserName"] == "lab_user"
    assert result["event_data"]["IpAddress"] == "192.168.1.50"


def test_parse_invalid_xml():
    with pytest.raises(EventParsingError):
        EventParser().parse("<Event><System>")


def test_parse_missing_system():
    with pytest.raises(EventParsingError):
        EventParser().parse("<Event></Event>")


def test_parse_missing_event_id():
    invalid_event = """
    <Event>
        <System>
            <Computer>LAB-PC</Computer>
        </System>
    </Event>
    """

    with pytest.raises(EventParsingError):
        EventParser().parse(invalid_event)


def test_parse_empty_event_data():
    event = """
    <Event>
        <System>
            <EventID>4625</EventID>
        </System>
    </Event>
    """

    result = EventParser().parse(event)

    assert result["event_id"] == 4625
    assert result["username"] is None
    assert result["source_ip"] is None
    assert result["event_data"] == {}


def test_reject_non_string_input():
    with pytest.raises(TypeError):
        EventParser().parse(123)
