
import sys

# Make the src directory available for imports.
sys.path.insert(0, "src")

from event_analyzer.collector import EventLogCollector
from event_analyzer.parser import EventParser


def main():
    print("Starting live Windows Event Log test...")

    # Collect up to five recent failed logon events.
    collector = EventLogCollector()

    events = collector.collect(
        event_ids=[4625],
        max_events=5
    )

    print("Events collected:", len(events))

    # Parse the XML returned by the collector.
    parser = EventParser()

    parsed_events = [
        parser.parse(event)
        for event in events
    ]

    print("Events parsed:", len(parsed_events))
    print("\nParsed event information:")

    for event in parsed_events:
        print("------------------------------")
        print("Event ID:", event["event_id"])
        print("Timestamp:", event["timestamp"])
        print("Computer:", event["computer"])
        print("Username:", event["username"])
        print("Source IP:", event["source_ip"])
        print("Logon Type:", event["logon_type"])

    print("\nLive parser test completed.")


if __name__ == "__main__":
    main()
