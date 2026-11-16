
"""
Windows Event Log Analyzer
Module: cli.py

Provides the command-line interface for the analyzer.
"""

import argparse

from event_analyzer.collector import EventLogCollector
from event_analyzer.parser import EventParser
from event_analyzer.detector import BruteForceDetector
from event_analyzer.alert_manager import AlertManager
from event_analyzer.pipeline import EventPipeline, PipelineExecutionError


def positive_integer(value):
    """Validates that a CLI argument is a positive integer."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Value must be an integer."
        ) from exc

    if number < 1:
        raise argparse.ArgumentTypeError(
            "Value must be greater than zero."
        )

    return number

def minimum_two(value):
    """Validates that a value is an integer greater than or equal to 2."""
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "Value must be an integer."
        ) from exc

    if number < 2:
        raise argparse.ArgumentTypeError(
            "Value must be greater than or equal to 2."
        )

    return number

def build_argument_parser():
    """Creates and configures CLI arguments."""

    parser = argparse.ArgumentParser(
        prog="windows-event-log-analyzer",
        description=(
            "Collects and analyzes Windows Security events "
            "to identify suspicious authentication activity."
        ),
    )

    parser.add_argument(
        "--event-id",
        nargs="+",
        type=positive_integer,
        default=[4625],
        help="Windows Event IDs to collect. Default: 4625.",
    )

    parser.add_argument(
        "--max-events",
        type=positive_integer,
        default=100,
        help="Maximum number of events to collect. Default: 100.",
    )

    parser.add_argument(
        "--threshold",
        type=minimum_two,
        default=5,
        help="Failed attempts required to trigger an alert. Default: 5.",
    )

    parser.add_argument(
        "--window-minutes",
        type=positive_integer,
        default=5,
        help="Detection time window in minutes. Default: 5.",
    )

    parser.add_argument(
        "--channel",
        default="Security",
        help="Windows Event Log channel. Default: Security.",
    )

    parser.add_argument(
        "--storage",
        default="data/alerts.json",
        help="Path used to store alerts.",
    )

    return parser


def display_results(result):
    """Displays pipeline statistics and newly stored alerts."""

    print("\n========== ANALYSIS RESULTS ==========")
    print(f"Events collected: {result['collected_events']}")
    print(f"Events parsed: {result['parsed_events']}")
    print(f"Alerts detected: {result['detected_alerts']}")
    print(f"New alerts stored: {result['new_alerts']}")

    print("\n========== NEW ALERTS ==========")

    if not result["alerts"]:
        print("No new alerts to display.")
        return

    for index, alert in enumerate(result["alerts"], start=1):
        print(f"\nAlert #{index}")
        print(f"Alert ID: {alert['alert_id']}")
        print(f"Rule: {alert['rule_id']}")
        print(f"Severity: {alert['severity']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Failed attempts: {alert['failed_attempts']}")
        print(f"First seen: {alert['first_seen']}")
        print(f"Last seen: {alert['last_seen']}")
        print(f"Usernames: {', '.join(alert['usernames'])}")
        print(f"Description: {alert['description']}")
        print(f"Recommendation: {alert['recommendation']}")


def main(argv=None):
    """Runs the Windows Event Log Analyzer CLI."""

    argument_parser = build_argument_parser()
    args = argument_parser.parse_args(argv)

    try:
        collector = EventLogCollector(
            channel=args.channel,
        )

        parser = EventParser()

        detector = BruteForceDetector(
            threshold=args.threshold,
            window_minutes=args.window_minutes,
        )

        alert_manager = AlertManager(
            storage_path=args.storage,
        )

        pipeline = EventPipeline(
            collector=collector,
            parser=parser,
            detector=detector,
            alert_manager=alert_manager,
        )

        result = pipeline.run(
            event_ids=args.event_id,
            max_events=args.max_events,
        )

        display_results(result)

        print("\n[OK] Analysis completed successfully.")
        return 0

    except (PipelineExecutionError, ValueError) as error:
        print(f"\n[ERROR] {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
