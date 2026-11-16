
from event_analyzer.collector import EventLogCollector
from event_analyzer.parser import EventParser
from event_analyzer.detector import BruteForceDetector
from event_analyzer.alert_manager import AlertManager
from event_analyzer.pipeline import EventPipeline, PipelineExecutionError


def main():
    collector = EventLogCollector(channel="Security")
    parser = EventParser()
    detector = BruteForceDetector(
        threshold=5,
        window_minutes=5,
    )

    # Arquivo separado para não misturar os alertas
    # deste teste com os dados anteriores do projeto.
    alert_manager = AlertManager(
        storage_path="data/live_test_alerts.json"
    )

    pipeline = EventPipeline(
        collector=collector,
        parser=parser,
        detector=detector,
        alert_manager=alert_manager,
    )

    try:
        result = pipeline.run(
            event_ids=[4625],
            max_events=100,
        )

    except PipelineExecutionError as error:
        print("\n[ERROR] Pipeline execution failed:")
        print(error)
        return

    print("\n========== LIVE PIPELINE RESULTS ==========")
    print(f"Collected events: {result['collected_events']}")
    print(f"Parsed events: {result['parsed_events']}")
    print(f"Detected alerts: {result['detected_alerts']}")
    print(f"New alerts stored: {result['new_alerts']}")

    print("\n========== ALERT DETAILS ==========")

    if not result["alerts"]:
        print("No new brute-force alerts detected.")
    else:
        for alert in result["alerts"]:
            print(f"Alert ID: {alert['alert_id']}")
            print(f"Source IP: {alert['source_ip']}")
            print(f"Severity: {alert['severity']}")
            print(f"Failed attempts: {alert['failed_attempts']}")
            print(f"Rule: {alert['rule_id']}")
            print("-" * 40)

    print("\n[OK] Live pipeline execution completed.")


if __name__ == "__main__":
    main()
