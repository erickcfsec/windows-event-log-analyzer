
class PipelineExecutionError(Exception):
    """Raised when the event analysis pipeline fails."""


class EventPipeline:
    """
    Coordinates event collection, parsing, detection and alert storage.
    """

    def __init__(self, collector, parser, detector, alert_manager):
        self.collector = collector
        self.parser = parser
        self.detector = detector
        self.alert_manager = alert_manager

    def run(self, event_ids=None, max_events=100):
        """
        Executes the complete event analysis workflow.

        Returns execution statistics and newly stored alerts.
        """

        try:
            # 1. Collect raw Windows events.
            raw_events = self.collector.collect(
                event_ids=event_ids,
                max_events=max_events,
            )

            # 2. Parse XML events into normalized dictionaries.
            parsed_events = [
                self.parser.parse(raw_event)
                for raw_event in raw_events
            ]

            # 3. Detect suspicious authentication activity.
            detected_alerts = self.detector.detect(parsed_events)

            # 4. Store only new alerts.
            new_alerts = self.alert_manager.add_alerts(
                detected_alerts
            )

            return {
                "collected_events": len(raw_events),
                "parsed_events": len(parsed_events),
                "detected_alerts": len(detected_alerts),
                "new_alerts": len(new_alerts),
                "alerts": new_alerts,
            }

        except Exception as error:
            raise PipelineExecutionError(
                f"Pipeline execution failed: {error}"
            ) from error
