
from unittest.mock import patch

import pytest

from event_analyzer.cli import (
    build_argument_parser,
    display_results,
    main,
)


def test_default_arguments():
    parser = build_argument_parser()
    args = parser.parse_args([])

    assert args.event_id == [4625]
    assert args.max_events == 100
    assert args.threshold == 5
    assert args.window_minutes == 5
    assert args.channel == "Security"
    assert args.storage == "data/alerts.json"


def test_custom_arguments():
    parser = build_argument_parser()
    args = parser.parse_args([
        "--event-id", "4625", "4624",
        "--max-events", "50",
        "--threshold", "3",
        "--window-minutes", "10",
        "--channel", "Security",
        "--storage", "data/test.json",
    ])

    assert args.event_id == [4625, 4624]
    assert args.max_events == 50
    assert args.threshold == 3
    assert args.window_minutes == 10
    assert args.storage == "data/test.json"


@pytest.mark.parametrize(
    "arguments",
    [
        ["--max-events", "0"],
        ["--threshold", "-1"],
        ["--window-minutes", "0"],
        ["--event-id", "invalid"],
    ],
)
def test_invalid_arguments(arguments):
    parser = build_argument_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(arguments)


def test_display_results_without_alerts(capsys):
    result = {
        "collected_events": 2,
        "parsed_events": 2,
        "detected_alerts": 0,
        "new_alerts": 0,
        "alerts": [],
    }

    display_results(result)

    output = capsys.readouterr().out

    assert "Events collected: 2" in output
    assert "No new alerts to display." in output


@patch("event_analyzer.cli.EventPipeline")
@patch("event_analyzer.cli.EventLogCollector")
def test_main_success(mock_collector, mock_pipeline, capsys):
    mock_pipeline.return_value.run.return_value = {
        "collected_events": 2,
        "parsed_events": 2,
        "detected_alerts": 0,
        "new_alerts": 0,
        "alerts": [],
    }

    result = main([])

    assert result == 0
    mock_collector.assert_called_once()
    mock_pipeline.return_value.run.assert_called_once()

    output = capsys.readouterr().out
    assert "Analysis completed successfully." in output


@patch("event_analyzer.cli.EventPipeline")
@patch("event_analyzer.cli.EventLogCollector")
def test_main_pipeline_error(mock_collector, mock_pipeline, capsys):
    from event_analyzer.pipeline import PipelineExecutionError

    mock_pipeline.return_value.run.side_effect = (
        PipelineExecutionError("Simulated pipeline failure")
    )

    result = main([])

    assert result == 1

    output = capsys.readouterr().out
    assert "Simulated pipeline failure" in output
