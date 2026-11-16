# System Architecture

## 1. Overview

The Windows Event Log Analyzer uses a modular architecture to collect, parse, analyze, and store Windows Security Event Log data.

The application is organized around a processing pipeline. Each component has a specific responsibility, allowing individual modules to be tested and maintained independently.

## 2. Processing Flow

```text
Windows Security Event Log
            |
            v
     Event Collector
            |
            v
       Event Parser
            |
            v
     Brute Force Detector
            |
            v
       Alert Manager
            |
            v
       JSON Storage
```

The command-line interface initializes the components and executes the pipeline.

## 3. Components

### 3.1 Event Collector

File: `collector.py`

Responsible for retrieving raw event records from the Windows Event Log.

The collector uses the Windows Event Log API through `pywin32`.

Main responsibilities:

- Query a configured event log channel.
- Filter events by Event ID when requested.
- Limit the number of collected records.
- Return raw XML event representations.

The default channel is `Security`.

### 3.2 Event Parser

File: `parser.py`

Responsible for converting raw Windows Event XML into normalized Python dictionaries.

Relevant fields include:

- Event ID
- Timestamp
- Computer
- Provider
- Record ID
- Username
- Domain
- Source IP
- Logon type
- Status and sub-status
- Process information
- Event data

The normalized representation allows the detection engine to work independently of the original XML structure.

### 3.3 Brute Force Detector

File: `detector.py`

Responsible for identifying repeated failed authentication attempts.

Current detection behavior:

1. Receives normalized event dictionaries.
2. Processes Event ID 4625.
3. Validates and normalizes source IP addresses.
4. Parses timestamps and normalizes them to UTC.
5. Groups events by source IP.
6. Orders each group chronologically.
7. Evaluates events inside a sliding time window.
8. Generates an alert when the configured threshold is reached.

Default configuration:

- Threshold: 5 events.
- Time window: 5 minutes.

The detector generates at most one alert per source IP during a single detection execution.

### 3.4 Alert Manager

File: `alert_manager.py`

Responsible for persistent alert storage.

Main responsibilities:

- Generate deterministic alert identifiers.
- Store alerts in JSON format.
- Prevent duplicate alerts from being stored again.
- Maintain the local alert history.

The alert identifier is derived from selected alert attributes using SHA-256.

The current implementation is intended for a local lab environment and does not provide transactional guarantees for concurrent processes.

### 3.5 Event Pipeline

File: `pipeline.py`

Coordinates the complete workflow:

1. Collect raw events.
2. Parse each event.
3. Detect suspicious activity.
4. Store newly generated alerts.
5. Return execution statistics.

The pipeline returns:

- Number of collected events.
- Number of parsed events.
- Number of detected alerts.
- Number of newly stored alerts.
- Newly stored alert objects.

Pipeline failures are wrapped in `PipelineExecutionError`.

### 3.6 Command-Line Interface

File: `cli.py`

Provides command-line arguments for configuring the analysis.

Available options:

| Argument | Default | Description |
|---|---|---|
| `--event-id` | `4625` | Windows Event IDs to collect |
| `--max-events` | `100` | Maximum number of events |
| `--threshold` | `5` | Failed attempts required for an alert |
| `--window-minutes` | `5` | Detection window |
| `--channel` | `Security` | Windows Event Log channel |
| `--storage` | `data/alerts.json` | Alert storage path |

The package can be executed using:

```powershell
python -m event_analyzer
```

## 4. Error Handling

The application defines component-specific exceptions, including:

- `EventLogCollectionError`
- `EventParsingError`
- `EventDetectionError`
- `AlertManagementError`
- `PipelineExecutionError`

The pipeline wraps execution failures to provide a consistent error boundary for the CLI.

## 5. Testing Strategy

The project uses pytest.

Tests are organized by component:

- Collector tests.
- Parser tests.
- Detector tests.
- Alert manager tests.
- Pipeline tests.
- CLI tests.

The current development version has 62 passing test cases.

## 6. Design Considerations

The modular architecture separates Windows-specific collection from parsing and detection logic.

This separation makes it possible to test detection behavior with synthetic events without requiring every test to access the actual Windows Security log.

The current architecture is designed for a local educational environment. It is not a distributed monitoring platform or a production SIEM.
