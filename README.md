# 🛡️ Windows Event Log Analyzer

[🇺🇸 English](README.md) | [🇧🇷 Português (Brasil)](README.pt-BR.md)

A Python-based Windows Security Event Log analyzer designed to identify suspicious authentication activity, detect potential brute-force patterns, and generate structured security alerts.

This project is part of a hands-on cybersecurity portfolio focused on Blue Team operations, security monitoring, and SOC analysis.

## 🎯 Overview

The Windows Event Log Analyzer collects Windows Security events, parses their XML representation, identifies repeated failed logon attempts, and stores generated alerts in a JSON file.

The current detection logic focuses on Windows Security Event ID **4625** — An account failed to log on.

The main objective is to demonstrate a practical security monitoring workflow using Python and native Windows event logs.

## ⚙️ Features

- Collect Windows Security Event Logs.
- Parse raw Windows Event XML.
- Normalize relevant event fields.
- Detect repeated failed logon attempts from the same source IP.
- Apply a configurable attempt threshold and time window.
- Generate structured security alerts.
- Persist alerts in JSON format.
- Deduplicate previously stored alerts.
- Execute the analysis through a command-line interface.
- Run automated tests with pytest.

## 🚨 Detection Rule

| Attribute | Value |
|---|---|
| Rule ID | `WIN-AUTH-001` |
| Event ID | `4625` |
| Description | Multiple failed Windows logon attempts from the same source IP |
| Default threshold | 5 attempts |
| Default time window | 5 minutes |
| Severity | High |

The rule groups valid failed logon events by source IP and checks whether the configured threshold is reached within the configured time window.

An alert is generated when the threshold is met.

**Important:** This rule identifies a suspicious authentication pattern. It does not independently prove that a brute-force attack occurred.

See [Detection Rules](docs/detection_rules.md) for details.

## 🏗️ Architecture

The application follows a modular processing pipeline:

1. **Collector:** retrieves raw Windows Security Event Log records.
2. **Parser:** converts event XML into normalized dictionaries.
3. **Detector:** analyzes parsed events and identifies suspicious authentication patterns.
4. **Alert Manager:** stores new alerts and prevents duplicate records.
5. **CLI:** provides command-line execution and displays analysis results.

See [Architecture](docs/architecture.md).

## 💻 Technology Stack

- Python
- Windows Event Log API
- pywin32
- XML parsing
- JSON
- pytest
- PowerShell

## 📋 Requirements

- Windows operating system.
- Python 3.10 or newer.
- Access to the Windows Security Event Log.
- Appropriate permissions to read the Security log.

The project uses `pywin32` to interact with the Windows Event Log API.

## 📦 Installation

Clone the repository:

```powershell
git clone https://github.com/erickcfsec/windows-event-log-analyzer.git
cd windows-event-log-analyzer
```

Create a virtual environment:

```powershell
python -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -e ".[dev]"
```

## 🖥️ Usage

Run the analyzer:

```powershell
python -m event_analyzer
```

The default configuration is:

- Event ID: `4625`
- Maximum events: `100`
- Detection threshold: `5`
- Detection window: `5` minutes
- Event channel: `Security`
- Alert storage: `data/alerts.json`

Display available options:

```powershell
python -m event_analyzer --help
```

### 🔧 Custom Execution

Example using a threshold of 10 failed attempts within 10 minutes:

```powershell
python -m event_analyzer --event-id 4625 --max-events 200 --threshold 10 --window-minutes 10
```

Specify a different alert storage path:

```powershell
python -m event_analyzer --storage data/custom_alerts.json
```

Reading the Windows Security log may require an elevated PowerShell session and appropriate Windows permissions.

## 🔍 Example Detection Scenario

The following is an illustrative scenario, not a real incident:

- Five failed logon events (Event ID 4625).
- All events originate from the same source IP.
- All five events occur within five minutes.
- The configured threshold is five attempts.

**Expected result:** the analyzer generates a `WIN-AUTH-001` alert with High severity.

The alert includes the source IP, number of failed attempts, timestamps, usernames, and event record IDs when available.

See [Investigation Examples](docs/investigation_examples.md).

## 🧪 Testing

Run the automated test suite:

```powershell
python -m pytest -v -p no:cacheprovider --basetemp=.pytest-tmp
```

Tests cover the collector, parser, detector, alert manager, pipeline, and command-line interface.

## 📁 Project Structure

```text
windows-event-log-analyzer/
├── docs/
│   ├── architecture.md
│   ├── detection_rules.md
│   └── investigation_examples.md
├── scripts/
│   ├── verify_detection.py
│   ├── verify_detector.py
│   ├── verify_parser_live.py
│   └── verify_pipeline_live.py
├── src/
│   └── event_analyzer/
│       ├── __init__.py
│       ├── __main__.py
│       ├── alert_manager.py
│       ├── cli.py
│       ├── collector.py
│       ├── detector.py
│       ├── parser.py
│       └── pipeline.py
├── tests/
├── .gitignore
├── pyproject.toml
├── requirements.txt
└── README.md
```

## ⚠️ Current Limitations

- Detection currently focuses on Event ID 4625.
- Events without a valid source IP or parseable timestamp are ignored by the detector.
- Detection is performed on the collected batch; it is not continuous real-time monitoring.
- A repeated failed logon pattern does not automatically establish malicious activity.
- The alert storage uses local JSON files, not a SIEM database.
- The current rule groups events by source IP and does not correlate activity across multiple IP addresses.
- The tool does not independently block IP addresses or disable accounts.

## 🗺️ Roadmap

- Add structured application logging.
- Expand authentication detection rules.
- Improve investigation context and alert enrichment.
- Add additional Windows Event ID coverage.
- Improve reporting capabilities.
- Integrate with a SIEM or security monitoring platform in a future iteration.

## ⚖️ Disclaimer

This project is intended for educational purposes and authorized security monitoring.

Use it only on systems and environments where you have permission to access Windows Security Event Logs.

## 👨‍💻 Author

**Erick Ferreira**

- GitHub: [@erickcfsec](https://github.com/erickcfsec)
- LinkedIn: [linkedin.com/in/erickcferreirasec](https://www.linkedin.com/in/erickcferreirasec/)
