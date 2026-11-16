# 📸 Project Evidence

[🇺🇸 English](README.md) | [🇧🇷 Português (Brasil)](README.pt-BR.md)

This directory contains screenshots documenting the execution, functionality, and testing of the **Windows Event Log Analyzer** project.

The evidence demonstrates the main capabilities of the tool, including Windows Security Event Log collection, brute force detection, automated testing, alert generation, and command-line interface usage.

---

## 📂 Evidence Overview

### 🖥️ 01 — Live Event Collection

**File:** `01-live-event-collection.png`

**Objective:** Demonstrate the collection of real Windows Security events from the local environment.

**What it demonstrates:**
- Connection to the Windows Security Event Log.
- Collection of authentication events.
- Event parsing and processing.
- Number of events collected and successfully parsed.

**Data classification:** Real events collected from the local Windows environment.

---

### 🚨 02 — Brute Force Detection

**File:** `02-bruteforce-detection.png`

**Objective:** Demonstrate the detection of repeated failed authentication attempts.

**What it demonstrates:**
- Simulated Windows Event ID 4625 records.
- Multiple failed logon attempts from the same source IP.
- Detection rule `WIN-AUTH-001`.
- High-severity alert generation.

**Detection scenario:**
- Event ID: `4625`
- Source IP: `192.0.2.10`
- Failed attempts: `5`
- Detection window: `5 minutes`

**Data classification:** Synthetic test data.

---

### 🧪 03 — Automated Tests

**File:** `03-automated-tests.png`

**Objective:** Demonstrate automated testing and project validation.

**What it demonstrates:**
- Pytest execution.
- Test suite results.
- Successful validation of project components.

**Test result:** 62 tests passed in the validated test run.

---

### 📄 04 — Synthetic Detection Alert

**File:** `04-synthetic-detection-alert.png`

**Objective:** Demonstrate the structure and persistence of a generated security alert.

**What it demonstrates:**
- Detection rule: `WIN-AUTH-001`.
- Severity: `High`.
- Event ID: `4625`.
- Source IP: `192.0.2.10`.
- Five failed authentication attempts.
- First and last observed timestamps.
- Associated usernames and event record IDs.
- Unique alert identifier.

**Data classification:** Synthetic test data.

The IP address `192.0.2.10` is reserved for documentation and examples. This scenario does not represent a real security incident.

---

### 💻 05 — Command-Line Interface

**File:** `05-cli-interface.png`

**Objective:** Demonstrate the command-line interface and its configuration options.

**What it demonstrates:**
- CLI help output.
- Available command-line arguments.
- Custom execution parameters.
- Detection threshold and time-window configuration.

**Example commands:**

```powershell
python -m event_analyzer --help
```

```powershell
python -m event_analyzer --threshold 10 --window-minutes 10
```

---

## 🔍 Evidence Notes

- Live collection evidence comes from the local Windows environment.
- Brute force detection uses controlled synthetic events.
- Synthetic scenarios are intended for safe testing and educational purposes.
- Screenshots document the project's current functionality and test results.
- These demonstrations do not represent production-grade security monitoring.

---

## 🎯 Project Purpose

The evidence supports the educational goals of this project:

- Windows Security Event Log analysis.
- Authentication failure monitoring.
- Basic brute force detection.
- Security alert generation and persistence.
- Python development and automated testing.

**Project:** Windows Event Log Analyzer
**Focus:** Blue Team | SOC | Windows Security Monitoring