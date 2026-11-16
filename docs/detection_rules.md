# Detection Rules

## WIN-AUTH-001 — Repeated Failed Logon Attempts

### 1. Rule Overview

| Attribute | Value |
|---|---|
| Rule ID | `WIN-AUTH-001` |
| Event ID | `4625` |
| Severity | High |
| Category | Authentication |
| Detection type | Threshold-based |
| Default threshold | 5 attempts |
| Default time window | 5 minutes |
| Grouping field | Source IP |

### 2. Objective

Identify repeated failed Windows logon attempts originating from the same source IP within a configurable time window.

This behavior may indicate password guessing, brute-force activity, misconfigured applications, or legitimate users repeatedly entering incorrect credentials.

The alert indicates suspicious activity requiring investigation. It does not prove malicious intent.

### 3. Event Source

Windows Security Event Log.

Event ID 4625:

**An account failed to log on.**

The detector relies on the normalized event fields produced by the parser.

Relevant fields:

- `event_id`
- `timestamp`
- `source_ip`
- `username`
- `record_id`

### 4. Detection Logic

The detector performs the following operations:

1. Accepts a list of normalized events.
2. Ignores events whose Event ID is not 4625.
3. Validates source IP addresses.
4. Ignores events with invalid or missing source IP addresses.
5. Parses timestamps and normalizes them to UTC.
6. Ignores events with invalid or missing timestamps.
7. Groups remaining events by source IP.
8. Sorts each IP group by timestamp.
9. Evaluates chronological events using a sliding time window.
10. Generates an alert when the number of events inside the window reaches the configured threshold.

### 5. Default Detection Scenario

Example:

| Event | Source IP | Timestamp |
|---|---|---|
| 1 | `192.0.2.10` | 10:00:00 |
| 2 | `192.0.2.10` | 10:01:00 |
| 3 | `192.0.2.10` | 10:02:00 |
| 4 | `192.0.2.10` | 10:03:00 |
| 5 | `192.0.2.10` | 10:04:00 |

All five events are Event ID 4625.

Expected result:

- Threshold reached: Yes.
- Time window satisfied: Yes.
- Alert generated: Yes.

The IP address `192.0.2.10` belongs to a documentation range and is used here only as an illustrative example.

### 6. Alert Structure

The generated alert includes:

- `rule_id`
- `severity`
- `source_ip`
- `event_id`
- `failed_attempts`
- `first_seen`
- `last_seen`
- `usernames`
- `record_ids`
- `description`
- `recommendation`

The rule identifier is `WIN-AUTH-001`, and the severity is `High`.

### 7. Investigation Recommendation

When an alert is generated:

1. Identify the source IP and determine whether it is internal or external.
2. Identify the targeted usernames.
3. Review related authentication events.
4. Check whether successful logons occurred after the failures.
5. Correlate the activity with other security telemetry.
6. Determine whether the behavior is expected or suspicious.
7. Document findings and response actions.

### 8. False Positive Considerations

Potential benign explanations include:

- Users repeatedly entering incorrect passwords.
- Applications using outdated credentials.
- Scheduled tasks or services with expired passwords.
- Administrative systems attempting authentication with invalid credentials.
- Legitimate systems generating repeated authentication failures.

The alert must be investigated in context.

### 9. Current Limitations

- Only Event ID 4625 is evaluated.
- Events are grouped by source IP.
- Events without valid IP addresses are ignored.
- Events without parseable timestamps are ignored.
- The detector evaluates collected batches rather than a continuous event stream.
- Only one alert is generated per source IP during a detection execution.
- The rule does not independently determine whether an authentication attempt is malicious.
- The rule does not correlate multiple source IPs targeting the same account.

### 10. Future Improvements

Potential improvements include:

- Detection based on multiple source IPs targeting one account.
- Detection of password spraying patterns.
- Correlation between failed and successful logons.
- Additional Windows authentication Event IDs.
- Context enrichment for source IP addresses.
- Configurable severity and rule metadata.
- Continuous event monitoring.
