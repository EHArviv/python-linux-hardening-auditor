# Python Linux Hardening Auditor

A Python security automation tool that performs basic read-only Linux hardening checks and generates multiple report formats for IT, Security, SOC, SIEM, and compliance workflows.

## Features

* Collect operating system information
* Check SSH root login configuration
* Check SSH password authentication configuration
* Check firewall status
* List open listening ports
* Identify sudo group users
* Check for world-writable files in `/tmp`
* Generate CSV reports
* Generate TXT summary reports
* Generate JSON reports
* Generate structured security findings
* Generate NDJSON events for SIEM-style ingestion
* Run from the command line

## Project Structure

```text
python-linux-hardening-auditor/
├── docs/
│   ├── screenshots/
│   │   └── .gitkeep
│   ├── audit-checks.md
│   └── project-notes.md
├── reports/
│   └── .gitkeep
├── sample_outputs/
│   └── .gitkeep
├── src/
│   └── linux_auditor.py
├── README.md
├── requirements.txt
└── .gitignore
```

## Safety Notice

This tool is read-only.

It does not:

* Modify SSH settings
* Enable or disable firewall rules
* Modify users
* Close ports
* Delete files
* Apply hardening automatically

It only checks and reports.

## Recommended Environment

This tool is designed for Linux systems.

Recommended test environments:

* WSL Ubuntu
* Ubuntu VM
* Kali VM
* Linux lab machine
* Test server

The tool can run on Windows, but some Linux-specific checks may be skipped or unavailable.

## Installation

No external dependencies are required.

This project uses only Python standard library modules.

## Usage

Run the auditor from the project root:

```bash
python src/linux_auditor.py
```

On Linux systems where Python 3 is invoked as `python3`, use:

```bash
python3 src/linux_auditor.py
```

## Audit Checks

The tool currently performs the following checks:

| Check                          | Purpose                                                     |
| ------------------------------ | ----------------------------------------------------------- |
| Operating System               | Collects OS, kernel, architecture, and hostname information |
| SSH Root Login                 | Checks whether direct SSH root login appears disabled       |
| SSH Password Authentication    | Checks whether SSH password authentication appears disabled |
| Firewall Status                | Checks UFW firewall status                                  |
| Open Ports                     | Lists listening TCP/UDP services using `ss` or `netstat`    |
| Sudo Users                     | Lists users in the sudo group                               |
| World-Writable Files in `/tmp` | Checks for world-writable files in `/tmp`                   |

More details are available in:

```text
docs/audit-checks.md
```

## Generated Reports

The script generates the following files locally inside the `reports/` folder:

```text
linux_hardening_report.csv
linux_hardening_summary.txt
linux_hardening_report.json
findings.json
events.ndjson
```

These generated report files are ignored by Git and should not be committed to the repository.

## Report Types

### CSV Report

```text
linux_hardening_report.csv
```

Used for spreadsheet-based review, filtering, sorting, and manual analysis.

### TXT Summary

```text
linux_hardening_summary.txt
```

Used for a human-readable summary of the audit results.

### JSON Report

```text
linux_hardening_report.json
```

Used for automation, dashboards, APIs, or integration with other tools.

### Findings JSON

```text
findings.json
```

Used to represent security findings in a structured format.

Each finding includes:

* Finding ID
* Check name
* Status
* Severity
* Details
* Recommendation

### NDJSON Events

```text
events.ndjson
```

Used for SIEM-style event ingestion.

Each line is a separate JSON event.

## Example Console Output

```text
============================================================
Linux Security Hardening Auditor
============================================================
INFO | Info | Operating System
SKIPPED | Info | SSH Configuration
SKIPPED | Info | Firewall Status
SKIPPED | Info | Open Ports
SKIPPED | Info | Sudo Users
PASS | Low | World-Writable Files in /tmp
============================================================
CSV report created: reports/linux_hardening_report.csv
TXT summary created: reports/linux_hardening_summary.txt
JSON report created: reports/linux_hardening_report.json
Findings JSON created: reports/findings.json
NDJSON events created: reports/events.ndjson
```

## Example JSON Report Structure

```json
{
  "tool_name": "Python Linux Hardening Auditor",
  "report_type": "linux_security_hardening_audit",
  "generated_at": "2026-06-18T13:00:00+00:00",
  "host": "ubuntu-lab",
  "platform": {
    "system": "Linux",
    "release": "6.5.0",
    "machine": "x86_64"
  },
  "summary": {
    "total_checks": 6,
    "pass": 1,
    "fail": 1,
    "info": 2,
    "skipped": 2,
    "high": 1,
    "medium": 1,
    "low": 1,
    "info_severity": 3
  },
  "checks": []
}
```

## Example Finding

```json
{
  "id": "FINDING-001",
  "name": "SSH Root Login",
  "severity": "High",
  "status": "FAIL",
  "details": "Root login over SSH may not be disabled.",
  "recommendation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config."
}
```

## Example NDJSON Event

```json
{"timestamp":"2026-06-18T13:00:00+00:00","event_type":"linux_hardening_check","host":"ubuntu-lab","check_name":"SSH Root Login","status":"FAIL","severity":"High","message":"SSH Root Login returned FAIL with severity High.","recommendation":"Set 'PermitRootLogin no' in /etc/ssh/sshd_config."}
```

## Documentation

Additional documentation is stored in the `docs/` folder:

```text
docs/audit-checks.md
docs/project-notes.md
docs/screenshots/
```

## Sample Outputs

The `sample_outputs/` folder is reserved for selected example output files that can be safely shared in the repository.

Generated reports are created locally under `reports/` and are ignored by Git.

## SOC / SIEM Outputs

This project generates multiple output formats commonly used in security operations:

* CSV for spreadsheet-based review
* TXT for human-readable summaries
* JSON for automation, dashboards, and APIs
* `findings.json` for structured security findings
* `events.ndjson` for SIEM/log ingestion workflows

## Requirements

No external dependencies are required.

This project uses only Python standard library modules:

* csv
* json
* platform
* subprocess
* datetime
* pathlib

## Skills Demonstrated

* Python automation
* Linux security basics
* Linux hardening checks
* Safe read-only command execution
* SSH configuration review
* Firewall status review
* Open port review
* Sudo user review
* CSV report generation
* TXT summary generation
* JSON report generation
* NDJSON event generation
* Structured findings
* SOC/SIEM-friendly output formats
* IT/Security automation workflow

## Example Resume Description

Built a Python Linux hardening audit tool that performs read-only security checks, reviews SSH configuration, firewall status, open ports, sudo users, and temporary file exposure, and generates CSV/TXT/JSON/NDJSON reports for IT, Security, SOC, SIEM, and compliance workflows.
