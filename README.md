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
* Check package update status
* Calculate an overall risk score
* Assign an overall risk level
* Run selected checks only
* Generate CSV reports
* Generate TXT summary reports
* Generate JSON reports
* Generate structured security findings
* Generate NDJSON events for SIEM-style ingestion
* Generate HTML reports
* Print suggested remediation actions without applying changes
* Run from the command line
* Includes unit tests
* Includes GitHub Actions workflow

## Project Structure

```text
python-linux-hardening-auditor/
├── .github/
│   └── workflows/
│       └── python-check.yml
├── docs/
│   ├── screenshots/
│   │   └── .gitkeep
│   ├── audit-checks.md
│   ├── cis-style-categories.md
│   └── project-notes.md
├── reports/
│   └── .gitkeep
├── sample_outputs/
│   ├── linux_hardening_summary_example.txt
│   ├── linux_hardening_report_example.json
│   ├── findings_example.json
│   ├── events_example.ndjson
│   └── linux_hardening_report_example.html
├── src/
│   └── linux_auditor.py
├── tests/
│   └── test_risk_score.py
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

The `suggest-remediation` mode prints recommended actions but does not apply changes.

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

```bash
pip install -r requirements.txt
```

## Basic Usage

Run the auditor from the project root:

```bash
python src/linux_auditor.py
```

On Linux systems where Python 3 is invoked as `python3`, use:

```bash
python3 src/linux_auditor.py
```

## Advanced Usage

Run all checks and generate all report formats:

```bash
python src/linux_auditor.py --output reports --format all
```

Run selected checks only:

```bash
python src/linux_auditor.py --checks os,ssh,firewall --output reports --format all
```

Generate only JSON reports:

```bash
python src/linux_auditor.py --format json --output reports
```

Generate only HTML report:

```bash
python src/linux_auditor.py --format html --output reports
```

Print suggested remediation actions without applying changes:

```bash
python src/linux_auditor.py --mode suggest-remediation --output reports --format txt
```

## Command-Line Options

| Option     | Description                                                              | Example                      |
| ---------- | ------------------------------------------------------------------------ | ---------------------------- |
| `--output` | Output directory for generated reports                                   | `--output reports`           |
| `--format` | Report format to generate: `all`, `csv`, `txt`, `json`, `ndjson`, `html` | `--format json`              |
| `--checks` | Comma-separated list of checks to run                                    | `--checks os,ssh,firewall`   |
| `--mode`   | Run mode: `audit` or `suggest-remediation`                               | `--mode suggest-remediation` |

## Available Checks

The tool supports the following check names:

```text
os
ssh
firewall
ports
sudo
tmp
updates
```

Example:

```bash
python src/linux_auditor.py --checks os,ssh,firewall
```

## Audit Checks

The tool currently performs the following checks:

| Check                          | Category           | Purpose                                                     |
| ------------------------------ | ------------------ | ----------------------------------------------------------- |
| Operating System               | System Information | Collects OS, kernel, architecture, and hostname information |
| SSH Root Login                 | SSH Hardening      | Checks whether direct SSH root login appears disabled       |
| SSH Password Authentication    | SSH Hardening      | Checks whether SSH password authentication appears disabled |
| Firewall Status                | Network Security   | Checks UFW firewall status                                  |
| Open Ports                     | Network Exposure   | Lists listening TCP/UDP services using `ss` or `netstat`    |
| Sudo Users                     | User Privileges    | Lists users in the sudo group                               |
| World-Writable Files in `/tmp` | File Permissions   | Checks for world-writable files in `/tmp`                   |
| Package Update Status          | Patch Management   | Checks whether package updates may be available             |

More details are available in:

```text
docs/audit-checks.md
docs/cis-style-categories.md
```

## Risk Scoring

The tool calculates an overall risk score based on findings:

```text
High   = 10 points
Medium = 5 points
Low    = 2 points
Info   = 0 points
```

Risk level logic:

```text
0-7     = Low
8-19    = Medium
20+     = High
```

The risk score appears in:

```text
linux_hardening_summary.txt
linux_hardening_report.json
linux_hardening_report.html
console output
```

## Generated Reports

The script generates the following files locally inside the `reports/` folder:

```text
linux_hardening_report.csv
linux_hardening_summary.txt
linux_hardening_report.json
findings.json
events.ndjson
linux_hardening_report.html
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
* Category
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

### HTML Report

```text
linux_hardening_report.html
```

Used for a browser-readable report with summary information and detailed checks.

## Example Console Output

```text
============================================================
Linux Security Hardening Auditor
============================================================
Risk Score: 7
Risk Level: Low
============================================================
INFO | Info | System Information | Operating System
SKIPPED | Info | SSH Hardening | SSH Configuration
SKIPPED | Info | Network Security | Firewall Status
SKIPPED | Info | Network Exposure | Open Ports
SKIPPED | Info | User Privileges | Sudo Users
PASS | Low | File Permissions | World-Writable Files in /tmp
PASS | Low | Patch Management | Package Update Status
============================================================
CSV report created: reports/linux_hardening_report.csv
TXT summary created: reports/linux_hardening_summary.txt
JSON report created: reports/linux_hardening_report.json
Findings JSON created: reports/findings.json
NDJSON events created: reports/events.ndjson
HTML report created: reports/linux_hardening_report.html
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
  "risk": {
    "score": 17,
    "level": "Medium"
  },
  "summary": {
    "total_checks": 7,
    "pass": 2,
    "fail": 1,
    "info": 2,
    "skipped": 2,
    "high": 1,
    "medium": 1,
    "low": 2,
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
  "category": "SSH Hardening",
  "severity": "High",
  "status": "FAIL",
  "details": "Root login over SSH may not be disabled.",
  "recommendation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config."
}
```

## Example NDJSON Event

```json
{"timestamp":"2026-06-18T13:00:00+00:00","event_type":"linux_hardening_check","host":"ubuntu-lab","category":"SSH Hardening","check_name":"SSH Root Login","status":"FAIL","severity":"High","message":"SSH Root Login returned FAIL with severity High.","recommendation":"Set 'PermitRootLogin no' in /etc/ssh/sshd_config."}
```

## Documentation

Additional documentation is stored in the `docs/` folder:

```text
docs/audit-checks.md
docs/project-notes.md
docs/cis-style-categories.md
docs/screenshots/
```

## Sample Outputs

The `sample_outputs/` folder contains selected example output files that can be safely shared in the repository.

Generated reports are created locally under `reports/` and are ignored by Git.

Example files:

```text
sample_outputs/linux_hardening_summary_example.txt
sample_outputs/linux_hardening_report_example.json
sample_outputs/findings_example.json
sample_outputs/events_example.ndjson
sample_outputs/linux_hardening_report_example.html
```

## SOC / SIEM Outputs

This project generates multiple output formats commonly used in security operations:

* CSV for spreadsheet-based review
* TXT for human-readable summaries
* JSON for automation, dashboards, and APIs
* `findings.json` for structured security findings
* `events.ndjson` for SIEM/log ingestion workflows
* HTML for browser-readable reporting

## GitHub Actions

This project includes a GitHub Actions workflow that:

* Checks Python syntax
* Runs unit tests
* Runs the auditor on an Ubuntu runner

Workflow file:

```text
.github/workflows/python-check.yml
```

## Tests

Run unit tests locally:

```bash
python -m unittest discover -s tests
```

The current tests cover:

* Risk score calculation
* Overall risk level classification

## Requirements

No external dependencies are required.

This project uses only Python standard library modules:

* argparse
* csv
* html
* json
* platform
* subprocess
* datetime
* pathlib
* unittest

## Skills Demonstrated

* Python automation
* Linux security basics
* Linux hardening checks
* Safe read-only command execution
* SSH configuration review
* Firewall status review
* Open port review
* Sudo user review
* File permission review
* Patch management awareness
* Risk scoring
* Command-line arguments with `argparse`
* CSV report generation
* TXT summary generation
* JSON report generation
* NDJSON event generation
* HTML report generation
* Structured findings
* Unit testing
* GitHub Actions
* SOC/SIEM-friendly output formats
* IT/Security automation workflow

## Example Resume Description

Built a Python Linux hardening audit tool that performs read-only security checks, reviews SSH configuration, firewall status, open ports, sudo users, file permissions, and package update status, calculates risk scores, supports command-line options, and generates CSV/TXT/JSON/NDJSON/HTML reports for IT, Security, SOC, SIEM, and compliance workflows.
