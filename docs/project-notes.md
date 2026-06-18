# Project Notes

## Project Name

Python Linux Hardening Auditor

## Project Goal

The goal of this project is to build a Python-based security automation tool that performs basic Linux hardening checks and generates reports in formats useful for IT, Security, SOC, SIEM, and compliance workflows.

## Why This Project Matters

Security Engineers often need to review system configuration, identify risky settings, and provide clear recommendations.

This project demonstrates the ability to:

* Automate Linux security checks
* Read system configuration files
* Execute safe read-only commands
* Classify findings by status and severity
* Generate structured reports
* Create SOC/SIEM-friendly outputs

## Report Formats

The tool generates multiple output formats:

### CSV

Useful for spreadsheet-based analysis, filtering, and reporting.

### TXT Summary

Useful for human-readable summaries and quick reviews.

### JSON

Useful for automation, dashboards, APIs, and integration with other tools.

### Findings JSON

Useful for structured security findings and remediation workflows.

### NDJSON

Useful for SIEM-style event ingestion, where each line is a separate JSON event.

## Safety Notes

This tool is read-only.

It does not:

* Change SSH settings
* Enable or disable firewall rules
* Modify users
* Close ports
* Delete files
* Apply hardening automatically

It only checks and reports.

## Future Improvements

Possible future improvements:

* Add JSON schema validation
* Add command-line arguments
* Add severity scoring
* Add support for exporting HTML reports
* Add support for Debian/Ubuntu-specific package update checks
* Add support for CIS-style check categories
* Add optional remediation suggestions
* Add unit tests
* Add GitHub Actions workflow
