import argparse
import csv
import html
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path


CHECKS = []

SEVERITY_POINTS = {
    "High": 10,
    "Medium": 5,
    "Low": 2,
    "Info": 0,
}


AVAILABLE_CHECKS = {
    "os": "Operating system information",
    "ssh": "SSH configuration",
    "firewall": "Firewall status",
    "ports": "Open ports",
    "sudo": "Sudo users",
    "tmp": "World-writable files in /tmp",
    "updates": "Package update status",
}


def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
        )

        return {
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "return_code": result.returncode,
        }

    except subprocess.TimeoutExpired:
        return {
            "stdout": "",
            "stderr": "Command timed out",
            "return_code": 1,
        }


def add_check(name, category, status, severity, details, recommendation):
    CHECKS.append(
        {
            "name": name,
            "category": category,
            "status": status,
            "severity": severity,
            "details": details,
            "recommendation": recommendation,
        }
    )


def check_os():
    system = platform.system()
    release = platform.release()
    machine = platform.machine()
    hostname = platform.node()

    add_check(
        name="Operating System",
        category="System Information",
        status="INFO",
        severity="Info",
        details=f"{system} {release} ({machine}) on host {hostname}",
        recommendation="Use a supported and updated operating system.",
    )


def check_ssh_config():
    ssh_config = Path("/etc/ssh/sshd_config")

    if not ssh_config.exists():
        add_check(
            name="SSH Configuration",
            category="SSH Hardening",
            status="SKIPPED",
            severity="Info",
            details="/etc/ssh/sshd_config was not found.",
            recommendation="Run this check on a Linux system with OpenSSH installed.",
        )
        return

    content = ssh_config.read_text(encoding="utf-8", errors="ignore")

    if "PermitRootLogin no" in content:
        add_check(
            name="SSH Root Login",
            category="SSH Hardening",
            status="PASS",
            severity="Low",
            details="Root login over SSH appears to be disabled.",
            recommendation="Keep PermitRootLogin set to no.",
        )
    else:
        add_check(
            name="SSH Root Login",
            category="SSH Hardening",
            status="FAIL",
            severity="High",
            details="Root login over SSH may not be disabled.",
            recommendation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config.",
        )

    if "PasswordAuthentication no" in content:
        add_check(
            name="SSH Password Authentication",
            category="SSH Hardening",
            status="PASS",
            severity="Low",
            details="SSH password authentication appears to be disabled.",
            recommendation="Keep PasswordAuthentication set to no and use SSH keys.",
        )
    else:
        add_check(
            name="SSH Password Authentication",
            category="SSH Hardening",
            status="FAIL",
            severity="Medium",
            details="SSH password authentication may still be enabled.",
            recommendation="Use SSH keys and set 'PasswordAuthentication no'.",
        )


def check_firewall():
    ufw_result = run_command("ufw status")

    if "Status: active" in ufw_result["stdout"]:
        add_check(
            name="Firewall Status",
            category="Network Security",
            status="PASS",
            severity="Low",
            details="UFW firewall is active.",
            recommendation="Keep firewall rules minimal and documented.",
        )
    elif ufw_result["return_code"] == 0:
        add_check(
            name="Firewall Status",
            category="Network Security",
            status="FAIL",
            severity="Medium",
            details="UFW firewall does not appear to be active.",
            recommendation="Enable firewall after reviewing allowed services.",
        )
    else:
        add_check(
            name="Firewall Status",
            category="Network Security",
            status="SKIPPED",
            severity="Info",
            details="Could not determine UFW firewall status.",
            recommendation="Check firewall manually using ufw, firewalld, or iptables.",
        )


def check_open_ports():
    commands = ["ss -tuln", "netstat -tuln"]
    output = ""

    for command in commands:
        result = run_command(command)
        if result["stdout"]:
            output = result["stdout"]
            break

    if not output:
        add_check(
            name="Open Ports",
            category="Network Exposure",
            status="SKIPPED",
            severity="Info",
            details="Could not retrieve open ports.",
            recommendation="Install ss or netstat and review listening services.",
        )
        return

    listening_lines = [
        line for line in output.splitlines()
        if "LISTEN" in line or "udp" in line.lower()
    ]

    details = "\n".join(listening_lines[:15])

    add_check(
        name="Open Ports",
        category="Network Exposure",
        status="INFO",
        severity="Info",
        details=details if details else "No listening ports found.",
        recommendation="Review all listening services and close unnecessary ports.",
    )


def check_sudo_users():
    sudo_group_result = run_command("getent group sudo")

    if not sudo_group_result["stdout"]:
        add_check(
            name="Sudo Users",
            category="User Privileges",
            status="SKIPPED",
            severity="Info",
            details="Could not retrieve sudo group members.",
            recommendation="Review privileged users manually.",
        )
        return

    add_check(
        name="Sudo Users",
        category="User Privileges",
        status="INFO",
        severity="Medium",
        details=sudo_group_result["stdout"],
        recommendation="Ensure only approved administrators have sudo privileges.",
    )


def check_world_writable_tmp():
    result = run_command("find /tmp -type f -perm -0002 2>/dev/null | head -n 10")

    if result["stdout"]:
        add_check(
            name="World-Writable Files in /tmp",
            category="File Permissions",
            status="INFO",
            severity="Low",
            details=result["stdout"],
            recommendation="Review world-writable files and remove unnecessary temporary files.",
        )
    else:
        add_check(
            name="World-Writable Files in /tmp",
            category="File Permissions",
            status="PASS",
            severity="Low",
            details="No world-writable files found in /tmp sample check.",
            recommendation="Continue monitoring temporary directories.",
        )


def check_package_updates():
    if platform.system() != "Linux":
        add_check(
            name="Package Update Status",
            category="Patch Management",
            status="SKIPPED",
            severity="Info",
            details="Package update check is only available on Linux.",
            recommendation="Run this check on a Linux system.",
        )
        return

    result = run_command("apt list --upgradable 2>/dev/null | head -n 20")

    if result["stdout"]:
        add_check(
            name="Package Update Status",
            category="Patch Management",
            status="INFO",
            severity="Medium",
            details=result["stdout"],
            recommendation="Review available package updates and apply security updates according to change management policy.",
        )
    else:
        add_check(
            name="Package Update Status",
            category="Patch Management",
            status="PASS",
            severity="Low",
            details="No upgradable packages detected or apt is not available.",
            recommendation="Continue regular patch monitoring.",
        )


def calculate_summary():
    summary = {
        "total_checks": len(CHECKS),
        "pass": 0,
        "fail": 0,
        "info": 0,
        "skipped": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info_severity": 0,
    }

    for check in CHECKS:
        status = check["status"]
        severity = check["severity"]

        if status == "PASS":
            summary["pass"] += 1
        elif status == "FAIL":
            summary["fail"] += 1
        elif status == "INFO":
            summary["info"] += 1
        elif status == "SKIPPED":
            summary["skipped"] += 1

        if severity == "High":
            summary["high"] += 1
        elif severity == "Medium":
            summary["medium"] += 1
        elif severity == "Low":
            summary["low"] += 1
        elif severity == "Info":
            summary["info_severity"] += 1

    return summary


def calculate_risk_score(checks):
    score = 0

    for check in checks:
        if check["status"] in ["FAIL", "INFO"]:
            score += SEVERITY_POINTS.get(check["severity"], 0)

    return score


def calculate_overall_risk_level(risk_score):
    if risk_score >= 20:
        return "High"
    if risk_score >= 8:
        return "Medium"
    return "Low"


def build_findings():
    findings = []
    index = 1

    for check in CHECKS:
        if check["status"] in ["FAIL", "INFO"]:
            findings.append(
                {
                    "id": f"FINDING-{index:03d}",
                    "name": check["name"],
                    "category": check["category"],
                    "severity": check["severity"],
                    "status": check["status"],
                    "details": check["details"],
                    "recommendation": check["recommendation"],
                }
            )
            index += 1

    return findings


def save_csv_report(output_dir):
    report_file = output_dir / "linux_hardening_report.csv"

    with report_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(
            ["check_name", "category", "status", "severity", "details", "recommendation"]
        )

        for check in CHECKS:
            writer.writerow(
                [
                    check["name"],
                    check["category"],
                    check["status"],
                    check["severity"],
                    check["details"],
                    check["recommendation"],
                ]
            )

    print(f"CSV report created: {report_file}")


def save_txt_summary(output_dir):
    report_file = output_dir / "linux_hardening_summary.txt"
    summary = calculate_summary()
    risk_score = calculate_risk_score(CHECKS)
    risk_level = calculate_overall_risk_level(risk_score)

    with report_file.open("w", encoding="utf-8") as file:
        file.write("Linux Security Hardening Audit Summary\n")
        file.write("-------------------------------------\n\n")

        file.write("Risk Summary\n")
        file.write("------------\n")
        file.write(f"Overall risk score: {risk_score}\n")
        file.write(f"Overall risk level: {risk_level}\n\n")

        file.write("Check Summary\n")
        file.write("-------------\n")
        file.write(f"Total checks: {summary['total_checks']}\n")
        file.write(f"PASS: {summary['pass']}\n")
        file.write(f"FAIL: {summary['fail']}\n")
        file.write(f"INFO: {summary['info']}\n")
        file.write(f"SKIPPED: {summary['skipped']}\n\n")

        file.write("Severity Summary\n")
        file.write("----------------\n")
        file.write(f"High: {summary['high']}\n")
        file.write(f"Medium: {summary['medium']}\n")
        file.write(f"Low: {summary['low']}\n")
        file.write(f"Info: {summary['info_severity']}\n\n")

        file.write("Detailed Checks\n")
        file.write("---------------\n\n")

        for check in CHECKS:
            file.write(f"Check: {check['name']}\n")
            file.write(f"Category: {check['category']}\n")
            file.write(f"Status: {check['status']}\n")
            file.write(f"Severity: {check['severity']}\n")
            file.write(f"Details:\n{check['details']}\n")
            file.write(f"Recommendation: {check['recommendation']}\n")
            file.write("\n" + "-" * 60 + "\n\n")

    print(f"TXT summary created: {report_file}")


def save_json_report(output_dir):
    report_file = output_dir / "linux_hardening_report.json"
    summary = calculate_summary()
    risk_score = calculate_risk_score(CHECKS)
    risk_level = calculate_overall_risk_level(risk_score)

    data = {
        "tool_name": "Python Linux Hardening Auditor",
        "report_type": "linux_security_hardening_audit",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "risk": {
            "score": risk_score,
            "level": risk_level,
        },
        "summary": summary,
        "checks": CHECKS,
    }

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)

    print(f"JSON report created: {report_file}")


def save_findings_json(output_dir, findings):
    report_file = output_dir / "findings.json"

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(findings, file, indent=2)

    print(f"Findings JSON created: {report_file}")


def save_events_ndjson(output_dir):
    report_file = output_dir / "events.ndjson"

    with report_file.open("w", encoding="utf-8") as file:
        for check in CHECKS:
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "linux_hardening_check",
                "host": platform.node(),
                "category": check["category"],
                "check_name": check["name"],
                "status": check["status"],
                "severity": check["severity"],
                "message": f"{check['name']} returned {check['status']} with severity {check['severity']}.",
                "recommendation": check["recommendation"],
            }

            file.write(json.dumps(event) + "\n")

    print(f"NDJSON events created: {report_file}")


def save_html_report(output_dir):
    report_file = output_dir / "linux_hardening_report.html"
    summary = calculate_summary()
    risk_score = calculate_risk_score(CHECKS)
    risk_level = calculate_overall_risk_level(risk_score)

    rows = ""

    for check in CHECKS:
        rows += f"""
        <tr>
          <td>{html.escape(check['name'])}</td>
          <td>{html.escape(check['category'])}</td>
          <td>{html.escape(check['status'])}</td>
          <td>{html.escape(check['severity'])}</td>
          <td><pre>{html.escape(check['details'])}</pre></td>
          <td>{html.escape(check['recommendation'])}</td>
        </tr>
        """

    content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Linux Hardening Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background-color: #f2f2f2; }}
    pre {{ white-space: pre-wrap; }}
  </style>
</head>
<body>
  <h1>Linux Security Hardening Audit Report</h1>

  <h2>Risk Summary</h2>
  <p><strong>Risk Score:</strong> {risk_score}</p>
  <p><strong>Risk Level:</strong> {html.escape(risk_level)}</p>

  <h2>Check Summary</h2>
  <ul>
    <li>Total checks: {summary['total_checks']}</li>
    <li>PASS: {summary['pass']}</li>
    <li>FAIL: {summary['fail']}</li>
    <li>INFO: {summary['info']}</li>
    <li>SKIPPED: {summary['skipped']}</li>
  </ul>

  <h2>Detailed Checks</h2>
  <table>
    <tr>
      <th>Check</th>
      <th>Category</th>
      <th>Status</th>
      <th>Severity</th>
      <th>Details</th>
      <th>Recommendation</th>
    </tr>
    {rows}
  </table>
</body>
</html>
"""

    report_file.write_text(content, encoding="utf-8")
    print(f"HTML report created: {report_file}")


def print_console_summary():
    risk_score = calculate_risk_score(CHECKS)
    risk_level = calculate_overall_risk_level(risk_score)

    print("=" * 60)
    print("Linux Security Hardening Auditor")
    print("=" * 60)
    print(f"Risk Score: {risk_score}")
    print(f"Risk Level: {risk_level}")
    print("=" * 60)

    for check in CHECKS:
        print(
            f"{check['status']} | {check['severity']} | {check['category']} | {check['name']}"
        )

    print("=" * 60)


def parse_selected_checks(checks_argument):
    if checks_argument == "all":
        return set(AVAILABLE_CHECKS.keys())

    selected = {item.strip() for item in checks_argument.split(",") if item.strip()}
    invalid = selected - set(AVAILABLE_CHECKS.keys())

    if invalid:
        raise ValueError(f"Invalid checks selected: {', '.join(sorted(invalid))}")

    return selected


def run_checks(selected_checks):
    if "os" in selected_checks:
        check_os()

    if "ssh" in selected_checks:
        check_ssh_config()

    if "firewall" in selected_checks:
        check_firewall()

    if "ports" in selected_checks:
        check_open_ports()

    if "sudo" in selected_checks:
        check_sudo_users()

    if "tmp" in selected_checks:
        check_world_writable_tmp()

    if "updates" in selected_checks:
        check_package_updates()


def save_reports(output_dir, report_format):
    findings = build_findings()

    if report_format in ["all", "csv"]:
        save_csv_report(output_dir)

    if report_format in ["all", "txt"]:
        save_txt_summary(output_dir)

    if report_format in ["all", "json"]:
        save_json_report(output_dir)
        save_findings_json(output_dir, findings)

    if report_format in ["all", "ndjson"]:
        save_events_ndjson(output_dir)

    if report_format in ["all", "html"]:
        save_html_report(output_dir)


def print_suggested_remediation():
    print()
    print("Suggested Remediation Actions")
    print("-----------------------------")
    print("This tool is read-only and does not apply changes automatically.")
    print()

    for check in CHECKS:
        if check["status"] in ["FAIL", "INFO"]:
            print(f"- {check['name']}: {check['recommendation']}")


def build_arg_parser():
    parser = argparse.ArgumentParser(
        description="Read-only Linux security hardening auditor."
    )

    parser.add_argument(
        "--output",
        default="reports",
        help="Output directory for generated reports. Default: reports",
    )

    parser.add_argument(
        "--format",
        default="all",
        choices=["all", "csv", "txt", "json", "ndjson", "html"],
        help="Report format to generate. Default: all",
    )

    parser.add_argument(
        "--checks",
        default="all",
        help="Comma-separated checks to run. Options: all, os, ssh, firewall, ports, sudo, tmp, updates",
    )

    parser.add_argument(
        "--mode",
        default="audit",
        choices=["audit", "suggest-remediation"],
        help="Run mode. Default: audit. suggest-remediation prints recommendations but does not apply changes.",
    )

    return parser


def main():
    parser = build_arg_parser()
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if platform.system() != "Linux":
        print("Warning: This tool is designed for Linux systems.")
        print("Some checks may be skipped or unavailable on this operating system.")
        print()

    try:
        selected_checks = parse_selected_checks(args.checks)
    except ValueError as error:
        print(f"Error: {error}")
        return

    run_checks(selected_checks)
    print_console_summary()
    save_reports(output_dir, args.format)

    if args.mode == "suggest-remediation":
        print_suggested_remediation()


if __name__ == "__main__":
    main()
