import csv
import json
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path


CHECKS = []


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


def add_check(name, status, severity, details, recommendation):
    CHECKS.append(
        {
            "name": name,
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

    add_check(
        name="Operating System",
        status="INFO",
        severity="Info",
        details=f"{system} {release} ({machine})",
        recommendation="Use a supported and updated operating system.",
    )


def check_ssh_config():
    ssh_config = Path("/etc/ssh/sshd_config")

    if not ssh_config.exists():
        add_check(
            name="SSH Configuration",
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
            status="PASS",
            severity="Low",
            details="Root login over SSH appears to be disabled.",
            recommendation="Keep PermitRootLogin set to no.",
        )
    else:
        add_check(
            name="SSH Root Login",
            status="FAIL",
            severity="High",
            details="Root login over SSH may not be disabled.",
            recommendation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config.",
        )

    if "PasswordAuthentication no" in content:
        add_check(
            name="SSH Password Authentication",
            status="PASS",
            severity="Low",
            details="SSH password authentication appears to be disabled.",
            recommendation="Keep PasswordAuthentication set to no and use SSH keys.",
        )
    else:
        add_check(
            name="SSH Password Authentication",
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
            status="PASS",
            severity="Low",
            details="UFW firewall is active.",
            recommendation="Keep firewall rules minimal and documented.",
        )
    elif ufw_result["return_code"] == 0:
        add_check(
            name="Firewall Status",
            status="FAIL",
            severity="Medium",
            details="UFW firewall does not appear to be active.",
            recommendation="Enable firewall after reviewing allowed services.",
        )
    else:
        add_check(
            name="Firewall Status",
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
            status="SKIPPED",
            severity="Info",
            details="Could not retrieve open ports.",
            recommendation="Install ss or netstat and review listening services.",
        )
        return

    listening_lines = [
        line
        for line in output.splitlines()
        if "LISTEN" in line or "udp" in line.lower()
    ]

    details = "\n".join(listening_lines[:15])

    add_check(
        name="Open Ports",
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
            status="SKIPPED",
            severity="Info",
            details="Could not retrieve sudo group members.",
            recommendation="Review privileged users manually.",
        )
        return

    add_check(
        name="Sudo Users",
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
            status="INFO",
            severity="Low",
            details=result["stdout"],
            recommendation="Review world-writable files and remove unnecessary temporary files.",
        )
    else:
        add_check(
            name="World-Writable Files in /tmp",
            status="PASS",
            severity="Low",
            details="No world-writable files found in /tmp sample check.",
            recommendation="Continue monitoring temporary directories.",
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


def build_findings():
    findings = []
    index = 1

    for check in CHECKS:
        if check["status"] in ["FAIL", "INFO"]:
            findings.append(
                {
                    "id": f"FINDING-{index:03d}",
                    "name": check["name"],
                    "severity": check["severity"],
                    "status": check["status"],
                    "details": check["details"],
                    "recommendation": check["recommendation"],
                }
            )
            index += 1

    return findings


def save_csv_report():
    report_file = Path("reports/linux_hardening_report.csv")

    with report_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(
            ["check_name", "status", "severity", "details", "recommendation"]
        )

        for check in CHECKS:
            writer.writerow(
                [
                    check["name"],
                    check["status"],
                    check["severity"],
                    check["details"],
                    check["recommendation"],
                ]
            )

    print(f"CSV report created: {report_file}")


def save_txt_summary():
    report_file = Path("reports/linux_hardening_summary.txt")
    summary = calculate_summary()

    with report_file.open("w", encoding="utf-8") as file:
        file.write("Linux Security Hardening Audit Summary\n")
        file.write("-------------------------------------\n\n")

        file.write("Summary\n")
        file.write("-------\n")
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
            file.write(f"Status: {check['status']}\n")
            file.write(f"Severity: {check['severity']}\n")
            file.write(f"Details:\n{check['details']}\n")
            file.write(f"Recommendation: {check['recommendation']}\n")
            file.write("\n" + "-" * 60 + "\n\n")

    print(f"TXT summary created: {report_file}")


def save_json_report():
    report_file = Path("reports/linux_hardening_report.json")
    summary = calculate_summary()

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
        "summary": summary,
        "checks": CHECKS,
    }

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)

    print(f"JSON report created: {report_file}")


def save_findings_json(findings):
    report_file = Path("reports/findings.json")

    with report_file.open("w", encoding="utf-8") as file:
        json.dump(findings, file, indent=2)

    print(f"Findings JSON created: {report_file}")


def save_events_ndjson():
    report_file = Path("reports/events.ndjson")

    with report_file.open("w", encoding="utf-8") as file:
        for check in CHECKS:
            event = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": "linux_hardening_check",
                "host": platform.node(),
                "check_name": check["name"],
                "status": check["status"],
                "severity": check["severity"],
                "message": f"{check['name']} returned {check['status']} with severity {check['severity']}.",
                "recommendation": check["recommendation"],
            }

            file.write(json.dumps(event) + "\n")

    print(f"NDJSON events created: {report_file}")


def print_console_summary():
    print("=" * 60)
    print("Linux Security Hardening Auditor")
    print("=" * 60)

    for check in CHECKS:
        print(f"{check['status']} | {check['severity']} | {check['name']}")

    print("=" * 60)


def run_checks():
    check_os()
    check_ssh_config()
    check_firewall()
    check_open_ports()
    check_sudo_users()
    check_world_writable_tmp()


def main():
    Path("reports").mkdir(exist_ok=True)

    if platform.system() != "Linux":
        print("Warning: This tool is designed for Linux systems.")
        print("Some checks may be skipped or unavailable on this operating system.")
        print()

    run_checks()
    findings = build_findings()

    print_console_summary()
    save_csv_report()
    save_txt_summary()
    save_json_report()
    save_findings_json(findings)
    save_events_ndjson()


if __name__ == "__main__":
    main()
