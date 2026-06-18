# Audit Checks

This document explains the security checks performed by the Python Linux Hardening Auditor.

## Purpose

The goal of this tool is to perform a basic read-only Linux security hardening audit and generate structured reports for IT, Security, SOC, and compliance workflows.

The tool does not modify system settings. It only collects information and reports findings.

## Checks Included

### Operating System Information

The tool collects basic operating system information such as:

* Operating system name
* Kernel release
* Machine architecture
* Hostname

This helps identify the system being audited.

### SSH Configuration

The tool checks whether the OpenSSH server configuration file exists at:

```text
/etc/ssh/sshd_config
```

It checks for:

```text
PermitRootLogin no
PasswordAuthentication no
```

These settings are important because:

* Disabling SSH root login reduces the risk of direct privileged access.
* Disabling password authentication encourages the use of SSH keys.

### Firewall Status

The tool checks the status of UFW using:

```bash
ufw status
```

If UFW is active, the firewall check is marked as PASS.

If UFW is inactive or unavailable, the tool reports it as a finding or skipped check.

### Open Ports

The tool attempts to list listening network services using:

```bash
ss -tuln
```

If `ss` is unavailable, it tries:

```bash
netstat -tuln
```

Open ports are reported so administrators can review exposed services.

### Sudo Users

The tool checks users in the sudo group using:

```bash
getent group sudo
```

This helps identify users with administrative privileges.

### World-Writable Files in `/tmp`

The tool checks for world-writable files in `/tmp` using:

```bash
find /tmp -type f -perm -0002
```

This helps identify temporary files that may require review.

## Output Files

The tool generates the following local reports:

```text
reports/linux_hardening_report.csv
reports/linux_hardening_summary.txt
reports/linux_hardening_report.json
reports/findings.json
reports/events.ndjson
```

These files are ignored by Git and should not be committed to the repository.

## Notes

This tool is designed for learning, portfolio building, and basic security auditing.

It should be tested in a controlled environment such as:

* WSL Ubuntu
* Ubuntu VM
* Kali VM
* Linux lab machine
* Test server

Do not rely on this tool as a full compliance scanner or enterprise-grade security solution.
