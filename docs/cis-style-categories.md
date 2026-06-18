# CIS-Style Categories

This project is not a full CIS benchmark scanner.

However, the checks are organized into security categories inspired by common Linux hardening and security audit workflows.

## Categories Used

### System Information

Collects basic information about the host, operating system, kernel, and architecture.

### SSH Hardening

Reviews SSH settings related to privileged access and authentication.

Examples:

- SSH root login
- SSH password authentication

### Network Security

Reviews firewall status and basic network exposure.

### Network Exposure

Lists listening services and open ports for manual review.

### User Privileges

Reviews users with administrative privileges.

### File Permissions

Reviews potentially risky file permissions, such as world-writable files.

### Patch Management

Checks whether package updates may be available.

## Notes

This project is designed for learning and portfolio purposes.

It does not replace:

- CIS-CAT
- Lynis
- OpenSCAP
- Enterprise vulnerability scanners
- Full compliance audits
