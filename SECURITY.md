# Security policy

## Security design and operational risks

### SSH and TLS

- SSH is launched through the system OpenSSH client with agent forwarding and port forwarding disabled.
- Passwords are neither collected by Python nor written to disk. MCP uses batch mode and requires an SSH key or agent.
- JSON/MCP report host fields use `NAS` plus a stable fingerprint rather than the configured IP/hostname. IP/MAC addresses in SSH output and NAS account names in errors are redacted.
- ADM HTTPS certificate validation is on by default. `--insecure` is for a known test host and lowers authenticity guarantees; reports preserve that fact.
- SSH host-key verification follows the local OpenSSH configuration. Review and trust the NAS host key before first use.

### Remote command boundary

Observation commands come from a fixed allowlist. Host, user and port are validated; scan duration is limited to 1–3600 seconds and result count to 1–10,000. The DeadBolt file search reads filenames only, does not follow other mounted filesystems, and never deletes, renames or quarantines a file.

Kernel module actions are a separate, explicitly mutating feature:

- Require a Linux 6.1+ kernel and an allowlisted DMI vendor/product pair.
- Require `--confirm-risk`, a local module-state backup, and an exact interactive confirmation. `--force` skips only the interactive prompt; it does not skip the acknowledgement, backup, identity, or compatibility checks.
- Use only the fixed `asustor`, `asustor_it87`, and `asustor_gpio_it87` module names. A loaded `it87` module blocks operations that would load `asustor_it87`.
- Use `modprobe`; never use forced kernel-module removal. Remote privilege escalation is non-interactive (`sudo -n`) so it cannot unexpectedly wait for or transmit a password.
- Keep the backup on the operator's machine. `--reset` restores the recorded module loaded-state only when the host, kernel release, and DMI identity match.

Loading or unloading a hardware driver can affect GPIO-backed LEDs/buttons, fan monitoring, or cooling behavior and may destabilize the NAS. A module-state backup is not a firmware or data backup; reset is best-effort and cannot recover from a kernel crash or hardware damage. Do not perform these operations without a separate, tested NAS data backup and a recovery path.

### Ransomware findings

The DeadBolt audit and scan are narrow, versioned checks, not antivirus or incident response. File-name matches and portal strings are indicators to investigate. No matches, even with complete coverage, do not prove the NAS is clean. Do not use this tool as the only basis for remediation or restore decisions.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository when available. Do not include NAS passwords, private keys, public IPs, serial numbers, or unredacted incident artifacts in public issues.
