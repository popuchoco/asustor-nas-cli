# Troubleshooting

## SSH connection and authentication

Confirm the system OpenSSH client is installed and available as `ssh` on `PATH`:

```console
ssh -V
```

For interactive CLI use, OpenSSH may ask for the NAS account password in the terminal. The CLI does not accept a password argument. MCP runs SSH in batch mode, so configure an identity file or ssh-agent before starting the MCP server.

If SSH reports a host-key mismatch, verify the NAS identity through a trusted channel first. After confirming that the key change is expected, remove the old entry with `ssh-keygen -R NAS-HOST` and connect again to review the new fingerprint. Do not disable host-key checking to work around a mismatch.

Set connection options with `ASUSTOR_HOST`, `ASUSTOR_USER`, `ASUSTOR_SSH_PORT`, and `ASUSTOR_SSH_IDENTITY_FILE`, or pass the equivalent CLI options.

To isolate SSH reachability and authentication, test the same host, port, and account directly:

```console
ssh -vvv -o ConnectTimeout=8 -p 22 nas-user@nas.example
```

Keep host-key checking enabled. If the CLI reports a connection timeout, first confirm that the NAS is reachable on the selected port and that the workstation firewall or network path permits it. Increase `--timeout` for slow links, for example `adm status --host nas.example --user nas-user --timeout 20`; it controls the CLI's SSH connection and command timeout. Confirm any changed fingerprint through a trusted channel before updating the local known-hosts entry.

`Permission denied` usually means the account, key/agent, or NAS SSH access policy does not permit login. Confirm the account can open an SSH shell and that the configured identity belongs to that account. MCP cannot answer password prompts; it needs a working key or agent. Ordinary observations use fixed read-only commands, but SMART results can be partial if the account cannot run `smartctl` against the device.

## HTTPS certificate errors

Certificate validation is enabled by default. Install a certificate chain trusted by the workstation or pass its CA bundle with `--ca FILE.pem`. The `--insecure` option disables validation for that request and is intended only for a known test device. Do not use `--ca` and `--insecure` together.

## Incomplete or unavailable observations

A `partial` or `unavailable` coverage state means the CLI could not collect or parse all expected observations. Check NAS reachability, SSH privileges, available ADM/Linux tools, and the command-specific scope. Do not interpret missing data as a healthy result.

- `adm temperature` uses generic Linux thermal-zone entries. Older ADM kernels or hardware may not expose them; this is reported as unavailable.
- `adm smart` needs `smartctl` and supported block-device names. Standby drives are deliberately not woken and can remain unknown.
- `adm incident scan` requires a bounded scan environment with `find -xdev`, `timeout`, and `awk`. If those capabilities are missing, file coverage is unavailable rather than clean.
- `adm health` reports command output. It does not turn every observation into a hardware-health verdict.
- `adm health --summary` also needs SMART and thermal commands. A missing tool or unreadable sensor is recorded as incomplete/unavailable; check the report's coverage before treating a summary as complete.

## Platform-module control is blocked

The module commands are allowed only when the reported kernel is Linux 6.1 or newer, the exact DMI vendor/product pair is allowlisted, no conflicting `it87` module blocks the requested load, and the fixed `modprobe -n` plan succeeds.

The NAS account must be root or have non-interactive `sudo -n` access. Supply a new local `--backup` path for load/unload. For reset, use the matching backup from the same host, kernel, and DMI identity; the CLI also creates a current-state rollback snapshot before applying reset. An existing backup path blocks the operation.

If the error says privilege escalation is unavailable, verify `sudo -n` directly for the NAS account. The CLI will not send a sudo password or switch to an interactive root prompt. Module controls require this access; ordinary read-only queries do not use the module-control path.

`--force` skips only the interactive phrase prompt. It does not bypass `--confirm-risk`, backup creation, compatibility checks, dry-run checks, or privilege requirements. The AS-202TE test unit uses Linux 3.4, and no Linux 6.1+ ASUSTOR unit was available for live validation. Do not weaken the compatibility gate to work around a refusal.

## Sharing reports and support requests

Before sharing output, review it for file paths, DMI model identifiers, IP addresses, account names, serial numbers, and other environment details. Never attach passwords, private keys, module backups, or unredacted incident artifacts to a public issue. Follow the reporting instructions in [SECURITY.md](../SECURITY.md).
