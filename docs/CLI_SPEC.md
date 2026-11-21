# CLI and report specification

## Global behavior

- Executable: `adm`; Python package: `asustor-nas-cli`; MCP server: `adm mcp`.
- Python 3.10+, standard-library runtime, OpenSSH client required for NAS connections.
- `--host` accepts an IP address or DNS hostname. `ASUSTOR_HOST` and `ASUSTOR_USER` provide defaults.
- SSH defaults to port 22; HTTPS defaults to 8001. `ASUSTOR_SSH_PORT`, `ASUSTOR_HTTPS_PORT`, `--port`, and `--https-port` can override them.
- SSH key path comes from `ASUSTOR_SSH_IDENTITY_FILE` or `--identity-file`.
- HTTPS validation is enabled by default. `--ca` selects a PEM CA file; `--insecure` disables validation for that request. The options are mutually exclusive.
- `--json` emits UTF-8 JSON for command results. Human output is for display and is not a stable parsing interface.
- JSON and MCP outputs use the host label `NAS` and a stable `host_id` fingerprint instead of the configured address. IP/MAC addresses in SSH output and NAS account names in errors are redacted. SSH passwords and private-key contents are never returned or stored.

## Command catalog

| Command | Data source / side effect | JSON `report_type` or top-level `command` |
| --- | --- | --- |
| `probe` | HTTPS `/portal/`; read-only | `probe` |
| `doctor` | HTTPS + SSH observations; read-only | `doctor` |
| `status` | hostname, kernel, CPU, memory, uptime | `status` |
| `health` | System, storage, RAID, network, smartctl device list; read-only | `health` |
| `storage` | `df -hP` | `storage` |
| `raid` | `/proc/mdstat` | `raid` |
| `network` | `ip -o link/addr` | `network` |
| `disks` | `smartctl --scan`; no SMART health | `disks` |
| `smart` | `smartctl -H -n standby`; health only, no self-test or drive wake-up | `smart-health`, schema v1 |
| `temperature` | Read `/sys/class/thermal/thermal_zone*/temp`; observations only, no threshold verdict | `temperature-observation`, schema v1 |
| `disk-topology` | `/sys/block`, `/proc/mdstat`, `/proc/mounts` | `disk-topology`, schema v1 |
| `security audit` | ADM portal version + local TCP listeners + operator assertions | `security-audit`, schema v1 |
| `incident scan` | Bounded filename scan + ADM portal text | `incident-scan`, schema v1 |
| `security compare` | Two saved audit/scan reports | `comparison`, schema v1 |
| `platform status` | Kernel, DMI, module state; read-only | `platform-status`, schema v1 |
| `platform module --load/--unload/--reset` | Fixed `modprobe` operations after compatibility gate | `platform-module-operation`, schema v1 |

`disk-topology` records device model and size but excludes serial numbers and SMART health. Array state reflects the kernel's md status output, not a full filesystem or drive-health assessment.

## Platform-module safety contract

Commands:

```text
adm platform status [SSH options] [--json]
adm platform module --load   --backup FILE --confirm-risk [--force] [SSH options]
adm platform module --unload --backup FILE --confirm-risk [--force] [SSH options]
adm platform module --reset  --backup FILE --confirm-risk [--force] [SSH options]
```

- `--load` loads the fixed driver stack in dependency order: `asustor_gpio_it87`, `asustor_it87`, `asustor`.
- `--unload` removes those modules in dependency order: `asustor`, `asustor_it87`, `asustor_gpio_it87`.
- Before load/unload, `--backup FILE` must name a new local path. Existing files are never overwritten. The CLI snapshots managed module states, host, SSH port, kernel release, and DMI identity before the remote change.
- `--reset` reads a prior backup and restores only the recorded loaded/unloaded states. Host, kernel release and DMI identity must still match. Before reset, a second snapshot of the current state is created at `<backup>.before-reset.json` (or the path supplied with `--rollback-backup`); an existing file there blocks the reset rather than being overwritten.
- Reset backup input is capped at 1 MB; malformed or oversized files are rejected before any remote module operation.
- All operations need `--confirm-risk`. Without `--force`, the operator must type `LOAD NAS <host_id>`, `UNLOAD NAS <host_id>`, or `RESET NAS <host_id>` exactly. `--force` skips that prompt only.
- Before confirmation and backup, `modprobe -n` must resolve the fixed module plan; this dry-run makes no module changes.
- Operations require Linux >= 6.1, a DMI allowlist match and no conflicting `it87` module when `asustor_it87` needs to be loaded. The operating account must be root or have non-interactive `sudo -n` access.
- The tool does not install/build modules, alter boot configuration, write LED or fan sysfs settings, or use forced module-unload flags.
- The backup contains module loaded-state only. It is not a full system snapshot or hardware-state rollback.

## JSON schemas

Schemas use JSON Schema Draft 2020-12 and are published under [`schemas/`](../schemas/):

- `disk-topology.schema.json`
- `security-audit.schema.json`
- `incident-scan.schema.json`
- `comparison.schema.json`
- `platform-status.schema.json`
- `platform-module-backup.schema.json`
- `platform-module-operation.schema.json`
- `smart-health.schema.json`
- `temperature-observation.schema.json`

For each schema version, required field meaning is stable. Parsers should ignore unknown optional fields. `schema_version` is an integer, not the CLI package version.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Command completed; for an incident scan, no indicator was observed and both coverage areas were complete |
| `1` | Connection/configuration/input error, incomplete general observation, unsupported platform-module operation, or requested module state did not match |
| `2` | Security audit found a failing check, or incident scan observed one or more indicators |
| `3` | Incident scan is incomplete and did not report an indicator |
| `4` | Reserved for user cancellation in future; current declined confirmation returns `1` |

Warnings and unknown audit checks return `1`. Disk topology returns `1` when an md array reports degraded membership. `health` returning `0` means its observation commands ran; it does not mean hardware is healthy.

`adm smart` returns `0` only when every observed supported drive reports a passing SMART health status. It returns `2` when a drive reports a failed status and `1` when the tool, device, or coverage is unavailable or incomplete. The command never starts a SMART self-test.

`adm temperature` returns `0` when at least one generic thermal-zone reading is parsed completely. It returns `1` if readings are unavailable or incomplete. Values are converted from millidegrees Celsius as specified by the Linux thermal-zone sysfs interface; this command does not apply model-specific thresholds or report a thermal-health verdict.

## MCP interface

`adm mcp` implements JSON-RPC 2.0 over stdio and uses the same read-only observation functions. It advertises read-only tool annotations. Tools include `adm_status`, `adm_health`, `adm_storage`, `adm_raid`, `adm_network`, `adm_disks`, `adm_smart`, `adm_temperature`, `adm_disk_topology`, `adm_platform_status`, `adm_security_audit`, `adm_security_compare`, and `adm_incident_scan`.

`adm_security_compare` accepts two JSON report objects (security audit or incident scan, schema version 1), enforces a 1 MB limit per report, and does not connect to the NAS or access local files. `adm_smart` and `adm_temperature` use fixed read-only SSH commands. Temperature sensors may be unavailable on older kernels or models.

MCP configuration is supplied only through environment variables: `ASUSTOR_HOST`, `ASUSTOR_USER`, `ASUSTOR_SSH_PORT`, `ASUSTOR_HTTPS_PORT`, `ASUSTOR_TIMEOUT`, `ASUSTOR_SSH_IDENTITY_FILE`, `ASUSTOR_CA`, and `ASUSTOR_INSECURE`. MCP SSH uses batch mode; configure an SSH key/agent before launching the server. Mutating module operations are intentionally absent from MCP.
