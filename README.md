# ASUSTOR NAS CLI

[![CI](https://github.com/popuchoco/asustor-nas-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/popuchoco/asustor-nas-cli/actions/workflows/ci.yml)

Safety-first Python CLI for ASUSTOR ADM NAS diagnostics, disk topology, DeadBolt ransomware checks, and guarded platform-driver module management. The command is named `adm`, after ASUSTOR's operating system.

[繁體中文](README.zh-TW.md) · [Command specification](docs/CLI_SPEC.md) · [Compatibility notes](docs/COMPATIBILITY.md) · [Troubleshooting](docs/TROUBLESHOOTING.md) · [Cookbook](docs/COOKBOOK.md) · [Report examples](examples/reports/README.md) · [Security](SECURITY.md) · [Research and licenses](docs/RESEARCH_AND_LICENSES.md)

## What it does

- Runs fixed, read-only SSH commands for ADM system, storage, RAID, network, and disk observations.
- Reads SMART health status without starting self-tests; standby drives are left unqueried.
- Reads available Linux thermal-zone temperatures as observations, without applying model-specific health thresholds.
- Maps physical disks, partitions, Linux software RAID arrays, and `/volumeN` mounts through `/sys` and `/proc`.
- Audits a DeadBolt prevention baseline, scans a bounded set of filenames and ADM portal text for known indicators, and compares saved JSON reports.
- Checks whether the host meets the kernel and hardware requirements for `asustor-platform-driver`; on supported Linux hosts, it can load or unload that driver family after creating a local state backup and completing explicit confirmation.
- Offers a dependency-free, read-only MCP server over stdio, including structured health summaries and a concise risk-signals tool.

This project is an operations aid. It does not read file contents for malware, verify backup integrity, determine whether services are exposed through a router, or prove that a NAS is clean.

## Install

Requirements: Python 3.10 or newer and the operating system's OpenSSH client. Runtime code uses only the Python standard library.

```console
python -m pip install .
adm --help
```

For isolated installs, use `pipx install asustor-nas-cli` after the package is published. Windows PowerShell and offline wheel instructions are in [publishing and installation](docs/PUBLISHING.md).

For local development without installing:

```powershell
$env:PYTHONPATH = '.\src'
python -m asustor_nas_cli --help
```

## Quick start

```powershell
$env:ASUSTOR_HOST = 'nas.example'
$env:ASUSTOR_USER = 'nas-user'
adm probe --insecure --json
adm health --json
adm disk-topology --json
```

SSH normally uses port 22; ADM HTTPS uses port 8001. Set `ASUSTOR_SSH_PORT` or `ASUSTOR_HTTPS_PORT`, or pass `--port` / `--https-port`. For key authentication, set `ASUSTOR_SSH_IDENTITY_FILE` or pass `--identity-file`. The CLI does not store SSH passwords. Password login requires an interactive terminal; MCP uses OpenSSH batch mode and therefore needs a working key or agent.

The sample NAS has a self-signed HTTPS certificate. `--insecure` skips certificate verification for that request and the report records the unverified state. Prefer a trusted certificate or `--ca FILE.pem` for routine use. `--ca` and `--insecure` cannot be combined.

## Privacy defaults

CLI JSON and MCP responses label the device as `NAS` and include a stable `host_id` fingerprint for report comparison; they do not emit the configured host address. IP/MAC addresses in SSH output and NAS account names in error text are redacted. The client never accepts, displays, or stores a NAS password or private-key content. Treat incident file paths and DMI model identifiers as operational data when sharing reports.

## Commands

| Command | Purpose |
| --- | --- |
| `adm probe` | Check the ADM HTTPS portal and certificate |
| `adm doctor` | Probe HTTPS and collect SSH diagnostics |
| `adm status --summary`, `health --summary`, `storage --summary`, `raid --summary` | Add structured summaries while retaining raw sections |
| `adm status`, `health`, `storage`, `raid`, `network`, `disks` | Read ADM and Linux observations |
| `adm disk-topology` | Map disks, partitions, md arrays, and volumes |
| `adm smart` | Read SMART health status without starting self-tests |
| `adm temperature` | Read available thermal-zone temperatures; no health thresholds are applied |
| `adm security audit` | Review the DeadBolt prevention baseline |
| `adm incident scan` | Search volume filenames and portal text for bounded DeadBolt indicators |
| `adm security compare` | Compare two compatible audit or scan JSON reports |
| `adm platform status` | Read kernel, DMI, and platform-driver module state |
| `adm platform module --load/--unload/--reset` | Guarded module lifecycle control on verified compatible Linux hosts |
| `adm mcp` | Serve read-only MCP tools over stdio |

All NAS observation commands support `--json`. JSON reports use `schema_version: 1`; supported report schemas are in [`schemas/`](schemas/). Command exit codes are documented in the [CLI specification](docs/CLI_SPEC.md).

`--summary` adds a versioned `diagnostic-summary` JSON report and keeps the original command output in `sections`. `adm health --summary` also collects SMART and thermal-zone observations. Its default temperature warning is a generic, adjustable 80 °C advisory; sensor IDs do not identify a component, so this is not a model-specific thermal-health verdict. `--exit-on-warning` opts into the summary's recommended code: `2` for detected RAID/SMART/temperature findings, `1` for incomplete coverage, and `0` for complete observations without findings.

`adm smart` runs only `smartctl -H -n standby` for supported block-device names. It does not start SMART self-tests or include disk serials/attributes; sleeping drives may be reported as unknown. A live read-only smoke on the AS-202TE saw two supported devices, both with unknown health and partial coverage, so it does not establish drive health.

`adm temperature` reads `/sys/class/thermal/thermal_zone*/temp`, a read-only Linux thermal-zone interface whose values are reported in millidegrees Celsius. It exposes only generic zone IDs and Celsius values. Sensor coverage varies by model and kernel; the AS-202TE smoke found no available thermal-zone sensors. This command alone applies no thresholds.

See the [daily inspection and incident-response cookbook](docs/COOKBOOK.md) for an end-to-end example.

## DeadBolt prevention and detection

`adm security audit` checks the ADM version against ASUSTOR's AS-2022-008 DeadBolt advisory, inspects the local TCP listener list, and looks for limited DeadBolt-related strings in the ADM portal. The advisory lists ADM 3.5 and 4.0 as affected; a pass for ADM 4.1+ or 5.x means only that those branches are outside this notice's affected list. It does not mean the NAS is fully patched or current; review [current ASUSTOR advisories](https://www.asustor.com/en/security/security_advisory) and [ADM release notes](https://www.asustor.com/zh-tw/service/release_notes). Backup readiness, password strength, EZ-Connect, and router exposure remain unknown until an operator confirms them; confirmation flags record operator assertions, not automatic verification.

`adm incident scan` searches filenames ending in `.deadbolt` on `/volumeN` mounts and checks limited portal text. It does not inspect file contents, quarantine or delete files, or stop services. The search has configurable limits (`--max-seconds` and `--max-hits`). It discovers `find`, `timeout`, and `awk` through `PATH` and checks `find -xdev` support before starting; if a required bounded-scan capability is missing, the report marks file coverage unavailable. An incomplete scan stays incomplete, and a missing indicator is not proof that the NAS is uninfected.

```powershell
adm security audit --host nas.example --user nas-user --insecure --json > audit-before.json
adm incident scan --host nas.example --user nas-user --insecure --json > scan-before.json
# Save later reports, then compare like with like:
adm security compare --before scan-before.json --after scan-after.json
```

The checks are based on ASUSTOR's [DeadBolt advisory](https://www.asustor.com/en/security/security_advisory_detail?id=9), [ADM release notes](https://www.asustor.com/zh-tw/service/release_notes), and [prevention guidance](https://www.asustor.com/zh-tw/knowledge/detail/?group_id=628&id=6). The current rule set is intentionally narrow and versioned as `asustor-deadbolt-v1`.

## Platform-driver module controls

The [platform driver](https://github.com/mafredri/asustor-platform-driver) can expose GPIO-backed LEDs and buttons; its optional IT87 module can expose fan PWM controls. Incorrect GPIO mappings can destabilize a system or damage hardware. This CLI therefore checks the running kernel and exact DMI vendor/product pair before permitting a module operation. The driver project documents Linux 6.1 and newer as its supported kernel floor, and its compatibility list does not include AS-202TE. The AS-202TE test unit runs Linux 3.4, so this CLI reports it as unsupported and refuses module changes.

Module changes are disabled unless all these conditions hold:

1. The NAS reports Linux 6.1 or newer.
2. Its DMI vendor/product pair is in the verified allowlist documented in [compatibility](docs/COMPATIBILITY.md).
3. The conflicting `it87` module is not loaded when the operation needs `asustor_it87`.
4. The operator supplies `--confirm-risk` and a local backup path.
5. `modprobe -n` resolves the fixed module plan without changing module state.
6. The normal path also requires typing the exact action and masked NAS fingerprint at a prompt.

Example load and rollback:

```console
adm platform status --host NAS-IP --user nas-user
adm platform module --load --host NAS-IP --user nas-user \
  --backup ./platform-before.json --confirm-risk
adm platform module --reset --host NAS-IP --user nas-user \
  --backup ./platform-before.json --confirm-risk
```

Before loading or unloading, the CLI writes a non-overwriting local JSON backup of the three managed modules' loaded/unloaded state. `--reset` restores that state only when host, kernel release, and DMI identity still match. Before reset, it also creates a snapshot of the current state at `<backup>.before-reset.json` (customize with `--rollback-backup`) so a later reset can reverse that operation. The backup does not include module binaries, NAS data, firmware settings, LED brightness, or fan PWM values; reset is a best-effort module-state restore, not a full system rollback. The CLI does not install/build kernel modules or write LED/fan sysfs values.

Advanced automation may add `--force` to skip the interactive second confirmation. It still requires `--confirm-risk`, a valid backup (or existing matching backup for `--reset`), and all compatibility checks. `--force` never maps to the kernel's forced module-unload option.

## Read-only MCP server

Configure your MCP client to launch `adm mcp` and provide its environment:

```json
{
  "mcpServers": {
    "asustor": {
      "command": "adm",
      "args": ["mcp"],
      "env": {
        "ASUSTOR_HOST": "nas.example",
        "ASUSTOR_USER": "nas-user",
        "ASUSTOR_SSH_IDENTITY_FILE": "/path/to/id_ed25519",
        "ASUSTOR_HTTPS_PORT": "8001"
      }
    }
  }
}
```

The server requires SSH key/agent authentication, uses fixed SSH commands, and exposes read-only tools only. `adm_health_summary` returns structured health fields with raw sections, while `adm_risk_signals` returns coverage and notable RAID, SMART, and temperature signals without raw sections. The configurable temperature value is a generic advisory. `adm_security_compare` compares two report objects without connecting to the NAS. `adm_platform_status` is read-only; module load, unload, and reset are not available over MCP. See [MCP and JSON interface details](docs/CLI_SPEC.md#mcp-interface) and [example reports](examples/reports/README.md).

## Project design and contribution

The CLI follows the product conventions of [synology-nas-cli](https://github.com/akari-sora/synology-nas-cli) and [qnap-nas-cli](https://github.com/popuchoco/qnap-nas-cli): OS-named command, structured reports, MCP, explicit safety boundaries, compatibility notes, and reusable docs. The [reference review](docs/REFERENCE_REVIEW.md) explains what was adopted and what was excluded from the three ASUSTOR projects.

See [architecture](docs/ARCHITECTURE.md), [troubleshooting](docs/TROUBLESHOOTING.md), [cookbook](docs/COOKBOOK.md), [release checklist](docs/RELEASE_CHECKLIST.md), [security review](docs/SECURITY_REVIEW.md), [contributing](CONTRIBUTING.md), [publishing and installation](docs/PUBLISHING.md), [change log](CHANGELOG.md), and [security policy](SECURITY.md).

## License and trademarks

This project's original code and documentation are licensed under MIT; see [LICENSE](LICENSE). Research sources and the license review are recorded in [Research and licenses](docs/RESEARCH_AND_LICENSES.md), with design decisions in the [reference review](docs/REFERENCE_REVIEW.md).

This is an independent community project. It is not affiliated with, endorsed by, or sponsored by ASUSTOR Inc. ASUSTOR, ADM, and ASUSTOR product and model names are trademarks of their respective rights holders.
