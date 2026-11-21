# Architecture

## Runtime model

The `adm` executable runs on an operator workstation. It connects to ADM over HTTPS for portal checks and over OpenSSH for fixed shell queries. Python executes no code on the NAS itself. SSH commands are selected from the static allowlist in `commands.py`; user-supplied values are limited to validated host/account/port fields and bounded integer scan limits.

```text
adm CLI ── HTTPS ──> ADM portal
   │
   └────── SSH ────> fixed read-only shell queries ──> /proc, /sys, df, ip, smartctl
                       │
                       └── guarded module lifecycle actions (Linux compatibility gate only)

MCP stdio ──> same read-only query/report functions
```

MCP and ordinary inspection commands are read-only. MCP includes raw health observations, a structured health summary, and a concise risk-signals report. Kernel-module load/unload is available only through the explicit CLI module operation, never through MCP.

## Modules

| Module | Responsibility |
| --- | --- |
| `cli.py` | Command routing and top-level error handling |
| `cli_parser.py` | `adm` argument parsing and input validation |
| `cli_support.py` | Shared JSON output and redacted, read-only SSH sections |
| `cli_security.py` | DeadBolt audit, incident-scan, and report-comparison handlers |
| `cli_report.py` / `report_markdown.py` | Bounded offline rendering of structured reports; omits raw SSH sections |
| `cli_platform.py` | Guarded platform-module command flow |
| `cli_smart.py` | Read-only SMART health command handler |
| `cli_temperature.py` | Read-only thermal-zone temperature handler |
| `summaries.py` | Parse optional system, storage, RAID, SMART, and thermal observations into derived summaries and risk signals |
| `client.py` | HTTPS probe and OpenSSH transport; no password storage |
| `commands.py` | Fixed ADM/Linux query allowlist and section parser |
| `topology.py` | Parse `/sys/block`, `/proc/mdstat`, and `/proc/mounts` observations |
| `security/` | DeadBolt audit rules, bounded scan parser, report comparison, rendering |
| `platform.py` | Platform-driver preflight, module-state backup/validation, fixed load/unload plan |
| `smart_health.py` | Fixed SMART health command and privacy-preserving status parser |
| `temperature.py` | Fixed thermal-zone sysfs query and temperature observation parser |
| `mcp.py` | Dependency-free JSON-RPC/MCP stdio server using read-only functions |

## Guarded platform-module flow

1. Read kernel release, DMI vendor/product, and loaded states for the three managed modules plus the conflicting `it87` module. The parser accepts state fields only inside one complete status frame and rejects duplicate or invalid state markers.
2. Require Linux 6.1 or newer and a DMI pair in the explicit preflight allowlist. The driver still performs its own hardware probing after module load.
3. Resolve the fixed plan with `modprobe -n` dry-run calls; abort before confirmation and backup if module resolution fails.
4. Require `--confirm-risk`; unless `--force` is set, require the operator to type the exact action and masked host fingerprint.
5. For load/unload, write a non-overwriting JSON snapshot to the operator's local backup path before the remote change. For reset, verify the supplied snapshot matches host, kernel release, and DMI identity, then write a second snapshot of the current state.
6. Run only fixed `modprobe` operations over SSH. Privilege escalation uses `sudo -n`; a password prompt is never sent over the command channel. The module unload plan does not use `rmmod -f` or modprobe force options.
7. Read module state again and report whether it matches the requested target. If a partial operation fails, the local backup remains available for `--reset`.

The backup captures loaded/unloaded state only. It does not capture driver binaries, system data, firmware settings, LED values, fan PWM values, or sensor calibration. A reset is not a complete rollback and cannot promise hardware safety after a failed kernel-driver operation.

The local backup reader rejects malformed data and files over 1 MB before sending any module-change command.

## Design constraints

- No dynamic remote shell command assembled from arbitrary user input.
- No password or private key contents in reports.
- No serial numbers or SMART health in disk-topology output.
- Temperature reports contain generic thermal-zone IDs and values only; no model thresholds or health verdicts are inferred.
- Structured summaries retain their source sections and represent unavailable or malformed observations as incomplete; the configurable 80 °C health-summary threshold is a generic advisory, not a model-specific verdict.
- No writes through MCP.
- No claim of a clean infection scan from the absence of filename/portal indicators.
- `schema_version` changes only when a report's required structure or interpretation changes.
