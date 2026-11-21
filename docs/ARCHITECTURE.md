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

MCP and ordinary inspection commands are read-only. Kernel-module load/unload is available only through the explicit CLI module operation, never through MCP.

## Modules

| Module | Responsibility |
| --- | --- |
| `cli.py` | `adm` parser, validation, human/JSON output, exit status |
| `client.py` | HTTPS probe and OpenSSH transport; no password storage |
| `commands.py` | Fixed ADM/Linux query allowlist and section parser |
| `topology.py` | Parse `/sys/block`, `/proc/mdstat`, and `/proc/mounts` observations |
| `security/` | DeadBolt audit rules, bounded scan parser, report comparison, rendering |
| `platform.py` | Platform-driver preflight, module-state backup/validation, fixed load/unload plan |
| `mcp.py` | Dependency-free JSON-RPC/MCP stdio server using read-only functions |

## Guarded platform-module flow

1. Read kernel release, DMI vendor/product, and loaded states for the three managed modules plus the conflicting `it87` module.
2. Require Linux 6.1 or newer and a DMI pair in the explicit preflight allowlist. The driver still performs its own hardware probing after module load.
3. Resolve the fixed plan with `modprobe -n` dry-run calls; abort before confirmation and backup if module resolution fails.
4. Require `--confirm-risk`; unless `--force` is set, require the operator to type the exact action and masked host fingerprint.
5. For load/unload, write a non-overwriting JSON snapshot to the operator's local backup path before the remote change. For reset, verify the supplied snapshot matches host, kernel release, and DMI identity, then write a second snapshot of the current state.
6. Run only fixed `modprobe` operations over SSH. Privilege escalation uses `sudo -n`; a password prompt is never sent over the command channel. The module unload plan does not use `rmmod -f` or modprobe force options.
7. Read module state again and report whether it matches the requested target. If a partial operation fails, the local backup remains available for `--reset`.

The backup captures loaded/unloaded state only. It does not capture driver binaries, system data, firmware settings, LED values, fan PWM values, or sensor calibration. A reset is not a complete rollback and cannot promise hardware safety after a failed kernel-driver operation.

## Design constraints

- No dynamic remote shell command assembled from arbitrary user input.
- No password or private key contents in reports.
- No serial numbers or SMART health in disk-topology output.
- No writes through MCP.
- No claim of a clean infection scan from the absence of filename/portal indicators.
- `schema_version` changes only when a report's required structure or interpretation changes.
