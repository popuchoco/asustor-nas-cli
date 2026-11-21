# CLI and report specification

## Global behavior

- Executable: `adm`; Python package: `asustor-nas-cli`; MCP server: `adm mcp`.
- Python 3.11+, standard-library runtime, OpenSSH client required for NAS connections.
- `--host` accepts an IP address or DNS hostname. `ASUSTOR_HOST` and `ASUSTOR_USER` provide defaults.
- SSH defaults to port 22; HTTPS defaults to 8001. `ASUSTOR_SSH_PORT`, `ASUSTOR_HTTPS_PORT`, `--port`, and `--https-port` can override them.
- SSH key path comes from `ASUSTOR_SSH_IDENTITY_FILE` or `--identity-file`.
- HTTPS validation is enabled by default. `--ca` selects a PEM CA file; `--insecure` disables validation for that request. The options are mutually exclusive.
- `--json` emits UTF-8 JSON for command results. Human output is for display and is not a stable parsing interface.
- `--compact-json` selects single-line JSON and implies `--json`; it is available on JSON-capable observation, comparison, and platform commands.
- `report render --input FILE` reads a local schema-v1 supported report (maximum 1 MB) and writes at most 2 MB of Markdown to stdout. `--input -` reads stdin. This offline command does not connect to a NAS, omits raw SSH `sections`, redacts path fields, host labels, IP/MAC addresses, and account/secret fields.
- `status`, `storage`, and `raid` accept `--summary` to add a structured `diagnostic-summary` while retaining the raw SSH section in `sections`. `raid` also accepts `--exit-on-warning` to return the summary's recommended code.
- `health --summary` adds structured system, storage, RAID, SMART, temperature, service-process, UPS, and TCP-state observations while retaining the raw sections. Service/process counts, UPS values, and connection counts do not create risk findings or affect the health exit-code policy. It also reports whether the raw network and disk-list sections were returned.
- `health --summary --temperature-warning-celsius C` changes the generic temperature advisory threshold (default `80`). It is not a model-specific safe-temperature limit or health verdict.
- `health --summary --exit-on-warning` returns `2` if a degraded RAID array, failed SMART state, or reading at/above the advisory temperature threshold is observed; otherwise it returns `1` for incomplete/unavailable coverage and `0` for complete observations without those signals. Without this option, successful collection returns `0` as before.
- Structured `diagnostic-summary` and `risk-signals` reports include an optional UTC `generated_at` timestamp for offline history comparisons.
- `report compare --before FILE --after FILE` compares schema-v1 structured summaries from the same NAS and report type. It reports risk-signal and summary-field changes, treats missing fields as not reobserved when the later report is incomplete, and never connects to the NAS.
- JSON and MCP outputs use the host label `NAS` and a stable `host_id` fingerprint instead of the configured address. IP/MAC addresses in SSH output and NAS account names in errors are redacted. SSH passwords and private-key contents are never returned or stored.

## Command catalog

| Command | Data source / side effect | JSON `report_type` or top-level `command` |
| --- | --- | --- |
| `probe` | HTTPS `/portal/`; read-only | `probe` |
| `doctor` | HTTPS + SSH observations; read-only | `doctor` |
| `status` | hostname, kernel, CPU, memory, uptime | `status` |
| `health` | System, storage, RAID, network, disk, allowlisted service, local NUT UPS, and TCP-state observations; read-only. With `--summary`, also structured SMART and thermal observations | `health` or `diagnostic-summary` |
| `storage` | `df -hP` | `storage` |
| `raid` | `/proc/mdstat` | `raid` |
| `network` | `ip -o link/addr` | `network` |
| `disks` | `smartctl --scan`; no SMART health | `disks` |
| `smart` | `smartctl -H -n standby`; health only, no self-test or drive wake-up | `smart-health`, schema v1 |
| `temperature` | Read `/sys/class/thermal/thermal_zone*/temp`; observations only, no threshold verdict | `temperature-observation`, schema v1 |
| `services` | Count exact names from a fixed `/proc/*/comm` allowlist; no arguments or raw process command lines | `service-observations`, schema v1 |
| `ups` | Query local NUT `upsc` for configured device count and the first device's standardized status/battery charge; names omitted, multiple devices yield partial coverage | `ups-observations`, schema v1 |
| `connections` | Count total, established, and listening TCP sockets from `/proc/net/tcp*`; addresses omitted | `connection-observations`, schema v1 |
| `disk-topology` | `/sys/block`, `/proc/mdstat`, `/proc/mounts` | `disk-topology`, schema v1 |
| `security audit` | ADM portal version + local TCP listeners + operator assertions | `security-audit`, schema v1 |
| `incident scan` | Bounded filename scan + ADM portal text | `incident-scan`, schema v1 |
| `security compare` | Two saved audit/scan reports | `comparison`, schema v1 |
| `report render` | Saved diagnostic, security, incident, platform, topology, SMART, temperature, observation, or comparison JSON; local and offline | Markdown text |
| `report compare` | Two saved diagnostic-summary or risk-signals reports; local and offline | `report-comparison`, schema v1 |
| `platform status` | Kernel, DMI, module state; read-only | `platform-status`, schema v1 |
| `platform module --load/--unload/--reset` | Fixed `modprobe` operations after compatibility gate | `platform-module-operation`, schema v1 |

`report render` accepts `diagnostic-summary`, `risk-signals`, `security-audit`, `incident-scan`, `platform-status`, `disk-topology`, `smart-health`, `temperature-observation`, `service-observations`, `ups-observations`, `connection-observations`, `comparison`, `report-comparison`, and `platform-module-operation`. It omits raw SSH `sections` and redacts paths so incident reports can be rendered without copying full NAS paths into Markdown.

The `diagnostic-summary` schema is versioned independently from the package release. Summary coverage describes the completeness of parsed observations. Missing SMART or temperature support is reported as incomplete/unavailable, not as a passing health check. Raw SSH sections remain available to support review of the derived summary.

The `health --summary` and `risk-signals` reports include service, UPS, and TCP observations under `summary.observations`. These are not entries in the `risk_signals` array and do not alter the summary state or health exit-code policy. Each observation records its own coverage.

### Summary state and coverage

`coverage` uses the same three values across diagnostic and risk-signals reports:

| Value | Meaning |
| --- | --- |
| `complete` | The command returned enough expected data for its parser checks to complete. This describes collection and parsing, not device health. |
| `partial` | Some values were usable, but expected output was missing, malformed, or limited. |
| `unavailable` | No usable observation was available from that source. |

The health summary's top-level coverage is complete only when all required component sources are complete. It is unavailable when all those sources are unavailable; mixed or partial source coverage produces partial. Service, UPS, and TCP observations expose their own coverage but do not change health summary coverage, state, or exit code. The optional raw network and disk-list sections are recorded separately under `additional_sections`.

`state` is report-specific. Status and storage summaries use `observed` only with complete coverage, otherwise `unknown`. Health and risk-signals summaries use `attention` when a configured RAID, SMART, or thermal signal is observed; otherwise they use `observed` for complete coverage or `unknown` for incomplete coverage. A RAID component has its own state (`degraded`, `unknown`, `observed`, or `no_arrays`); a well-formed `/proc/mdstat` response with no arrays is `no_arrays`, not proof of a healthy storage pool. SMART uses `passed`, `failed`, or `unknown`.

With `--exit-on-warning`, a detected signal takes precedence and returns `2`, including when other sources are incomplete. Without a signal, incomplete coverage returns `1`; complete observations without signals return `0`. These states and codes describe the collected observations only. `unknown`, `no_arrays`, or an empty risk-signal list must not be interpreted as a clean bill of health.

`disk-topology` records device model and size but excludes serial numbers and SMART health. Array state reflects the kernel's md status output, not a full filesystem or drive-health assessment.

The `firmware.deadbolt_patch` result is scoped to ASUSTOR advisory [AS-2022-008](https://www.asustor.com/en/security/security_advisory_detail?id=9). ADM 4.1+ and 5.x are not listed among that notice's affected branches, so the check reports them outside its scope. A pass does not mean the installed firmware is current or that other vulnerabilities are fixed; review the [current security advisories](https://www.asustor.com/en/security/security_advisory) and [ADM release notes](https://www.asustor.com/zh-tw/service/release_notes).

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
- `report-comparison.schema.json`
- `platform-status.schema.json`
- `platform-module-backup.schema.json`
- `platform-module-operation.schema.json`
- `smart-health.schema.json`
- `temperature-observation.schema.json`
- `service-observations.schema.json`
- `ups-observations.schema.json`
- `connection-observations.schema.json`
- `diagnostic-summary.schema.json`
- `risk-signals.schema.json`

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

Structured diagnostic summaries normally return `0` after successful collection. Only `raid --exit-on-warning` and `health --summary --exit-on-warning` opt into their `recommended_exit_code`: `2` for a detected finding, `1` for incomplete coverage without a finding, or `0` for complete coverage without a finding. Combine `health --summary --exit-on-warning --compact-json` for a one-line scheduled-job result plus a meaningful process exit code. The 80 °C default in `health --summary` is a generic advisory and may not match the NAS model or sensor type.

`adm smart` returns `0` only when every observed supported drive reports a passing SMART health status. It returns `2` when a drive reports a failed status and `1` when the tool, device, or coverage is unavailable or incomplete. The command never starts a SMART self-test.

`adm temperature` returns `0` when at least one generic thermal-zone reading is parsed completely. It returns `1` if readings are unavailable or incomplete. Values are converted from millidegrees Celsius as specified by the Linux thermal-zone sysfs interface; this command does not apply model-specific thresholds or report a thermal-health verdict.

## MCP interface

`adm mcp` implements JSON-RPC 2.0 over stdio and uses the same read-only observation functions. It advertises read-only tool annotations. Tools include `adm_status`, `adm_health`, `adm_health_summary`, `adm_risk_signals`, `adm_storage`, `adm_raid`, `adm_network`, `adm_disks`, `adm_smart`, `adm_temperature`, `adm_disk_topology`, `adm_platform_status`, `adm_security_audit`, `adm_security_compare`, and `adm_incident_scan`.

`adm_health_summary` returns the `diagnostic-summary` report and preserves its raw sections. `adm_risk_signals` returns the `risk-signals` schema with coverage and concise RAID, SMART, and thermal details, without raw sections. Both accept an optional `temperature_warning_celsius` number from 1 to 150; the default 80 °C value is a generic advisory, not a model-specific safe limit. Unknown or unavailable sensors do not count as healthy.

`adm_security_compare` accepts two JSON report objects (security audit or incident scan, schema version 1), enforces a 1 MB limit per report, and does not connect to the NAS or access local files. Its text output names new observations, status changes, and items not reobserved during incomplete scans; absence from a later report is not proof that a threat was cleared. `adm_smart` and `adm_temperature` use fixed read-only SSH commands. Temperature sensors may be unavailable on older kernels or models. Redacted synthetic report examples are in [`examples/reports/`](../examples/reports/README.md).

MCP configuration is supplied only through environment variables: `ASUSTOR_HOST`, `ASUSTOR_USER`, `ASUSTOR_SSH_PORT`, `ASUSTOR_HTTPS_PORT`, `ASUSTOR_TIMEOUT`, `ASUSTOR_SSH_IDENTITY_FILE`, `ASUSTOR_CA`, and `ASUSTOR_INSECURE`. MCP SSH uses batch mode; configure an SSH key/agent before launching the server. Mutating module operations are intentionally absent from MCP.
