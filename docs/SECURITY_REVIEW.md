# Security review

Review date: 2026-11-21

## Scope

This was a code-level review of SSH command construction, module-control confirmation and backup handling, report parsing, output privacy, MCP exposure, and release publication controls. It is not a penetration test or an independent security audit.

## Controls reviewed

- NAS host, account, port, and scan limits are validated before commands are formed. SSH is invoked without a local shell, and agent forwarding and port forwarding are disabled.
- Observation commands are fixed. The module path uses only the three managed module names and fixed load/unload order.
- Platform-operation output is parsed only inside one complete marker pair. Missing fields, duplicate fields, malformed module states, unsupported kernels, unknown DMI pairs, and conflicting modules fail closed.
- The post-operation status output includes kernel, DMI, and module markers so the same parser can verify the result.
- A module load/unload requires compatibility preflight, a successful `modprobe -n` plan, `--confirm-risk`, and a new local non-overwriting backup before remote mutation. `--force` skips only the interactive phrase.
- Reset checks the saved host fingerprint, SSH port, kernel release, and DMI identity and creates a second current-state snapshot before changing module state. Backup loading is capped at 1 MB.
- JSON and MCP outputs redact the configured NAS address and account names from errors. The source and commit history were checked for the NAS address and login material supplied during setup; none were present.
- MCP exposes read-only annotations and has no module-mutation tool. Its health-summary and risk-signals tools share the fixed read-only observation paths; report comparison accepts only bounded schema-version-1 security reports and does not connect to the NAS.
- Structured CLI summaries preserve raw source sections, surface incomplete coverage separately from detected findings, and require an explicit flag before their recommended nonzero exit codes affect scripting. The health summary's default 80 °C threshold is adjustable and described as a generic advisory.
- The AS-202TE live SMART check observed two devices with unknown health; the thermal-zone query found no sensors. Neither result was presented as a pass, and no SMART self-test was started.
- PyPI publication requires a separate manual workflow dispatch and OIDC Trusted Publisher configuration; repository secrets are not used for a long-lived PyPI token.

## Findings addressed

The reviewed post-operation parser previously required DMI fields that the module command did not emit, so a successful module change could be reported as incomplete. The result command now emits the DMI fields. The parser now ignores markers outside the framed response and rejects invalid module-state values. Local platform backup reads are bounded.

## Remaining limits

- No Linux 6.1+ ASUSTOR hardware was available. The DMI allowlist and module mutation path have not been live-validated; no module load/unload/reset was attempted.
- The AS-202TE/Linux 3.4 unit is intentionally refused for module changes.
- Loading a kernel driver can affect GPIO, LEDs, buttons, or fan behavior. The JSON backup restores managed module loaded-state only and cannot roll back firmware, data, a kernel crash, or hardware damage.
- Ransomware checks cover a narrow DeadBolt baseline and filename/portal indicators. They do not inspect file contents or prove the NAS is clean.
- The standalone temperature command returns observations only. `health --summary` may flag readings at a configurable generic threshold (80 °C by default), which is not a model-specific health verdict.
- Cross-platform CI exercises packaging and unit behavior; it does not establish live NAS compatibility on each workstation operating system.
