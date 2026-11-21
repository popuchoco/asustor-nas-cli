# Changelog

## 1.0.0 — 2026-11-21

- Harden platform-status parsing by limiting fields to complete marker frames and rejecting malformed module states, non-text output, and extreme kernel-version values.
- Include kernel and DMI markers in post-operation verification so guarded module changes can be accurately reported.
- Limit local module-backup input to 1 MB and reject oversized or deeply nested JSON.
- Add Windows/macOS package-install CI, troubleshooting guidance, a security review, and a release checklist.
- Remove the standalone compatibility section from both READMEs; add license, research-source, trademark, and non-affiliation links and notices.
- Keep the Linux 6.1+ live hardware test out of scope because no such ASUSTOR unit is available; the DMI allowlist remains unvalidated on a live device.

## 0.6.0 — 2026-11-21

- Add `adm temperature` for read-only Linux thermal-zone temperature observations; no model-specific thresholds or health verdicts are applied.
- Add MCP tools for SMART health, temperature observations, and offline comparison of bounded security-report objects.
- Add the temperature observation JSON Schema, schema coverage, and shell-command checks.
- Add reproducible wheel/sdist build checks and an opt-in PyPI Trusted Publisher workflow with installation guidance.
- State explicitly that temperature and SMART commands have not been live-tested on the AS-202TE.

## 0.5.0 — 2026-11-21

- Add `adm smart` for read-only SMART health status; no self-tests are started and standby drives are skipped.
- Add JSON Schema validation tests for every published report schema using the optional `test` dependency extra.
- Add the first `smart-health` JSON Schema and document the absence of Linux 6.1+ live hardware.

## 0.4.0 — 2026-11-21

- Add GitHub Actions CI for Python 3.10–3.13 and Ruff linting.
- Derive package metadata and HTTPS User-Agent from one version value; apply `--timeout` to SSH connection setup.
- Split argument parsing, shared helpers, platform controls, and security handlers out of `cli.py`.
- Add malformed/partial marker, SSH timeout, scan-tool capability, backup-conflict, and reviewed AS-202TE profile coverage.
- Discover scan tools through `PATH` and fail closed with a specific coverage reason if bounded volume scanning is unsupported.

## 0.3.0 — 2026-11-21

- Split DeadBolt audit, scan, comparison, and rendering into a dedicated `security` package.
- Add read-only physical disk, partition, RAID, and volume topology reporting.
- Add stdio MCP tools for read-only ADM diagnostics, disk topology, platform status, and DeadBolt checks.
- Add guarded platform-driver module status/load/unload/reset commands with local loaded-state backup, explicit risk acknowledgement, and interactive confirmation. AS-202TE/Linux 3.4.26 is intentionally refused for mutation.
- Add bilingual product README, architecture/compatibility/security/CLI/reference docs, report schemas, and MIT license.
