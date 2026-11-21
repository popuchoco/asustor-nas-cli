# Changelog

## 0.3.0 — 2026-11-21

- Split DeadBolt audit, scan, comparison, and rendering into a dedicated `security` package.
- Add read-only physical disk, partition, RAID, and volume topology reporting.
- Add stdio MCP tools for read-only ADM diagnostics, disk topology, platform status, and DeadBolt checks.
- Add guarded platform-driver module status/load/unload/reset commands with local loaded-state backup, explicit risk acknowledgement, and interactive confirmation. AS-202TE/Linux 3.4.26 is intentionally refused for mutation.
- Add bilingual product README, architecture/compatibility/security/CLI/reference docs, report schemas, and MIT license.
