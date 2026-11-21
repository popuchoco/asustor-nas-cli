# Changelog

## 1.9.0 — 2026-11-21

- Add a platform installation guide for Windows, macOS, and Ubuntu using the reviewed GitHub source tag and isolated `pipx` environments; do not imply that PyPI publication has occurred.
- Add CI wheel/sdist build validation, artifact retention, and an installed-wheel CLI smoke test; require the release workflow's installed `adm --version` to match the pushed tag.
- Standardize readable diagnostic-summary text fields and make empty risk-signal output explicit; clarify report-specific `state`, shared `coverage`, and exit-code semantics.
- Improve storage-summary parsing for case-insensitive `df` headers, mount points with spaces, and impossible usage percentages; malformed rows now stay out of schema-bound values and mark coverage partial.
- Refine read-only MCP summary tool descriptions and add concrete anomaly interpretation examples to the cookbook and troubleshooting guide.

## 1.8.0 — 2026-11-21

- Raise the supported Python minimum to 3.11 after Python 3.10 reached end of life; test Python 3.11–3.14 in CI and build release distributions on 3.14.
- Add weekly Dependabot checks for GitHub Actions and Python package metadata; the existing action versions and optional test-dependency constraint were already current at review time.
- Keep compatibility claims tied to available AS-202TE evidence. No additional live-device fixture or Linux 6.1+ test was added.

## 1.7.0 — 2026-11-21

- Expand offline Markdown rendering to security audits, incident scans, platform status, topology, SMART, temperature, observations, comparisons, and module-operation reports; raw SSH sections and path fields are omitted or redacted.
- Add `--compact-json` to JSON-capable commands. It implies `--json` and emits one line for scripts and scheduled jobs.
- Document a cron-friendly health workflow that combines compact JSON with the existing opt-in health exit-code policy.

## 1.6.0 — 2026-11-21

- Add allowlisted `adm services`, local NUT `adm ups`, and address-free TCP `adm connections` observations.
- Include those observations in health-summary and risk-signals reports without using them as health findings or changing the exit-code policy.
- Record read-only AS-202TE smoke results for service-process counts, UPS availability, and TCP state counts; retain only redacted normalized values.

## 1.5.0 — 2026-11-21

- Add offline `adm report compare` for diagnostic-summary and risk-signals history, including changed risk signals and structured fields.
- Mark missing observations as not reobserved when the later report has incomplete coverage; require matching host fingerprints and report types.
- Add UTC `generated_at` metadata and publish the `report-comparison` schema and daily comparison cookbook.
- Remove the design-only project inventory and references from the README; keep research/license records limited to software and sources used by implemented behavior or workflows.

## 1.4.0 — 2026-11-21

- Add `adm report render` for offline Markdown export of schema-v1 diagnostic-summary and risk-signals reports, with 1 MB input and 2 MB output caps plus stdin support.
- Omit raw SSH sections and redact host labels, IP/MAC addresses, and account/secret-named fields in the rendered output.
- Document daily health-report export and add tests for unsupported, malformed, oversized, and Markdown-injection inputs.

## 1.3.0 — 2026-11-21

- Make the DeadBolt firmware check explicit for ADM 4.1+ and 5.x; a pass means outside the affected list for AS-2022-008 only, not a current-security verdict.
- Add branch-coverage tests for ADM 4.0, 4.1–4.3, and 5.x, while keeping unknown build identifiers unranked.
- Add SSH timeout, login, SMART permission, and module-privilege troubleshooting guidance.
- Update artifact workflow actions and pin the optional PyPI publisher to its current release; record only the workflow actions actually used in the license inventory.
- No additional live NAS fixture was available; the Linux 6.1+ path remains an accepted, unvalidated limitation.

## 1.2.0 — 2026-11-21

- Add read-only MCP tools for structured health summaries and concise RAID/SMART/temperature risk signals.
- Highlight newly observed, changed, and not-reobserved findings in human-readable offline report comparisons.
- Publish synthetic, redacted health-summary and risk-signal JSON examples and validate them against their schemas.
- Keep failed SMART devices distinct from devices with unknown status in derived health summaries.

## 1.1.0 — 2026-11-21

- Add optional structured summaries for status, health, storage, and RAID while preserving the raw diagnostic sections.
- Add explicit degraded RAID, failed/unknown SMART device, and generic thermal-warning observations with opt-in summary exit codes.
- Live-smoke SMART and thermal-zone reads on the AS-202TE; record the unknown SMART states and unavailable thermal sensors in the redacted reviewed profile.
- Add daily inspection and read-only incident-response examples.
- Limit the research/license record to software and technical sources actually used by this project.

## 1.0.0 — 2026-11-21

- Harden platform-status parsing by limiting fields to complete marker frames and rejecting malformed module states, non-text output, and extreme kernel-version values.
- Include kernel and DMI markers in post-operation verification so guarded module changes can be accurately reported.
- Limit local module-backup input to 1 MB and reject oversized, malformed, or unsupported backup data.
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
