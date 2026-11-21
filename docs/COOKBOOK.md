# Daily inspection and incident response

This cookbook uses placeholder host and account values. Keep NAS addresses and login details out of committed examples. Reports can contain storage mount points and incident file paths, so review access before sharing them.

## Daily read-only inspection

Collect a structured health summary and preserve the raw system, storage, RAID, network, and disk-list sections in the same report:

```powershell
adm health --host nas.example --user nas-user --summary --json > .\health.json
$healthExitCode = $LASTEXITCODE
```

The ordinary health command returns `0` when collection succeeds. To make detected findings or incomplete coverage visible to scripts, opt in to the summary exit policy:

```powershell
adm health --host nas.example --user nas-user --summary --exit-on-warning --json > .\health.json
$healthExitCode = $LASTEXITCODE
```

For a scheduled job that expects one line of JSON, use `--compact-json`; it enables JSON output automatically:

```powershell
adm health --host nas.example --user nas-user --summary --exit-on-warning --compact-json > .\health.jsonl
$healthExitCode = $LASTEXITCODE
```

Interpret the result as follows:

- `0`: all included observations were complete and no configured risk signal was found.
- `1`: at least one required health source was incomplete or unavailable. Unknown SMART states and unavailable temperature sensors do not count as healthy. Optional service, UPS, and connection observations report their own coverage without changing this code.
- `2`: a degraded RAID array, failed SMART health state, or thermal-zone reading at/above the advisory threshold was observed.

The default temperature advisory is 80 °C and can be adjusted with `--temperature-warning-celsius`. Sensor IDs are generic Linux zone names; they do not identify a component, and the threshold is not a model-specific safety limit. Review raw sections and verify any warning with the NAS vendor's guidance.

### Interpreting common observations

| Example | What the report says | Follow-up |
| --- | --- | --- |
| `coverage=partial`, no risk signals, exit code `1` | At least one required source was missing, malformed, or limited; no configured signal was observed in the available data. | Inspect the component coverage and raw sections, then repeat the relevant read-only command. Do not treat the empty signal list as an all-clear. |
| `raid.state=degraded` or `raid_degraded` | `/proc/mdstat` reported a degraded software RAID member set. | Check the array and disk status in ADM, verify a current backup, and follow the storage vendor's recovery guidance before making changes. |
| `smart.state=unknown` | The CLI could not confirm SMART health for one or more supported devices, for example because a drive was in standby or `smartctl` was unavailable. | Check device visibility and permissions. Unknown is not the same as passed; the CLI does not wake drives or start SMART self-tests. |
| `temperature_high` | A generic Linux thermal-zone reading met the configured advisory threshold. The zone ID does not identify a component. | Recheck the reading and consult model-specific ADM or vendor guidance. The default 80 °C threshold is not a safe-temperature limit. |
| `storage.maximum_use_percent=95` | The largest parsed filesystem usage was 95%; the CLI has no configured capacity warning threshold. | Identify the corresponding mount point in the report and review growth and free space using the NAS's normal storage tools. |
| `raid.state=no_arrays` | The response was parseable and no Linux software RAID array was listed. | Confirm whether this model or volume layout is expected to use `/proc/mdstat`; this state is not a storage-health verdict. |
| `not_reobserved` in a comparison | A field or signal from the earlier report was absent from a later report with incomplete coverage. | Collect a complete later report before concluding that the earlier condition cleared. |

The health report also carries three optional operations observations: allowlisted service-process counts, local NUT UPS status and battery charge, and IPv4/IPv6 TCP state counts. These fields do not add risk signals or alter health summary exit codes. A zero process count means only that the process name was not observed; it does not say that a service is expected to run. Missing UPS support is reported as unavailable, not as a failed health check.

Collect those observations individually when useful:

```powershell
adm services --host nas.example --user nas-user --json > .\services.json
adm ups --host nas.example --user nas-user --json > .\ups.json
adm connections --host nas.example --user nas-user --json > .\connections.json
```

The service report exposes names from a fixed process allowlist and counts, never full command lines. UPS names are not emitted. The connection report contains counts only and omits local and remote addresses and ports.

For a quick single-area check, `adm status --summary`, `adm storage --summary`, and `adm raid --summary` preserve each raw section alongside its parsed fields. `adm raid --summary --exit-on-warning` returns a nonzero status when coverage is incomplete or an array is degraded.

Export the structured result to a shareable Markdown summary without reconnecting to the NAS:

```powershell
adm health --host nas.example --user nas-user --summary --json > .\health.json
$healthExitCode = $LASTEXITCODE
adm report render --input .\health.json > .\health.md
$renderExitCode = $LASTEXITCODE
```

The Markdown renderer accepts supported schema-v1 diagnostic, security, incident, platform, topology, SMART, temperature, observation, and comparison reports up to 1 MB and writes at most 2 MB. It omits raw SSH sections and redacts paths, host labels, IP/MAC addresses, and account/secret fields. Review the remaining operational details before sharing the file.

The same offline step can render a prevention audit or incident scan. Incident file paths are redacted in Markdown output:

```powershell
adm security audit --host nas.example --user nas-user --json > .\audit.json
adm report render --input .\audit.json > .\audit.md
adm incident scan --host nas.example --user nas-user --json > .\scan.json
adm report render --input .\scan.json > .\scan.md
```

## Compare today's health summary with yesterday's

Keep one structured report per collection date, then compare two reports locally:

```powershell
adm health --host nas.example --user nas-user --summary --json > .\health-today.json
$todayExitCode = $LASTEXITCODE
adm report compare --before .\health-yesterday.json --after .\health-today.json --json > .\health-diff.json
$compareExitCode = $LASTEXITCODE
```

The comparison requires the same host fingerprint and report type. It shows changes to summary values and risk signals. A missing signal or field is marked `not_reobserved` when today's coverage is partial or unavailable; that is not evidence that a problem was fixed. Preserve both source reports because comparison does not change them.

## DeadBolt review and report comparison

Save a prevention audit and a bounded indicator scan before changing settings or beginning incident response:

```powershell
adm security audit --host nas.example --user nas-user --json > .\audit-before.json
$auditExitCode = $LASTEXITCODE
adm incident scan --host nas.example --user nas-user --json > .\scan-before.json
$scanExitCode = $LASTEXITCODE
```

Store reports with restricted access. A scan report may include matching file paths. The scan checks a limited set of filenames and portal text; it does not read file contents, quarantine files, stop services, or prove that the NAS is clean. An incomplete scan must be treated as unknown.

After collecting another report of the same type, compare them offline:

```powershell
adm security compare --before .\scan-before.json --after .\scan-after.json
```

Comparison does not connect to the NAS or alter either report. Review newly observed indicators and coverage changes manually. Preserve the original reports before taking incident-response actions, and follow current ASUSTOR advisories and your organization's incident process.

## Reading a partial AS-202TE result

The reviewed AS-202TE smoke found two supported block devices, both with unknown SMART health, and no exposed thermal-zone sensors. That result is partial/unavailable observation coverage; it does not establish disk or system temperature health. No SMART self-test was started. Other ADM versions and models may expose different tools and sensors.
