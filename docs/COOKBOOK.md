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

Interpret the result as follows:

- `0`: all included observations were complete and no configured risk signal was found.
- `1`: at least one source was incomplete or unavailable. Unknown SMART states and unavailable temperature sensors do not count as healthy.
- `2`: a degraded RAID array, failed SMART health state, or thermal-zone reading at/above the advisory threshold was observed.

The default temperature advisory is 80 °C and can be adjusted with `--temperature-warning-celsius`. Sensor IDs are generic Linux zone names; they do not identify a component, and the threshold is not a model-specific safety limit. Review raw sections and verify any warning with the NAS vendor's guidance.

For a quick single-area check, `adm status --summary`, `adm storage --summary`, and `adm raid --summary` preserve each raw section alongside its parsed fields. `adm raid --summary --exit-on-warning` returns a nonzero status when coverage is incomplete or an array is degraded.

Export the structured result to a shareable Markdown summary without reconnecting to the NAS:

```powershell
adm health --host nas.example --user nas-user --summary --json > .\health.json
$healthExitCode = $LASTEXITCODE
adm report render --input .\health.json > .\health.md
$renderExitCode = $LASTEXITCODE
```

The Markdown renderer accepts `diagnostic-summary` and `risk-signals` schema-v1 reports up to 1 MB and writes at most 2 MB. It omits raw SSH sections and redacts host labels, IP/MAC addresses, and account/secret fields. Review the remaining operational details before sharing the file.

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
