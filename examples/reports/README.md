# Example reports

These files are synthetic examples generated from test inputs. They contain no live NAS data, real address, account, host fingerprint, serial number, or incident path. The host fingerprint is a synthetic 16-character hexadecimal value.

- [`health-summary.json`](health-summary.json) shows a complete structured health observation with its raw diagnostic sections.
- [`risk-signals.json`](risk-signals.json) shows how degraded RAID, failed SMART, and a high thermal-zone reading are represented for scripting.

Both health report types include separate service, UPS, and TCP observations. They are not health verdicts and do not create risk signals or change health exit codes.

Structured summaries include a UTC `generated_at` value so separate reports can be compared with `adm report compare`.

Validate them against the published schemas under [`schemas/`](../../schemas/). A complete sample only demonstrates the report format; it is not a hardware-health baseline.
