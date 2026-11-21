# Example reports

These files are synthetic examples generated from test inputs. They contain no live NAS data, real address, account, host fingerprint, serial number, or incident path. `example-host-id` is a placeholder.

- [`health-summary.json`](health-summary.json) shows a complete structured health observation with its raw diagnostic sections.
- [`risk-signals.json`](risk-signals.json) shows how degraded RAID, failed SMART, and a high thermal-zone reading are represented for scripting.

Structured summaries include a UTC `generated_at` value so separate reports can be compared with `adm report compare`.

Validate them against the published schemas under [`schemas/`](../../schemas/). A complete sample only demonstrates the report format; it is not a hardware-health baseline.
