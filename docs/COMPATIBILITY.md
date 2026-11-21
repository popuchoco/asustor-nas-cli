# Compatibility

## This CLI's verified coverage

| Device / software | Verification | Result |
| --- | --- | --- |
| ASUSTOR AS-202TE, ADM 3.5.9.RWM1, Linux 3.4.26 i686, BusyBox 1.19.3 | Live read-only SSH/HTTPS checks | System, storage, RAID, network, disk listing, disk topology, DeadBolt audit, and bounded filename scan exercised |
| ASUSTOR AS-202TE SMART health command | Live read-only smoke | Two supported block devices were observed; both health states were unknown and coverage was partial. No self-tests were started |
| ASUSTOR AS-202TE temperature command | Live read-only smoke | No thermal-zone sensors were exposed; coverage was unavailable |
| ASUSTOR AS-202TE platform-module operations | Compatibility-gate evaluation | Refused: Linux 3.4 is below the driver project's Linux 6.1 floor; AS-202TE is not in its hardware allowlist |
| ASUSTOR AS5402T, ADM 5.1.4 | Reference-project report only | Not tested by this CLI |
| Other ASUSTOR models / ADM releases | None | Not yet verified |

CI also tests package installation and the `adm --version` entry point on Windows and macOS (Python 3.10 and 3.13). This validates workstation packaging only; it does not claim live NAS compatibility on those operating systems.

The AS-202TE HTTPS certificate used during the live check was not trusted. Checks performed with `--insecure` explicitly report that TLS was not verified.

The normalized, reviewed facts from that device are kept in [`tests/fixtures/as202te_live_profile.json`](../tests/fixtures/as202te_live_profile.json). It is a profile summary rather than a raw command transcript; it contains no host address, account, password, MAC address, or disk serial. No Linux 6.1+ ASUSTOR device was available for this review, so the DMI allowlist has not been live-validated by this CLI and no module mutation has been attempted.

## `asustor-platform-driver` preflight

The referenced driver documents support for kernels 6.1 and newer and identifies hardware through DMI plus driver-side hardware probing. The CLI applies a conservative DMI prefilter for these pairs:

| DMI system vendor | DMI product name |
| --- | --- |
| `ASUSTOR Inc.` | `AS-6xxT` |
| `Insyde` | `AS61xx` |
| `Insyde` | `GeminiLake` |
| `Intel Corporation` | `Jasper Lake Client Platform` |

Passing the preflight is not a guarantee that GPIO mappings are correct or that the driver will bind. The platform driver's own PCI/hardware detection and the operator's model-specific validation remain authoritative. The CLI does not override driver detection, install modules, or force-load modules.

The current AS-202TE test NAS reports Linux 3.4.26. It is not a supported target for this control path; the CLI permits status inspection only and refuses load/unload/reset operations on it.

## Reference-project coverage is not CLI support

The reference MCP project reports testing on AS5402T with ADM 5.1.4. This helps identify a possible future test platform, but does not transfer its ADM-version or model support to this CLI. See the [reference review](REFERENCE_REVIEW.md).
