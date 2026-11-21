# Research sources and licenses

This record lists software and technical sources actually used by the project. It does not list projects consulted only for design comparison; those comparisons remain in [REFERENCE_REVIEW.md](REFERENCE_REVIEW.md).

## Project license

The original code and documentation in this repository are licensed under MIT. See the root [LICENSE](../LICENSE). This license does not relicense external software or documentation.

## Software and integration targets used

| Component | How this project uses it | License / distribution status |
| --- | --- | --- |
| Python standard library | Runtime implementation | Python Software Foundation License; included with the user's Python distribution |
| OpenSSH client | Executes the fixed read-only ADM/Linux commands and guarded module commands | Supplied by the operating system; not bundled |
| `jsonschema` | Optional test extra for validating published JSON Schemas | MIT; see the [upstream license](https://github.com/python-jsonschema/jsonschema/blob/main/COPYING); not a runtime dependency |
| [asustor-platform-driver](https://github.com/mafredri/asustor-platform-driver) | The guarded `adm platform module` feature manages this driver's fixed module family and checks its published kernel/DMI compatibility boundary | GNU GPL v3 upstream; see its [LICENSE](https://github.com/mafredri/asustor-platform-driver/blob/main/LICENSE). No driver source or binary is copied or bundled |

## Technical sources used

| Source | Where it informs the project |
| --- | --- |
| [ASUSTOR DeadBolt security advisory](https://www.asustor.com/en/security/security_advisory_detail?id=9), [ADM release notes](https://www.asustor.com/zh-tw/service/release_notes), and [DeadBolt prevention guidance](https://www.asustor.com/zh-tw/knowledge/detail/?group_id=628&id=6) | The versioned, limited DeadBolt audit and its operator guidance |
| [Linux thermal sysfs ABI](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/sysfs-class-thermal) and [thermal sysfs API documentation](https://docs.kernel.org/driver-api/thermal/sysfs-api.html) | The read-only `/sys/class/thermal/thermal_zone*/temp` observation command |
| [PyPI Trusted Publisher documentation](https://docs.pypi.org/trusted-publishers/using-a-publisher/) | The optional OIDC package-publishing workflow |

The technical documents are linked and paraphrased for factual guidance; their content remains with the respective rights holders. The project does not bundle their documentation or code.

## Trademarks and affiliation

ASUSTOR, ADM, and ASUSTOR product and model names are trademarks of their respective rights holders. This independent community project is not affiliated with, endorsed by, or sponsored by ASUSTOR Inc. See the notices in the [README](../README.md#license-and-trademarks) and [Traditional Chinese README](../README.zh-TW.md#授權研究來源與商標).
