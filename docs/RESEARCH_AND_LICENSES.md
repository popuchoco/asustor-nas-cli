# Research sources and licenses

This file records the upstream research consulted during design and the license review relevant to this project. It is not a third-party dependency inventory. The design comparison and adoption decisions are in [REFERENCE_REVIEW.md](REFERENCE_REVIEW.md).

## This project

The original source code and documentation in this repository are licensed under the MIT License in the root [LICENSE](../LICENSE) file. The license applies to this repository's original work; it does not relicense the upstream projects or the external documentation linked below.

No source code, binaries, or substantial documentation text from the research repositories below has been copied into this project. Their licenses were reviewed to record provenance and clarify that this project's MIT license does not replace their terms. Names and links are attribution for research only.

## Software dependencies actually used

| Component | Use | License / record |
| --- | --- | --- |
| Python standard library | Runtime implementation; no Python runtime packages are required | Python Software Foundation License; the standard library is provided by the user's Python distribution |
| OpenSSH client | External executable used for SSH transport; not bundled or redistributed | Supplied and licensed by the user's operating system or package provider |
| `jsonschema` | Optional test extra used to validate report schemas; not a runtime dependency | MIT; see the [upstream license](https://github.com/python-jsonschema/jsonschema/blob/main/COPYING) |

GitHub Actions and their workflow components are used for CI/release automation but are not included in the Python distribution. Their upstream licenses and GitHub terms continue to apply to those services.

The built wheel and source distribution contain this project's package and metadata, not the NAS driver project, research repositories, or a bundled SSH executable.

## Research repositories and license review

License references below point to the upstream repository's license file on its default branch as reviewed on 2026-11-21. “Research only” means that repository informed evaluation or interface decisions; it does not mean its code is a dependency.

| Research source | License recorded upstream | How it informed this project | Code copied? |
| --- | --- | --- | --- |
| [synology-nas-cli](https://github.com/akari-sora/synology-nas-cli) ([LICENSE](https://github.com/akari-sora/synology-nas-cli/blob/main/LICENSE)) | MIT | OS-named CLI structure, modularity, structured output, and operations documentation | No |
| [qnap-nas-cli](https://github.com/popuchoco/qnap-nas-cli) ([LICENSE](https://github.com/popuchoco/qnap-nas-cli/blob/main/LICENSE)) | MIT | Safety boundaries, zero-runtime-dependency approach, compatibility and security documentation | No |
| [asustor-adm-mcp](https://github.com/varossoft/asustor-adm-mcp) ([LICENSE](https://github.com/varossoft/asustor-adm-mcp/blob/main/LICENSE)) | MIT | Read-only ADM observations and bounded structured-tool design | No |
| [asustor-platform-driver](https://github.com/mafredri/asustor-platform-driver) ([LICENSE](https://github.com/mafredri/asustor-platform-driver/blob/main/LICENSE)) | GNU GPL v3 | Module names, published kernel/model scope, and risk boundaries for optional module-state controls | No driver source or binaries copied |
| [asustor-nas-api](https://github.com/rimaulana/asustor-nas-api) ([LICENSE](https://github.com/rimaulana/asustor-nas-api/blob/master/LICENSE)) | MIT | Reviewed as an alternative API surface; its write-capable service model was not adopted | No |
| [asustor-nas-control](https://github.com/danganhtu01/asustor-nas-control) ([LICENSE](https://github.com/danganhtu01/asustor-nas-control/blob/main/LICENSE)) | MIT | Reviewed hardware-control hazards and model-specific assumptions | No |

Other exploratory repositories are listed in [REFERENCE_REVIEW.md](REFERENCE_REVIEW.md) as excluded research. Their code and binaries are not used here; this project does not claim or assign a license to them.

## Technical and security sources

These sources informed specific behavior or security wording. This project links to and paraphrases factual material; it does not reproduce their code or documentation text.

| Source | Project use |
| --- | --- |
| [ASUSTOR DeadBolt security advisory](https://www.asustor.com/en/security/security_advisory_detail?id=9) | Input to the intentionally narrow `asustor-deadbolt-v1` checks; advisory status should be rechecked by operators |
| [ASUSTOR ADM release notes](https://www.asustor.com/zh-tw/service/release_notes) | Context for ADM version observations; not treated as a complete vulnerability feed |
| [ASUSTOR DeadBolt prevention guidance](https://www.asustor.com/zh-tw/knowledge/detail/?group_id=628&id=6) | Source for operator-facing prevention context |
| [Linux thermal sysfs ABI](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/sysfs-class-thermal) and [thermal sysfs API documentation](https://docs.kernel.org/driver-api/thermal/sysfs-api.html) | Defines the generic `/sys/class/thermal/thermal_zone*/temp` observation surface used by `adm temperature` |
| [PyPI Trusted Publisher documentation](https://docs.pypi.org/trusted-publishers/using-a-publisher/) | Informs the optional OIDC-based PyPI publish job; publishing remains a separately configured manual release step |

## Trademarks and affiliation

ASUSTOR, ADM, and ASUSTOR product and model names are trademarks of their respective rights holders. This is an independent community project and is not affiliated with, endorsed by, or sponsored by ASUSTOR Inc. See the trademark notice in the [README](../README.md#license-and-trademarks) and [Traditional Chinese README](../README.zh-TW.md#授權研究來源與商標).
