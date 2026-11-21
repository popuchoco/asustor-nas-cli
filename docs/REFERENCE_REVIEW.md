# Reference-project review

This document records findings that shaped this project. It is a comparison and design note, not a bundled third-party inventory. No source code or binaries from the projects below are copied into this repository. Runtime dependencies are Python's standard library and the host's OpenSSH client.

## CLI design references

| Project | Useful pattern | Decision here |
| --- | --- | --- |
| [synology-nas-cli](https://github.com/akari-sora/synology-nas-cli) | OS-named CLI, modular Python package, MCP stdio, structured reports and operational docs | Use `adm`, split diagnostics/security/platform boundaries, and document report/exit semantics |
| [qnap-nas-cli](https://github.com/popuchoco/qnap-nas-cli) | Safety-first zero-runtime-dependency CLI/MCP, compatibility and security documentation | Keep runtime dependency-free, fixed command allowlist, explicit read-only annotations and product-level docs |

These projects informed interfaces and documentation, not copied implementation code.

## ASUSTOR ecosystem references

| Project | Findings | Applied decision |
| --- | --- | --- |
| [asustor-adm-mcp](https://github.com/varossoft/asustor-adm-mcp) | Read-only ADM MCP observations using `/proc`, `/sys`, ADM files and Docker APIs; its README reports ADM 5.1.4 testing on AS5402T | Adopt the idea of bounded, explicitly read-only structured tools. Do not infer this CLI supports ADM 5.x or add Docker API access |
| [asustor-platform-driver](https://github.com/mafredri/asustor-platform-driver) | Kernel driver for model-specific LEDs/buttons and optional IT87 fan/PWM features; wrong GPIO mappings can destabilize hardware. Maintainer build guidance supports Linux 6.1+ and lists DMI/model families | Add read-only module/platform status and guarded load/unload for exact module names on an allowlisted Linux/DMI preflight. Do not copy GPL driver code, install or compile modules, write GPIO/PWM, or allow MCP mutation |
| [asustor-nas-api](https://github.com/rimaulana/asustor-nas-api) | Standalone Node/Express service, API-key handling, no HTTPS in its documented setup, and endpoints that create folders/copy to USB | Do not deploy or call this service. Its endpoint/resource ideas do not justify adding a second write-capable network API |
| [asustor-nas-control](https://github.com/danganhtu01/asustor-nas-control) | Manual sysfs controls for AS6704 on Arch Linux; exposes fan PWM/RPM, LEDs and IT87 GPIO blink. Its fan daemon uses real sensors and drives the fan full on shutdown/failure because chip-local temperature inputs are unavailable on that board | Use as a safety-design reference only. Do not port fan curves or writable sysfs helpers: hardware sensors, PWM polarity, kernel, cooling minimums, and model differ. Current CLI changes only module loaded state |
| [asustor_as-6xxt](https://github.com/mafredri/asustor_as-6xxt) | AS-6xxT Linux/Debian reverse-engineering notes for thermal sensors, fans and LEDs; reports a legacy 3.12.20 kernel in that setup | Confirms that Linux-on-ASUSTOR hardware access can be model/kernel specific. Not an ADM command source and not used as proof for AS-202TE |
| [asustor-xpenology](https://github.com/liwei/asustor-xpenology) | A Synology/Xpenology kernel tree/configuration targeting AS-204TE | Not used: this is a different NAS model and replacement OS/kernel work, not an ADM CLI interface. No code or kernel configuration is imported |
| [asustor-linux-3.4.26](https://github.com/liwei/asustor-linux-3.4.26) | Linux 3.4.26 source repository described for AS-204TE; kernel source, not ADM userland command documentation | Its version aligns with the live-test NAS kernel generation, but the repository targets AS-204TE, not AS-202TE. It does not establish safe support for the modern platform driver; module changes stay blocked on the test NAS |

## What the comparison changed

- The CLI now has a read-only `adm platform status` query that reports kernel, DMI identity, loaded driver modules and preflight result.
- Module load/unload is not treated as a routine diagnostic. It requires a new local state backup, `--confirm-risk`, an exact interactive confirmation, and an explicit kernel/DMI preflight. `--force` skips only the prompt. `--reset` restores the captured loaded-module state when the host identity still matches.
- Fan PWM, LED brightness/triggers, GPIO mapping overrides, kernel/module installation, service management, folder creation, USB copy, and Docker operations remain outside the current control surface.
- A dedicated report schema and compatibility document separate this CLI's live-tested claims from capabilities reported by reference projects.
