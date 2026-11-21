"""Guarded inspection and lifecycle control for asustor-platform-driver."""

import json
import os
import re
from pathlib import Path

from .privacy import REDACTED_HOST, host_fingerprint

DRIVER_MODULES = ("asustor", "asustor_it87", "asustor_gpio_it87")
LOAD_ORDER = ("asustor_gpio_it87", "asustor_it87", "asustor")
UNLOAD_ORDER = ("asustor", "asustor_it87", "asustor_gpio_it87")
CONFLICT_MODULES = ("it87",)
MINIMUM_KERNEL = (6, 1)
SUPPORTED_DMI = {
    ("ASUSTOR Inc.", "AS-6xxT"),
    ("Insyde", "AS61xx"),
    ("Insyde", "GeminiLake"),
    ("Intel Corporation", "Jasper Lake Client Platform"),
}


def build_status_command():
    """Return a fixed read-only command that reports driver prerequisites."""
    lines = [
        "printf '__ADM_PLATFORM_BEGIN__\\n'",
        "printf '__ADM_PLATFORM_KERNEL__='; uname -r",
        "for dmi_field in sys_vendor product_name; do",
        "  dmi_value=",
        '  [ -r "/sys/class/dmi/id/$dmi_field" ] && dmi_value=$(cat "/sys/class/dmi/id/$dmi_field" 2>/dev/null) || :',
        '  printf "__ADM_PLATFORM_DMI_%s__=%s\\n" "$dmi_field" "$dmi_value"',
        "done",
    ]
    for module in (*DRIVER_MODULES, *CONFLICT_MODULES):
        lines.extend(
            (
                f'if [ -d "/sys/module/{module}" ]; then module_loaded=1; else module_loaded=0; fi',
                f"printf '__ADM_PLATFORM_MODULE_{module}__=%s\\n' \"$module_loaded\"",
            )
        )
    lines.extend(("printf '__ADM_PLATFORM_END__\\n'", "exit 0"))
    return "\n".join(lines)


def parse_platform_status(output, host=None, ssh_port=None, host_id=None):
    lines = output.splitlines()
    fields = {}
    duplicate_field = False
    for line in lines:
        if line.startswith("__ADM_PLATFORM_") and "=" in line:
            key, value = line.split("=", 1)
            duplicate_field = duplicate_field or key in fields
            fields[key] = value.strip()
    kernel = fields.get("__ADM_PLATFORM_KERNEL__", "")
    vendor = fields.get("__ADM_PLATFORM_DMI_sys_vendor__", "")
    product = fields.get("__ADM_PLATFORM_DMI_product_name__", "")
    modules = {
        module: fields.get(f"__ADM_PLATFORM_MODULE_{module}__") == "1"
        for module in (*DRIVER_MODULES, *CONFLICT_MODULES)
    }
    version_match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", kernel)
    kernel_version = tuple(int(part or 0) for part in version_match.groups()) if version_match else None
    kernel_supported = bool(kernel_version and kernel_version[:2] >= MINIMUM_KERNEL)
    dmi_allowlisted = (vendor, product) in SUPPORTED_DMI
    required_markers = {
        "__ADM_PLATFORM_KERNEL__",
        "__ADM_PLATFORM_DMI_sys_vendor__",
        "__ADM_PLATFORM_DMI_product_name__",
        *(f"__ADM_PLATFORM_MODULE_{name}__" for name in (*DRIVER_MODULES, *CONFLICT_MODULES)),
    }
    marker_pairs = (
        ("__ADM_PLATFORM_BEGIN__", "__ADM_PLATFORM_END__"),
        ("__ADM_PLATFORM_RESULT_BEGIN__", "__ADM_PLATFORM_RESULT_END__"),
    )
    complete_marker_pair = any(
        lines.count(begin) == 1
        and lines.count(end) == 1
        and lines.index(begin) < lines.index(end)
        for begin, end in marker_pairs
    )
    markers_ok = required_markers.issubset(fields) and complete_marker_pair and not duplicate_field
    conflicts = [name for name in CONFLICT_MODULES if modules[name]]
    preflight_passed = markers_ok and kernel_supported and dmi_allowlisted and not conflicts
    return {
        "schema_version": 1,
        "report_type": "platform-status",
        "host": REDACTED_HOST if host else None,
        "host_id": host_id or host_fingerprint(host),
        "ssh_port": ssh_port,
        "kernel_release": kernel or None,
        "kernel_supported": kernel_supported,
        "dmi": {"system_vendor": vendor or None, "product_name": product or None},
        "dmi_allowlisted": dmi_allowlisted,
        "preflight_passed": preflight_passed,
        "modules": modules,
        "conflicts": conflicts,
        "coverage": "complete" if markers_ok else "partial",
        "notes": [
            "Only the asustor-platform-driver module family is managed.",
            "Fan PWM values, LED states, module installation, and firmware settings are not changed by these commands.",
            "The kernel driver performs additional hardware probing; passing this preflight is not proof that GPIO mappings are correct.",
        ],
    }


def compatibility_error(status, action, target_states=None):
    if status["coverage"] != "complete":
        return "NAS platform details could not be read; kernel module changes are disabled."
    if not status["kernel_supported"]:
        return "The platform driver requires Linux kernel 6.1 or newer; this NAS kernel is not supported."
    if not status["dmi_allowlisted"]:
        return "This NAS model is not in the platform driver's verified DMI compatibility list."
    needs_hwmon = action == "load" or bool(target_states and target_states.get("asustor_it87"))
    if needs_hwmon and status["conflicts"]:
        return "Conflicting module(s) are loaded: " + ", ".join(status["conflicts"])
    return None


def _quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def build_module_change_command(target_states):
    """Create a fixed module plan; never use modprobe/rmmod force options."""
    if set(target_states) != set(DRIVER_MODULES) or any(type(value) is not bool for value in target_states.values()):
        raise ValueError("module target states must define all managed modules as booleans")
    lines = ["set -eu", "command -v modprobe >/dev/null 2>&1 || { echo 'modprobe is unavailable' >&2; exit 69; }"]
    for module in UNLOAD_ORDER:
        if not target_states[module]:
            lines.append(f'[ ! -d "/sys/module/{module}" ] || modprobe -r {module}')
    for module in LOAD_ORDER:
        if target_states[module]:
            lines.append(f'[ -d "/sys/module/{module}" ] || modprobe {module}')
    lines.extend(
        (
            "printf '__ADM_PLATFORM_RESULT_BEGIN__\\n'",
            "printf '__ADM_PLATFORM_KERNEL__='; uname -r",
        )
    )
    for module in (*DRIVER_MODULES, *CONFLICT_MODULES):
        lines.extend(
            (
                f'if [ -d "/sys/module/{module}" ]; then module_loaded=1; else module_loaded=0; fi',
                f"printf '__ADM_PLATFORM_MODULE_{module}__=%s\\n' \"$module_loaded\"",
            )
        )
    lines.append("printf '__ADM_PLATFORM_RESULT_END__\\n'")
    script = "\n".join(lines)
    return (
        'if [ "$(id -u)" -eq 0 ]; then\n'
        f"  sh -c {_quote(script)}\n"
        "elif command -v sudo >/dev/null 2>&1; then\n"
        f"  sudo -n -- sh -c {_quote(script)}\n"
        "else\n"
        "  echo 'root or passwordless sudo is required' >&2\n"
        "  exit 77\n"
        "fi"
    )


def build_module_preflight_command(target_states, current_states):
    """Ask modprobe to resolve the fixed plan in dry-run mode before prompting."""
    if set(target_states) != set(DRIVER_MODULES) or set(current_states) != set(DRIVER_MODULES):
        raise ValueError("module preflight requires complete current and target states")
    if any(type(value) is not bool for value in (*target_states.values(), *current_states.values())):
        raise ValueError("module preflight states must be booleans")
    lines = ["set -eu", "command -v modprobe >/dev/null 2>&1 || { echo 'modprobe is unavailable' >&2; exit 69; }"]
    for module in UNLOAD_ORDER:
        if current_states[module] and not target_states[module]:
            lines.append(f"modprobe -n -r {module}")
    for module in LOAD_ORDER:
        if target_states[module] and not current_states[module]:
            lines.append(f"modprobe -n {module}")
    lines.append("printf '%s\\n' '__ADM_PLATFORM_PREFLIGHT_OK__'")
    return "\n".join(lines)


def snapshot_for_backup(status):
    return {
        "schema_version": 1,
        "report_type": "platform-module-backup",
        "host": status["host"],
        "host_id": status["host_id"],
        "ssh_port": status["ssh_port"],
        "kernel_release": status["kernel_release"],
        "dmi": status["dmi"],
        "modules": {module: status["modules"][module] for module in DRIVER_MODULES},
        "scope": "Loaded-state snapshot for asustor, asustor_it87, and asustor_gpio_it87 only.",
        "restore_limit": "This file does not contain kernel binaries, firmware settings, fan PWM values, LED values, or NAS data.",
    }


def write_backup(path, backup):
    """Create a local backup without overwriting an existing file."""
    backup_path = Path(path).expanduser()
    payload = json.dumps(backup, ensure_ascii=False, indent=2) + "\n"
    descriptor = os.open(backup_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as backup_file:
        backup_file.write(payload)
    return backup_path.resolve()


def load_backup(path):
    try:
        with Path(path).expanduser().open("r", encoding="utf-8") as backup_file:
            backup = json.load(backup_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("Could not read the platform backup; check the local file and JSON format") from error
    if not isinstance(backup, dict) or backup.get("schema_version") != 1 or backup.get("report_type") != "platform-module-backup":
        raise ValueError("Unsupported platform module backup format")
    if not isinstance(backup.get("host"), str) or not isinstance(backup.get("modules"), dict):
        raise ValueError("Platform backup is missing host or module state")
    modules = backup["modules"]
    if set(modules) != set(DRIVER_MODULES) or any(type(value) is not bool for value in modules.values()):
        raise ValueError("Platform backup contains an invalid module state")
    return backup


def validate_backup_target(backup, status):
    for field in ("host_id", "ssh_port", "kernel_release", "dmi"):
        if backup.get(field) != status.get(field):
            raise ValueError(f"Platform backup {field} does not match this NAS; refusing reset")
    return dict(backup["modules"])


def action_target(action, status, backup=None):
    if action == "load":
        return {module: True for module in DRIVER_MODULES}
    if action == "unload":
        return {module: False for module in DRIVER_MODULES}
    if action == "reset" and backup is not None:
        return validate_backup_target(backup, status)
    raise ValueError("unknown platform module action")
