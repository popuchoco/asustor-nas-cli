"""Structured summaries for fixed ADM observation sections."""

import re

from .privacy import REDACTED_HOST, host_fingerprint
from .topology import parse_mdstat


def parse_system_summary(output):
    fields = {}
    memory = None
    parse_errors = 0
    if not isinstance(output, str):
        output = ""
    for line in output.splitlines():
        label = re.match(r"^\s*(hostname|kernel|uptime|cpu):\s*(.*)$", line, re.IGNORECASE)
        if label:
            fields[label.group(1).lower()] = label.group(2).strip() or None
            continue
        memory_line = re.match(r"^\s*Mem:\s+(\d+)\s+(\d+)\s+(\d+)(?:\s|$)", line)
        if memory_line:
            memory = {
                "total_mib": int(memory_line.group(1)),
                "used_mib": int(memory_line.group(2)),
                "free_mib": int(memory_line.group(3)),
            }
        elif re.match(r"^\s*Mem:", line):
            parse_errors += 1
    result = {
        "hostname": fields.get("hostname"),
        "kernel": fields.get("kernel"),
        "uptime": fields.get("uptime"),
        "cpu": fields.get("cpu"),
        "memory_mib": memory,
        "parse_errors": parse_errors,
    }
    result["coverage"] = (
        "complete"
        if result["kernel"] and result["uptime"] and memory and not parse_errors
        else "partial"
        if output
        else "unavailable"
    )
    return result


def parse_storage_summary(output):
    filesystems = []
    parse_errors = 0
    header_seen = False
    if not isinstance(output, str):
        output = ""
    for line in output.splitlines():
        columns = line.split()
        if not columns:
            continue
        if columns[0].lower() == "filesystem":
            if columns[:6] == ["Filesystem", "Size", "Used", "Avail", "Use%", "Mounted"] and columns[6:] == ["on"]:
                header_seen = True
            else:
                parse_errors += 1
            continue
        if len(columns) < 6 or not re.fullmatch(r"\d{1,3}%", columns[4]):
            parse_errors += 1
            continue
        filesystems.append(
            {
                "source": columns[0],
                "size": columns[1],
                "used": columns[2],
                "available": columns[3],
                "use_percent": int(columns[4][:-1]),
                "mountpoint": columns[5],
            }
        )
    result = {
        "filesystem_count": len(filesystems),
        "filesystems": filesystems,
        "maximum_use_percent": max((item["use_percent"] for item in filesystems), default=None),
        "parse_errors": parse_errors,
    }
    if filesystems:
        result["coverage"] = "partial" if parse_errors or not header_seen else "complete"
    else:
        result["coverage"] = "unavailable" if not output.strip() else "partial" if parse_errors or not header_seen else "complete"
    return result


def parse_raid_summary(output):
    if not isinstance(output, str):
        output = ""
    arrays = parse_mdstat(output)
    degraded_arrays = sorted(name for name, item in arrays.items() if item["degraded"] is True)
    unknown_arrays = sorted(name for name, item in arrays.items() if item["degraded"] is None)
    if degraded_arrays:
        state = "degraded"
    elif unknown_arrays:
        state = "unknown"
    elif arrays:
        state = "observed"
    else:
        state = "no_arrays" if output.strip() and "Personalities" in output else "unknown"
    malformed_report = "Personalities" not in output or "unused devices:" not in output
    coverage = (
        "unavailable"
        if not output.strip()
        else "partial"
        if unknown_arrays or malformed_report
        else "complete"
    )
    return {
        "state": state,
        "coverage": coverage,
        "array_count": len(arrays),
        "degraded_arrays": degraded_arrays,
        "unknown_arrays": unknown_arrays,
        "arrays": [arrays[name] for name in sorted(arrays)],
    }


def _smart_observation(report):
    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    devices = report.get("devices", []) if isinstance(report, dict) else []
    return {
        "coverage": report.get("coverage", "unavailable") if isinstance(report, dict) else "unavailable",
        "state": summary.get("state", "unknown"),
        "device_count": summary.get("device_count", 0),
        "failed_count": summary.get("failed_count", 0),
        "unknown_count": summary.get("unknown_count", 0),
        "failed_devices": [
            device.get("device")
            for device in devices
            if isinstance(device, dict)
            and isinstance(device.get("device"), str)
            and device.get("health") == "failed"
        ],
        "unknown_devices": [
            device.get("device")
            for device in devices
            if isinstance(device, dict)
            and isinstance(device.get("device"), str)
            and (device.get("health") == "unknown" or device.get("tool_exit_code") != 0)
        ],
    }


def _temperature_observation(report, warning_celsius):
    summary = report.get("summary", {}) if isinstance(report, dict) else {}
    sensors = report.get("sensors", []) if isinstance(report, dict) else []
    hot_sensors = [
        sensor
        for sensor in sensors
        if isinstance(sensor, dict)
        and isinstance(sensor.get("celsius"), (int, float))
        and sensor["celsius"] >= warning_celsius
    ]
    return {
        "coverage": report.get("coverage", "unavailable") if isinstance(report, dict) else "unavailable",
        "sensor_count": summary.get("sensor_count", 0),
        "minimum_celsius": summary.get("minimum_celsius"),
        "maximum_celsius": summary.get("maximum_celsius"),
        "warning_threshold_celsius": warning_celsius,
        "high_count": len(hot_sensors),
        "high_sensors": [
            {"sensor": sensor["sensor"], "celsius": sensor["celsius"]} for sensor in hot_sensors
        ],
    }


def _coverage_status(statuses):
    if statuses and all(value == "complete" for value in statuses):
        return "complete"
    if statuses and all(value == "unavailable" for value in statuses):
        return "unavailable"
    return "partial"


def build_diagnostic_summary(command, sections, host, ssh_port, host_id=None):
    if command == "status":
        system = parse_system_summary(sections.get("system", ""))
        summary = {
            "state": "observed" if system["coverage"] == "complete" else "unknown",
            "coverage": system["coverage"],
            "risk_signals": [],
            "recommended_exit_code": 0 if system["coverage"] == "complete" else 1,
            "system": system,
        }
    elif command == "storage":
        storage = parse_storage_summary(sections.get("storage", ""))
        summary = {
            "state": "observed" if storage["coverage"] == "complete" else "unknown",
            "coverage": storage["coverage"],
            "risk_signals": [],
            "recommended_exit_code": 0 if storage["coverage"] == "complete" else 1,
            "storage": storage,
        }
    elif command == "raid":
        raid = parse_raid_summary(sections.get("raid", ""))
        risk_signals = (
            [
                {
                    "code": "raid_degraded",
                    "severity": "warning",
                    "message": "Degraded RAID array(s): " + ", ".join(raid["degraded_arrays"]),
                }
            ]
            if raid["degraded_arrays"]
            else []
        )
        code = 2 if risk_signals else 0 if raid["coverage"] == "complete" else 1
        summary = {
            "state": "attention" if risk_signals else raid["state"],
            "coverage": raid["coverage"],
            "risk_signals": risk_signals,
            "recommended_exit_code": code,
            "raid": raid,
        }
    else:
        raise ValueError(f"unsupported summary command: {command}")
    return {
        "schema_version": 1,
        "report_type": "diagnostic-summary",
        "command": command,
        "host": REDACTED_HOST,
        "host_id": host_id or host_fingerprint(host),
        "ssh_port": ssh_port,
        "summary": summary,
        "sections": sections,
    }


def build_health_summary(sections, smart_report, temperature_report, host, ssh_port, warning_celsius, host_id=None):
    system = parse_system_summary(sections.get("system", ""))
    storage = parse_storage_summary(sections.get("storage", ""))
    raid = parse_raid_summary(sections.get("raid", ""))
    smart = _smart_observation(smart_report)
    temperature = _temperature_observation(temperature_report, warning_celsius)
    additional_sections = {
        name: "complete" if isinstance(sections.get(name), str) and sections[name].strip() else "unavailable"
        for name in ("network", "disks")
    }
    risk_signals = []
    if raid["degraded_arrays"]:
        risk_signals.append(
            {
                "code": "raid_degraded",
                "severity": "warning",
                "message": "Degraded RAID array(s): " + ", ".join(raid["degraded_arrays"]),
            }
        )
    if smart["failed_count"]:
        risk_signals.append(
            {
                "code": "smart_failed",
                "severity": "critical",
                "message": f"SMART health failed on {smart['failed_count']} device(s).",
            }
        )
    if temperature["high_count"]:
        names = ", ".join(item["sensor"] for item in temperature["high_sensors"])
        risk_signals.append(
            {
                "code": "temperature_high",
                "severity": "warning",
                "message": f"Thermal-zone reading(s) at or above {warning_celsius:g} °C: {names}.",
            }
        )
    coverage = _coverage_status(
        [
            system["coverage"],
            storage["coverage"],
            raid["coverage"],
            smart["coverage"],
            temperature["coverage"],
            *additional_sections.values(),
        ]
    )
    state = "attention" if risk_signals else "observed" if coverage == "complete" else "unknown"
    recommended_exit_code = 2 if risk_signals else 0 if coverage == "complete" else 1
    return {
        "schema_version": 1,
        "report_type": "diagnostic-summary",
        "command": "health",
        "host": REDACTED_HOST,
        "host_id": host_id or host_fingerprint(host),
        "ssh_port": ssh_port,
        "summary": {
            "state": state,
            "coverage": coverage,
            "risk_signals": risk_signals,
            "recommended_exit_code": recommended_exit_code,
            "temperature_warning_celsius": warning_celsius,
            "system": system,
            "storage": storage,
            "raid": raid,
            "smart": smart,
            "temperature": temperature,
            "additional_sections": additional_sections,
        },
        "sections": sections,
    }


def format_diagnostic_summary(report):
    summary = report["summary"]
    lines = [
        f"{report['command'].title()} summary: {summary['state']} | coverage: {summary['coverage']} | recommended exit code: {summary['recommended_exit_code']}"
    ]
    if "system" in summary:
        system = summary["system"]
        memory = system.get("memory_mib") or {}
        lines.append(
            "System: "
            f"{system.get('kernel') or 'kernel unknown'}; "
            f"memory {memory.get('used_mib', '?')}/{memory.get('total_mib', '?')} MiB"
        )
    if "storage" in summary:
        storage = summary["storage"]
        lines.append(
            f"Storage: {storage['filesystem_count']} filesystem(s); "
            f"maximum use {storage['maximum_use_percent']}%" if storage["maximum_use_percent"] is not None
            else f"Storage: {storage['filesystem_count']} filesystem(s); usage unavailable"
        )
    if "raid" in summary:
        raid = summary["raid"]
        lines.append(
            f"RAID: {raid['state']} | {raid['array_count']} array(s); "
            f"degraded: {', '.join(raid['degraded_arrays']) or 'none'}"
        )
    if "smart" in summary:
        smart = summary["smart"]
        lines.append(
            f"SMART: {smart['state']} | {smart['device_count']} device(s), "
            f"failed {smart['failed_count']} ({', '.join(smart['failed_devices']) or 'none'}), "
            f"unknown {smart['unknown_count']} ({', '.join(smart['unknown_devices']) or 'none'})"
        )
    if "temperature" in summary:
        temperature = summary["temperature"]
        lines.append(
            f"Temperature: {temperature['coverage']} | {temperature['sensor_count']} sensor(s); "
            f"high {temperature['high_count']} at >= {temperature['warning_threshold_celsius']:g} °C"
        )
    for signal in summary["risk_signals"]:
        lines.append(f"[{signal['severity']}] {signal['code']}: {signal['message']}")
    for name, output in report["sections"].items():
        lines.extend((f"--- raw {name} ---", output or "(no output)"))
    return "\n".join(lines)
