"""Read-only service, UPS, and network-connection observations."""

import re

from .commands import SERVICE_PROCESS_NAMES
from .privacy import REDACTED_HOST, host_fingerprint
from .security.common import utc_now

_SERVICE_ROW = re.compile(r"__ADM_SERVICE__=([a-z][a-z0-9-]*)\|(\d+)\Z")
_UPS_DEVICE_ROW = re.compile(
    r"__ADM_UPS_DEVICE__=(\d+)\|(online|on_battery|low_battery|charging|discharging|other|unavailable)\|([0-9.]+|unavailable)\Z"
)
_TCP_ROW = re.compile(r"__ADM_TCP__=(tcp|tcp6)\|(\d+)\|(\d+)\|(\d+)\Z")


def _has_markers(output, begin, end):
    lines = output.splitlines()
    return lines.count(begin) == 1 and lines.count(end) == 1 and lines.index(begin) < lines.index(end)


def _report(report_type, observation, host, ssh_port, host_id):
    return {
        "schema_version": 1,
        "report_type": report_type,
        "generated_at": utc_now(),
        "host": REDACTED_HOST,
        "host_id": host_id or host_fingerprint(host),
        "ssh_port": ssh_port,
        **observation,
    }


def _bounded_count(value, maximum=1_000_000_000):
    if not value.isdigit() or len(value) > 9:
        return None
    count = int(value)
    return count if count <= maximum else None


def parse_services_output(output):
    output = output if isinstance(output, str) else ""
    lines = output.splitlines()
    start = lines.index("__ADM_SERVICES_BEGIN__") if "__ADM_SERVICES_BEGIN__" in lines else -1
    end = lines.index("__ADM_SERVICES_END__") if "__ADM_SERVICES_END__" in lines else -1
    counts = {}
    malformed = False
    if start >= 0 and end > start and _has_markers(
        output, "__ADM_SERVICES_BEGIN__", "__ADM_SERVICES_END__"
    ):
        for line in lines[start + 1 : end]:
            if not line.startswith("__ADM_SERVICE__="):
                continue
            match = _SERVICE_ROW.fullmatch(line)
            if not match:
                malformed = True
                continue
            name, count = match.groups()
            if name not in SERVICE_PROCESS_NAMES or name in counts:
                malformed = True
                continue
            parsed_count = _bounded_count(count)
            if parsed_count is None:
                malformed = True
                continue
            counts[name] = parsed_count
    coverage = (
        "complete"
        if not malformed and set(counts) == set(SERVICE_PROCESS_NAMES)
        else "partial"
        if counts
        else "unavailable"
    )
    return {
        "coverage": coverage,
        "processes": [
            {"name": name, "process_count": counts[name]}
            for name in SERVICE_PROCESS_NAMES
            if name in counts
        ],
        "note": "只計算固定 allowlist 中的程序名稱與數量，不提供健康判定。",
    }


def parse_ups_output(output):
    output = output if isinstance(output, str) else ""
    lines = output.splitlines()
    source_values = []
    count_values = []
    devices = {}
    malformed = False
    has_markers = _has_markers(output, "__ADM_UPS_BEGIN__", "__ADM_UPS_END__")
    if has_markers:
        start = lines.index("__ADM_UPS_BEGIN__")
        end = lines.index("__ADM_UPS_END__")
        for line in lines[start + 1 : end]:
            if line.startswith("__ADM_UPS_SOURCE__="):
                source_values.append(line.partition("=")[2])
                continue
            if line.startswith("__ADM_UPS_COUNT__="):
                count_values.append(line.partition("=")[2])
                continue
            if line.startswith("__ADM_UPS_DEVICE__="):
                match = _UPS_DEVICE_ROW.fullmatch(line)
                if not match:
                    malformed = True
                    continue
                index_text, status, charge_text = match.groups()
                index = _bounded_count(index_text, maximum=100_000)
                if index is None or index in devices or index < 1:
                    malformed = True
                    continue
                try:
                    charge = None if charge_text == "unavailable" else float(charge_text)
                except ValueError:
                    malformed = True
                    charge = None
                if charge is not None and not 0 <= charge <= 100:
                    malformed = True
                    charge = None
                devices[index] = {
                    "index": index,
                    "status": status,
                    "battery_charge_percent": charge,
                }
    else:
        malformed = True

    if len(source_values) != 1 or source_values[0] not in {"nut", "none"}:
        malformed = True
    if len(count_values) > 1:
        malformed = True

    source = source_values[0] if len(source_values) == 1 and source_values[0] == "nut" else None
    device_count = None
    if len(count_values) == 1:
        device_count = _bounded_count(count_values[0], maximum=100_000)
        if device_count is None:
            malformed = True
    if source == "nut" and device_count:
        if any(index > device_count for index in devices):
            malformed = True
        if malformed:
            coverage = "partial" if device_count else "unavailable"
        else:
            coverage = "complete" if len(devices) == device_count and all(
                device["status"] != "unavailable" for device in devices.values()
            ) else "partial"
    else:
        coverage = "unavailable"
    return {
        "coverage": coverage,
        "source": source,
        "device_count": device_count,
        "devices": [devices[index] for index in sorted(devices)],
        "note": "只回報首個本機 NUT UPS 的狀態與電量，不作健康判定，且不輸出 UPS 名稱；多台裝置時 coverage 為 partial。",
    }


def parse_connections_output(output):
    output = output if isinstance(output, str) else ""
    lines = output.splitlines()
    start = lines.index("__ADM_CONNECTIONS_BEGIN__") if "__ADM_CONNECTIONS_BEGIN__" in lines else -1
    end = lines.index("__ADM_CONNECTIONS_END__") if "__ADM_CONNECTIONS_END__" in lines else -1
    families = {}
    malformed = False
    if start >= 0 and end > start and _has_markers(
        output, "__ADM_CONNECTIONS_BEGIN__", "__ADM_CONNECTIONS_END__"
    ):
        for line in lines[start + 1 : end]:
            if not line.startswith("__ADM_TCP__="):
                continue
            match = _TCP_ROW.fullmatch(line)
            if not match:
                malformed = True
                continue
            family, total_text, established_text, listening_text = match.groups()
            if family in families:
                malformed = True
                continue
            counts = tuple(
                _bounded_count(value)
                for value in (total_text, established_text, listening_text)
            )
            if any(value is None for value in counts):
                malformed = True
                continue
            total, established, listening = counts
            families[family] = {
                "total": total,
                "established": established,
                "listening": listening,
            }
    coverage = (
        "complete"
        if not malformed and set(families) == {"tcp", "tcp6"}
        else "partial"
        if families
        else "unavailable"
    )
    return {
        "coverage": coverage,
        "protocol": "TCP",
        "ipv4": families.get("tcp"),
        "ipv6": families.get("tcp6"),
        "note": "只提供 TCP 連線狀態計數；不輸出本機或遠端 IP、連接埠。",
    }


def build_services_report(output, host, ssh_port, host_id=None):
    return _report(
        "service-observations", parse_services_output(output), host, ssh_port, host_id
    )


def build_ups_report(output, host, ssh_port, host_id=None):
    return _report("ups-observations", parse_ups_output(output), host, ssh_port, host_id)


def build_connections_report(output, host, ssh_port, host_id=None):
    return _report(
        "connection-observations", parse_connections_output(output), host, ssh_port, host_id
    )


def format_services_report(report):
    processes = ", ".join(
        f"{item['name']}={item['process_count']}" for item in report["processes"]
    ) or "no process observations"
    return f"Service process observations: {report['coverage']} | {processes} | counts only; no health judgment."


def format_ups_report(report):
    devices = ", ".join(
        f"UPS {item['index']}: {item['status']}, battery {item['battery_charge_percent']}%"
        if item["battery_charge_percent"] is not None
        else f"UPS {item['index']}: {item['status']}, battery unavailable"
        for item in report["devices"]
    ) or "no UPS observation"
    return f"UPS observations: {report['coverage']} | {devices} | no health judgment or device names."


def format_connections_report(report):
    def family(name, value):
        if value is None:
            return f"{name}=unavailable"
        return (
            f"{name}=total {value['total']}, established {value['established']}, "
            f"listening {value['listening']}"
        )

    return (
        f"TCP connection observations: {report['coverage']} | "
        f"{family('IPv4', report['ipv4'])}; {family('IPv6', report['ipv6'])} | addresses omitted."
    )
