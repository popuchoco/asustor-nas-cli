"""Offline Markdown rendering for structured CLI reports."""

import json
import re

from .privacy import redact_sensitive_text

MAX_REPORT_BYTES = 1_000_000
MAX_MARKDOWN_BYTES = 2_000_000
MAX_MARKDOWN_FIELDS = 5_000
SUPPORTED_REPORT_TYPES = {
    "diagnostic-summary",
    "risk-signals",
    "security-audit",
    "incident-scan",
    "platform-status",
    "disk-topology",
    "smart-health",
    "temperature-observation",
    "service-observations",
    "ups-observations",
    "connection-observations",
    "report-comparison",
    "comparison",
    "platform-module-operation",
}
_REQUIRED_FIELDS = {
    "diagnostic-summary": {"summary": dict},
    "risk-signals": {"summary": dict},
    "security-audit": {"summary": dict, "checks": list},
    "incident-scan": {"summary": dict, "coverage": dict, "findings": list},
    "platform-status": {"dmi": dict, "modules": dict, "conflicts": list, "notes": list},
    "disk-topology": {
        "summary": dict,
        "coverage": dict,
        "disks": list,
        "partitions": list,
        "arrays": list,
        "volumes": list,
    },
    "smart-health": {"summary": dict, "devices": list, "notes": list},
    "temperature-observation": {"summary": dict, "sensors": list, "notes": list},
    "service-observations": {"coverage": str, "processes": list, "note": str},
    "ups-observations": {"coverage": str, "devices": list, "note": str},
    "connection-observations": {},
    "report-comparison": {"changes": dict, "counts": dict},
    "comparison": {"changes": dict, "counts": dict},
    "platform-module-operation": {
        "modules_before": dict,
        "modules_after": dict,
        "modules_expected": dict,
    },
}
_REPORT_TITLES = {
    "diagnostic-summary": "Health summary",
    "risk-signals": "Risk signals",
    "security-audit": "Security audit",
    "incident-scan": "Incident scan",
    "platform-status": "Platform status",
    "disk-topology": "Disk topology",
    "smart-health": "SMART health",
    "temperature-observation": "Temperature observations",
    "service-observations": "Service observations",
    "ups-observations": "UPS observations",
    "connection-observations": "Connection observations",
    "report-comparison": "Health report comparison",
    "comparison": "Security report comparison",
    "platform-module-operation": "Platform module operation",
}
_SENSITIVE_FIELD = re.compile(
    r"(?:password|passwd|secret|credential|token|(?:^|_)(?:user|username|account|ip|mac|address|serial|key|private_key|identity|path|filepath|directory|mountpoint|backup_file|rollback_backup_file)(?:$|_))",
    re.IGNORECASE,
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|secret|token|credential)\b(\s*[:=]\s*)([^\s,;]+)"
)


class ReportFormatError(ValueError):
    """The input is not a supported structured CLI report."""


def _reject_nonstandard_constant(value):
    raise ValueError(f"non-standard JSON constant: {value}")


def parse_report_bytes(payload):
    if len(payload) > MAX_REPORT_BYTES:
        raise ReportFormatError("input exceeds the 1 MB report limit")
    try:
        report = json.loads(
            payload.decode("utf-8"),
            parse_constant=_reject_nonstandard_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ReportFormatError("input is not valid UTF-8 JSON") from error

    if not isinstance(report, dict):
        raise ReportFormatError("JSON report must be an object")
    schema_version = report.get("schema_version")
    if isinstance(schema_version, bool) or not isinstance(schema_version, int) or schema_version != 1:
        raise ReportFormatError("only schema_version 1 reports are supported")
    report_type = report.get("report_type")
    if not isinstance(report_type, str) or report_type not in SUPPORTED_REPORT_TYPES:
        raise ReportFormatError("supported report types do not include this report type")
    for field, expected_type in _REQUIRED_FIELDS[report_type].items():
        if not isinstance(report.get(field), expected_type):
            raise ReportFormatError(f"report field {field} has an invalid shape")
    summary = report.get("summary", {})
    if not isinstance(summary, dict):
        raise ReportFormatError("report field summary has an invalid shape")
    if report_type == "connection-observations":
        if not isinstance(report.get("coverage"), str) or report.get("protocol") != "TCP":
            raise ReportFormatError("connection observation metadata has an invalid shape")
        if "ipv4" not in report or "ipv6" not in report:
            raise ReportFormatError("connection observations require ipv4 and ipv6 fields")
        if report.get("ipv4") is not None and not isinstance(report["ipv4"], dict):
            raise ReportFormatError("report field ipv4 has an invalid shape")
        if report.get("ipv6") is not None and not isinstance(report["ipv6"], dict):
            raise ReportFormatError("report field ipv6 has an invalid shape")
    risk_signals = summary.get("risk_signals", [])
    if not isinstance(risk_signals, list) or any(
        not isinstance(signal, dict) for signal in risk_signals
    ):
        raise ReportFormatError("summary risk_signals must be a list of objects")
    return report


def _display_value(value):
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _inline_code(value):
    value = redact_sensitive_text(value, include_all_ips=True)
    value = _SENSITIVE_ASSIGNMENT.sub(r"\1\2[redacted]", value)
    visible = "".join(
        character if character.isprintable() else f"\\u{ord(character):04x}"
        for character in value
    )
    longest_run = max((len(match) for match in re.findall(r"`+", visible)), default=0)
    delimiter = "`" * (longest_run + 1)
    padding = " " if visible.startswith(("`", " ")) or visible.endswith(("`", " ")) else ""
    return f"{delimiter}{padding}{visible}{padding}{delimiter}"


def _flatten(value, prefix):
    rows = []
    truncated = False

    def visit(item, field, depth):
        nonlocal truncated
        if len(rows) >= MAX_MARKDOWN_FIELDS:
            truncated = True
            return
        if depth >= 32 or not isinstance(item, (dict, list)):
            rows.append((field, _display_value(item)))
            return
        if isinstance(item, dict):
            if not item:
                rows.append((field, "{}"))
                return
            for key, child in item.items():
                if len(rows) >= MAX_MARKDOWN_FIELDS:
                    truncated = True
                    return
                if _SENSITIVE_FIELD.search(str(key)):
                    rows.append((f"{field}.{key}", "[redacted]"))
                else:
                    visit(child, f"{field}.{key}", depth + 1)
            return
        if not item:
            rows.append((field, "[]"))
            return
        for index, child in enumerate(item):
            if len(rows) >= MAX_MARKDOWN_FIELDS:
                truncated = True
                return
            visit(child, f"{field}[{index}]", depth + 1)

    visit(value, prefix, 0)
    if truncated:
        rows.append((prefix, f"[additional fields omitted after {MAX_MARKDOWN_FIELDS} entries]"))
    return rows


def render_report_markdown(report):
    """Render supported schema-v1 reports while omitting raw SSH sections and paths."""
    report_type = report["report_type"]
    summary = report.get("summary", {})
    title = _REPORT_TITLES[report_type]
    lines = [
        f"# ASUSTOR NAS CLI {title}",
        "",
        f"- Report type: {_inline_code(report_type)}",
        f"- Schema version: {_inline_code(str(report['schema_version']))}",
    ]
    if "command" in report:
        lines.append(f"- Command: {_inline_code(_display_value(report['command']))}")
    if "host" in report:
        lines.append("- Host label: `NAS`")
    if "host_id" in report:
        lines.append(f"- Host ID: {_inline_code(_display_value(report['host_id']))}")
    if "ssh_port" in report:
        lines.append(f"- SSH port: {_inline_code(_display_value(report['ssh_port']))}")

    lines.extend(["", "## Summary", ""])
    summary_fields = {
        key: value for key, value in summary.items() if key != "risk_signals"
    }
    if summary_fields:
        for key, value in _flatten(summary_fields, "summary"):
            lines.append(f"- {_inline_code(key)}: {_inline_code(value)}")
    else:
        lines.append("- No summary fields were provided.")

    detail_fields = {
        key: value
        for key, value in report.items()
        if key
        not in {
            "schema_version",
            "report_type",
            "host",
            "host_id",
            "ssh_port",
            "sections",
            "summary",
        }
    }
    if detail_fields:
        lines.extend(["", "## Report details", ""])
        for key, value in _flatten(detail_fields, "report"):
            lines.append(f"- {_inline_code(key)}: {_inline_code(value)}")

    signals = summary.get("risk_signals", [])
    if report_type in {"diagnostic-summary", "risk-signals"}:
        lines.extend(["", "## Risk signals", ""])
    if report_type in {"diagnostic-summary", "risk-signals"} and signals:
        for signal in signals[:MAX_MARKDOWN_FIELDS]:
            severity = _inline_code(_display_value(signal.get("severity", "unknown")))
            code = _inline_code(_display_value(signal.get("code", "unknown")))
            message = _inline_code(_display_value(signal.get("message", "")))
            lines.append(f"- {severity} {code}: {message}")
        if len(signals) > MAX_MARKDOWN_FIELDS:
            lines.append(
                f"- [additional risk signals omitted after {MAX_MARKDOWN_FIELDS} entries]"
            )
    elif report_type in {"diagnostic-summary", "risk-signals"}:
        lines.append("- None reported.")

    lines.extend(
        [
            "",
            "> Raw SSH `sections` and path fields are omitted or redacted. Review operational details before sharing this report.",
            "",
        ]
    )
    markdown = "\n".join(lines)
    if len(markdown.encode("utf-8")) > MAX_MARKDOWN_BYTES:
        raise ReportFormatError("rendered Markdown exceeds the 2 MB output limit")
    return markdown
