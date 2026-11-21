"""Dependency-free, read-only Model Context Protocol server over stdio."""

import ipaddress
import json
import math
import os
import re
import sys
from types import SimpleNamespace

from . import __version__
from .client import CliError, inspect_adm_portal, run_ssh
from .commands import (
    DOCTOR_SECTIONS,
    HEALTH_OBSERVATION_SECTIONS,
    build_remote_command,
    parse_sections,
)
from .platform import build_status_command as build_platform_status_command
from .platform import parse_platform_status
from .privacy import REDACTED_HOST, host_fingerprint, redact_sensitive_text
from .security import (
    build_incident_report,
    build_scan_command,
    build_security_audit,
    compare_reports,
)
from .smart_health import build_smart_health_command, parse_smart_health_output
from .summaries import (
    DEFAULT_TEMPERATURE_WARNING_CELSIUS,
    build_health_summary,
    build_risk_signals_report,
)
from .temperature import build_temperature_command, parse_temperature_output
from .topology import parse_disk_topology

PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
READ_ONLY = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
INSTRUCTIONS = (
    "Read-only tools for one ASUSTOR ADM NAS. SSH commands are fixed and allow-listed. "
    "No tool changes NAS data or services. Temperature readings are observations, not health verdicts. "
    "Coverage is complete when expected observations parse, partial when some are missing or malformed, and unavailable when none are usable. "
    "Summary state is report-specific; unknown or incomplete coverage is not a clean bill of health. "
    "Health summaries include generic configurable thermal advisories. "
    "Report comparison accepts bounded report objects and does not connect to the NAS. "
    "File-name IOC scans are bounded and are not proof of no infection."
)


def _object(properties=None, required=()):
    schema = {"type": "object", "properties": properties or {}, "additionalProperties": False}
    if required:
        schema["required"] = list(required)
    return schema


NO_ARGUMENTS = _object()
SCAN_ARGUMENTS = _object(
    {
        "max_seconds": {"type": "integer", "minimum": 1, "maximum": 3600, "default": 60},
        "max_hits": {"type": "integer", "minimum": 1, "maximum": 10000, "default": 100},
    }
)
AUDIT_ARGUMENTS = _object(
    {
        "backup_verified": {"type": "boolean", "description": "Operator assertion; not read from the NAS."},
        "strong_password_confirmed": {"type": "boolean", "description": "Operator assertion; the password is never read."},
        "ezconnect_disabled": {"type": "boolean", "description": "Operator assertion; not read from the NAS."},
        "remote_access_reviewed": {"type": "boolean", "description": "Operator assertion; router state is not read."},
    }
)
COMPARE_ARGUMENTS = _object(
    {
        "before": {"type": "object", "description": "Earlier security-audit or incident-scan JSON report."},
        "after": {"type": "object", "description": "Later report of the same type and NAS."},
    },
    required=("before", "after"),
)
HEALTH_SUMMARY_ARGUMENTS = _object(
    {
        "temperature_warning_celsius": {
            "type": "number",
            "minimum": 1,
            "maximum": 150,
            "default": DEFAULT_TEMPERATURE_WARNING_CELSIUS,
            "description": "Generic advisory threshold, not a model-specific safety limit.",
        }
    }
)

TOOLS = [
    {"name": "adm_status", "description": "Read system, CPU, memory and uptime observations over fixed SSH commands.", "inputSchema": NO_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_health", "description": "Collect system, storage, RAID, network and disk observations; raw output is not a health guarantee.", "inputSchema": NO_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_health_summary", "description": "Collect read-only system, storage, RAID, SMART, temperature, service, UPS, and TCP observations. Returns a diagnostic-summary with raw sections, per-source coverage, report-specific state, risk signals, and recommended exit code. An unknown state is not a clean bill of health. Optional temperature_warning_celsius defaults to a generic 80 °C advisory, not a model-specific safety limit.", "inputSchema": HEALTH_SUMMARY_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_risk_signals", "description": "Collect the same read-only observations as adm_health_summary and return a concise risk-signals report without raw SSH sections. Signals cover degraded RAID, failed SMART, and readings at or above the generic temperature_warning_celsius threshold (default 80 °C); service, UPS, and TCP observations do not add signals or change state/exit code. Unknown or incomplete coverage is not a clean bill of health.", "inputSchema": HEALTH_SUMMARY_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_storage", "description": "Read mounted filesystem capacity.", "inputSchema": NO_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_raid", "description": "Read Linux software RAID status from /proc/mdstat.", "inputSchema": NO_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_network", "description": "Read network interface and address observations.", "inputSchema": NO_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_disks", "description": "List disk paths reported by smartctl; does not read SMART health attributes.", "inputSchema": NO_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_smart", "description": "Read SMART health status without starting self-tests or waking standby drives.", "inputSchema": NO_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_temperature", "description": "Read temperature values exposed by sysfs; no model-specific health thresholds are applied.", "inputSchema": NO_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_disk_topology", "description": "Map sysfs disk models and sizes to partitions, md arrays and mounted volumes; excludes serial numbers and SMART health.", "inputSchema": NO_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_platform_status", "description": "Read kernel, DMI and loaded-module state to report whether guarded platform-driver control is supported; does not change modules or hardware state.", "inputSchema": NO_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_security_audit", "description": "Read-only DeadBolt prevention baseline; some controls remain unknown or are operator assertions.", "inputSchema": AUDIT_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_security_compare", "description": "Compare two saved security-audit or incident-scan report objects without connecting to the NAS.", "inputSchema": COMPARE_ARGUMENTS, "annotations": READ_ONLY},
    {"name": "adm_incident_scan", "description": "Bounded read-only .deadbolt filename and ADM portal indicator scan; never returns a clean verdict.", "inputSchema": SCAN_ARGUMENTS, "annotations": READ_ONLY},
]


class McpError(RuntimeError):
    """A tool configuration or NAS operation error safe to return to an MCP client."""


def _env_int(name, default, minimum, maximum):
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise McpError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise McpError(f"{name} must be from {minimum} to {maximum}")
    return value


def _valid_host(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return bool(
            len(value) <= 253
            and all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in value.rstrip(".").split(".")
            )
        )


def _settings():
    host = os.environ.get("ASUSTOR_HOST", "").strip()
    user = os.environ.get("ASUSTOR_USER", "").strip()
    if not host or not _valid_host(host):
        raise McpError("Set ASUSTOR_HOST to the NAS IP address or hostname")
    if not user or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.@-]*", user):
        raise McpError("Set ASUSTOR_USER to a valid SSH account")
    insecure = os.environ.get("ASUSTOR_INSECURE", "").lower() in {"1", "true", "yes"}
    return SimpleNamespace(
        host=host,
        user=user,
        port=_env_int("ASUSTOR_SSH_PORT", 22, 1, 65535),
        https_port=_env_int("ASUSTOR_HTTPS_PORT", 8001, 1, 65535),
        timeout=_env_int("ASUSTOR_TIMEOUT", 8, 1, 3600),
        identity_file=os.environ.get("ASUSTOR_SSH_IDENTITY_FILE") or None,
        ca=os.environ.get("ASUSTOR_CA") or None,
        insecure=insecure,
    )


def _ssh_sections(args, names):
    try:
        output = run_ssh(
            args.host,
            args.user,
            args.port,
            build_remote_command(names),
            args.timeout,
            identity_file=args.identity_file,
            batch=True,
        )
    except CliError as error:
        raise McpError(redact_sensitive_text(error, args.host, args.user)) from error
    sections = parse_sections(output, names)
    return {
        name: redact_sensitive_text(
            value,
            args.host,
            args.user,
            include_all_ips=True,
        )
        for name, value in sections.items()
    }


def _portal(args):
    try:
        return inspect_adm_portal(
            args.host,
            args.https_port,
            args.timeout,
            ca_file=args.ca,
            insecure=args.insecure,
        ), None
    except CliError as error:
        return None, redact_sensitive_text(error, args.host, args.user)


def _collect_smart_report(args):
    try:
        output = run_ssh(
            args.host,
            args.user,
            args.port,
            build_smart_health_command(),
            max(args.timeout, 60),
            identity_file=args.identity_file,
            batch=True,
        )
        return parse_smart_health_output(
            output,
            host=REDACTED_HOST,
            ssh_port=args.port,
            host_id=host_fingerprint(args.host),
        )
    except CliError as error:
        report = parse_smart_health_output(
            "",
            host=REDACTED_HOST,
            ssh_port=args.port,
            host_id=host_fingerprint(args.host),
        )
        report["coverage"] = "unavailable"
        report["tool_error"] = "ssh_unavailable"
        report["notes"].append(redact_sensitive_text(error, args.host, args.user))
        return report


def _collect_temperature_report(args):
    try:
        output = run_ssh(
            args.host,
            args.user,
            args.port,
            build_temperature_command(),
            args.timeout,
            identity_file=args.identity_file,
            batch=True,
        )
        return parse_temperature_output(
            output,
            host=REDACTED_HOST,
            ssh_port=args.port,
            host_id=host_fingerprint(args.host),
        )
    except CliError as error:
        report = parse_temperature_output(
            "",
            host=REDACTED_HOST,
            ssh_port=args.port,
            host_id=host_fingerprint(args.host),
        )
        report["coverage"] = "unavailable"
        report["notes"].append(redact_sensitive_text(error, args.host, args.user))
        return report


def _collect_health_summary(args, warning_celsius):
    sections = _ssh_sections(args, (*DOCTOR_SECTIONS, *HEALTH_OBSERVATION_SECTIONS))
    return build_health_summary(
        sections,
        _collect_smart_report(args),
        _collect_temperature_report(args),
        host=args.host,
        ssh_port=args.port,
        warning_celsius=warning_celsius,
        host_id=host_fingerprint(args.host),
    )


def _validate_arguments(name, arguments):
    schemas = {tool["name"]: tool["inputSchema"] for tool in TOOLS}
    if name not in schemas:
        raise McpError(f"Unknown ADM tool: {name}")
    if not isinstance(arguments, dict):
        raise McpError("Tool arguments must be an object")
    properties = schemas[name]["properties"]
    unknown = set(arguments) - set(properties)
    if unknown:
        raise McpError("Unsupported argument(s): " + ", ".join(sorted(unknown)))
    if name == "adm_incident_scan":
        for key, minimum, maximum in (("max_seconds", 1, 3600), ("max_hits", 1, 10000)):
            value = arguments.get(key)
            if value is not None and (type(value) is not int or not minimum <= value <= maximum):
                raise McpError(f"{key} must be an integer from {minimum} to {maximum}")
    if name == "adm_security_audit":
        for key, value in arguments.items():
            if type(value) is not bool:
                raise McpError(f"{key} must be a boolean")
    if name == "adm_security_compare":
        for key in ("before", "after"):
            report = arguments.get(key)
            if not isinstance(report, dict):
                raise McpError(f"{key} must be a report object")
            if len(json.dumps(report, ensure_ascii=False).encode("utf-8")) > 1_000_000:
                raise McpError(f"{key} report exceeds the 1 MB limit")
            if type(report.get("schema_version")) is not int or report["schema_version"] != 1:
                raise McpError(f"{key} is not a supported ADM CLI report")
            if report.get("report_type") not in {"security-audit", "incident-scan"}:
                raise McpError(f"{key} report type is not supported for comparison")
            if not isinstance(report.get("host"), str) or not report["host"]:
                raise McpError(f"{key} report is missing its host label")
            if not isinstance(report.get("rule_set"), str) or not report["rule_set"]:
                raise McpError(f"{key} report is missing its rule set")
            item_key = "checks" if report["report_type"] == "security-audit" else "findings"
            items = report.get(item_key)
            if not isinstance(items, list) or any(
                not isinstance(item, dict)
                or not isinstance(item.get("id"), str)
                or not isinstance(item.get("status"), str)
                for item in items
            ):
                raise McpError(f"{key} report has invalid {item_key}")
            if report["report_type"] == "incident-scan":
                if not isinstance(report.get("scope"), dict):
                    raise McpError(f"{key} incident report is missing its scope")
                if not isinstance(report.get("coverage"), dict):
                    raise McpError(f"{key} incident report is missing its coverage")
    if name in {"adm_health_summary", "adm_risk_signals"}:
        threshold = arguments.get("temperature_warning_celsius")
        if threshold is not None and (
            isinstance(threshold, bool)
            or not isinstance(threshold, (int, float))
            or not math.isfinite(threshold)
            or not 1 <= threshold <= 150
        ):
            raise McpError("temperature_warning_celsius must be a number from 1 to 150")


def call_tool(name, arguments=None):
    arguments = {} if arguments is None else arguments
    _validate_arguments(name, arguments)
    if name == "adm_security_compare":
        return compare_reports(arguments["before"], arguments["after"])
    args = _settings()

    if name in {"adm_health_summary", "adm_risk_signals"}:
        threshold = arguments.get("temperature_warning_celsius", DEFAULT_TEMPERATURE_WARNING_CELSIUS)
        report = _collect_health_summary(args, threshold)
        return report if name == "adm_health_summary" else build_risk_signals_report(report)

    section_by_tool = {
        "adm_status": ("system",),
        "adm_health": (*DOCTOR_SECTIONS, *HEALTH_OBSERVATION_SECTIONS),
        "adm_storage": ("storage",),
        "adm_raid": ("raid",),
        "adm_network": ("network",),
        "adm_disks": ("disks",),
    }
    if name in section_by_tool:
        sections = _ssh_sections(args, section_by_tool[name])
        return {
            "command": name.removeprefix("adm_"),
            "host": REDACTED_HOST,
            "host_id": host_fingerprint(args.host),
            "ssh_port": args.port,
            "ok": True,
            "sections": sections,
        }
    if name == "adm_smart":
        return _collect_smart_report(args)
    if name == "adm_temperature":
        return _collect_temperature_report(args)
    if name == "adm_disk_topology":
        sections = _ssh_sections(args, ("disk_topology",))
        report = parse_disk_topology(sections["disk_topology"], host=REDACTED_HOST)
        report["host_id"] = host_fingerprint(args.host)
        return report
    if name == "adm_platform_status":
        try:
            output = run_ssh(
                args.host,
                args.user,
                args.port,
                build_platform_status_command(),
                args.timeout,
                identity_file=args.identity_file,
                batch=True,
            )
        except CliError as error:
            raise McpError(redact_sensitive_text(error, args.host, args.user)) from error
        return parse_platform_status(output, host=args.host, ssh_port=args.port)
    if name == "adm_security_audit":
        sections = _ssh_sections(args, ("security",))
        portal, portal_error = _portal(args)
        return build_security_audit(
            REDACTED_HOST,
            args.port,
            sections["security"],
            portal,
            portal_error=portal_error,
            backup_verified=arguments.get("backup_verified", False),
            strong_password_confirmed=arguments.get("strong_password_confirmed", False),
            ezconnect_disabled=arguments.get("ezconnect_disabled", False),
            remote_access_reviewed=arguments.get("remote_access_reviewed", False),
            host_id=host_fingerprint(args.host),
        )
    if name == "adm_incident_scan":
        max_seconds = arguments.get("max_seconds", 60)
        max_hits = arguments.get("max_hits", 100)
        try:
            scan_output = run_ssh(
                args.host,
                args.user,
                args.port,
                build_scan_command(max_seconds, max_hits),
                max(args.timeout, max_seconds + 15),
                identity_file=args.identity_file,
                batch=True,
            )
            scan_error = None
        except CliError as error:
            scan_output = None
            scan_error = redact_sensitive_text(error, args.host, args.user)
        if scan_output is not None:
            scan_output = redact_sensitive_text(scan_output, args.host, args.user, include_all_ips=True)
        portal, portal_error = _portal(args)
        return build_incident_report(
            REDACTED_HOST,
            args.port,
            scan_output=scan_output,
            scan_error=scan_error,
            portal=portal,
            portal_error=portal_error,
            max_seconds=max_seconds,
            max_hits=max_hits,
            host_id=host_fingerprint(args.host),
        )
    raise McpError(f"Unknown ADM tool: {name}")


def _response(request_id, result=None, error=None):
    value = {"jsonrpc": "2.0", "id": request_id}
    value["error" if error is not None else "result"] = error if error is not None else result
    return value


def handle_line(line):
    try:
        request = json.loads(line)
    except (TypeError, ValueError):
        return _response(None, error={"code": -32700, "message": "Parse error"})
    if not isinstance(request, dict) or request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
        request_id = request.get("id") if isinstance(request, dict) else None
        return _response(request_id, error={"code": -32600, "message": "Invalid Request"})

    request_id = request.get("id")
    notification = "id" not in request
    method = request["method"]
    params = request.get("params", {})
    if not isinstance(params, dict):
        return None if notification else _response(request_id, error={"code": -32602, "message": "Invalid params"})
    try:
        if method == "initialize":
            requested_version = params.get("protocolVersion")
            protocol_version = requested_version if requested_version in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
            result = {
                "protocolVersion": protocol_version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "asustor-nas-cli", "version": __version__},
                "instructions": INSTRUCTIONS,
            }
        elif method == "notifications/initialized":
            return None
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            name = params.get("name")
            arguments = params.get("arguments", {})
            if not isinstance(name, str) or not isinstance(arguments, dict):
                return None if notification else _response(
                    request_id, error={"code": -32602, "message": "tools/call requires a name and object arguments"}
                )
            try:
                data = call_tool(name, arguments)
                result = {
                    "content": [{"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=2)}],
                    "structuredContent": data,
                }
            except (CliError, McpError, ValueError) as error:
                message = str(error)
                result = {
                    "isError": True,
                    "content": [{"type": "text", "text": message}],
                    "structuredContent": {"ok": False, "error": message},
                }
        else:
            return None if notification else _response(request_id, error={"code": -32601, "message": "Method not found"})
        return None if notification else _response(request_id, result=result)
    except (TypeError, ValueError) as error:
        return None if notification else _response(request_id, error={"code": -32602, "message": str(error)})


def serve():
    """Serve newline-delimited JSON-RPC on stdin/stdout; diagnostics stay off stdout."""
    for line in sys.stdin:
        response = handle_line(line)
        if response is not None:
            print(json.dumps(response, ensure_ascii=False, separators=(",", ":")), flush=True)
    return 0
