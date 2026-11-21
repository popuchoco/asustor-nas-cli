"""Argument parsing and validation for the ADM command line."""

import argparse
import ipaddress
import math
import os
import re

from . import __version__
from .summaries import DEFAULT_TEMPERATURE_WARNING_CELSIUS


def valid_host(value):
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass

    if len(value) <= 253 and all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in value.rstrip(".").split(".")
    ):
        return value
    raise argparse.ArgumentTypeError("host must be an IP address or DNS hostname")

def positive_port(value):
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be from 1 to 65535")
    return port

def bounded_integer(value, minimum, maximum, label):
    try:
        number = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"{label} must be an integer") from error
    if not minimum <= number <= maximum:
        raise argparse.ArgumentTypeError(f"{label} must be from {minimum} to {maximum}")
    return number

def scan_seconds(value):
    return bounded_integer(value, 1, 3600, "--max-seconds")

def scan_hits(value):
    return bounded_integer(value, 1, 10000, "--max-hits")


def temperature_warning(value):
    try:
        temperature = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("temperature warning must be a number") from error
    if not math.isfinite(temperature) or not 1 <= temperature <= 150:
        raise argparse.ArgumentTypeError("temperature warning must be from 1 to 150 °C")
    return temperature

def add_common_arguments(parser, needs_ssh=False):
    parser.add_argument(
        "--host",
        type=valid_host,
        default=os.environ.get("ASUSTOR_HOST"),
        help="NAS IP address or hostname (default: ASUSTOR_HOST)",
    )
    parser.add_argument("--json", action="store_true", help="print JSON output")
    parser.add_argument(
        "--timeout",
        type=int,
        default=8,
        help="connection timeout in seconds (default: 8)",
    )
    if needs_ssh:
        parser.add_argument(
            "--user",
            default=os.environ.get("ASUSTOR_USER"),
            help="SSH account (default: ASUSTOR_USER)",
        )
        parser.add_argument(
            "--port",
            type=positive_port,
            default=positive_port(os.environ.get("ASUSTOR_SSH_PORT", "22")),
            help="SSH port (default: ASUSTOR_SSH_PORT or 22)",
        )
        parser.add_argument(
            "--identity-file",
            default=os.environ.get("ASUSTOR_SSH_IDENTITY_FILE"),
            help="OpenSSH private-key path (default: ASUSTOR_SSH_IDENTITY_FILE)",
        )

def add_probe_arguments(parser):
    parser.add_argument(
        "--https-port",
        type=positive_port,
        default=positive_port(os.environ.get("ASUSTOR_HTTPS_PORT", "8001")),
        help="ADM HTTPS port (default: ASUSTOR_HTTPS_PORT or 8001)",
    )
    parser.add_argument("--ca", help="PEM CA bundle used to verify the ADM certificate")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="skip certificate verification for a known test host",
    )

def build_parser():
    parser = argparse.ArgumentParser(
        prog="adm",
        description="Safety-first diagnostics, ransomware checks and guarded platform-module controls for ASUSTOR ADM NAS devices.",
    )
    parser.add_argument("--version", action="version", version=f"adm {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    probe = commands.add_parser("probe", help="check the ADM HTTPS portal")
    add_common_arguments(probe)
    add_probe_arguments(probe)

    doctor = commands.add_parser("doctor", help="check HTTPS and read NAS status over SSH")
    add_common_arguments(doctor, needs_ssh=True)
    add_probe_arguments(doctor)

    health = commands.add_parser("health", help="collect read-only system and storage observations")
    add_common_arguments(health, needs_ssh=True)
    health.add_argument("--summary", action="store_true", help="include structured RAID, SMART and temperature observations")
    health.add_argument("--exit-on-warning", action="store_true", help="return the summary's recommended nonzero exit code for warnings or incomplete coverage")
    health.add_argument("--temperature-warning-celsius", type=temperature_warning, default=DEFAULT_TEMPERATURE_WARNING_CELSIUS, help="advisory thermal-zone threshold in °C for `health --summary` (default: 80)")

    for name, description in (
        ("status", "read system, CPU and memory information over SSH"),
        ("storage", "read mounted filesystem capacity over SSH"),
        ("raid", "read Linux software RAID status over SSH"),
        ("network", "read network interface status over SSH"),
        ("disks", "list disks visible to ADM smartctl over SSH"),
        ("smart", "read SMART health status without starting drive tests"),
        ("temperature", "read sysfs temperature observations without applying health thresholds"),
        ("disk-topology", "map physical disks, Linux RAID members, and volume mounts"),
    ):
        command_parser = commands.add_parser(name, help=description)
        add_common_arguments(command_parser, needs_ssh=True)
        if name in {"status", "storage", "raid"}:
            command_parser.add_argument("--summary", action="store_true", help="include structured summary and preserve raw sections")
        if name == "raid":
            command_parser.add_argument("--exit-on-warning", action="store_true", help="return the summary's recommended nonzero exit code for degraded or unavailable RAID status")

    security = commands.add_parser("security", help="audit ransomware prevention and compare reports")
    security_commands = security.add_subparsers(dest="security_action", required=True)

    audit = security_commands.add_parser("audit", help="audit read-only DeadBolt prevention controls")
    add_common_arguments(audit, needs_ssh=True)
    add_probe_arguments(audit)
    audit.add_argument(
        "--backup-verified",
        action="store_true",
        help="operator confirms backups are current and restore-tested",
    )
    audit.add_argument(
        "--strong-password-confirmed",
        action="store_true",
        help="operator confirms the administrator account password is unique and strong",
    )
    audit.add_argument(
        "--ezconnect-disabled",
        action="store_true",
        help="operator confirms EZ-Connect is disabled",
    )
    audit.add_argument(
        "--remote-access-reviewed",
        action="store_true",
        help="operator confirms router forwarding, UPnP, DDNS, and external access were reviewed",
    )

    compare = security_commands.add_parser("compare", help="compare two saved audit or scan reports")
    compare.add_argument("--before", required=True, help="earlier JSON report")
    compare.add_argument("--after", required=True, help="later JSON report")
    compare.add_argument("--json", action="store_true", help="print JSON output")

    incident = commands.add_parser("incident", help="scan ransomware indicators without changing NAS data")
    incident_commands = incident.add_subparsers(dest="incident_action", required=True)
    scan = incident_commands.add_parser("scan", help="scan volume filenames and the ADM portal for DeadBolt IOCs")
    add_common_arguments(scan, needs_ssh=True)
    add_probe_arguments(scan)
    scan.add_argument(
        "--max-seconds",
        type=scan_seconds,
        default=60,
        help="maximum remote file-scan time in seconds (default: 60)",
    )
    scan.add_argument(
        "--max-hits",
        type=scan_hits,
        default=100,
        help="maximum matching filenames to return (default: 100)",
    )

    report = commands.add_parser("report", help="render supported saved reports offline")
    report_commands = report.add_subparsers(dest="report_action", required=True)
    report_render = report_commands.add_parser(
        "render", help="render a structured JSON summary as Markdown"
    )
    report_render.add_argument(
        "--input",
        required=True,
        help="diagnostic-summary or risk-signals JSON file, or '-' for stdin",
    )

    commands.add_parser("mcp", help="run the read-only MCP server over stdio")

    platform = commands.add_parser("platform", help="inspect or guardedly manage supported ASUSTOR kernel modules")
    platform_commands = platform.add_subparsers(dest="platform_action", required=True)
    platform_status = platform_commands.add_parser("status", help="read kernel, hardware and driver-module status")
    add_common_arguments(platform_status, needs_ssh=True)
    platform_module = platform_commands.add_parser("module", help="load, unload or restore the platform-driver module state")
    add_common_arguments(platform_module, needs_ssh=True)
    module_actions = platform_module.add_mutually_exclusive_group(required=True)
    module_actions.add_argument("--load", dest="module_action", action="store_const", const="load", help="load the supported driver module family")
    module_actions.add_argument("--unload", dest="module_action", action="store_const", const="unload", help="unload the supported driver module family")
    module_actions.add_argument("--reset", dest="module_action", action="store_const", const="reset", help="restore the module state from a prior local backup")
    platform_module.add_argument("--backup", required=True, help="local module-state backup file (created before load/unload; read by --reset)")
    platform_module.add_argument("--rollback-backup", help="local snapshot path to create before --reset (default: <backup>.before-reset.json)")
    platform_module.add_argument("--confirm-risk", action="store_true", help="acknowledge the kernel-module and hardware-control risks")
    platform_module.add_argument("--force", action="store_true", help="skip the interactive second confirmation; --confirm-risk and a valid backup are still required")

    return parser

def validate_user(parser, user):
    if not user:
        parser.error("provide an SSH account with --user or ASUSTOR_USER")
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.@-]*", user):
        parser.error("SSH account contains unsupported characters")
