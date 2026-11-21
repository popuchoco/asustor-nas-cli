"""Command-line interface named after ASUSTOR's ADM operating system."""

import argparse
import ipaddress
import json
import os
import re
import sys

from . import __version__
from .client import CliError, inspect_adm_portal, probe_adm, run_ssh
from .commands import DOCTOR_SECTIONS, build_remote_command, parse_sections
from .platform import (
    action_target,
    build_module_change_command,
    build_module_preflight_command,
    build_status_command as build_platform_status_command,
    compatibility_error,
    load_backup as load_platform_backup,
    parse_platform_status,
    snapshot_for_backup,
    validate_backup_target,
    write_backup as write_platform_backup,
)
from .privacy import REDACTED_HOST, host_fingerprint, redact_sensitive_text
from .security import (
    build_incident_report,
    build_scan_command,
    build_security_audit,
    compare_reports,
    format_audit,
    format_comparison,
    format_incident,
    load_report,
)
from .topology import format_disk_topology, parse_disk_topology


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

    for name, description in (
        ("status", "read system, CPU and memory information over SSH"),
        ("storage", "read mounted filesystem capacity over SSH"),
        ("raid", "read Linux software RAID status over SSH"),
        ("network", "read network interface status over SSH"),
        ("disks", "list disks visible to ADM smartctl over SSH"),
        ("disk-topology", "map physical disks, Linux RAID members, and volume mounts"),
    ):
        command_parser = commands.add_parser(name, help=description)
        add_common_arguments(command_parser, needs_ssh=True)

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


def print_json(result):
    print(json.dumps(result, indent=2, ensure_ascii=False))


def run_probe(args):
    try:
        result = probe_adm(
            args.host,
            args.https_port,
            args.timeout,
            ca_file=args.ca,
            insecure=args.insecure,
        )
    except CliError as error:
        safe_error = redact_sensitive_text(error, args.host)
        if args.json:
            print_json({"command": "probe", "host": REDACTED_HOST, "host_id": host_fingerprint(args.host), "ok": False, "error": safe_error})
        else:
            print(f"adm: {safe_error}", file=sys.stderr)
        return 1

    result["command"] = "probe"
    result["host"] = REDACTED_HOST
    result["host_id"] = host_fingerprint(args.host)
    result["ok"] = True
    if args.json:
        print_json(result)
    else:
        tls_state = "verified" if result["tls_verified"] else "not verified"
        version = result["adm_version"] or "version unavailable"
        print(
            f"ADM {version} | HTTP {result['http_status']} | TLS {tls_state} "
            f"| {result['elapsed_ms']} ms"
        )
    return 0


def run_ssh_sections(args, section_names):
    remote_command = build_remote_command(section_names)
    output = run_ssh(
        args.host,
        args.user,
        args.port,
        remote_command,
        args.timeout,
        identity_file=getattr(args, "identity_file", None),
    )
    sections = parse_sections(output, section_names)
    return {
        name: redact_sensitive_text(
            value,
            args.host,
            getattr(args, "user", None),
            include_all_ips=True,
        )
        for name, value in sections.items()
    }


def run_read_command(args):
    section_name = "system" if args.command == "status" else args.command
    sections = run_ssh_sections(args, (section_name,))
    if args.json:
        print_json(
            {
                "command": args.command,
                "host": REDACTED_HOST,
                "host_id": host_fingerprint(args.host),
                "ssh_port": args.port,
                "sections": sections,
            }
        )
    else:
        print(sections[section_name])
    return 0


def run_health(args):
    sections = run_ssh_sections(args, DOCTOR_SECTIONS)
    if args.json:
        print_json(
            {
                "command": "health",
                "host": REDACTED_HOST,
                "host_id": host_fingerprint(args.host),
                "ssh_port": args.port,
                "ok": True,
                "sections": sections,
            }
        )
    else:
        for name, output in sections.items():
            print(f"--- {name} ---")
            print(output or "(no output)")
    return 0


def run_disk_topology(args):
    sections = run_ssh_sections(args, ("disk_topology",))
    report = parse_disk_topology(sections["disk_topology"], host=REDACTED_HOST)
    report["host_id"] = host_fingerprint(args.host)
    if args.json:
        print_json(report)
    else:
        print(format_disk_topology(report))
    return 1 if report["summary"]["state"] == "degraded" else 0


def _read_platform_status(args):
    output = run_ssh(
        args.host,
        args.user,
        args.port,
        build_platform_status_command(),
        args.timeout,
        identity_file=args.identity_file,
    )
    return parse_platform_status(output, host=args.host, ssh_port=args.port)


def _confirm_platform_action(args):
    if not args.confirm_risk:
        raise CliError("module changes require --confirm-risk and a pre-operation backup")
    if args.force:
        return "--force supplied; interactive confirmation skipped after explicit risk acknowledgement"
    phrase = f"{args.module_action.upper()} NAS {host_fingerprint(args.host)}"
    print(
        "WARNING: kernel-module changes can disable GPIO controls, affect LEDs/buttons, "
        "cause instability, or corrupt data. Fan-control side effects are not managed."
    )
    print("A local module-state backup will be created before the remote change.")
    try:
        answer = input(f"Type {phrase} to continue: ")
    except EOFError as error:
        raise CliError("interactive confirmation unavailable; use --force with --confirm-risk and a valid backup") from error
    if answer.strip() != phrase:
        raise CliError("confirmation did not match; no kernel-module change was made")
    return "interactive confirmation completed"


def _format_platform_status(report):
    modules = ", ".join(
        f"{name}={'loaded' if state else 'not loaded'}" for name, state in report["modules"].items()
    )
    support = "preflight passed for guarded control" if report["preflight_passed"] else "read-only / control blocked"
    return (
        f"Platform driver: {support}\n"
        f"Kernel: {report['kernel_release'] or 'unknown'} (minimum 6.1)\n"
        f"Hardware: {report['dmi']['system_vendor'] or 'unknown'} / {report['dmi']['product_name'] or 'unknown'}\n"
        f"Modules: {modules}\n"
        "Fan PWM and LED values are not changed or included in the module-state backup."
    )


def run_platform(args):
    try:
        if args.platform_action == "status":
            report = _read_platform_status(args)
            if args.json:
                print_json(report)
            else:
                print(_format_platform_status(report))
            return 0 if report["coverage"] == "complete" else 1

        if not args.confirm_risk:
            raise CliError("module changes require --confirm-risk and a pre-operation backup")
        backup = load_platform_backup(args.backup) if args.module_action == "reset" else None
        current = _read_platform_status(args)
        if args.module_action == "reset":
            target = validate_backup_target(backup, current)
            compatibility = compatibility_error(current, "reset", target)
        else:
            target = action_target(args.module_action, current)
            compatibility = compatibility_error(current, args.module_action)
        if compatibility:
            raise CliError(compatibility)

        dry_run = build_module_preflight_command(
            target,
            {name: current["modules"][name] for name in target},
        )
        preflight_output = run_ssh(
            args.host,
            args.user,
            args.port,
            dry_run,
            args.timeout,
            identity_file=args.identity_file,
        )
        if "__ADM_PLATFORM_PREFLIGHT_OK__" not in preflight_output:
            raise CliError("kernel module dry-run did not complete; no module change was attempted")

        confirmation = _confirm_platform_action(args)

        if args.module_action != "reset":
            local_backup = snapshot_for_backup(current)
            backup_path = write_platform_backup(args.backup, local_backup)
            rollback_backup_path = None
        else:
            backup_path = os.path.abspath(os.path.expanduser(args.backup))
            rollback_path = args.rollback_backup or (os.path.splitext(backup_path)[0] + ".before-reset.json")
            rollback_backup_path = write_platform_backup(rollback_path, snapshot_for_backup(current))

        remote = build_module_change_command(target)
        output = run_ssh(
            args.host,
            args.user,
            args.port,
            remote,
            max(args.timeout, 60),
            identity_file=args.identity_file,
        )
        after = parse_platform_status(output, host=args.host, ssh_port=args.port)
        actual = {name: after["modules"][name] for name in target}
        ok = (
            after["coverage"] == "complete"
            and actual == target
            and (not target["asustor_it87"] or not after["conflicts"])
        )
        report = {
            "schema_version": 1,
            "report_type": "platform-module-operation",
            "host": REDACTED_HOST,
            "host_id": host_fingerprint(args.host),
            "action": args.module_action,
            "ok": ok,
            "confirmation": confirmation,
            "backup_file": "[local path redacted]",
            "rollback_backup_file": "[local path redacted]" if rollback_backup_path else None,
            "backup_scope": "loaded-state snapshot of the three managed modules only",
            "modules_before": current["modules"],
            "modules_after": after["modules"],
            "modules_expected": target,
            "note": "Use adm platform module --reset --backup FILE to restore the saved loaded-module state.",
        }
        if args.json:
            print_json(report)
        else:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if ok else 1
    except (CliError, ValueError, OSError) as error:
        safe_error = redact_sensitive_text(error, args.host, getattr(args, "user", None))
        if args.json:
            command = "platform status" if args.platform_action == "status" else "platform module"
            print_json({"command": command, "host": REDACTED_HOST, "host_id": host_fingerprint(args.host), "ok": False, "error": safe_error})
        else:
            print(f"adm: {safe_error}", file=sys.stderr)
        return 1


def run_security_audit(args):
    sections = run_ssh_sections(args, ("security",))
    portal = None
    portal_error = None
    try:
        portal = inspect_adm_portal(
            args.host,
            args.https_port,
            args.timeout,
            ca_file=args.ca,
            insecure=args.insecure,
        )
    except CliError as error:
        portal_error = redact_sensitive_text(error, args.host, args.user)
    report = build_security_audit(
        REDACTED_HOST,
        args.port,
        sections["security"],
        portal,
        portal_error=portal_error,
        backup_verified=args.backup_verified,
        strong_password_confirmed=args.strong_password_confirmed,
        ezconnect_disabled=args.ezconnect_disabled,
        remote_access_reviewed=args.remote_access_reviewed,
        host_id=host_fingerprint(args.host),
    )
    if args.json:
        print_json(report)
    else:
        print(format_audit(report))
    if report["summary"]["counts"]["fail"]:
        return 2
    if report["summary"]["counts"]["warn"] or report["summary"]["counts"]["unknown"]:
        return 1
    return 0


def run_incident_scan(args):
    scan_output = None
    scan_error = None
    try:
        scan_output = run_ssh(
            args.host,
            args.user,
            args.port,
            build_scan_command(args.max_seconds, args.max_hits),
            max(args.timeout, args.max_seconds + 15),
            identity_file=args.identity_file,
        )
    except CliError as error:
        scan_error = redact_sensitive_text(error, args.host, args.user)
    if scan_output is not None:
        scan_output = redact_sensitive_text(scan_output, args.host, args.user, include_all_ips=True)

    portal = None
    portal_error = None
    try:
        portal = inspect_adm_portal(
            args.host,
            args.https_port,
            args.timeout,
            ca_file=args.ca,
            insecure=args.insecure,
        )
    except CliError as error:
        portal_error = redact_sensitive_text(error, args.host, args.user)

    report = build_incident_report(
        REDACTED_HOST,
        args.port,
        scan_output=scan_output,
        scan_error=scan_error,
        portal=portal,
        portal_error=portal_error,
        max_seconds=args.max_seconds,
        max_hits=args.max_hits,
        host_id=host_fingerprint(args.host),
    )
    if args.json:
        print_json(report)
    else:
        print(format_incident(report))
    if report["summary"]["state"] == "indicators_observed":
        return 2
    if report["summary"]["state"] == "incomplete":
        return 3
    return 0


def run_security_compare(args):
    try:
        report = compare_reports(load_report(args.before), load_report(args.after))
    except ValueError as error:
        if args.json:
            print_json({"command": "security compare", "ok": False, "error": str(error)})
        else:
            print(f"adm: {error}", file=sys.stderr)
        return 1
    if args.json:
        print_json(report)
    else:
        print(format_comparison(report))
    return 0


def run_doctor(args):
    probe_result = None
    probe_error = None
    try:
        probe_result = probe_adm(
            args.host,
            args.https_port,
            args.timeout,
            ca_file=args.ca,
            insecure=args.insecure,
        )
    except CliError as error:
        probe_error = redact_sensitive_text(error, args.host, args.user)

    ssh_result = None
    ssh_error = None
    try:
        ssh_result = run_ssh_sections(args, DOCTOR_SECTIONS)
    except CliError as error:
        ssh_error = redact_sensitive_text(error, args.host, args.user)

    ok = probe_error is None and ssh_error is None
    if probe_result is not None:
        probe_result["host"] = REDACTED_HOST
        probe_result["host_id"] = host_fingerprint(args.host)
    if args.json:
        result = {
            "command": "doctor",
            "host": REDACTED_HOST,
            "host_id": host_fingerprint(args.host),
            "ok": ok,
            "https": (
                {"ok": True, **probe_result}
                if probe_result is not None
                else {"ok": False, "error": probe_error}
            ),
            "ssh": (
                {"ok": True, "ssh_port": args.port, "sections": ssh_result}
                if ssh_result is not None
                else {"ok": False, "ssh_port": args.port, "error": ssh_error}
            ),
        }
        print_json(result)
    else:
        if probe_result is not None:
            version = probe_result["adm_version"] or "version unavailable"
            tls_state = "verified" if probe_result["tls_verified"] else "not verified"
            print(f"ADM HTTPS: OK, {version}, TLS {tls_state}")
        else:
            print(f"ADM HTTPS: FAILED, {probe_error}")
        if ssh_result is not None:
            print(f"SSH: OK on port {args.port}")
            for name, output in ssh_result.items():
                print(f"\n--- {name} ---")
                print(output or "(no output)")
        else:
            print(f"SSH: FAILED, {ssh_error}")
    return 0 if ok else 1


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "security" and args.security_action == "compare":
        return run_security_compare(args)
    if args.command == "mcp":
        from .mcp import serve

        return serve()
    if not args.host:
        parser.error("provide a NAS address with --host or ASUSTOR_HOST")
    if args.timeout < 1:
        parser.error("--timeout must be at least 1 second")

    if args.command == "probe":
        if args.ca and args.insecure:
            parser.error("--ca and --insecure cannot be used together")
        return run_probe(args)

    if getattr(args, "ca", None) and getattr(args, "insecure", False):
        parser.error("--ca and --insecure cannot be used together")

    if hasattr(args, "user"):
        validate_user(parser, args.user)
    if args.command == "platform":
        return run_platform(args)
    try:
        if args.command == "doctor":
            return run_doctor(args)
        if args.command == "health":
            return run_health(args)
        if args.command == "disk-topology":
            return run_disk_topology(args)
        if args.command == "security" and args.security_action == "audit":
            return run_security_audit(args)
        if args.command == "incident" and args.incident_action == "scan":
            return run_incident_scan(args)
        return run_read_command(args)
    except CliError as error:
        safe_error = redact_sensitive_text(error, args.host, getattr(args, "user", None))
        if args.json:
            print_json(
                {
                    "command": f"{args.command} {getattr(args, 'security_action', '')}".strip()
                    if args.command == "security"
                    else f"{args.command} {getattr(args, 'incident_action', '')}".strip()
                    if args.command == "incident"
                    else args.command,
                    "host": REDACTED_HOST,
                    "host_id": host_fingerprint(args.host),
                    "ok": False,
                    "error": safe_error,
                }
            )
        else:
            print(f"adm: {safe_error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
