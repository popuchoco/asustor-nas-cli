"""Command-line interface named after ASUSTOR's ADM operating system."""

import sys

from .cli_parser import build_parser, validate_user
from .cli_platform import run_platform
from .cli_report import run_report_render
from .cli_security import run_incident_scan, run_security_audit, run_security_compare
from .cli_smart import collect_smart_health, run_smart_health
from .cli_support import print_json, run_ssh_sections
from .cli_temperature import collect_temperature, run_temperature
from .client import CliError, probe_adm
from .commands import DOCTOR_SECTIONS
from .privacy import REDACTED_HOST, host_fingerprint, redact_sensitive_text
from .summaries import build_diagnostic_summary, build_health_summary, format_diagnostic_summary
from .topology import format_disk_topology, parse_disk_topology


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

def run_read_command(args):
    section_name = "system" if args.command == "status" else args.command
    sections = run_ssh_sections(args, (section_name,))
    if getattr(args, "summary", False):
        report = build_diagnostic_summary(
            args.command,
            sections,
            host=args.host,
            ssh_port=args.port,
            host_id=host_fingerprint(args.host),
        )
        if args.json:
            print_json(report)
        else:
            print(format_diagnostic_summary(report))
        if getattr(args, "exit_on_warning", False):
            return report["summary"]["recommended_exit_code"]
        return 0
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
    if args.summary:
        smart_report, _ = collect_smart_health(args)
        temperature_report, _ = collect_temperature(args)
        report = build_health_summary(
            sections,
            smart_report,
            temperature_report,
            host=args.host,
            ssh_port=args.port,
            warning_celsius=args.temperature_warning_celsius,
            host_id=host_fingerprint(args.host),
        )
        if args.json:
            print_json(report)
        else:
            print(format_diagnostic_summary(report))
        if args.exit_on_warning:
            return report["summary"]["recommended_exit_code"]
        return 0
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
    if args.command == "report" and args.report_action == "render":
        return run_report_render(args)
    if args.command == "mcp":
        from .mcp import serve

        return serve()
    if not args.host:
        parser.error("provide a NAS address with --host or ASUSTOR_HOST")
    if args.timeout < 1:
        parser.error("--timeout must be at least 1 second")
    if getattr(args, "exit_on_warning", False) and not getattr(args, "summary", False):
        parser.error("--exit-on-warning requires --summary")

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
        if args.command == "smart":
            return run_smart_health(args)
        if args.command == "temperature":
            return run_temperature(args)
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
