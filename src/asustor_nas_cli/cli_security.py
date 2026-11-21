"""DeadBolt audit, incident-scan and comparison command handlers."""

import sys

from .cli_support import print_json, run_ssh_sections
from .client import CliError, inspect_adm_portal, run_ssh
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
