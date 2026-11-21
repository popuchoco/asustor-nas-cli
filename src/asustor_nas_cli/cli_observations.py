"""CLI handlers for bounded, read-only operations observations."""

from .cli_support import print_json, run_ssh_sections
from .observations import (
    build_connections_report,
    build_services_report,
    build_ups_report,
    format_connections_report,
    format_services_report,
    format_ups_report,
)
from .privacy import host_fingerprint

_OBSERVATIONS = {
    "services": (build_services_report, format_services_report),
    "ups": (build_ups_report, format_ups_report),
    "connections": (build_connections_report, format_connections_report),
}


def run_observation(args):
    section = args.command
    build_report, format_report = _OBSERVATIONS[section]
    sections = run_ssh_sections(args, (section,))
    report = build_report(
        sections[section],
        host=args.host,
        ssh_port=args.port,
        host_id=host_fingerprint(args.host),
    )
    if args.json:
        print_json(report, compact=args.compact_json)
    else:
        print(format_report(report))
    return 0 if report["coverage"] == "complete" else 1
