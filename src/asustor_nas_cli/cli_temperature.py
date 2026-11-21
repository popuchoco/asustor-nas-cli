"""CLI handler for read-only sysfs temperature observations."""

import sys

from .cli_support import print_json
from .client import CliError, run_ssh
from .privacy import REDACTED_HOST, host_fingerprint, redact_sensitive_text
from .temperature import build_temperature_command, format_temperature, parse_temperature_output


def collect_temperature(args):
    try:
        output = run_ssh(
            args.host,
            args.user,
            args.port,
            build_temperature_command(),
            args.timeout,
            identity_file=args.identity_file,
        )
        report = parse_temperature_output(
            output,
            host=REDACTED_HOST,
            ssh_port=args.port,
            host_id=host_fingerprint(args.host),
        )
    except CliError as error:
        safe_error = redact_sensitive_text(error, args.host, args.user)
        report = parse_temperature_output(
            "",
            host=REDACTED_HOST,
            ssh_port=args.port,
            host_id=host_fingerprint(args.host),
        )
        report["coverage"] = "unavailable"
        report["notes"].append(safe_error)
        return report, safe_error
    return report, None


def run_temperature(args):
    report, error = collect_temperature(args)
    if error:
        if args.json:
            print_json(report)
        else:
            print(f"adm: {error}", file=sys.stderr)
        return 1

    if args.json:
        print_json(report)
    else:
        print(format_temperature(report))
    return 0 if report["coverage"] == "complete" else 1
