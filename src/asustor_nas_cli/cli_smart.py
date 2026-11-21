"""CLI handler for read-only SMART health observations."""

import sys

from .cli_support import print_json
from .client import CliError, run_ssh
from .privacy import REDACTED_HOST, host_fingerprint, redact_sensitive_text
from .smart_health import (
    build_smart_health_command,
    format_smart_health,
    parse_smart_health_output,
)


def run_smart_health(args):
    try:
        output = run_ssh(
            args.host,
            args.user,
            args.port,
            build_smart_health_command(),
            max(args.timeout, 60),
            identity_file=args.identity_file,
        )
        report = parse_smart_health_output(
            output,
            host=REDACTED_HOST,
            ssh_port=args.port,
            host_id=host_fingerprint(args.host),
        )
    except CliError as error:
        safe_error = redact_sensitive_text(error, args.host, args.user)
        report = parse_smart_health_output(
            "",
            host=REDACTED_HOST,
            ssh_port=args.port,
            host_id=host_fingerprint(args.host),
        )
        report["coverage"] = "unavailable"
        report["tool_error"] = "ssh_unavailable"
        report["notes"].append(safe_error)
        if args.json:
            print_json(report)
        else:
            print(f"adm: {safe_error}", file=sys.stderr)
        return 1

    if args.json:
        print_json(report)
    else:
        print(format_smart_health(report))
    if report["summary"]["state"] == "failed":
        return 2
    if report["coverage"] != "complete":
        return 1
    return 0
