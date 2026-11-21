"""Offline report commands."""

import sys

from .cli_support import print_json
from .report_comparison import (
    compare_health_reports,
    format_report_comparison,
    load_structured_report,
)
from .report_markdown import (
    MAX_REPORT_BYTES,
    ReportFormatError,
    parse_report_bytes,
    render_report_markdown,
)


def run_report_render(args):
    try:
        if args.input == "-":
            payload = sys.stdin.buffer.read(MAX_REPORT_BYTES + 1)
        else:
            with open(args.input, "rb") as report_file:
                payload = report_file.read(MAX_REPORT_BYTES + 1)
        report = parse_report_bytes(payload)
        print(render_report_markdown(report))
    except OSError as error:
        print(
            f"adm report render: could not read input report ({error.__class__.__name__})",
            file=sys.stderr,
        )
        return 1
    except ReportFormatError as error:
        print(f"adm report render: {error}", file=sys.stderr)
        return 1
    return 0


def run_report_compare(args):
    try:
        before = load_structured_report(args.before)
        after = load_structured_report(args.after)
        report = compare_health_reports(before, after)
    except ValueError as error:
        if args.json:
            print_json({"command": "report compare", "ok": False, "error": str(error)})
        else:
            print(f"adm report compare: {error}", file=sys.stderr)
        return 1
    if args.json:
        print_json(report)
    else:
        print(format_report_comparison(report))
    return 0
