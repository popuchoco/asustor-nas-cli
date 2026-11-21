"""Offline report commands."""

import sys

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
