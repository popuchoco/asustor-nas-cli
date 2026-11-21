"""Shared output and read-only SSH helpers for CLI command handlers."""

import json

from .client import run_ssh
from .commands import build_remote_command, parse_sections
from .privacy import redact_sensitive_text


def print_json(result, compact=False):
    if compact:
        print(json.dumps(result, separators=(",", ":"), ensure_ascii=False))
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))

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
