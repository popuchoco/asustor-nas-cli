"""Command-line interface named after ASUSTOR's ADM operating system."""

import argparse
import ipaddress
import json
import os
import re
import sys

from .client import CliError, probe_adm, run_ssh
from .commands import DOCTOR_SECTIONS, build_remote_command, parse_sections


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
        description="Read-only command-line diagnostics for ASUSTOR ADM NAS devices.",
    )
    parser.add_argument("--version", action="version", version="adm 0.1.0")
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
    ):
        command_parser = commands.add_parser(name, help=description)
        add_common_arguments(command_parser, needs_ssh=True)

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
        if args.json:
            print_json({"command": "probe", "host": args.host, "ok": False, "error": str(error)})
        else:
            print(f"adm: {error}", file=sys.stderr)
        return 1

    result["command"] = "probe"
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
    output = run_ssh(args.host, args.user, args.port, remote_command, args.timeout)
    return parse_sections(output, section_names)


def run_read_command(args):
    section_name = "system" if args.command == "status" else args.command
    sections = run_ssh_sections(args, (section_name,))
    if args.json:
        print_json(
            {
                "command": args.command,
                "host": args.host,
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
                "host": args.host,
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
        probe_error = str(error)

    ssh_result = None
    ssh_error = None
    try:
        ssh_result = run_ssh_sections(args, DOCTOR_SECTIONS)
    except CliError as error:
        ssh_error = str(error)

    ok = probe_error is None and ssh_error is None
    if args.json:
        result = {
            "command": "doctor",
            "host": args.host,
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
    if not args.host:
        parser.error("provide a NAS address with --host or ASUSTOR_HOST")
    if args.timeout < 1:
        parser.error("--timeout must be at least 1 second")

    if args.command == "probe":
        if args.ca and args.insecure:
            parser.error("--ca and --insecure cannot be used together")
        return run_probe(args)

    if args.command == "doctor" and args.ca and args.insecure:
        parser.error("--ca and --insecure cannot be used together")

    validate_user(parser, args.user)
    try:
        if args.command == "doctor":
            return run_doctor(args)
        if args.command == "health":
            return run_health(args)
        return run_read_command(args)
    except CliError as error:
        if args.json:
            print_json(
                {
                    "command": args.command,
                    "host": args.host,
                    "ok": False,
                    "error": str(error),
                }
            )
        else:
            print(f"adm: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
