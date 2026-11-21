"""Guarded platform-module command handlers."""

import json
import os
import sys

from .cli_support import print_json
from .client import CliError, run_ssh
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
