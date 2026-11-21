import tempfile
import unittest
from pathlib import Path

from asustor_nas_cli.platform import (
    DRIVER_MODULES,
    action_target,
    build_module_change_command,
    build_module_preflight_command,
    build_status_command,
    compatibility_error,
    load_backup,
    parse_platform_status,
    snapshot_for_backup,
    validate_backup_target,
    write_backup,
)
from asustor_nas_cli.cli import build_parser


def status_output(kernel="6.8.0", vendor="Intel Corporation", product="Jasper Lake Client Platform", loaded=()):
    lines = [
        "__ADM_PLATFORM_BEGIN__",
        f"__ADM_PLATFORM_KERNEL__={kernel}",
        f"__ADM_PLATFORM_DMI_sys_vendor__={vendor}",
        f"__ADM_PLATFORM_DMI_product_name__={product}",
    ]
    for module in (*DRIVER_MODULES, "it87"):
        lines.append(f"__ADM_PLATFORM_MODULE_{module}__={int(module in loaded)}")
    lines.append("__ADM_PLATFORM_END__")
    return "\n".join(lines)


class PlatformModuleTests(unittest.TestCase):
    def test_read_only_status_preflight_accepts_supported_signature(self):
        report = parse_platform_status(status_output(), "192.0.2.10", 22)
        self.assertTrue(report["kernel_supported"])
        self.assertTrue(report["dmi_allowlisted"])
        self.assertTrue(report["preflight_passed"])
        self.assertIsNone(compatibility_error(report, "load"))

    def test_as202te_kernel_is_refused(self):
        report = parse_platform_status(
            status_output("3.4.26", "ASUSTOR Inc.", "AS-202TE"),
            "192.0.2.10",
            22,
        )
        self.assertFalse(report["kernel_supported"])
        self.assertFalse(report["dmi_allowlisted"])
        self.assertIn("6.1", compatibility_error(report, "load"))

    def test_conflicting_it87_only_blocks_load_that_needs_it87(self):
        report = parse_platform_status(status_output(loaded=("it87",)))
        self.assertIn("it87", compatibility_error(report, "load"))
        self.assertIsNone(compatibility_error(report, "unload"))

    def test_module_command_uses_fixed_order_and_never_forces_unload(self):
        load_command = build_module_change_command({name: True for name in DRIVER_MODULES})
        unload_command = build_module_change_command({name: False for name in DRIVER_MODULES})
        self.assertLess(load_command.index("modprobe asustor_gpio_it87"), load_command.index("modprobe asustor_it87"))
        self.assertLess(load_command.index("modprobe asustor_it87"), load_command.index("modprobe asustor\n"))
        self.assertLess(unload_command.index("modprobe -r asustor\n"), unload_command.index("modprobe -r asustor_it87"))
        self.assertNotIn("--force", load_command + unload_command)
        self.assertNotIn("rmmod -f", load_command + unload_command)

    def test_backup_is_local_non_overwriting_and_reset_is_identity_bound(self):
        report = parse_platform_status(status_output(), "nas.example", 22)
        backup = snapshot_for_backup(report)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "before.json"
            self.assertEqual(write_backup(path, backup), path.resolve())
            self.assertEqual(load_backup(path), backup)
            with self.assertRaises(FileExistsError):
                write_backup(path, backup)
        target = validate_backup_target(backup, report)
        self.assertEqual(target, {module: False for module in DRIVER_MODULES})
        other_host = parse_platform_status(status_output(), "other.example", 22)
        with self.assertRaisesRegex(ValueError, "host"):
            validate_backup_target(backup, other_host)
        self.assertEqual(action_target("reset", report, backup), target)

    def test_status_command_has_no_mutating_operations(self):
        command = build_status_command()
        self.assertNotIn("modprobe", command)
        self.assertNotIn("sudo", command)
        self.assertIn("/sys/module/asustor_it87", command)

    def test_module_plan_is_resolved_in_dry_run_before_mutation(self):
        target = {name: True for name in DRIVER_MODULES}
        current = {name: False for name in DRIVER_MODULES}
        command = build_module_preflight_command(target, current)
        self.assertIn("modprobe -n asustor_gpio_it87", command)
        self.assertIn("modprobe -n asustor_it87", command)
        self.assertIn("__ADM_PLATFORM_PREFLIGHT_OK__", command)
        self.assertNotIn("modprobe asustor\n", command)

    def test_cli_requires_explicit_action_backup_and_risk_flag_arguments(self):
        args = build_parser().parse_args(
            [
                "platform",
                "module",
                "--load",
                "--host",
                "nas.example",
                "--user",
                "nas-user",
                "--backup",
                "before.json",
                "--confirm-risk",
            ]
        )
        self.assertEqual(args.module_action, "load")
        self.assertEqual(args.backup, "before.json")
        self.assertTrue(args.confirm_risk)
        self.assertFalse(args.force)


if __name__ == "__main__":
    unittest.main()
