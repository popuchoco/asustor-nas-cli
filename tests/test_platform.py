import json
import tempfile
import unittest
from pathlib import Path

from asustor_nas_cli.cli import build_parser
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

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "as202te_live_profile.json"


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
        fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        report = parse_platform_status(
            status_output(fixture["kernel_release"], "ASUSTOR Inc.", fixture["device_model"]),
            "192.0.2.10",
            22,
        )
        self.assertFalse(report["kernel_supported"])
        self.assertFalse(report["dmi_allowlisted"])
        self.assertIn("6.1", compatibility_error(report, "load"))
        self.assertFalse(fixture["platform_module_mutation_attempted"])

    def test_missing_or_malformed_platform_markers_are_partial(self):
        complete = status_output()
        for malformed in (
            complete.replace("__ADM_PLATFORM_END__", ""),
            complete.replace("__ADM_PLATFORM_BEGIN__", "__ADM_PLATFORM_END__"),
        ):
            report = parse_platform_status(malformed, "nas.example", 22)
            self.assertEqual(report["coverage"], "partial")

    def test_duplicate_platform_fields_are_not_treated_as_complete(self):
        malformed = status_output().replace(
            "__ADM_PLATFORM_KERNEL__=6.8.0",
            "__ADM_PLATFORM_KERNEL__=6.8.0\n__ADM_PLATFORM_KERNEL__=6.8.0",
        )
        self.assertEqual(parse_platform_status(malformed)["coverage"], "partial")

    def test_platform_fields_outside_markers_and_invalid_module_values_fail_closed(self):
        complete = status_output()
        spoofed = complete + "\n__ADM_PLATFORM_DMI_product_name__=Jasper Lake Client Platform"
        invalid_module = complete.replace("__ADM_PLATFORM_MODULE_asustor__=0", "__ADM_PLATFORM_MODULE_asustor__=unknown")
        self.assertEqual(parse_platform_status(spoofed)["coverage"], "complete")
        self.assertEqual(parse_platform_status(invalid_module)["coverage"], "partial")

    def test_non_text_and_extreme_kernel_values_fail_closed(self):
        self.assertEqual(parse_platform_status(None)["coverage"], "partial")
        extreme_kernel = status_output().replace("6.8.0", "9" * 5000)
        self.assertFalse(parse_platform_status(extreme_kernel)["kernel_supported"])

    def test_module_operation_result_contains_required_dmi_observations(self):
        command = build_module_change_command({name: True for name in DRIVER_MODULES})
        self.assertIn("__ADM_PLATFORM_DMI_%s__=%s", command)
        self.assertIn("/sys/class/dmi/id/$dmi_field", command)

    def test_module_operation_result_markers_are_accepted(self):
        output = status_output().replace(
            "__ADM_PLATFORM_BEGIN__", "__ADM_PLATFORM_RESULT_BEGIN__"
        ).replace("__ADM_PLATFORM_END__", "__ADM_PLATFORM_RESULT_END__")
        self.assertEqual(parse_platform_status(output)["coverage"], "complete")

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
            original = path.read_bytes()
            with self.assertRaises(FileExistsError):
                write_backup(path, backup)
            self.assertEqual(path.read_bytes(), original)
        target = validate_backup_target(backup, report)
        self.assertEqual(target, {module: False for module in DRIVER_MODULES})
        other_host = parse_platform_status(status_output(), "other.example", 22)
        with self.assertRaisesRegex(ValueError, "host"):
            validate_backup_target(backup, other_host)
        self.assertEqual(action_target("reset", report, backup), target)

    def test_backup_loader_rejects_oversized_local_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            path.write_bytes(b" " * 1_000_001)
            with self.assertRaisesRegex(ValueError, "1 MB size limit"):
                load_backup(path)

    def test_backup_loader_rejects_deeply_nested_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested.json"
            path.write_bytes(b"[" * 5000 + b"]" * 5000)
            with self.assertRaisesRegex(ValueError, "Could not read the platform backup"):
                load_backup(path)

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
