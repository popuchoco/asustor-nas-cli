import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from jsonschema import Draft202012Validator

from asustor_nas_cli.cli_support import print_json
from asustor_nas_cli.platform import (
    DRIVER_MODULES,
    parse_platform_status,
    snapshot_for_backup,
)
from asustor_nas_cli.security import (
    build_incident_report,
    build_security_audit,
    compare_reports,
)
from asustor_nas_cli.smart_health import parse_smart_health_output
from asustor_nas_cli.temperature import parse_temperature_output
from asustor_nas_cli.topology import parse_disk_topology

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
SCHEMAS = {
    path.name.removesuffix(".schema.json"): json.loads(path.read_text(encoding="utf-8"))
    for path in SCHEMA_DIR.glob("*.schema.json")
}
PORTAL = {
    "http_status": 200,
    "asustor_marker": True,
    "tls_verified": True,
    "adm_version": "3.5.9.RWM1",
    "deadbolt_indicators": [],
}


def platform_output():
    lines = [
        "__ADM_PLATFORM_BEGIN__",
        "__ADM_PLATFORM_KERNEL__=6.8.0",
        "__ADM_PLATFORM_DMI_sys_vendor__=Intel Corporation",
        "__ADM_PLATFORM_DMI_product_name__=Jasper Lake Client Platform",
    ]
    lines.extend(
        f"__ADM_PLATFORM_MODULE_{module}__=0"
        for module in (*DRIVER_MODULES, "it87")
    )
    lines.append("__ADM_PLATFORM_END__")
    return "\n".join(lines)


def incident_report():
    return build_incident_report(
        "NAS",
        22,
        scan_output=(
            "__ADM_VOLUME__=/volume1\n"
            "__ADM_SCAN_ELAPSED__=1\n"
            "__ADM_SCAN_EXIT__=0\n"
        ),
        portal=PORTAL,
        host_id="fixture-host",
    )


class PublishedSchemaTests(unittest.TestCase):
    def test_every_published_schema_is_valid_draft_2020_12(self):
        self.assertEqual(len(SCHEMAS), len(list(SCHEMA_DIR.glob("*.json"))))
        for name, schema in SCHEMAS.items():
            with self.subTest(schema=name):
                Draft202012Validator.check_schema(schema)

    def test_all_published_report_schemas_validate_a_sample(self):
        audit = build_security_audit(
            "NAS",
            22,
            "__ADM_NETSTAT_UNAVAILABLE__",
            PORTAL,
            host_id="fixture-host",
        )
        before = incident_report()
        after = incident_report()
        comparison = compare_reports(before, after)
        topology = parse_disk_topology(
            "__ADM_SYSFS_BEGIN__\n"
            "__ADM_DISK__=sda|Example Disk|2048\n"
            "__ADM_SYSFS_END__\n"
            "__ADM_MDSTAT_BEGIN__\n"
            "Personalities : [raid1]\n"
            "__ADM_MDSTAT_END__\n"
            "__ADM_MOUNTS_BEGIN__\n"
            "__ADM_VOLUME__=/dev/sda1|/volume1|ext4\n"
            "__ADM_MOUNTS_END__\n",
            host="NAS",
        )
        topology["host_id"] = "fixture-host"
        status = parse_platform_status(platform_output(), host="NAS", ssh_port=22)
        backup = snapshot_for_backup(status)
        smart = parse_smart_health_output(
            "__ADM_SMART_BEGIN__\n"
            "__ADM_SMART_DEVICE__=sda\n"
            "__ADM_SMART_HEALTH__=passed\n"
            "__ADM_SMART_EXIT__=0\n"
            "__ADM_SMART_END__\n",
            host="NAS",
            ssh_port=22,
        )
        temperature = parse_temperature_output(
            "__ADM_TEMP_BEGIN__\n"
            "__ADM_TEMP_SENSOR__=thermal_zone0|42000\n"
            "__ADM_TEMP_END__\n",
            host="NAS",
            ssh_port=22,
        )
        operation = {
            "schema_version": 1,
            "report_type": "platform-module-operation",
            "host": "NAS",
            "host_id": "fixture-host",
            "action": "load",
            "ok": True,
            "confirmation": "fixture acknowledgement",
            "backup_file": "[local path redacted]",
            "rollback_backup_file": None,
            "backup_scope": "loaded-state snapshot",
            "modules_before": {module: False for module in DRIVER_MODULES},
            "modules_after": {module: True for module in DRIVER_MODULES},
            "modules_expected": {module: True for module in DRIVER_MODULES},
            "note": "Use the reset command to restore the prior module state.",
        }
        samples = {
            "comparison": comparison,
            "disk-topology": topology,
            "incident-scan": before,
            "platform-module-backup": backup,
            "platform-module-operation": operation,
            "platform-status": status,
            "security-audit": audit,
            "smart-health": smart,
            "temperature-observation": temperature,
        }
        self.assertEqual(set(samples), set(SCHEMAS))
        for name, report in samples.items():
            with self.subTest(report=name):
                output = io.StringIO()
                with redirect_stdout(output):
                    print_json(report)
                json_output = json.loads(output.getvalue())
                Draft202012Validator(SCHEMAS[name]).validate(json_output)


if __name__ == "__main__":
    unittest.main()
