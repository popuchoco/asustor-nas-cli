import unittest

from asustor_nas_cli.cli_parser import build_parser
from asustor_nas_cli.temperature import (
    build_temperature_command,
    format_temperature,
    parse_temperature_output,
)


class TemperatureTests(unittest.TestCase):
    def test_command_only_reads_generic_thermal_zone_sysfs(self):
        command = build_temperature_command()
        self.assertIn("/sys/class/thermal/thermal_zone[0-9]*/temp", command)
        self.assertNotIn("/sys/class/hwmon", command)
        self.assertIn('cat "$path"', command)
        self.assertNotIn("modprobe", command)
        self.assertNotIn("echo", command.replace("printf", ""))

    def test_parses_thermal_values_as_observations(self):
        report = parse_temperature_output(
            "__ADM_TEMP_BEGIN__\n"
            "__ADM_TEMP_SENSOR__=thermal_zone0|42000\n"
            "__ADM_TEMP_END__",
            host="NAS",
            ssh_port=22,
        )
        self.assertEqual(report["coverage"], "complete")
        self.assertEqual(report["summary"]["sensor_count"], 1)
        self.assertEqual(report["summary"]["minimum_celsius"], 42.0)
        self.assertEqual(report["summary"]["maximum_celsius"], 42.0)
        self.assertFalse(report["scope"]["thresholds_applied"])
        self.assertIn("42.000°C", format_temperature(report))

    def test_partial_markers_bad_values_and_duplicate_sensors_are_visible(self):
        partial = parse_temperature_output(
            "__ADM_TEMP_BEGIN__\n"
            "__ADM_TEMP_SENSOR__=thermal_zone0|41000\n"
            "__ADM_TEMP_SENSOR__=thermal_zone1|unknown\n"
        )
        duplicate = parse_temperature_output(
            "__ADM_TEMP_BEGIN__\n"
            "__ADM_TEMP_SENSOR__=thermal_zone0|41000\n"
            "__ADM_TEMP_SENSOR__=thermal_zone0|42000\n"
            "__ADM_TEMP_END__"
        )
        self.assertEqual(partial["coverage"], "partial")
        self.assertEqual(partial["parse_errors"], 1)
        self.assertEqual(duplicate["coverage"], "partial")
        self.assertEqual(duplicate["parse_errors"], 1)

    def test_missing_sensor_and_untrusted_identifiers_fail_closed(self):
        missing = parse_temperature_output(
            "__ADM_TEMP_BEGIN__\n__ADM_TEMP_NO_SENSORS__\n__ADM_TEMP_END__"
        )
        invalid = parse_temperature_output(
            "__ADM_TEMP_BEGIN__\n__ADM_TEMP_SENSOR__=thermal_zone0;evil|41000\n__ADM_TEMP_END__"
        )
        self.assertEqual(missing["coverage"], "unavailable")
        self.assertEqual(invalid["coverage"], "unavailable")
        self.assertEqual(invalid["sensors"], [])
        self.assertEqual(invalid["parse_errors"], 1)

    def test_parser_exposes_temperature_command(self):
        args = build_parser().parse_args(
            ["temperature", "--host", "nas.example", "--user", "nas-user"]
        )
        self.assertEqual(args.command, "temperature")


if __name__ == "__main__":
    unittest.main()
