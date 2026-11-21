"""Read-only temperature observations from Linux sysfs."""

import re

from .privacy import REDACTED_HOST, host_fingerprint
from .security.common import utc_now

SENSOR_ID = re.compile(r"thermal_zone[0-9]+")


def build_temperature_command():
    """Return a fixed POSIX-shell query for supported sysfs temperature inputs."""
    return r'''printf '%s\n' '__ADM_TEMP_BEGIN__'
found=0
for path in /sys/class/thermal/thermal_zone[0-9]*/temp; do
  [ -r "$path" ] || continue
  case "$path" in
    */thermal_zone[0-9]*/temp)
      zone=${path%/temp}
      sensor=${zone##*/}
      ;;
    *) continue ;;
  esac
  value=$(cat "$path" 2>/dev/null) || value=__read_error__
  printf '__ADM_TEMP_SENSOR__=%s|%s\n' "$sensor" "$value"
  found=1
done
[ "$found" -eq 1 ] || printf '%s\n' '__ADM_TEMP_NO_SENSORS__'
printf '%s\n' '__ADM_TEMP_END__'
exit 0'''


def parse_temperature_output(output, host=None, ssh_port=None, host_id=None):
    lines = output.splitlines()
    begin_markers = [index for index, line in enumerate(lines) if line == "__ADM_TEMP_BEGIN__"]
    end_markers = [index for index, line in enumerate(lines) if line == "__ADM_TEMP_END__"]
    complete_markers = (
        len(begin_markers) == 1
        and len(end_markers) == 1
        and begin_markers[0] < end_markers[0]
    )
    sensors = []
    seen = set()
    parse_errors = 0
    no_sensors = False

    for line in lines:
        if line.startswith("__ADM_TEMP_SENSOR__="):
            marker = line.split("=", 1)[1]
            sensor, separator, raw_value = marker.partition("|")
            if not separator or not SENSOR_ID.fullmatch(sensor) or sensor in seen:
                parse_errors += 1
                continue
            seen.add(sensor)
            if not re.fullmatch(r"-?[0-9]{1,7}", raw_value):
                parse_errors += 1
                continue
            milli_celsius = int(raw_value)
            if not -273150 <= milli_celsius <= 1000000:
                parse_errors += 1
                continue
            sensors.append({"sensor": sensor, "celsius": round(milli_celsius / 1000, 3)})
        elif line == "__ADM_TEMP_NO_SENSORS__":
            no_sensors = True
        elif line in {"__ADM_TEMP_BEGIN__", "__ADM_TEMP_END__"} or not line.strip():
            continue
        else:
            parse_errors += 1

    if no_sensors or not sensors:
        coverage = "unavailable"
    elif not complete_markers or parse_errors:
        coverage = "partial"
    else:
        coverage = "complete"
    values = [sensor["celsius"] for sensor in sensors]
    return {
        "schema_version": 1,
        "report_type": "temperature-observation",
        "generated_at": utc_now(),
        "host": REDACTED_HOST if host else None,
        "host_id": host_id or host_fingerprint(host),
        "ssh_port": ssh_port,
        "scope": {"operation": "read thermal-zone sysfs temperature inputs", "thresholds_applied": False},
        "coverage": coverage,
        "parse_errors": parse_errors,
        "sensors": sensors,
        "summary": {
            "sensor_count": len(sensors),
            "minimum_celsius": min(values) if values else None,
            "maximum_celsius": max(values) if values else None,
        },
        "notes": [
            "Sensor availability and names vary by ADM kernel, model, and driver.",
            "No model-specific safe-temperature thresholds are applied; readings are observations only.",
        ],
    }


def format_temperature(report):
    values = ", ".join(
        f"{sensor['sensor']}={sensor['celsius']:.3f}°C" for sensor in report["sensors"]
    ) or "no supported temperature inputs observed"
    return f"Temperature observations: {report['coverage']} | {values}"
