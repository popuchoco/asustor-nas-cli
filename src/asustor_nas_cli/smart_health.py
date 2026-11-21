"""Read-only SMART health-status command and report parser."""

import re

from .privacy import REDACTED_HOST, host_fingerprint
from .security.common import utc_now

DEVICE_NAME = re.compile(r"(?:sd[a-z]+|nvme\d+n\d+)")
TOOL_ERRORS = {"smartctl_unavailable", "awk_unavailable"}


def build_smart_health_command():
    return r'''printf '%s\n' '__ADM_SMART_BEGIN__'
if ! command -v smartctl >/dev/null 2>&1; then
  printf '%s\n' '__ADM_SMART_ERROR__=smartctl_unavailable'
elif ! command -v awk >/dev/null 2>&1; then
  printf '%s\n' '__ADM_SMART_ERROR__=awk_unavailable'
else
  found_device=0
  for device in /dev/sd[a-z] /dev/nvme[0-9]n[0-9]; do
    [ -b "$device" ] || continue
    found_device=1
    device_name=${device##*/}
    printf '__ADM_SMART_DEVICE__=%s\n' "$device_name"
    smart_output=$(smartctl -H -n standby "$device" 2>&1)
    smart_exit=$?
    printf '%s\n' "$smart_output" | awk '
      /SMART overall-health self-assessment test result:/ {
        sub(/^.*result:[[:space:]]*/, "")
        value = toupper($0)
        if (value == "PASSED" || value == "OK" || value == "GOOD") state = "passed"
        else if (value ~ /FAIL|BAD/) state = "failed"
        else state = "unknown"
        print "__ADM_SMART_HEALTH__=" state
        found = 1
      }
      /SMART Health Status:/ {
        sub(/^.*Status:[[:space:]]*/, "")
        value = toupper($0)
        if (value == "PASSED" || value == "OK" || value == "GOOD") state = "passed"
        else if (value ~ /FAIL|BAD/) state = "failed"
        else state = "unknown"
        print "__ADM_SMART_HEALTH__=" state
        found = 1
      }
      END { if (!found) print "__ADM_SMART_HEALTH__=unknown" }
    '
    printf '__ADM_SMART_EXIT__=%s\n' "$smart_exit"
  done
  [ "$found_device" -eq 1 ] || printf '%s\n' '__ADM_SMART_NO_DEVICES__'
fi
printf '%s\n' '__ADM_SMART_END__'
exit 0'''


def parse_smart_health_output(output, host=None, ssh_port=None, host_id=None):
    lines = output.splitlines()
    begin_markers = [index for index, line in enumerate(lines) if line == "__ADM_SMART_BEGIN__"]
    end_markers = [index for index, line in enumerate(lines) if line == "__ADM_SMART_END__"]
    complete_markers = (
        len(begin_markers) == 1
        and len(end_markers) == 1
        and begin_markers[0] < end_markers[0]
    )
    devices = []
    parse_errors = 0
    tool_error = None
    no_devices = False
    current = None

    for line in lines:
        if line.startswith("__ADM_SMART_DEVICE__="):
            name = line.split("=", 1)[1]
            if not DEVICE_NAME.fullmatch(name):
                parse_errors += 1
                current = None
                continue
            current = {"device": name, "health": "unknown", "tool_exit_code": None}
            devices.append(current)
        elif line.startswith("__ADM_SMART_HEALTH__="):
            value = line.split("=", 1)[1]
            if current is None or value not in {"passed", "failed", "unknown"}:
                parse_errors += 1
            else:
                current["health"] = value
        elif line.startswith("__ADM_SMART_EXIT__="):
            try:
                exit_code = int(line.split("=", 1)[1])
            except ValueError:
                parse_errors += 1
            else:
                if current is None:
                    parse_errors += 1
                else:
                    current["tool_exit_code"] = exit_code
        elif line.startswith("__ADM_SMART_ERROR__="):
            error_code = line.split("=", 1)[1]
            if error_code in TOOL_ERRORS:
                tool_error = error_code
            else:
                tool_error = "unknown_tool_error"
                parse_errors += 1
        elif line == "__ADM_SMART_NO_DEVICES__":
            no_devices = True
        elif line in {"__ADM_SMART_BEGIN__", "__ADM_SMART_END__"} or not line.strip():
            continue
        else:
            parse_errors += 1

    failed_count = sum(device["health"] == "failed" for device in devices)
    unknown_count = sum(
        device["health"] == "unknown" or device["tool_exit_code"] != 0
        for device in devices
    )
    if failed_count:
        state = "failed"
    elif devices and not unknown_count and complete_markers:
        state = "passed"
    else:
        state = "unknown"

    if tool_error or no_devices:
        coverage = "unavailable"
    elif not complete_markers or parse_errors or unknown_count:
        coverage = "partial"
    else:
        coverage = "complete"

    return {
        "schema_version": 1,
        "report_type": "smart-health",
        "generated_at": utc_now(),
        "host": REDACTED_HOST if host else None,
        "host_id": host_id or host_fingerprint(host),
        "ssh_port": ssh_port,
        "scope": {
            "operation": "SMART health status only",
            "self_tests_started": False,
            "device_contents_read": False,
        },
        "coverage": coverage,
        "tool_error": tool_error,
        "parse_errors": parse_errors,
        "devices": devices,
        "summary": {
            "state": state,
            "device_count": len(devices),
            "failed_count": failed_count,
            "unknown_count": unknown_count,
        },
        "notes": [
            "SMART health reads do not replace attribute review, backups, or manufacturer diagnostics.",
            "Drives reported as standby may be left unqueried by smartctl -n standby.",
            "No SMART self-test or data write is requested.",
        ],
    }


def format_smart_health(report):
    summary = report["summary"]
    devices = ", ".join(
        f"/dev/{item['device']}={item['health']}" for item in report["devices"]
    ) or "no supported block devices observed"
    return (
        f"SMART health: {summary['state']} | coverage: {report['coverage']}\n"
        f"Devices: {devices}\n"
        "Only SMART health status was queried; no self-test was started."
    )
