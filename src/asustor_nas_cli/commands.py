"""Fixed, read-only commands verified against ADM 3.5 on an AS-202TE."""

import re

SERVICE_PROCESS_NAMES = (
    "sshd",
    "httpd",
    "nginx",
    "smbd",
    "nmbd",
    "afpd",
    "avahi-daemon",
    "crond",
    "mysqld",
    "minidlna",
    "upsd",
    "upsmon",
)

READ_ONLY_COMMANDS = {
    "system": """printf 'hostname: '; hostname
printf 'kernel: '; uname -srm
printf 'uptime: '; uptime
printf 'cpu: '; grep -m1 'model name' /proc/cpuinfo | cut -d: -f2-
printf 'memory (MiB):\\n'; free -m
if [ -x /usr/builtin/sbin/get_soc_info_utility ]; then
  printf 'SoC: '; /usr/builtin/sbin/get_soc_info_utility NAME STRING
fi""",
    "storage": "df -hP",
    "raid": "cat /proc/mdstat",
    "network": """printf '%s\\n' '--- interfaces ---'; ip -o link show
printf '%s\\n' '--- addresses ---'; ip -o addr show""",
    "disks": "smartctl --scan",
    "services": (
        "printf '%s\\n' '__ADM_SERVICES_BEGIN__'\nfor service in "
        + " ".join(SERVICE_PROCESS_NAMES)
        + """; do
  count=0
  for comm_file in /proc/[0-9]*/comm; do
    [ -r "$comm_file" ] || continue
    IFS= read -r proc_name < "$comm_file" || continue
    [ "$proc_name" = "$service" ] && count=$((count + 1))
  done
  printf '__ADM_SERVICE__=%s|%s\\n' "$service" "$count"
done
printf '%s\\n' '__ADM_SERVICES_END__'"""
    ),
    "ups": """printf '%s\\n' '__ADM_UPS_BEGIN__'
if ! command -v upsc >/dev/null 2>&1; then
  printf '%s\\n' '__ADM_UPS_SOURCE__=none'
  printf '%s\\n' '__ADM_UPS_UNAVAILABLE__=upsc_unavailable'
else
  printf '%s\\n' '__ADM_UPS_SOURCE__=nut'
  ups_names=$(upsc -l localhost 2>/dev/null || true)
  if [ -z "$ups_names" ]; then
    printf '%s\\n' '__ADM_UPS_COUNT__=0'
    printf '%s\\n' '__ADM_UPS_UNAVAILABLE__=server_or_device_unavailable'
  else
    ups_count=$(printf '%s\\n' "$ups_names" | sed '/^$/d' | wc -l | tr -d ' ')
    printf '__ADM_UPS_COUNT__=%s\\n' "$ups_count"
    ups_name=$(printf '%s\\n' "$ups_names" | sed -n "1p")
    if [ -z "$ups_name" ]; then
      printf '%s\\n' '__ADM_UPS_UNAVAILABLE__=unsafe_device_name'
    else
      case "$ups_name" in
        *[!A-Za-z0-9_.-]*)
          printf '%s\\n' '__ADM_UPS_UNAVAILABLE__=unsafe_device_name'
          ;;
        *)
          ups_status=$(upsc "${ups_name}@localhost" ups.status 2>/dev/null || true)
          if [ -z "$ups_status" ]; then
            status=unavailable
          else
            case " $ups_status " in
              *' LB '*) status=low_battery ;;
              *' OB '*) status=on_battery ;;
              *' OL '*) status=online ;;
              *' CHRG '*) status=charging ;;
              *' DISCHRG '*) status=discharging ;;
              *) status=other ;;
            esac
          fi
          charge=$(upsc "${ups_name}@localhost" battery.charge 2>/dev/null || true)
          case "$charge" in
            ''|*[!0-9.]*) charge=unavailable ;;
          esac
          printf '__ADM_UPS_DEVICE__=1|%s|%s\\n' "$status" "$charge"
          ;;
      esac
    fi
  fi
fi
printf '%s\\n' '__ADM_UPS_END__'""",
    "connections": """printf '%s\\n' '__ADM_CONNECTIONS_BEGIN__'
for table in tcp tcp6; do
  table_path="/proc/net/$table"
  if [ ! -r "$table_path" ]; then
    printf '__ADM_TCP__=%s|unavailable|unavailable|unavailable\\n' "$table"
    continue
  fi
  total=0
  established=0
  listening=0
  while read slot local_address remote_address state remaining; do
    [ "$slot" = 'sl' ] && continue
    [ -n "$state" ] || continue
    total=$((total + 1))
    case "$state" in
      01) established=$((established + 1)) ;;
      0A) listening=$((listening + 1)) ;;
    esac
  done < "$table_path"
  printf '__ADM_TCP__=%s|%s|%s|%s\\n' "$table" "$total" "$established" "$listening"
done
printf '%s\\n' '__ADM_CONNECTIONS_END__'""",
    "security": """if command -v netstat >/dev/null 2>&1; then
  netstat -lnt 2>/dev/null
else
  printf '%s\\n' '__ADM_NETSTAT_UNAVAILABLE__'
fi""",
    "disk_topology": """printf '%s\\n' '__ADM_SYSFS_BEGIN__'
for sys_disk in /sys/block/sd* /sys/block/nvme*n*; do
  [ -d \"$sys_disk\" ] || continue
  disk=${sys_disk##*/}
  model=
  sectors=
  [ -r \"$sys_disk/device/model\" ] && model=$(cat \"$sys_disk/device/model\" 2>/dev/null)
  [ -r \"$sys_disk/size\" ] && sectors=$(cat \"$sys_disk/size\" 2>/dev/null)
  printf '__ADM_DISK__=%s|%s|%s\\n' \"$disk\" \"$model\" \"$sectors\"
  for part in \"$sys_disk\"/\"$disk\"[0-9]* \"$sys_disk\"/\"$disk\"p[0-9]*; do
    [ -r \"$part/partition\" ] || continue
    part_name=${part##*/}
    part_number=$(cat \"$part/partition\" 2>/dev/null)
    part_sectors=$(cat \"$part/size\" 2>/dev/null)
    printf '__ADM_PARTITION__=%s|%s|%s|%s\\n' \"$part_name\" \"$disk\" \"$part_number\" \"$part_sectors\"
  done
done
for md_path in /sys/block/md[0-9]*; do
  [ -d \"$md_path/slaves\" ] || continue
  md_name=${md_path##*/}
  for member_path in \"$md_path\"/slaves/*; do
    [ -e \"$member_path\" ] || continue
    printf '__ADM_ARRAY_MEMBER__=%s|%s\\n' \"$md_name\" \"${member_path##*/}\"
  done
done
printf '%s\\n' '__ADM_SYSFS_END__'
printf '%s\\n' '__ADM_MDSTAT_BEGIN__'
cat /proc/mdstat 2>/dev/null
printf '%s\\n' '__ADM_MDSTAT_END__'
printf '%s\\n' '__ADM_MOUNTS_BEGIN__'
while read source mountpoint fstype rest; do
  case \"$mountpoint\" in
    /volume[0-9]*) printf '__ADM_VOLUME__=%s|%s|%s\\n' \"$source\" \"$mountpoint\" \"$fstype\" ;;
  esac
done < /proc/mounts
printf '%s\\n' '__ADM_MOUNTS_END__'""",
}

DOCTOR_SECTIONS = ("system", "storage", "raid", "network", "disks")
HEALTH_OBSERVATION_SECTIONS = ("services", "ups", "connections")


def build_remote_command(section_names):
    """Build a shell command only from the fixed command table above."""
    sections = []
    for section_name in section_names:
        command = READ_ONLY_COMMANDS[section_name]
        marker = f"__ADM_SECTION_{section_name}__"
        sections.append(f"printf '%s\\n' '{marker}'; {command}")
    return "set -e; " + "; ".join(sections)


def parse_sections(output, section_names):
    sections = {name: "" for name in section_names}
    marker_pattern = re.compile(r"__ADM_SECTION_([A-Za-z0-9_]+)__")
    markers = list(marker_pattern.finditer(output))
    requested_order = {name: index for index, name in enumerate(section_names)}
    encountered = [
        requested_order[match.group(1)]
        for match in markers
        if match.group(1) in requested_order
    ]
    if encountered != sorted(encountered) or len(encountered) != len(set(encountered)):
        return sections

    for index, marker in enumerate(markers):
        name = marker.group(1)
        if name not in sections:
            continue
        end = markers[index + 1].start() if index + 1 < len(markers) else len(output)
        sections[name] = output[marker.end():end].strip()
    return sections
