"""Fixed, read-only commands verified against ADM 3.5 on an AS-202TE."""

import re

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
