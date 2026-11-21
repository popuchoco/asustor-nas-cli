"""Fixed, read-only commands verified against ADM 3.5 on an AS-202TE."""

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
    sections = {}
    for index, section_name in enumerate(section_names):
        marker = f"__ADM_SECTION_{section_name}__"
        following_marker = (
            f"__ADM_SECTION_{section_names[index + 1]}__"
            if index + 1 < len(section_names)
            else None
        )
        start = output.find(marker)
        if start < 0:
            sections[section_name] = ""
            continue
        start += len(marker)
        end = output.find(following_marker, start) if following_marker else -1
        value = output[start:end if end >= 0 else None].strip()
        sections[section_name] = value
    return sections
