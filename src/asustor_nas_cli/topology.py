"""Read-only physical-disk, software-RAID, and volume topology parsing."""

import re

SECTOR_BYTES = 512


def _integer(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_mdstat(text):
    arrays = {}
    current = None
    for line in text.splitlines():
        header = re.match(r"^(md\d+)\s*:\s*(.*)$", line)
        if header:
            name = header.group(1)
            detail = header.group(2).split()
            current = arrays.setdefault(name, {"name": name, "members": []})
            current["state"] = detail[0] if detail else None
            current["level"] = next((part for part in detail if re.fullmatch(r"raid\d+|linear", part)), None)
            current["members"].extend(re.findall(r"([A-Za-z0-9_-]+)\[\d+\]", header.group(2)))
            continue
        if current is None:
            continue
        status = re.search(r"\[(\d+)/(\d+)\]\s+\[([U_]+)\]", line)
        if status:
            current["expected_members"] = int(status.group(1))
            current["active_members"] = int(status.group(2))
            current["member_status"] = status.group(3)
            current["degraded"] = "_" in status.group(3)
        operation = re.search(r"\b(resync|recovery|reshape|check)\s*=\s*([\d.]+)%", line)
        if operation:
            current["operation"] = operation.group(1)
            current["progress_percent"] = float(operation.group(2))
    for array in arrays.values():
        array["members"] = sorted(set(array["members"]))
        array.setdefault("degraded", None)
    return arrays


def parse_disk_topology(output, host=None):
    disks = {}
    partitions = {}
    array_members = {}
    volumes = []
    mdstat_lines = []
    section = None
    markers = {"sysfs_begin": False, "sysfs_end": False, "mdstat_begin": False, "mdstat_end": False, "mounts_begin": False, "mounts_end": False}
    parse_errors = 0

    for line in output.splitlines():
        if line == "__ADM_SYSFS_BEGIN__":
            markers["sysfs_begin"] = True
            section = "sysfs"
            continue
        if line == "__ADM_SYSFS_END__":
            markers["sysfs_end"] = True
            section = None
            continue
        if line == "__ADM_MDSTAT_BEGIN__":
            markers["mdstat_begin"] = True
            section = "mdstat"
            continue
        if line == "__ADM_MDSTAT_END__":
            markers["mdstat_end"] = True
            section = None
            continue
        if line == "__ADM_MOUNTS_BEGIN__":
            markers["mounts_begin"] = True
            section = "mounts"
            continue
        if line == "__ADM_MOUNTS_END__":
            markers["mounts_end"] = True
            section = None
            continue

        if line.startswith("__ADM_DISK__="):
            values = line.split("=", 1)[1].split("|", 2)
            if len(values) != 3 or not re.fullmatch(r"(?:sd[a-z]+|nvme\d+n\d+)", values[0]):
                parse_errors += 1
                continue
            sectors = _integer(values[2])
            disks[values[0]] = {
                "name": values[0],
                "model": values[1].strip() or None,
                "sectors": sectors,
                "size_bytes": sectors * SECTOR_BYTES if sectors is not None else None,
                "partitions": [],
                "arrays": [],
            }
            continue
        if line.startswith("__ADM_PARTITION__="):
            values = line.split("=", 1)[1].split("|", 3)
            if len(values) != 4 or values[1] not in disks:
                parse_errors += 1
                continue
            sectors = _integer(values[3])
            partitions[values[0]] = {
                "name": values[0],
                "disk": values[1],
                "number": _integer(values[2]),
                "sectors": sectors,
                "size_bytes": sectors * SECTOR_BYTES if sectors is not None else None,
                "arrays": [],
            }
            disks[values[1]]["partitions"].append(values[0])
            continue
        if line.startswith("__ADM_ARRAY_MEMBER__="):
            values = line.split("=", 1)[1].split("|", 1)
            if len(values) != 2 or not re.fullmatch(r"md\d+", values[0]):
                parse_errors += 1
                continue
            array_members.setdefault(values[0], set()).add(values[1])
            continue
        if line.startswith("__ADM_VOLUME__="):
            values = line.split("=", 1)[1].split("|", 2)
            if len(values) != 3:
                parse_errors += 1
                continue
            volumes.append({"source": values[0], "mountpoint": values[1], "filesystem": values[2]})
            continue
        if section == "mdstat" and line.strip():
            mdstat_lines.append(line)
        elif line.strip() and line.startswith("__ADM_"):
            parse_errors += 1

    arrays = parse_mdstat("\n".join(mdstat_lines))
    for name, members in array_members.items():
        item = arrays.setdefault(name, {"name": name, "state": None, "level": None, "degraded": None})
        item["members"] = sorted(set(item.get("members", [])) | members)

    for name, array in arrays.items():
        array["volumes"] = sorted(
            volume["mountpoint"]
            for volume in volumes
            if volume["source"].rstrip("/").split("/")[-1] == name
        )
        for member in array["members"]:
            partition = partitions.get(member)
            if partition:
                partition["arrays"].append(name)
                disk = disks.get(partition["disk"])
                if disk:
                    disk["arrays"].append(name)

    for disk in disks.values():
        disk["partitions"].sort()
        disk["arrays"] = sorted(set(disk["arrays"]))
    for partition in partitions.values():
        partition["arrays"].sort()

    sysfs_complete = markers["sysfs_begin"] and markers["sysfs_end"]
    mdstat_complete = markers["mdstat_begin"] and markers["mdstat_end"]
    mounts_complete = markers["mounts_begin"] and markers["mounts_end"]
    return {
        "schema_version": 1,
        "report_type": "disk-topology",
        "host": host,
        "sector_size_bytes": SECTOR_BYTES,
        "disks": [disks[name] for name in sorted(disks)],
        "partitions": [partitions[name] for name in sorted(partitions)],
        "arrays": [arrays[name] for name in sorted(arrays)],
        "volumes": sorted(volumes, key=lambda item: item["mountpoint"]),
        "coverage": {
            "sysfs_disks": "complete" if sysfs_complete and disks else "unknown",
            "raid_status": "complete" if mdstat_complete else "unknown",
            "volume_mounts": "complete" if mounts_complete else "unknown",
            "parse_errors": parse_errors,
        },
        "limits": {
            "smart_health_read": False,
            "serial_numbers_included": False,
            "sysfs_size_unit": "512-byte sectors",
        },
        "summary": {
            "disk_count": len(disks),
            "array_count": len(arrays),
            "degraded_arrays": sorted(name for name, item in arrays.items() if item.get("degraded") is True),
            "state": "degraded" if any(item.get("degraded") is True for item in arrays.values()) else "observed",
        },
    }


def format_disk_topology(report):
    lines = [f"Disk topology: {report.get('host') or 'NAS'}"]
    for disk in report["disks"]:
        size = disk["size_bytes"]
        size_text = f"{size / (1024 ** 3):.1f} GiB" if size is not None else "size unknown"
        model = disk["model"] or "model unknown"
        arrays = ", ".join(disk["arrays"]) or "no md array observed"
        lines.append(f"  {disk['name']}: {model}, {size_text}; arrays: {arrays}")
    for array in report["arrays"]:
        member_state = array.get("member_status") or "member status unknown"
        state = "degraded" if array.get("degraded") is True else array.get("state") or "state unknown"
        members = ", ".join(array.get("members", [])) or "members unknown"
        volumes = ", ".join(array.get("volumes", [])) or "no volume mount observed"
        lines.append(f"  {array['name']}: {state} {array.get('level') or ''} [{member_state}]; {members}; {volumes}")
    for volume in report["volumes"]:
        lines.append(f"  {volume['mountpoint']}: {volume['source']} ({volume['filesystem']})")
    if not report["disks"]:
        lines.append("  Physical disk metadata unavailable through sysfs.")
    lines.append("SMART health was not read; this report describes topology, not complete drive health.")
    return "\n".join(lines)
