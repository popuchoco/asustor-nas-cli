import json

from ..privacy import REDACTED_HOST, host_fingerprint


def load_report(path):
    try:
        with open(path, "r", encoding="utf-8") as report_file:
            report = json.load(report_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError("無法讀取報告檔；請確認路徑、權限與 JSON 格式。") from error
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError("不是支援的 ADM CLI 報告格式")
    if report.get("report_type") not in {"security-audit", "incident-scan"}:
        raise ValueError("此 ADM CLI 報告類型不支援比對")
    if not isinstance(report.get("host"), str) or not report["host"]:
        raise ValueError("此 ADM CLI 報告缺少 NAS host 欄位")
    return report


def _report_items(report):
    report_type = report["report_type"]
    field = "checks" if report_type == "security-audit" else "findings"
    items = report.get(field)
    if not isinstance(items, list):
        raise ValueError(f"{report_type} 報告缺少 {field} 清單")
    keyed = {}
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError(f"{report_type} 報告包含格式錯誤的 {field} 項目")
        key = item["id"]
        if report_type == "incident-scan":
            key += "\0" + str(item.get("path") or item.get("indicator") or "")
        keyed[key] = item
    return keyed


def compare_reports(before, after):
    for field in ("report_type", "rule_set"):
        if before.get(field) != after.get(field):
            raise ValueError(f"前後報告的 {field} 不一致，不能直接比對")
    before_host_id = before.get("host_id") or host_fingerprint(before.get("host"))
    after_host_id = after.get("host_id") or host_fingerprint(after.get("host"))
    if before_host_id != after_host_id:
        raise ValueError("前後報告的 host 不一致，不能直接比對")
    before_items = _report_items(before)
    after_items = _report_items(after)
    changes = {
        "newly_observed": [],
        "no_longer_observed": [],
        "not_reobserved_in_incomplete_scan": [],
        "status_changed": [],
        "unchanged": [],
    }
    is_incident = before["report_type"] == "incident-scan"
    same_scope = not is_incident or (
        before.get("scope", {}).get("volumes") == after.get("scope", {}).get("volumes")
        and before.get("scope", {}).get("filename_suffix")
        == after.get("scope", {}).get("filename_suffix")
    )
    after_complete = not is_incident or (
        after.get("coverage", {}).get("files") == "complete"
        and after.get("coverage", {}).get("portal") == "complete"
        and same_scope
    )

    for key, current in after_items.items():
        previous = before_items.get(key)
        if previous is None:
            changes["newly_observed"].append(current)
        elif previous.get("status") != current.get("status"):
            changes["status_changed"].append(
                {"before": previous, "after": current}
            )
        else:
            changes["unchanged"].append(current)

    for key, previous in before_items.items():
        if key in after_items:
            continue
        bucket = "no_longer_observed" if after_complete else "not_reobserved_in_incomplete_scan"
        changes[bucket].append(previous)

    return {
        "schema_version": 1,
        "report_type": "comparison",
        "compared_type": before["report_type"],
        "host": REDACTED_HOST,
        "host_id": before_host_id,
        "before_generated_at": before.get("generated_at"),
        "after_generated_at": after.get("generated_at"),
        "coverage_before": before.get("coverage"),
        "coverage_after": after.get("coverage"),
        "scope_before": before.get("scope"),
        "scope_after": after.get("scope"),
        "scope_changed": is_incident and not same_scope,
        "coverage_state_changed": is_incident
        and (
            before.get("coverage", {}).get("files") != after.get("coverage", {}).get("files")
            or before.get("coverage", {}).get("portal") != after.get("coverage", {}).get("portal")
        ),
        "changes": changes,
        "counts": {name: len(items) for name, items in changes.items()},
        "note": (
            "檔案或頁面線索未再次出現不代表威脅已清除；掃描無 IOC 也不代表沒有感染。"
            "比對只呈現兩份報告可觀察到的差異。"
        ),
    }
