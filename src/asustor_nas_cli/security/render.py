import json


def format_audit(report):
    lines = [
        f"勒索病毒預防稽核：{report['host']} (ADM {report.get('adm_version') or 'unknown'})",
        f"狀態：{report['summary']['state']}",
    ]
    for item in report["checks"]:
        lines.append(f"[{item['status'].upper()}] {item['title']} — {item['evidence']}")
        if item["status"] in {"fail", "warn", "unknown"}:
            lines.append(f"  建議：{item['recommendation']}")
    lines.append("本報告是有限基線稽核，不代表 NAS 已確認安全。")
    return "\n".join(lines)


def format_incident(report):
    lines = [
        f"DeadBolt IOC 掃描：{report['host']}",
        f"狀態：{report['summary']['state']}",
        f"檔案覆蓋：{report['coverage']['files']} — {report['coverage']['files_reason']}",
        f"管理頁覆蓋：{report['coverage']['portal']} — {report['coverage']['portal_reason']}",
        f"觀察到 IOC 數：{len(report['findings'])}",
    ]
    for finding in report["findings"]:
        detail = finding.get("path") or finding.get("indicator")
        lines.append(f"[IOC] {finding['id']}: {detail}")
    lines.append(report["summary"]["note"])
    return "\n".join(lines)


def format_comparison(report):
    def visible(value):
        raw = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
        return "".join(character if character.isprintable() else f"\\u{ord(character):04x}" for character in raw)

    def detail(item):
        return visible(item.get("path") or item.get("indicator") or item.get("status") or "no item detail")

    lines = [
        f"報告比對：{visible(report['host'])} ({visible(report['compared_type'])})",
        f"涵蓋範圍：before {visible(report.get('coverage_before') or 'not recorded')} → after {visible(report.get('coverage_after') or 'not recorded')}",
        f"新增觀察：{report['counts']['newly_observed']}",
        f"不再觀察：{report['counts']['no_longer_observed']}",
        f"部分掃描或範圍變動未重見：{report['counts']['not_reobserved_in_incomplete_scan']}",
        f"狀態改變：{report['counts']['status_changed']}",
        f"不變：{report['counts']['unchanged']}",
        f"掃描範圍改變：{'是' if report['scope_changed'] else '否'}",
        f"覆蓋狀態改變：{'是' if report['coverage_state_changed'] else '否'}",
    ]
    for item in report["changes"]["newly_observed"]:
        lines.append(f"  [+ NEW] {visible(item.get('id', 'unknown'))}: {detail(item)}")
    for item in report["changes"]["no_longer_observed"]:
        lines.append(f"  [? NOT OBSERVED] {visible(item.get('id', 'unknown'))}: {detail(item)}")
    for item in report["changes"]["not_reobserved_in_incomplete_scan"]:
        lines.append(f"  [? INCOMPLETE / NOT REOBSERVED] {visible(item.get('id', 'unknown'))}: {detail(item)}")
    for change in report["changes"]["status_changed"]:
        before = change.get("before", {})
        after = change.get("after", {})
        lines.append(
            f"  [~ STATUS CHANGED] {visible(after.get('id', before.get('id', 'unknown')))}: "
            f"{visible(before.get('status', 'unknown'))} → {visible(after.get('status', 'unknown'))}; {detail(after)}"
        )
    lines.append(report["note"])
    return "\n".join(lines)
