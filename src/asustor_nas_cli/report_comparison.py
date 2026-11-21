"""Offline comparison of structured health and risk-signal reports."""

import json
import re
from datetime import datetime

from .privacy import REDACTED_HOST, redact_sensitive_text
from .report_markdown import MAX_REPORT_BYTES, ReportFormatError, parse_report_bytes

MAX_SUMMARY_FIELDS = 5_000
_SENSITIVE_FIELD = re.compile(
    r"(?:password|passwd|secret|credential|token|(?:^|_)(?:user|username|account|ip|mac|address|serial|key|private_key|identity)(?:$|_))",
    re.IGNORECASE,
)
_HOST_ID = re.compile(r"[a-f0-9]{16}\Z")
_REPORT_STATES = {
    "diagnostic-summary": {"observed", "attention", "degraded", "no_arrays", "unknown"},
    "risk-signals": {"observed", "attention", "unknown"},
}


def _validate_structured_report(report):
    report_type = report.get("report_type")
    if not isinstance(report_type, str) or report_type not in _REPORT_STATES:
        raise ValueError("只支援 diagnostic-summary 與 risk-signals 報告。")
    if not isinstance(report.get("host_id"), str) or not _HOST_ID.fullmatch(report["host_id"]):
        raise ValueError("報告的 host_id 格式無效，預期為 16 位十六進位指紋。")
    generated_at = report.get("generated_at")
    if generated_at is not None:
        if not isinstance(generated_at, str):
            raise ValueError("generated_at 必須是 ISO 8601 字串或 null。")
        try:
            timestamp = datetime.fromisoformat(generated_at[:-1] + "+00:00" if generated_at.endswith("Z") else generated_at)
        except ValueError as error:
            raise ValueError("generated_at 必須是 ISO 8601 日期時間。") from error
        if timestamp.tzinfo is None:
            raise ValueError("generated_at 必須包含時區。")
    summary = report.get("summary")
    if not isinstance(summary, dict):
        raise ValueError("報告的 summary 必須是物件。")
    coverage = summary.get("coverage")
    if not isinstance(coverage, str) or coverage not in {"complete", "partial", "unavailable"}:
        raise ValueError("結構化報告缺少有效的 summary.coverage。")
    state = summary.get("state")
    if not isinstance(state, str) or state not in _REPORT_STATES[report_type]:
        raise ValueError("結構化報告缺少有效的 summary.state。")
    if report_type == "diagnostic-summary":
        command = report.get("command")
        if not isinstance(command, str) or command not in {"status", "health", "storage", "raid"}:
            raise ValueError("diagnostic-summary 缺少有效的 command。")
    elif "command" in report and report["command"] is not None:
        raise ValueError("risk-signals 不應包含 command 欄位。")
    signals = summary.get("risk_signals", [])
    if not isinstance(signals, list):
        raise ValueError("summary.risk_signals 必須是清單。")
    seen_codes = set()
    for signal in signals:
        if not isinstance(signal, dict):
            raise ValueError("risk signal 必須是物件。")
        code = signal.get("code")
        severity = signal.get("severity")
        message = signal.get("message")
        if (
            not isinstance(code, str)
            or code not in {"raid_degraded", "smart_failed", "temperature_high"}
            or not isinstance(severity, str)
            or severity not in {"warning", "critical"}
            or not isinstance(message, str)
            or not message
        ):
            raise ValueError("risk signal 缺少有效的 code、severity 或 message。")
        if code in seen_codes:
            raise ValueError("每份報告的 risk signal code 必須唯一。")
        seen_codes.add(code)


def load_structured_report(path):
    try:
        with open(path, "rb") as report_file:
            payload = report_file.read(MAX_REPORT_BYTES + 1)
    except OSError as error:
        raise ValueError("無法讀取結構化報告檔。") from error
    try:
        report = parse_report_bytes(payload)
    except ReportFormatError as error:
        raise ValueError(str(error)) from error
    _validate_structured_report(report)
    return report


def _safe_value(value):
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return redact_sensitive_text(value, include_all_ips=True)


def _flatten_summary(summary):
    fields = {}
    truncated = False

    def visit(value, path, depth):
        nonlocal truncated
        if len(fields) >= MAX_SUMMARY_FIELDS:
            truncated = True
            return
        if depth >= 32 or not isinstance(value, (dict, list)):
            fields[path] = _safe_value(value)
            return
        if isinstance(value, dict):
            if not value:
                fields[path] = "{}"
                return
            for key, item in value.items():
                if len(fields) >= MAX_SUMMARY_FIELDS:
                    truncated = True
                    return
                child_path = f"{path}.{key}"
                if _SENSITIVE_FIELD.search(str(key)):
                    fields[child_path] = "[redacted]"
                else:
                    visit(item, child_path, depth + 1)
            return
        if not value:
            fields[path] = "[]"
            return
        for index, item in enumerate(value):
            if len(fields) >= MAX_SUMMARY_FIELDS:
                truncated = True
                return
            visit(item, f"{path}[{index}]", depth + 1)

    visit({key: value for key, value in summary.items() if key != "risk_signals"}, "summary", 0)
    if truncated:
        raise ValueError(f"summary exceeds the {MAX_SUMMARY_FIELDS}-field comparison limit.")
    return fields


def _signal_map(report):
    return {item["code"]: item for item in report["summary"].get("risk_signals", [])}


def _signal(item):
    return {
        "code": item["code"],
        "severity": item.get("severity", "unknown"),
        "message": _safe_value(item["message"]),
    }


def compare_health_reports(before, after):
    """Compare summaries without treating missing partial observations as cleared."""
    if before.get("report_type") != after.get("report_type"):
        raise ValueError("前後報告的 report_type 不一致，不能直接比對。")
    _validate_structured_report(before)
    _validate_structured_report(after)
    if before["report_type"] == "diagnostic-summary" and before.get("command") != after.get("command"):
        raise ValueError("前後 diagnostic-summary 的 command 不一致，不能直接比對。")
    if before.get("host_id") != after.get("host_id"):
        raise ValueError("前後報告的 host_id 不一致，不能直接比對。")

    old_signals = _signal_map(before)
    new_signals = _signal_map(after)
    before_codes = set(old_signals)
    after_codes = set(new_signals)
    changes = {
        "risk_added": [_signal(new_signals[code]) for code in sorted(after_codes - before_codes)],
        "risk_cleared": [],
        "risk_changed": [],
        "risk_not_reobserved": [],
        "risk_unchanged": [],
        "summary_changed": [],
        "summary_newly_observed": [],
        "summary_removed": [],
        "summary_not_reobserved": [],
    }
    after_complete = after["summary"]["coverage"] == "complete"
    for code in sorted(before_codes & after_codes):
        previous = _signal(old_signals[code])
        current = _signal(new_signals[code])
        if previous == current:
            changes["risk_unchanged"].append(current)
        else:
            changes["risk_changed"].append({"before": previous, "after": current})

    removed_codes = before_codes - after_codes
    removed_bucket = "risk_cleared" if after_complete else "risk_not_reobserved"
    changes[removed_bucket] = [_signal(old_signals[code]) for code in sorted(removed_codes)]

    old_fields = _flatten_summary(before["summary"])
    new_fields = _flatten_summary(after["summary"])
    old_keys = set(old_fields)
    new_keys = set(new_fields)
    changes["summary_changed"] = [
        {"field": key, "before": old_fields[key], "after": new_fields[key]}
        for key in sorted(old_keys & new_keys)
        if old_fields[key] != new_fields[key]
    ]
    changes["summary_newly_observed"] = [
        {"field": key, "value": new_fields[key]} for key in sorted(new_keys - old_keys)
    ]
    removed_fields = [
        {"field": key, "value": old_fields[key]} for key in sorted(old_keys - new_keys)
    ]
    changes["summary_removed" if after_complete else "summary_not_reobserved"] = removed_fields

    counts = {name: len(items) for name, items in changes.items()}
    result = {
        "schema_version": 1,
        "report_type": "report-comparison",
        "compared_type": before["report_type"],
        "command": before.get("command") if before["report_type"] == "diagnostic-summary" else None,
        "host": REDACTED_HOST,
        "host_id": before["host_id"],
        "generated_at_before": before.get("generated_at"),
        "generated_at_after": after.get("generated_at"),
        "summary_state_before": before["summary"].get("state"),
        "summary_state_after": after["summary"].get("state"),
        "coverage_before": before["summary"]["coverage"],
        "coverage_after": after["summary"]["coverage"],
        "changes": changes,
        "counts": counts,
        "note": (
            "比對只反映兩份結構化摘要中的差異。後次覆蓋不完整時，缺少的訊號或欄位標為未重見，"
            "不代表狀況已解除；摘要不是健康診斷。"
        ),
    }
    if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > 2_000_000:
        raise ValueError("comparison output exceeds the 2 MB limit.")
    return result


def format_report_comparison(report):
    def visible(value):
        raw = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
        safe = redact_sensitive_text(raw, include_all_ips=True)
        return "".join(character if character.isprintable() else f"\\u{ord(character):04x}" for character in safe)

    changes = report["changes"]
    lines = [
        f"健康報告比對：{report['command'] or report['compared_type']} / {report['host']}",
        f"前次狀態：{visible(report.get('summary_state_before') or 'unknown')}，覆蓋 {report['coverage_before']}",
        f"本次狀態：{visible(report.get('summary_state_after') or 'unknown')}，覆蓋 {report['coverage_after']}",
        f"新增風險：{report['counts']['risk_added']}；消失：{report['counts']['risk_cleared']}；變化：{report['counts']['risk_changed']}；未重見：{report['counts']['risk_not_reobserved']}",
        f"欄位變化：{report['counts']['summary_changed']}；新觀察：{report['counts']['summary_newly_observed']}；移除：{report['counts']['summary_removed']}；未重見：{report['counts']['summary_not_reobserved']}",
    ]
    for signal in changes["risk_added"]:
        lines.append(f"[+ NEW] {signal['code']} ({signal['severity']}): {visible(signal['message'])}")
    for signal in changes["risk_cleared"]:
        lines.append(f"[- CLEARED] {signal['code']}: {visible(signal['message'])}")
    for signal in changes["risk_not_reobserved"]:
        lines.append(f"[? NOT REOBSERVED] {signal['code']}: {visible(signal['message'])}")
    for change in changes["risk_changed"]:
        lines.append(
            f"[~ CHANGED] {change['after']['code']} "
            f"({change['before']['severity']} -> {change['after']['severity']}): "
            f"{visible(change['before']['message'])} -> {visible(change['after']['message'])}"
        )
    for change in changes["summary_changed"]:
        lines.append(
            f"[~ FIELD] {visible(change['field'])}: "
            f"{visible(change['before'])} -> {visible(change['after'])}"
        )
    for item in changes["summary_newly_observed"]:
        lines.append(f"[+ FIELD] {visible(item['field'])}: {visible(item['value'])}")
    for item in changes["summary_removed"]:
        lines.append(f"[- FIELD] {visible(item['field'])}: {visible(item['value'])}")
    for item in changes["summary_not_reobserved"]:
        lines.append(f"[? FIELD NOT REOBSERVED] {visible(item['field'])}: {visible(item['value'])}")
    lines.append(report["note"])
    return "\n".join(lines)
