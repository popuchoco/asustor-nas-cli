"""Read-only DeadBolt posture checks, IOC scanning, and report comparison."""

import json
import re
from datetime import datetime, timezone


ADVISORY_DEADBOLT = "https://www.asustor.com/en/security/security_advisory_detail?id=9"
RELEASE_NOTES = "https://www.asustor.com/zh-tw/service/release_notes"
PROTECTION_GUIDE = "https://www.asustor.com/zh-tw/knowledge/detail/?group_id=628&id=6"
RULE_SET = "asustor-deadbolt-v1"


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _check(check_id, status, title, evidence, recommendation, sources=(), **extra):
    item = {
        "id": check_id,
        "status": status,
        "title": title,
        "evidence": evidence,
        "recommendation": recommendation,
        "sources": list(sources),
    }
    item.update(extra)
    return item


def _firmware_check(adm_version):
    sources = [ADVISORY_DEADBOLT]
    if not adm_version:
        return _check(
            "firmware.deadbolt_patch",
            "unknown",
            "ADM DeadBolt 修補版本",
            "無法從 ADM 管理頁辨識韌體版本。",
            "確認 ADM 版本，並比對 ASUSTOR 公告列出的修補版本。",
            sources,
        )

    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)\.([A-Za-z0-9]+)", adm_version)
    if not match:
        status, evidence = "unknown", f"韌體版本格式無法辨識：{adm_version}。"
    else:
        major, minor, patch = (int(part) for part in match.group(1, 2, 3))
        build = match.group(4).upper()
        numeric = (major, minor, patch)
        status = "unknown"
        evidence = f"公告涵蓋 ADM 3.5 與 4.0；目前版本為 {adm_version}。"

        if (major, minor) == (3, 5):
            if numeric < (3, 5, 9):
                status = "fail"
                evidence = f"{adm_version} 低於公告所列 ADM 3.5 修補線 3.5.9.RUE3。"
            elif numeric == (3, 5, 9) and build in {"RUE3", "RWM1"}:
                status = "pass"
                evidence = (
                    f"{adm_version} 已達 AS-2022-008 的 3.5.9.RUE3 修補版本；"
                    if build == "RUE3"
                    else f"{adm_version} 的 ASUSTOR 發行資訊明確說明已修正 DeadBolt 相關安全問題。"
                )
                if build == "RWM1":
                    sources.append(RELEASE_NOTES)
            elif numeric == (3, 5, 9):
                evidence = (
                    f"{adm_version} 的 build 標記不在本工具核實過的修補版本清單；"
                    "此工具不以字母順序推測 ADM build 的先後。"
                )
            else:
                evidence = f"{adm_version} 不在已核實的 ADM 3.5 修補版本清單。"
        elif (major, minor) == (4, 0):
            if numeric < (4, 0, 5):
                status = "fail"
                evidence = f"{adm_version} 低於公告所列 ADM 4.0 修補線 4.0.5.RUE3。"
            elif numeric == (4, 0, 5) and build == "RUE3":
                status = "pass"
                evidence = f"{adm_version} 已達 AS-2022-008 的 ADM 4.0 修補版本。"
            elif numeric == (4, 0, 5):
                evidence = (
                    f"{adm_version} 與修補版本同屬 4.0.5，但 build 標記尚未核實；"
                    "此工具不以字母順序推測 ADM build 的先後。"
                )
            else:
                status = "pass"
                evidence = f"{adm_version} 高於公告所列 ADM 4.0 修補版 4.0.5.RUE3。"
        elif major > 4 or (major, minor) >= (4, 1):
            status = "pass"
            evidence = (
                f"AS-2022-008 僅列 ADM 3.5 與 4.0 為受影響產品；"
                f"{adm_version} 不在該公告列出的受影響分支。"
            )

    return _check(
        "firmware.deadbolt_patch",
        status,
        "ADM DeadBolt 修補版本",
        evidence,
        "若版本未知或低於修補線，請先查閱 ASUSTOR 對應機種的最新韌體與公告，再安排更新。",
        sources,
    )


def parse_listening_ports(output):
    ports = set()
    if not output or "__ADM_NETSTAT_UNAVAILABLE__" in output:
        return None
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[0].lower() != "tcp" or fields[-1].upper() != "LISTEN":
            continue
        match = re.search(r":(\d+)$", fields[3])
        if match:
            ports.add(int(match.group(1)))
    return ports


def _portal_check(portal, portal_error):
    if portal is None:
        return _check(
            "portal.deadbolt_signature",
            "unknown",
            "ADM 登入頁 DeadBolt 線索",
            portal_error or "未取得 ADM 登入頁內容。",
            "從可信的本機網路檢查 ADM 登入頁，確認頁面沒有勒索訊息或遭竄改。",
            [ADVISORY_DEADBOLT],
        )
    if portal.get("http_status") != 200:
        return _check(
            "portal.deadbolt_signature",
            "unknown",
            "ADM 登入頁 DeadBolt 線索",
            f"管理頁回應 HTTP {portal.get('http_status')}；未能完成頁面比對。",
            "從可信的本機網路人工確認 ADM 登入頁。",
            [ADVISORY_DEADBOLT],
        )
    indicators = portal.get("deadbolt_indicators", [])
    if indicators:
        return _check(
            "portal.deadbolt_signature",
            "fail",
            "ADM 登入頁 DeadBolt 線索",
            "管理頁含有 DeadBolt、bitcoin 或 .deadbolt 字串：" + ", ".join(indicators),
            "視為可能遭入侵；不要只依本掃描結果清除檔案，請依 ASUSTOR 事件應變指引人工處理。",
            [ADVISORY_DEADBOLT, PROTECTION_GUIDE],
            indicators=indicators,
        )
    if not portal.get("asustor_marker"):
        return _check(
            "portal.deadbolt_signature",
            "warn",
            "ADM 登入頁識別",
            "HTTPS 頁面未找到 ASUSTOR 標記；這不等於已確認 DeadBolt。",
            "從可信的本機網路人工確認登入頁是否為預期的 ADM 頁面。",
            [ADVISORY_DEADBOLT],
        )
    if not portal.get("tls_verified"):
        return _check(
            "portal.deadbolt_signature",
            "warn",
            "ADM 登入頁 DeadBolt 線索",
            "頁面有 ASUSTOR 標記且未觀察到 DeadBolt 字串，但 HTTPS 憑證未驗證；頁面內容來源尚未驗證。",
            "為此 NAS 安裝受信任的 TLS 憑證後重新檢查；若頁面外觀異常，請人工確認。",
            [ADVISORY_DEADBOLT],
        )
    return _check(
        "portal.deadbolt_signature",
        "pass",
        "ADM 登入頁 DeadBolt 線索",
        "頁面有 ASUSTOR 標記，且未觀察到本工具使用的 DeadBolt 字串線索；這不是完整惡意程式掃描。",
        "若登入頁外觀異常，仍應人工確認。",
        [ADVISORY_DEADBOLT],
    )


def _operator_check(check_id, title, confirmed, argument, recommendation):
    if confirmed:
        status = "pass"
        detail = f"操作者以 {argument} 確認；此項不是由 NAS 自動驗證。"
    else:
        status = "unknown"
        detail = "CLI 無法從 NAS 讀取此設定，尚未收到操作者確認。"
    return _check(
        check_id,
        status,
        title,
        detail,
        recommendation,
        [PROTECTION_GUIDE],
        evidence_source="operator_assertion" if confirmed else "not_observed",
    )


def build_security_audit(
    host,
    ssh_port,
    listener_output,
    portal,
    portal_error=None,
    backup_verified=False,
    strong_password_confirmed=False,
    ezconnect_disabled=False,
    remote_access_reviewed=False,
):
    checks = [_firmware_check(portal.get("adm_version") if portal else None)]
    checks.append(_portal_check(portal, portal_error))
    if portal is None:
        checks.append(
            _check(
                "portal.tls_verification",
                "unknown",
                "ADM HTTPS 憑證驗證",
                portal_error or "未取得 ADM HTTPS 資訊。",
                "使用受信任的 NAS 憑證或指定正確 CA 憑證。",
                [PROTECTION_GUIDE],
            )
        )
    elif portal.get("tls_verified"):
        checks.append(
            _check(
                "portal.tls_verification",
                "pass",
                "ADM HTTPS 憑證驗證",
                "HTTPS 憑證已通過本機信任驗證。",
                "維持受信任且有效的 HTTPS 憑證。",
                [PROTECTION_GUIDE],
            )
        )
    else:
        checks.append(
            _check(
                "portal.tls_verification",
                "warn",
                "ADM HTTPS 憑證驗證",
                "本次連線略過 HTTPS 憑證驗證；頁面內容無法驗證來源。",
                "安裝受信任的 NAS 憑證，或用正確 CA 憑證重新執行。",
                [PROTECTION_GUIDE],
            )
        )

    ports = parse_listening_ports(listener_output)
    if ports is None:
        checks.append(
            _check(
                "management.default_ports",
                "unknown",
                "ADM 預設管理連接埠",
                "無法讀取本機 TCP 監聽連接埠。",
                "確認 HTTP 8000、HTTPS 8001 已改為非預設連接埠；本機監聽狀態無法判斷路由器是否對外開放。",
                [ADVISORY_DEADBOLT],
            )
        )
    else:
        default_open = sorted(ports.intersection({8000, 8001}))
        if default_open:
            checks.append(
                _check(
                    "management.default_ports",
                    "warn",
                    "ADM 預設管理連接埠",
                    "本機觀察到預設管理連接埠正在監聽：" + ", ".join(str(port) for port in default_open),
                    "ASUSTOR 建議更改預設 HTTP 8000／HTTPS 8001；本機監聽狀態不代表這些埠已對外公開。",
                    [ADVISORY_DEADBOLT, PROTECTION_GUIDE],
                    observed_ports=default_open,
                )
            )
        else:
            checks.append(
                _check(
                    "management.default_ports",
                    "pass",
                    "ADM 預設管理連接埠",
                    "本機 TCP 監聽清單未觀察到 8000 或 8001。",
                    "仍請檢查路由器轉送、UPnP 與外部可達性；本機監聽狀態無法判斷對外暴露。",
                    [ADVISORY_DEADBOLT, PROTECTION_GUIDE],
                )
            )

    checks.append(
        _check(
            "remote_shell.ssh_sftp",
            "warn",
            "SSH／SFTP 服務",
            f"本次成功透過 SSH TCP {ssh_port} 連線；SFTP 子系統與外部可達性未檢查。",
            "若 SSH／SFTP 非必要，請停用；若需要，限制可連線來源並避免直接暴露至網際網路。",
            [ADVISORY_DEADBOLT, PROTECTION_GUIDE],
            observed_ssh_port=ssh_port,
        )
    )
    checks.extend(
        (
            _operator_check(
                "credentials.strong_password",
                "管理帳號密碼",
                strong_password_confirmed,
                "--strong-password-confirmed",
                "確認管理帳號使用唯一且強度足夠的密碼；工具不會讀取或保存密碼。",
            ),
            _operator_check(
                "backup.recovery_ready",
                "備份與還原準備",
                backup_verified,
                "--backup-verified",
                "確認近期備份可用，並定期測試還原；備份應與 NAS 保持隔離。",
            ),
            _operator_check(
                "remote_access.ezconnect_disabled",
                "EZ-Connect",
                ezconnect_disabled,
                "--ezconnect-disabled",
                "若不需要遠端連線，請停用 EZ-Connect。",
            ),
            _operator_check(
                "remote_access.reviewed",
                "外部管理介面暴露",
                remote_access_reviewed,
                "--remote-access-reviewed",
                "檢查路由器埠轉送、UPnP、DDNS 與外部可達的管理服務。",
            ),
        )
    )

    counts = {status: sum(item["status"] == status for item in checks) for status in ("fail", "warn", "unknown", "pass")}
    if counts["fail"]:
        state = "action_required"
    elif counts["warn"]:
        state = "review_recommended"
    elif counts["unknown"]:
        state = "manual_checks_remaining"
    else:
        state = "no_alerts_in_checked_controls"
    return {
        "schema_version": 1,
        "report_type": "security-audit",
        "rule_set": RULE_SET,
        "generated_at": utc_now(),
        "host": host,
        "adm_version": portal.get("adm_version") if portal else None,
        "portal_tls_verified": portal.get("tls_verified") if portal else None,
        "scope_statement": "DeadBolt 預防基線與有限管理頁線索；不是一般防毒或完整入侵鑑識。",
        "checks": checks,
        "summary": {"state": state, "counts": counts},
    }


def _shell_quote(value):
    return "'" + value.replace("'", "'\"'\"'") + "'"


def build_scan_command(max_seconds, max_hits):
    if not 1 <= int(max_seconds) <= 3600:
        raise ValueError("max_seconds must be from 1 to 3600")
    if not 1 <= int(max_hits) <= 10000:
        raise ValueError("max_hits must be from 1 to 10000")
    awk_program = (
        'index($0, "__ADM_VOLUME__=") == 1 { print; next } '
        'index($0, "find:") == 1 { print "__ADM_FIND_ERROR__"; next } '
        f'++hits <= {int(max_hits)} {{ print; next }} '
        '{ print "__ADM_SCAN_TRUNCATED__"; exit }'
    )
    return (
        "set -o pipefail 2>/dev/null\n"
        "for root in /volume[0-9]*; do\n"
        "  [ -d \"$root\" ] || continue\n"
        "  printf '__ADM_VOLUME__=%s\\n' \"$root\"\n"
        "done\n"
        "start=$(date +%s 2>/dev/null)\n"
        "printf '__ADM_SCAN_START__=%s\\n' \"$start\"\n"
        "if [ -x /usr/bin/timeout ]; then\n"
        f"  /usr/bin/timeout -t {int(max_seconds)} find /volume[0-9]* -xdev -type f -iname '*.deadbolt' -print 2>&1 | awk {_shell_quote(awk_program)}\n"
        "  rc=$?\n"
        "else\n"
        "  rc=125\n"
        "fi\n"
        "end=$(date +%s 2>/dev/null)\n"
        "case \"$start:$end\" in *[!0-9:]*|:*) elapsed= ;; *) elapsed=$((end - start)) ;; esac\n"
        "printf '__ADM_SCAN_ELAPSED__=%s\\n' \"$elapsed\"\n"
        "printf '__ADM_SCAN_EXIT__=%s\\n' \"$rc\"\n"
        "exit 0"
    )


def parse_scan_output(output):
    roots = []
    paths = []
    parse_errors = 0
    permission_errors = 0
    truncated = False
    exit_code = None
    elapsed_seconds = None
    for line in output.splitlines():
        if line.startswith("__ADM_VOLUME__="):
            roots.append(line.split("=", 1)[1])
        elif line == "__ADM_SCAN_TRUNCATED__":
            truncated = True
        elif line == "__ADM_FIND_ERROR__":
            permission_errors += 1
        elif line.startswith("__ADM_SCAN_EXIT__="):
            try:
                exit_code = int(line.split("=", 1)[1])
            except ValueError:
                parse_errors += 1
        elif line.startswith("__ADM_SCAN_ELAPSED__="):
            try:
                elapsed_seconds = int(line.split("=", 1)[1])
            except ValueError:
                parse_errors += 1
        elif line.startswith("__ADM_SCAN_START__="):
            continue
        elif line.startswith("/volume") and line.lower().endswith(".deadbolt"):
            paths.append(line)
        elif line.strip():
            parse_errors += 1
    return {
        "volumes": sorted(set(roots)),
        "paths": list(dict.fromkeys(paths)),
        "permission_errors": permission_errors,
        "parse_errors": parse_errors,
        "truncated": truncated,
        "exit_code": exit_code,
        "elapsed_seconds": elapsed_seconds,
    }


def build_incident_report(
    host,
    ssh_port,
    scan_output=None,
    scan_error=None,
    portal=None,
    portal_error=None,
    max_seconds=60,
    max_hits=100,
):
    parsed = parse_scan_output(scan_output or "")
    if scan_error:
        file_coverage = "unavailable"
        file_reason = scan_error
    elif parsed["exit_code"] == 125:
        file_coverage = "unavailable"
        file_reason = "NAS 沒有 /usr/bin/timeout；為避免無界掃描，未啟動檔案搜尋。"
    elif parsed["exit_code"] is None:
        file_coverage = "partial"
        file_reason = "掃描輸出缺少結束狀態標記，無法確認搜尋是否完成。"
    elif not parsed["volumes"]:
        if parsed["exit_code"] != 0 or parsed["parse_errors"]:
            file_coverage = "partial"
            file_reason = f"掃描命令未能辨識掛載點或失敗（結束碼 {parsed['exit_code']}）。"
        else:
            file_coverage = "unavailable"
            file_reason = "沒有發現可掃描的 /volumeN 掛載點。"
    elif (
        parsed["exit_code"] != 0
        or parsed["truncated"]
        or parsed["permission_errors"]
        or parsed["parse_errors"]
        or (parsed["elapsed_seconds"] is not None and parsed["elapsed_seconds"] >= max_seconds)
    ):
        file_coverage = "partial"
        reasons = []
        if parsed["exit_code"] not in (0, None):
            reasons.append(f"掃描結束碼 {parsed['exit_code']}")
        if parsed["truncated"]:
            reasons.append("命中數已達上限")
        if parsed["elapsed_seconds"] is not None and parsed["elapsed_seconds"] >= max_seconds:
            reasons.append(f"到達 {max_seconds} 秒時間上限")
        if parsed["permission_errors"]:
            reasons.append(f"{parsed['permission_errors']} 項 find 錯誤")
        if parsed["parse_errors"]:
            reasons.append(f"{parsed['parse_errors']} 行輸出無法解析")
        file_reason = "；".join(reasons)
    else:
        file_coverage = "complete"
        file_reason = "在時間與命中上限內完成可讀取掛載點的檔名搜尋。"

    if portal is None:
        portal_coverage = "unavailable"
        portal_reason = portal_error or "未取得 ADM 登入頁。"
    elif (
        portal.get("http_status") != 200
        or not portal.get("asustor_marker")
        or not portal.get("tls_verified")
    ):
        portal_coverage = "partial"
        portal_reason = (
            f"HTTP {portal.get('http_status')}，ASUSTOR 頁面標記={portal.get('asustor_marker')}，"
            f"TLS 已驗證={portal.get('tls_verified')}；"
            "需要人工確認頁面。"
        )
    else:
        portal_coverage = "complete"
        portal_reason = "已檢查 ADM HTTPS 頁面的有限 DeadBolt 字串線索。"

    findings = [
        {
            "id": "deadbolt.file_suffix",
            "status": "fail",
            "indicator": ".deadbolt filename suffix",
            "path": path,
            "evidence": "檔名符合 DeadBolt 已知副檔名線索；尚未分析檔案內容。",
            "sources": [ADVISORY_DEADBOLT],
        }
        for path in parsed["paths"]
    ]
    if portal is not None:
        for indicator in portal.get("deadbolt_indicators", []):
            findings.append(
                {
                    "id": "deadbolt.portal_text",
                    "status": "fail",
                    "indicator": indicator,
                    "evidence": "ADM 管理頁出現 DeadBolt 相關字串線索；請人工確認是否為勒索頁面。",
                    "sources": [ADVISORY_DEADBOLT],
                }
            )

    files_ok = file_coverage == "complete"
    portal_ok = portal_coverage == "complete"
    if findings:
        state = "indicators_observed"
    elif files_ok and portal_ok:
        state = "no_ioc_observed"
    else:
        state = "incomplete"

    return {
        "schema_version": 1,
        "report_type": "incident-scan",
        "rule_set": RULE_SET,
        "generated_at": utc_now(),
        "host": host,
        "adm_version": portal.get("adm_version") if portal else None,
        "portal_tls_verified": portal.get("tls_verified") if portal else None,
        "scope": {
            "volumes": parsed["volumes"],
            "filename_suffix": ".deadbolt",
            "max_seconds": max_seconds,
            "max_hits": max_hits,
            "file_contents_scanned": False,
        },
        "coverage": {
            "files": file_coverage,
            "files_reason": file_reason,
            "portal": portal_coverage,
            "portal_reason": portal_reason,
            "permission_errors": parsed["permission_errors"],
            "hit_limit_reached": parsed["truncated"],
            "scan_exit_code": parsed["exit_code"],
            "scan_elapsed_seconds": parsed["elapsed_seconds"],
        },
        "findings": findings,
        "summary": {
            "state": state,
            "ioc_observed": bool(findings),
            "file_ioc_count": len(parsed["paths"]),
            "portal_ioc_count": sum(item["id"] == "deadbolt.portal_text" for item in findings),
            "note": "沒有觀察到 IOC 不代表沒有感染；這不是完整防毒或鑑識掃描。",
        },
    }


def load_report(path):
    try:
        with open(path, "r", encoding="utf-8") as report_file:
            report = json.load(report_file)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"無法讀取報告 {path}: {error}") from error
    if not isinstance(report, dict) or report.get("schema_version") != 1:
        raise ValueError(f"{path} 不是支援的 ADM CLI 報告格式")
    if report.get("report_type") not in {"security-audit", "incident-scan"}:
        raise ValueError(f"{path} 的報告類型不支援比對")
    if not isinstance(report.get("host"), str) or not report["host"]:
        raise ValueError(f"{path} 缺少 NAS host 欄位")
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
    for field in ("report_type", "host", "rule_set"):
        if before.get(field) != after.get(field):
            raise ValueError(f"前後報告的 {field} 不一致，不能直接比對")
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
        "host": before["host"],
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
    lines = [
        f"報告比對：{report['host']} ({report['compared_type']})",
        f"新增觀察：{report['counts']['newly_observed']}",
        f"不再觀察：{report['counts']['no_longer_observed']}",
        f"部分掃描或範圍變動未重見：{report['counts']['not_reobserved_in_incomplete_scan']}",
        f"狀態改變：{report['counts']['status_changed']}",
        f"不變：{report['counts']['unchanged']}",
        f"掃描範圍改變：{'是' if report['scope_changed'] else '否'}",
        f"覆蓋狀態改變：{'是' if report['coverage_state_changed'] else '否'}",
        report["note"],
    ]
    return "\n".join(lines)
