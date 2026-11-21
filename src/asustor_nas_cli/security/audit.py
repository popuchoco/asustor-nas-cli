import re

from .common import ADVISORY_DEADBOLT, PROTECTION_GUIDE, RELEASE_NOTES, RULE_SET, utc_now


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
    host_id=None,
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
        "host_id": host_id,
        "adm_version": portal.get("adm_version") if portal else None,
        "portal_tls_verified": portal.get("tls_verified") if portal else None,
        "scope_statement": "DeadBolt 預防基線與有限管理頁線索；不是一般防毒或完整入侵鑑識。",
        "checks": checks,
        "summary": {"state": state, "counts": counts},
    }
