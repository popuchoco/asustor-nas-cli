from .common import ADVISORY_DEADBOLT, RULE_SET, utc_now


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
    host_id=None,
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
        "host_id": host_id,
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
