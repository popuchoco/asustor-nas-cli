"""Read-only DeadBolt posture checks, IOC scanning, and report comparison."""

from datetime import datetime, timezone

ADVISORY_DEADBOLT = "https://www.asustor.com/en/security/security_advisory_detail?id=9"
RELEASE_NOTES = "https://www.asustor.com/zh-tw/service/release_notes"
PROTECTION_GUIDE = "https://www.asustor.com/zh-tw/knowledge/detail/?group_id=628&id=6"
RULE_SET = "asustor-deadbolt-v1"


def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
