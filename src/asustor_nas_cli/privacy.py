"""Redaction helpers for NAS identifiers and network addresses in outputs."""

import hashlib
import ipaddress
import re
from pathlib import Path

REDACTED_HOST = "NAS"
REDACTED_ACCOUNT = "[redacted-account]"
REDACTED_IP = "[redacted-ip]"
_IP_TOKEN = re.compile(r"(?<![A-Za-z0-9_])([0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]+)?)(/\d{1,3})?(?![A-Za-z0-9_])")
_MAC_ADDRESS = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
_LOCAL_HOME = str(Path.home()).rstrip("\\/")


def host_fingerprint(host):
    """Return a stable comparison token without putting the address in reports."""
    if not host:
        return None
    normalized = str(host).strip().lower()
    try:
        normalized = ipaddress.ip_address(normalized).compressed
    except ValueError:
        pass
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


def redact_ip_addresses(text):
    def replace(match):
        token, prefix = match.groups()
        try:
            ipaddress.ip_address(token)
        except ValueError:
            return match.group(0)
        return REDACTED_IP + (prefix or "")

    return _IP_TOKEN.sub(replace, str(text))


def redact_sensitive_text(text, host=None, user=None, include_all_ips=False):
    value = str(text)
    if host:
        value = re.sub(re.escape(str(host)), "[redacted-host]", value, flags=re.IGNORECASE)
    if user:
        value = re.sub(
            rf"(?<![A-Za-z0-9_.-]){re.escape(str(user))}(?![A-Za-z0-9_.-])",
            REDACTED_ACCOUNT,
            value,
        )
    if _LOCAL_HOME and _LOCAL_HOME.lower() not in {"/", "\\"}:
        value = re.sub(re.escape(_LOCAL_HOME), "[local-path]", value, flags=re.IGNORECASE)
    if include_all_ips:
        value = redact_ip_addresses(value)
        value = _MAC_ADDRESS.sub("[redacted-mac]", value)
    return value
