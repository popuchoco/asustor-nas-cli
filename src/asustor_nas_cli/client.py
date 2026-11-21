"""HTTPS and SSH transport for the ASUSTOR ADM CLI."""

import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class CliError(RuntimeError):
    """An expected connection, configuration, or remote-command error."""


ANSI_ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def inspect_adm_portal(host, port, timeout, ca_file=None, insecure=False):
    try:
        context = ssl.create_default_context(cafile=ca_file)
    except (OSError, ssl.SSLError) as error:
        raise CliError(f"Could not read CA file: {error}") from error
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    url_host = f"[{host}]" if ":" in host else host
    url = f"https://{url_host}:{port}/portal/"
    request = Request(url, headers={"User-Agent": "asustor-nas-cli/0.3.0"})
    start = time.monotonic()

    status = None
    body = b""
    try:
        with urlopen(request, context=context, timeout=timeout) as response:
            status = response.status
            body = response.read(2_000_001)
            if len(body) > 2_000_000:
                raise CliError("ADM portal response exceeded the 2 MB limit")
    except HTTPError as error:
        status = error.code
        body = error.read(2_000_001)
        if len(body) > 2_000_000:
            raise CliError("ADM portal response exceeded the 2 MB limit") from error
    except CliError:
        raise
    except (URLError, OSError, ssl.SSLError, socket.timeout) as error:
        reason = getattr(error, "reason", error)
        raise CliError(f"ADM HTTPS probe failed: {reason}") from error

    html = body.decode("utf-8", errors="replace")
    version_match = re.search(r"_dc=(\d+\.\d+\.\d+\.[A-Za-z0-9]+)", html)
    indicator_patterns = (
        ("deadbolt", r"\bdeadbolt\b"),
        ("bitcoin", r"\bbitcoin\b"),
        ("deadbolt_extension", r"\.deadbolt\b"),
    )
    return {
        "host": host,
        "https_port": port,
        "http_status": status,
        "adm_version": version_match.group(1) if version_match else None,
        "tls_verified": not insecure,
        "elapsed_ms": round((time.monotonic() - start) * 1000),
        "asustor_marker": bool(re.search(r"\bASUSTOR\b", html, re.IGNORECASE)),
        "deadbolt_indicators": [
            name
            for name, pattern in indicator_patterns
            if re.search(pattern, html, re.IGNORECASE)
        ],
    }


def probe_adm(host, port, timeout, ca_file=None, insecure=False):
    result = inspect_adm_portal(host, port, timeout, ca_file=ca_file, insecure=insecure)
    if result["http_status"] != 200:
        raise CliError(f"ADM portal returned HTTP {result['http_status']}")
    if not result["asustor_marker"]:
        raise CliError("The HTTPS page did not identify itself as ASUSTOR")
    return result


def run_ssh(host, user, port, remote_command, timeout, identity_file=None, batch=False):
    ssh_path = shutil.which("ssh")
    if not ssh_path:
        raise CliError("OpenSSH client was not found on PATH")

    arguments = [
        ssh_path,
        "-T",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ClearAllForwardings=yes",
    ]
    if batch:
        arguments.extend(["-o", "BatchMode=yes"])
    if identity_file:
        arguments.extend(["-i", str(Path(identity_file).expanduser())])
    arguments.extend(["-p", str(port), "--", f"{user}@{host}", remote_command])
    interactive_terminal = sys.stdin.isatty() and sys.stderr.isatty()
    try:
        result = subprocess.run(
            arguments,
            check=False,
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=None if interactive_terminal else subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(timeout, 45),
        )
    except FileNotFoundError as error:
        raise CliError("OpenSSH client was not found on PATH") from error
    except subprocess.TimeoutExpired as error:
        raise CliError("SSH command timed out") from error

    if result.returncode != 0:
        detail = (result.stderr or "").strip()
        if detail:
            raise CliError(f"SSH failed: {detail}")
        if interactive_terminal:
            raise CliError(f"SSH command failed with exit code {result.returncode}")
        raise CliError(
            "SSH failed. Run adm from an interactive terminal for password login, "
            "or configure an SSH key."
        )
    clean_output = ANSI_ESCAPE.sub("", result.stdout)
    return clean_output.replace("\r\n", "\n").rstrip()
