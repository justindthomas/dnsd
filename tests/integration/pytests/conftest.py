"""Pytest fixtures for the dnsd integration suite.

All fixtures read env vars set by `run-tests.sh`. They assume the
test VM is already up — the orchestrator script is responsible for
boot + readiness.
"""

from __future__ import annotations

import os
import socket
import struct
import subprocess
from pathlib import Path

import pytest

HOST = "localhost"
SSH_PORT = int(os.environ.get("DNSD_TEST_SSH_PORT", "2290"))
VM_IP = os.environ.get("DNSD_TEST_VM_IP", "10.99.0.2")
HOST_IP = os.environ.get("DNSD_TEST_HOST_IP", "10.99.0.1")
PASSWORD = os.environ.get("DNSD_TEST_PASSWORD", "dnsd")


def _ssh(cmd: str, *, input_text: str | None = None, timeout: int = 30) -> tuple[int, str, str]:
    """Run `cmd` inside the test VM via ssh. Returns (rc, stdout, stderr)."""
    full = [
        "sshpass",
        "-p",
        PASSWORD,
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        "-p",
        str(SSH_PORT),
        f"root@{HOST}",
        cmd,
    ]
    r = subprocess.run(
        full,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return r.returncode, r.stdout, r.stderr


@pytest.fixture(scope="session")
def ssh():
    """`ssh(cmd)` runs a command in the VM."""
    return _ssh


@pytest.fixture(scope="session")
def dnsd_query(ssh):
    """`dnsd_query('stats')` runs dnsd-query inside the VM."""
    def _q(*args: str):
        rc, out, err = ssh(f"dnsd-query {' '.join(args)}")
        if rc != 0:
            return {"_error": f"rc={rc}: {err.strip() or out.strip()}"}
        import json

        try:
            return json.loads(out)
        except json.JSONDecodeError:
            return {"_raw": out.strip()}

    return _q


def _encode_name(name: str) -> bytes:
    parts = name.rstrip(".").split(".")
    return b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"


def _parse_rcode(flags: int) -> str:
    rcodes = [
        "NOERROR",
        "FORMERR",
        "SERVFAIL",
        "NXDOMAIN",
        "NOTIMP",
        "REFUSED",
    ]
    rc = flags & 0x0F
    return rcodes[rc] if rc < len(rcodes) else f"RCODE{rc}"


@pytest.fixture(scope="session")
def query_udp():
    """Fire a single DNS query from the build host at the VM's VPP
    IP via UDP. Returns a dict with rcode + answer count."""
    def _q(name: str, rtype: int = 1, timeout: float = 3.0, target: str = VM_IP):
        msg = (
            struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
            + _encode_name(name)
            + struct.pack(">HH", rtype, 1)
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(msg, (target, 53))
        try:
            data, _ = s.recvfrom(4096)
        except socket.timeout:
            return {"timeout": True}
        finally:
            s.close()
        txid, flags, qd, an, ns_, ar = struct.unpack(">HHHHHH", data[:12])
        return {
            "rcode": _parse_rcode(flags),
            "qd": qd,
            "an": an,
            "bytes": len(data),
            "raw": data,
        }

    return _q


@pytest.fixture(scope="session")
def query_tcp():
    """Fire a TCP DNS query at the VM's VPP IP (RFC 1035 §4.2.2
    2-byte length framing)."""
    def _q(name: str, rtype: int = 1, timeout: float = 5.0, target: str = VM_IP):
        msg = (
            struct.pack(">HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0)
            + _encode_name(name)
            + struct.pack(">HH", rtype, 1)
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((target, 53))
        except (socket.timeout, ConnectionRefusedError):
            return {"timeout": True}
        framed = struct.pack(">H", len(msg)) + msg
        s.sendall(framed)
        try:
            lenbuf = s.recv(2)
            if len(lenbuf) < 2:
                return {"error": "short length prefix"}
            n = struct.unpack(">H", lenbuf)[0]
            data = b""
            while len(data) < n:
                chunk = s.recv(n - len(data))
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            return {"timeout": True}
        finally:
            s.close()
        if len(data) < 12:
            return {"error": "short response"}
        txid, flags, qd, an, ns_, ar = struct.unpack(">HHHHHH", data[:12])
        return {
            "rcode": _parse_rcode(flags),
            "qd": qd,
            "an": an,
            "bytes": len(data),
        }

    return _q
