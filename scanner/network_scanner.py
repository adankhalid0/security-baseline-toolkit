"""
Small, dependency-free network scanning helpers.

These are deliberately simple, real implementations (not mocks):
  - scan_ports() does an actual TCP connect-scan against a host.
  - parse_nftables_default_policy() parses a real nftables ruleset file to
    find the default policy of a given chain (e.g. "input").

They are used by scanner.checks, but are also usable standalone -- this is
the same technique used in the Network Security Lab project (custom Python
port scanner against a segmented Docker network).
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass


@dataclass
class ScanResult:
    host: str
    open_ports: list[int]
    closed_or_filtered: list[int]


def scan_ports(host: str, ports: list[int], timeout: float = 0.4) -> ScanResult:
    """
    TCP connect-scan a host for a list of ports.

    Uses a plain connect() rather than a raw SYN scan, so it needs no
    elevated privileges and works the same on Linux/macOS/Windows.
    """
    open_ports: list[int] = []
    closed_ports: list[int] = []

    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
            else:
                closed_ports.append(port)

    return ScanResult(host=host, open_ports=open_ports, closed_or_filtered=closed_ports)


_CHAIN_BLOCK_RE = re.compile(
    r"chain\s+(\w+)\s*\{([^}]*)\}", re.IGNORECASE | re.DOTALL
)
_POLICY_RE = re.compile(r"policy\s+(\w+)\s*;")


def parse_nftables_default_policy(ruleset_text: str, chain: str) -> str | None:
    """
    Parse an nftables ruleset (as text) and return the default policy
    ("accept" / "drop" / "reject") configured for the given chain, or None
    if the chain or an explicit policy statement isn't found.

    Example input:
        table inet filter {
            chain input {
                type filter hook input priority 0; policy drop;
                ct state established,related accept
            }
        }
    """
    for match in _CHAIN_BLOCK_RE.finditer(ruleset_text):
        chain_name, body = match.group(1), match.group(2)
        if chain_name.lower() != chain.lower():
            continue
        policy_match = _POLICY_RE.search(body)
        if policy_match:
            return policy_match.group(1).lower()
    return None


def load_ruleset(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()
