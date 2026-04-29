"""
Thin wrapper around iptables — translates Rule objects into shell commands.

Falls back gracefully when iptables is unavailable (e.g. non-root, CI env).
"""
from __future__ import annotations

import subprocess
import shutil
from typing import Optional

from .rules import Rule, Action, Chain, Protocol


def _available() -> bool:
    return shutil.which("iptables") is not None


def _proto_flag(rule: Rule) -> list[str]:
    if rule.protocol == Protocol.ANY:
        return []
    return ["-p", rule.protocol.value]


def _addr_flag(flag: str, addr: str) -> list[str]:
    if addr in ("any", "*", ""):
        return []
    return [flag, addr]


def _port_flag(rule: Rule) -> list[str]:
    if rule.port is None:
        return []
    return ["--dport", str(rule.port)]


def _action_target(action: Action) -> str:
    mapping = {
        Action.ALLOW: "ACCEPT",
        Action.BLOCK: "REJECT",
        Action.DROP:  "DROP",
        Action.LOG:   "LOG",
    }
    return mapping[action]


def _build_cmd(op: str, rule: Rule) -> list[str]:
    cmd = ["iptables", op, rule.chain.value]
    cmd += _proto_flag(rule)
    cmd += _addr_flag("-s", rule.src)
    cmd += _addr_flag("-d", rule.dst)
    if rule.protocol != Protocol.ANY:
        cmd += _port_flag(rule)
    cmd += ["-j", _action_target(rule.action)]
    if rule.comment:
        cmd += ["-m", "comment", "--comment", rule.comment]
    return cmd


def apply_rule(rule: Rule) -> tuple[bool, str]:
    """Insert rule into iptables. Returns (success, message)."""
    if not _available():
        return False, "iptables non disponible — simulation uniquement"
    cmd = _build_cmd("-I", rule)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return True, " ".join(cmd)
    return False, result.stderr.strip()


def delete_rule(rule: Rule) -> tuple[bool, str]:
    if not _available():
        return False, "iptables non disponible — simulation uniquement"
    cmd = _build_cmd("-D", rule)
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return True, " ".join(cmd)
    return False, result.stderr.strip()


def list_rules(chain: Optional[Chain] = None) -> tuple[bool, str]:
    if not _available():
        return False, "iptables non disponible"
    cmd = ["iptables", "-L", "-v", "-n", "--line-numbers"]
    if chain:
        cmd.append(chain.value)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stdout or result.stderr


def flush_chain(chain: Optional[Chain] = None) -> tuple[bool, str]:
    if not _available():
        return False, "iptables non disponible"
    cmd = ["iptables", "-F"]
    if chain:
        cmd.append(chain.value)
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, "Chaîne vidée" if result.returncode == 0 else result.stderr
