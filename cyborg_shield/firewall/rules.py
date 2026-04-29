"""Firewall rule model and rule engine."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, asdict
from enum import Enum
from functools import lru_cache
from pathlib import Path
from typing import Optional


class Action(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    DROP  = "DROP"
    LOG   = "LOG"


class Chain(str, Enum):
    INPUT   = "INPUT"
    OUTPUT  = "OUTPUT"
    FORWARD = "FORWARD"


class Protocol(str, Enum):
    TCP  = "tcp"
    UDP  = "udp"
    ICMP = "icmp"
    ANY  = "any"


@dataclass
class Rule:
    id:        int
    chain:     Chain    = Chain.INPUT
    protocol:  Protocol = Protocol.ANY
    src:       str      = "any"
    dst:       str      = "any"
    port:      Optional[int] = None
    action:    Action   = Action.ALLOW
    enabled:   bool     = True
    hits:      int      = 0
    comment:   str      = ""

    # ------------------------------------------------------------------
    def matches(self, packet: "Packet") -> bool:
        if not self.enabled:
            return False
        if self.chain != packet.chain:
            return False
        if self.protocol != Protocol.ANY and self.protocol != packet.protocol:
            return False
        if not _match_addr(self.src, packet.src):
            return False
        if not _match_addr(self.dst, packet.dst):
            return False
        if self.port is not None and self.port != packet.port:
            return False
        return True

    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        d = asdict(self)
        d["chain"]    = self.chain.value
        d["protocol"] = self.protocol.value
        d["action"]   = self.action.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Rule":
        return cls(
            id=d["id"],
            chain=Chain(d.get("chain", "INPUT")),
            protocol=Protocol(d.get("protocol", "any")),
            src=d.get("src", "any"),
            dst=d.get("dst", "any"),
            port=d.get("port"),
            action=Action(d.get("action", "ALLOW")),
            enabled=d.get("enabled", True),
            hits=d.get("hits", 0),
            comment=d.get("comment", ""),
        )


@lru_cache(maxsize=512)
def _parse_network(pattern: str):
    return ipaddress.ip_network(pattern, strict=False)


def _match_addr(pattern: str, address: str) -> bool:
    if pattern in ("any", "*", ""):
        return True
    try:
        return ipaddress.ip_address(address) in _parse_network(pattern)
    except ValueError:
        return pattern == address


@dataclass
class Packet:
    src:      str
    dst:      str
    protocol: Protocol
    port:     Optional[int] = None
    size:     int           = 64
    chain:    Chain         = Chain.INPUT


class RuleEngine:
    """Evaluates packets against an ordered list of rules (first-match wins)."""

    DEFAULT_POLICY = Action.ALLOW

    def __init__(self, rules: list[Rule] | None = None):
        self._rules: list[Rule] = rules or []
        self._next_id = max((r.id for r in self._rules), default=0) + 1

    # ------------------------------------------------------------------  Rules CRUD
    def add_rule(self, rule: Rule) -> Rule:
        rule.id = self._next_id
        self._next_id += 1
        self._rules.append(rule)
        return rule

    def remove_rule(self, rule_id: int) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.id != rule_id]
        return len(self._rules) < before

    def toggle_rule(self, rule_id: int) -> Optional[Rule]:
        for r in self._rules:
            if r.id == rule_id:
                r.enabled = not r.enabled
                return r
        return None

    def get_rules(self) -> list[Rule]:
        return list(self._rules)

    def flush(self, chain: Chain | None = None):
        if chain is None:
            self._rules.clear()
        else:
            self._rules = [r for r in self._rules if r.chain != chain]

    # ------------------------------------------------------------------  Evaluation
    def evaluate(self, packet: Packet) -> Action:
        for rule in self._rules:
            if rule.matches(packet):
                rule.hits += 1
                return rule.action
        return self.DEFAULT_POLICY

    # ------------------------------------------------------------------  Persistence
    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            json.dump([r.to_dict() for r in self._rules], f, indent=2)

    @classmethod
    def load(cls, path: Path) -> "RuleEngine":
        with open(path) as f:
            data = json.load(f)
        return cls([Rule.from_dict(d) for d in data])
