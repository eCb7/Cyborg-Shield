"""Tests unitaires — moteur de règles."""
import pytest
from cyborg_shield.firewall.rules import (
    Rule, RuleEngine, Packet, Action, Chain, Protocol,
)


def make_engine(*rules):
    e = RuleEngine()
    for r in rules:
        e.add_rule(r)
    return e


def block_ssh():
    return Rule(0, Chain.INPUT, Protocol.TCP, "any", "any", 22, Action.BLOCK)


def allow_http():
    return Rule(0, Chain.INPUT, Protocol.TCP, "any", "any", 80, Action.ALLOW)


def drop_telnet():
    return Rule(0, Chain.INPUT, Protocol.TCP, "any", "any", 23, Action.DROP)


def pkt(port, proto=Protocol.TCP, chain=Chain.INPUT):
    return Packet("1.2.3.4", "10.0.0.1", proto, port, 64, chain)


# ──────────────────────────────────────── basic matching
class TestRuleMatching:
    def test_block_ssh(self):
        engine = make_engine(block_ssh())
        assert engine.evaluate(pkt(22)) == Action.BLOCK

    def test_allow_http(self):
        engine = make_engine(allow_http())
        assert engine.evaluate(pkt(80)) == Action.ALLOW

    def test_drop_telnet(self):
        engine = make_engine(drop_telnet())
        assert engine.evaluate(pkt(23)) == Action.DROP

    def test_default_policy_when_no_match(self):
        engine = make_engine(block_ssh())
        assert engine.evaluate(pkt(443)) == RuleEngine.DEFAULT_POLICY

    def test_first_match_wins(self):
        engine = make_engine(
            Rule(0, Chain.INPUT, Protocol.TCP, "any", "any", 22, Action.ALLOW),
            Rule(0, Chain.INPUT, Protocol.TCP, "any", "any", 22, Action.BLOCK),
        )
        assert engine.evaluate(pkt(22)) == Action.ALLOW

    def test_disabled_rule_skipped(self):
        r = block_ssh()
        r.enabled = False
        engine = make_engine(r)
        assert engine.evaluate(pkt(22)) == RuleEngine.DEFAULT_POLICY


# ──────────────────────────────────────── CIDR
class TestCIDRMatching:
    def test_cidr_match(self):
        rule   = Rule(0, Chain.INPUT, Protocol.ANY, "192.168.0.0/24", "any", None, Action.BLOCK)
        engine = make_engine(rule)
        p = Packet("192.168.0.55", "10.0.0.1", Protocol.TCP, 80, 64, Chain.INPUT)
        assert engine.evaluate(p) == Action.BLOCK

    def test_cidr_no_match(self):
        rule   = Rule(0, Chain.INPUT, Protocol.ANY, "192.168.1.0/24", "any", None, Action.BLOCK)
        engine = make_engine(rule)
        p = Packet("192.168.0.55", "10.0.0.1", Protocol.TCP, 80, 64, Chain.INPUT)
        assert engine.evaluate(p) == RuleEngine.DEFAULT_POLICY


# ──────────────────────────────────────── CRUD
class TestEngineCRUD:
    def test_add_increments_id(self):
        e  = RuleEngine()
        r1 = e.add_rule(Rule(0, Chain.INPUT, Protocol.TCP, "any", "any", 22, Action.BLOCK))
        r2 = e.add_rule(Rule(0, Chain.INPUT, Protocol.TCP, "any", "any", 80, Action.ALLOW))
        assert r1.id != r2.id

    def test_remove_rule(self):
        e = make_engine(block_ssh())
        rule_id = e.get_rules()[0].id
        assert e.remove_rule(rule_id) is True
        assert len(e.get_rules()) == 0

    def test_toggle_rule(self):
        e       = make_engine(block_ssh())
        rule_id = e.get_rules()[0].id
        e.toggle_rule(rule_id)
        assert e.get_rules()[0].enabled is False

    def test_flush_all(self):
        e = make_engine(block_ssh(), allow_http())
        e.flush()
        assert len(e.get_rules()) == 0

    def test_flush_chain(self):
        e = RuleEngine()
        e.add_rule(Rule(0, Chain.INPUT,  Protocol.TCP, "any", "any", 22, Action.BLOCK))
        e.add_rule(Rule(0, Chain.OUTPUT, Protocol.TCP, "any", "any", 80, Action.ALLOW))
        e.flush(Chain.INPUT)
        rules = e.get_rules()
        assert len(rules) == 1
        assert rules[0].chain == Chain.OUTPUT


# ──────────────────────────────────────── persistence
class TestPersistence:
    def test_save_load(self, tmp_path):
        path   = tmp_path / "rules.json"
        engine = make_engine(block_ssh(), allow_http())
        engine.save(path)
        loaded = RuleEngine.load(path)
        ids_original = {r.id for r in engine.get_rules()}
        ids_loaded   = {r.id for r in loaded.get_rules()}
        assert ids_original == ids_loaded

    def test_hits_persisted(self, tmp_path):
        path   = tmp_path / "rules.json"
        engine = make_engine(block_ssh())
        engine.evaluate(pkt(22))
        engine.evaluate(pkt(22))
        engine.save(path)
        loaded = RuleEngine.load(path)
        assert loaded.get_rules()[0].hits == 2
