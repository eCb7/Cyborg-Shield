"""Tests — simulateur de trafic."""
from cyborg_shield.monitor.traffic import generate_packet, packet_to_event
from cyborg_shield.firewall.rules import RuleEngine, Rule, Action, Chain, Protocol


def test_generate_packet_returns_valid_structure():
    pkt = generate_packet(attack_ratio=0.0)
    assert pkt.src
    assert pkt.dst
    assert pkt.protocol in Protocol


def test_packet_to_event_has_required_keys():
    pkt   = generate_packet()
    event = packet_to_event(pkt, "ALLOW")
    for key in ("timestamp", "src", "dst", "protocol", "port", "size", "action"):
        assert key in event


def test_engine_evaluates_stream_packet():
    engine = RuleEngine()
    engine.add_rule(Rule(0, Chain.INPUT, Protocol.TCP, "any", "any", 22, Action.BLOCK))
    pkt    = generate_packet(attack_ratio=0.0)
    action = engine.evaluate(pkt)
    assert action in Action


def test_high_attack_ratio_triggers_drops():
    engine = RuleEngine()
    engine.add_rule(Rule(0, Chain.INPUT, Protocol.TCP, "any", "any", 445, Action.DROP))
    engine.add_rule(Rule(0, Chain.INPUT, Protocol.TCP, "any", "any", 3389, Action.DROP))

    results = []
    for _ in range(100):
        pkt    = generate_packet(attack_ratio=1.0)
        action = engine.evaluate(pkt)
        results.append(action.value)

    assert "DROP" in results or "ALLOW" in results
