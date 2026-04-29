"""Traffic simulator — generates realistic packet events for demo/training."""
from __future__ import annotations

import random
import time
from datetime import datetime
from typing import Iterator

from ..firewall.rules import Packet, Chain, Protocol


_COMMON_PORTS = {
    22: "SSH", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
    5432: "PgSQL", 8080: "HTTP-ALT", 21: "FTP", 25: "SMTP",
    53: "DNS", 3389: "RDP", 445: "SMB", 23: "TELNET",
}

_ATTACK_SIGNATURES = [
    # (src_prefix, port, comment)
    ("192.168.99.", 22,   "SSH brute-force"),
    ("10.0.0.",     3389, "RDP scan"),
    ("172.16.",     445,  "SMB exploit attempt"),
    ("185.220.",    80,   "Tor exit node"),
    ("45.33.",      23,   "Telnet probe"),
]


def _random_ip(prefix: str = "") -> str:
    if prefix:
        return prefix + ".".join(str(random.randint(1, 254)) for _ in range(4 - prefix.count(".")))
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def generate_packet(attack_ratio: float = 0.2) -> Packet:
    if random.random() < attack_ratio:
        sig = random.choice(_ATTACK_SIGNATURES)
        return Packet(
            src=_random_ip(sig[0]),
            dst=_random_ip("10.10.10."),
            protocol=Protocol.TCP,
            port=sig[1],
            size=random.randint(40, 1500),
            chain=Chain.INPUT,
        )
    proto = random.choice([Protocol.TCP, Protocol.UDP, Protocol.ICMP])
    port  = random.choice(list(_COMMON_PORTS.keys())) if proto != Protocol.ICMP else None
    return Packet(
        src=_random_ip(),
        dst=_random_ip("10.10.10."),
        protocol=proto,
        port=port,
        size=random.randint(40, 9000),
        chain=random.choice([Chain.INPUT, Chain.OUTPUT, Chain.FORWARD]),
    )


def packet_to_event(packet: Packet, action: str) -> dict:
    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src":       packet.src,
        "dst":       packet.dst,
        "protocol":  packet.protocol.value,
        "port":      packet.port or "-",
        "size":      packet.size,
        "action":    action,
    }


def stream(engine, rate: float = 0.5, attack_ratio: float = 0.2) -> Iterator[dict]:
    """Yield traffic events at `rate` packets/second."""
    while True:
        pkt    = generate_packet(attack_ratio)
        action = engine.evaluate(pkt)
        yield packet_to_event(pkt, action.value)
        time.sleep(1.0 / rate)
