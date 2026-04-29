#!/usr/bin/env python3
"""
Le Bouclier Cyborg — CLI pare-feu pédagogique
  Mon corps est une machine. Mon réseau aussi.
"""
import sys
import time
from pathlib import Path
from collections import Counter

import click
from rich.console import Console
from rich.panel import Panel
from rich.align import Align
from rich.text import Text

from .firewall import Rule, RuleEngine, Packet, Action, Chain, Protocol
from .firewall import apply_rule, delete_rule, list_rules, flush_chain
from .monitor import stream
from .ui import (
    console, banner, rules_table, traffic_table,
    stats_panels, booyah, system_error, hud_line,
)
from .ui.theme import CYBORG_THEME
from .utils import log_event_csv, log_event_json, audit

_RULES_FILE = Path(__file__).resolve().parents[1] / "config" / "rules.json"


def _load_engine() -> RuleEngine:
    if _RULES_FILE.exists():
        return RuleEngine.load(_RULES_FILE)
    return RuleEngine()


def _save_engine(engine: RuleEngine):
    engine.save(_RULES_FILE)


# ═══════════════════════════════════════════════════════════  CLI root
@click.group()
@click.version_option("1.0.0", prog_name="Cyborg-Shield")
def cli():
    """⚙  Le Bouclier Cyborg — pare-feu pédagogique Teen Titans style."""


# ═══════════════════════════════════════════════════════════  rules
@cli.group()
def rules():
    """Gérer les règles de filtrage."""


@rules.command("list")
def rules_list():
    """Afficher toutes les règles actives."""
    banner()
    engine = _load_engine()
    if not engine.get_rules():
        console.print("[warning]Aucune règle configurée. Utilisez 'rules add' pour commencer.[/]")
        return
    console.print(rules_table([r.to_dict() for r in engine.get_rules()]))


@rules.command("add")
@click.option("--chain",    "-c", default="INPUT",   help="INPUT / OUTPUT / FORWARD")
@click.option("--protocol", "-p", default="any",     help="tcp / udp / icmp / any")
@click.option("--src",      "-s", default="any",     help="IP source ou CIDR")
@click.option("--dst",      "-d", default="any",     help="IP destination ou CIDR")
@click.option("--port",     "-P", default=None, type=int, help="Port destination")
@click.option("--action",   "-a", default="BLOCK",   help="ALLOW / BLOCK / DROP / LOG")
@click.option("--comment",  "-m", default="",        help="Commentaire libre")
@click.option("--apply-iptables", is_flag=True,      help="Appliquer dans iptables (root requis)")
def rules_add(chain, protocol, src, dst, port, action, comment, apply_iptables):
    """Ajouter une règle de filtrage."""
    banner()
    try:
        rule = Rule(
            id=0,
            chain=Chain(chain.upper()),
            protocol=Protocol(protocol.lower()),
            src=src, dst=dst, port=port,
            action=Action(action.upper()),
            comment=comment,
        )
    except ValueError as e:
        system_error(str(e))
        sys.exit(1)

    engine = _load_engine()
    engine.add_rule(rule)
    _save_engine(engine)
    audit("ADD_RULE", rule.to_dict().__str__())

    if apply_iptables:
        ok, msg = apply_rule(rule)
        hud_line(f"iptables: {msg}", "success" if ok else "warning")

    booyah(f"Règle #{rule.id} ajoutée — {action} {protocol} {src}→{dst}:{port or 'any'}")
    console.print(rules_table([rule.to_dict()]))


@rules.command("remove")
@click.argument("rule_id", type=int)
@click.option("--apply-iptables", is_flag=True, help="Supprimer dans iptables (root requis)")
def rules_remove(rule_id, apply_iptables):
    """Supprimer une règle par son ID."""
    engine = _load_engine()
    rule   = next((r for r in engine.get_rules() if r.id == rule_id), None)
    if not rule:
        system_error(f"Règle #{rule_id} introuvable.")
        sys.exit(1)

    if apply_iptables:
        ok, msg = delete_rule(rule)
        hud_line(f"iptables: {msg}", "success" if ok else "warning")

    engine.remove_rule(rule_id)
    _save_engine(engine)
    audit("DEL_RULE", f"id={rule_id}")
    booyah(f"Règle #{rule_id} supprimée.")


@rules.command("toggle")
@click.argument("rule_id", type=int)
def rules_toggle(rule_id):
    """Activer / désactiver une règle."""
    engine = _load_engine()
    rule   = engine.toggle_rule(rule_id)
    if not rule:
        system_error(f"Règle #{rule_id} introuvable.")
        sys.exit(1)
    _save_engine(engine)
    state = "ACTIVÉE" if rule.enabled else "DÉSACTIVÉE"
    booyah(f"Règle #{rule_id} {state}.")


@rules.command("flush")
@click.option("--chain", "-c", default=None, help="Chaîne spécifique ou toutes")
@click.option("--confirm", is_flag=True, help="Confirmer la suppression")
def rules_flush(chain, confirm):
    """Vider les règles (toutes ou par chaîne)."""
    if not confirm:
        console.print("[warning]Utilisez --confirm pour vider les règles.[/]")
        return
    engine = _load_engine()
    engine.flush(Chain(chain.upper()) if chain else None)
    _save_engine(engine)
    audit("FLUSH", chain or "ALL")
    booyah("Règles vidées — pare-feu réinitialisé.")


@rules.command("iptables")
@click.option("--chain", "-c", default=None, help="Afficher une chaîne spécifique")
def rules_iptables(chain):
    """Afficher les règles iptables système."""
    ok, output = list_rules(Chain(chain.upper()) if chain else None)
    if ok:
        console.print(Panel(output, title="[title]IPTABLES SYSTÈME[/]", border_style="bright_blue"))
    else:
        console.print(f"[warning]{output}[/]")


# ═══════════════════════════════════════════════════════════  simulate
@cli.command()
@click.option("--packets",      "-n", default=20,   help="Nombre de paquets à simuler")
@click.option("--attack-ratio", "-r", default=0.3,  help="Ratio trafic malveillant (0–1)")
@click.option("--rate",               default=5.0,  help="Paquets par seconde")
@click.option("--log-csv",      is_flag=True,       help="Journaliser en CSV")
@click.option("--log-json",     is_flag=True,       help="Journaliser en JSONL")
def simulate(packets, attack_ratio, rate, log_csv, log_json):
    """Simuler du trafic réseau et appliquer les règles."""
    banner()
    engine = _load_engine()

    if not engine.get_rules():
        console.print("[warning]Aucune règle — chargement des règles par défaut.[/]")
        _load_defaults(engine)

    stats   = Counter()
    events  = []
    gen     = stream(engine, rate=rate, attack_ratio=attack_ratio)
    total   = 0

    hud_line("Initialisation capteurs réseau...", "secondary")
    hud_line(f"Simulation: {packets} paquets | ratio attaque: {attack_ratio:.0%} | {rate} pkt/s", "primary")
    console.print()

    start = time.time()
    for event in gen:
        total += 1
        stats[event["action"]] += 1
        events.append(event)

        if log_csv:
            log_event_csv(event)
        if log_json:
            log_event_json(event)

        action_style = {"ALLOW": "allow", "BLOCK": "block", "DROP": "drop"}.get(event["action"], "muted")
        console.print(
            f"[muted]{event['timestamp']}[/]  "
            f"[accent]{event['src']:>15}[/] → [accent]{event['dst']:<15}[/]  "
            f"[primary]{event['protocol']:>4}[/]:{str(event['port']):<6}  "
            f"[{action_style}]{event['action']:>5}[/]"
        )

        if total >= packets:
            break

    uptime = f"{time.time() - start:.1f}s"
    console.print()
    console.print(stats_panels({
        "total": total,
        "allow": stats.get("ALLOW", 0),
        "block": stats.get("BLOCK", 0),
        "drop":  stats.get("DROP", 0),
        "rules": len(engine.get_rules()),
        "uptime": uptime,
    }))
    booyah(f"Simulation terminée — {total} paquets analysés en {uptime}")


# ═══════════════════════════════════════════════════════════  presets
@cli.command()
@click.argument("preset", type=click.Choice(["ssh-protect", "web-server", "dmz", "strict"]))
def preset(preset):
    """Charger un profil de sécurité prédéfini."""
    banner()
    engine = _load_engine()
    configs = {
        "ssh-protect": [
            Rule(0, Chain.INPUT,   Protocol.TCP, "any", "any", 22,   Action.ALLOW,  True, 0, "SSH autorisé"),
            Rule(0, Chain.INPUT,   Protocol.TCP, "any", "any", 23,   Action.DROP,   True, 0, "Telnet bloqué"),
            Rule(0, Chain.INPUT,   Protocol.TCP, "any", "any", 3389, Action.DROP,   True, 0, "RDP bloqué"),
        ],
        "web-server": [
            Rule(0, Chain.INPUT,   Protocol.TCP, "any", "any", 80,   Action.ALLOW,  True, 0, "HTTP"),
            Rule(0, Chain.INPUT,   Protocol.TCP, "any", "any", 443,  Action.ALLOW,  True, 0, "HTTPS"),
            Rule(0, Chain.INPUT,   Protocol.TCP, "any", "any", 22,   Action.ALLOW,  True, 0, "SSH admin"),
            Rule(0, Chain.INPUT,   Protocol.ANY, "any", "any", None, Action.DROP,   True, 0, "Défaut DROP"),
        ],
        "dmz": [
            Rule(0, Chain.FORWARD, Protocol.TCP, "10.0.0.0/8",  "any", 80,  Action.ALLOW, True, 0, "HTTP interne→DMZ"),
            Rule(0, Chain.FORWARD, Protocol.TCP, "10.0.0.0/8",  "any", 443, Action.ALLOW, True, 0, "HTTPS interne→DMZ"),
            Rule(0, Chain.FORWARD, Protocol.ANY, "any",         "any", None, Action.DROP, True, 0, "Isolation DMZ"),
        ],
        "strict": [
            Rule(0, Chain.INPUT,   Protocol.TCP, "any", "any", 22,   Action.ALLOW, True, 0, "SSH seul autorisé"),
            Rule(0, Chain.INPUT,   Protocol.ANY, "any", "any", None, Action.DROP,  True, 0, "Tout bloquer"),
            Rule(0, Chain.OUTPUT,  Protocol.ANY, "any", "any", None, Action.ALLOW, True, 0, "Sortie libre"),
        ],
    }
    for rule in configs[preset]:
        engine.add_rule(rule)
    _save_engine(engine)
    audit("PRESET", preset)
    booyah(f"Profil '{preset}' chargé — {len(configs[preset])} règles installées.")
    console.print(rules_table([r.to_dict() for r in engine.get_rules()]))


# ═══════════════════════════════════════════════════════════  test-packet
@cli.command("test-packet")
@click.option("--src",      "-s", required=True, help="IP source")
@click.option("--dst",      "-d", default="10.0.0.1", help="IP destination")
@click.option("--protocol", "-p", default="tcp", help="tcp / udp / icmp")
@click.option("--port",     "-P", default=None, type=int, help="Port")
@click.option("--chain",    "-c", default="INPUT", help="Chaîne")
def test_packet(src, dst, protocol, port, chain):
    """Tester un paquet contre les règles sans l'appliquer."""
    banner()
    engine = _load_engine()
    try:
        pkt = Packet(
            src=src, dst=dst,
            protocol=Protocol(protocol.lower()),
            port=port,
            chain=Chain(chain.upper()),
        )
    except ValueError as e:
        system_error(str(e))
        sys.exit(1)

    action = engine.evaluate(pkt)
    style  = {"ALLOW": "allow", "BLOCK": "block", "DROP": "drop"}.get(action.value, "muted")
    console.print(Panel(
        Align.center(Text(
            f"  {src} → {dst}:{port or 'any'} ({protocol.upper()})  →  {action.value}  ",
            style=style,
        )),
        title="[title]RÉSULTAT DU TEST[/]",
        border_style="bright_blue",
    ))
    _save_engine(engine)  # persist hits


# ═══════════════════════════════════════════════════════════  helpers
def _load_defaults(engine: RuleEngine):
    defaults = [
        Rule(0, Chain.INPUT,  Protocol.TCP, "any", "any", 22,   Action.ALLOW, True, 0, "SSH admin"),
        Rule(0, Chain.INPUT,  Protocol.TCP, "any", "any", 80,   Action.ALLOW, True, 0, "HTTP"),
        Rule(0, Chain.INPUT,  Protocol.TCP, "any", "any", 443,  Action.ALLOW, True, 0, "HTTPS"),
        Rule(0, Chain.INPUT,  Protocol.TCP, "any", "any", 23,   Action.DROP,  True, 0, "Bloquer Telnet"),
        Rule(0, Chain.INPUT,  Protocol.TCP, "any", "any", 445,  Action.DROP,  True, 0, "Bloquer SMB"),
        Rule(0, Chain.INPUT,  Protocol.TCP, "any", "any", 3389, Action.DROP,  True, 0, "Bloquer RDP"),
    ]
    for r in defaults:
        engine.add_rule(r)
    _save_engine(engine)
    audit("LOAD_DEFAULTS", "6 règles de base installées")


if __name__ == "__main__":
    cli()
