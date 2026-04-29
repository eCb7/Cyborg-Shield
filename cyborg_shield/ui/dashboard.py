"""Terminal dashboard — Cyborg's HUD."""
import time
from datetime import datetime
from typing import List

from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich import box

from .ascii_art import CYBORG_BANNER, TAGLINE
from .theme import CYBORG_THEME, BORDER_STYLE


console = Console(theme=CYBORG_THEME)


def banner():
    console.print(Text(CYBORG_BANNER, style="primary"))
    console.print(Align.center(Text(TAGLINE, style="accent")))
    console.print()


def _status_badge(action: str) -> Text:
    styles = {"ALLOW": "allow", "BLOCK": "block", "DROP": "drop", "LOG": "log"}
    return Text(f" {action} ", style=styles.get(action.upper(), "muted"))


def rules_table(rules: List[dict]) -> Table:
    t = Table(
        title="⚙  RÈGLES PARE-FEU ACTIVES",
        title_style="title",
        box=box.DOUBLE_EDGE,
        border_style=BORDER_STYLE,
        header_style="secondary",
        show_lines=True,
    )
    t.add_column("#",       style="muted",   width=4,  justify="right")
    t.add_column("CHAÎNE",  style="accent",  width=8)
    t.add_column("PROTO",   style="primary", width=7)
    t.add_column("SOURCE",  style="accent",  width=18)
    t.add_column("DEST",    style="accent",  width=18)
    t.add_column("PORT",    style="primary", width=8)
    t.add_column("ACTION",  width=9,         justify="center")
    t.add_column("HITS",    style="muted",   width=8,  justify="right")
    t.add_column("COMMENTAIRE", style="muted")

    for r in rules:
        t.add_row(
            str(r.get("id", "?")),
            r.get("chain", "-"),
            r.get("protocol", "any"),
            r.get("src", "any"),
            r.get("dst", "any"),
            str(r.get("port", "-")),
            _status_badge(r.get("action", "ALLOW")),
            str(r.get("hits", 0)),
            r.get("comment", ""),
        )
    return t


def traffic_table(events: List[dict]) -> Table:
    t = Table(
        title="📡  FLUX RÉSEAU — TEMPS RÉEL",
        title_style="title",
        box=box.SIMPLE_HEAVY,
        border_style=BORDER_STYLE,
        header_style="secondary",
        show_lines=False,
    )
    t.add_column("TIMESTAMP",  style="muted",   width=21)
    t.add_column("SRC",        style="accent",  width=20)
    t.add_column("DST",        style="accent",  width=20)
    t.add_column("PROTO",      style="primary", width=7)
    t.add_column("PORT",       style="primary", width=6,  justify="right")
    t.add_column("TAILLE",     style="muted",   width=8,  justify="right")
    t.add_column("DÉCISION",   width=9,         justify="center")

    for e in events:
        t.add_row(
            e.get("timestamp", ""),
            e.get("src", ""),
            e.get("dst", ""),
            e.get("protocol", ""),
            str(e.get("port", "")),
            f"{e.get('size', 0)}B",
            _status_badge(e.get("action", "ALLOW")),
        )
    return t


def stats_panels(stats: dict) -> Columns:
    def _panel(label, value, style):
        return Panel(
            Align.center(Text(str(value), style=style, justify="center")),
            title=f"[accent]{label}[/]",
            border_style=BORDER_STYLE,
            padding=(0, 2),
        )

    return Columns([
        _panel("PAQUETS TRAITÉS", stats.get("total", 0),   "primary"),
        _panel("AUTORISÉS",       stats.get("allow", 0),   "allow"),
        _panel("BLOQUÉS",         stats.get("block", 0),   "block"),
        _panel("DROPPÉS",         stats.get("drop", 0),    "drop"),
        _panel("RÈGLES ACTIVES",  stats.get("rules", 0),   "secondary"),
        _panel("UPTIME",          stats.get("uptime", "0s"), "accent"),
    ], equal=True)


def booyah(message: str = "RÈGLE APPLIQUÉE"):
    console.print()
    console.print(Panel(
        Align.center(Text(f"⚡  BOOYAH!  —  {message}  ⚡", style="bold #00FF88")),
        border_style="bright_green",
        padding=(0, 4),
    ))
    console.print()


def system_error(message: str):
    console.print(Panel(
        Align.center(Text(f"[SYSTEM ERROR]  {message}", style="danger")),
        title="[danger]ALERTE CRITIQUE[/]",
        border_style="red",
    ))


def hud_line(message: str, style: str = "muted"):
    ts = datetime.now().strftime("%H:%M:%S")
    console.print(f"[muted][[/][primary]{ts}[/][muted]][/] {Text(message, style=style)}")
