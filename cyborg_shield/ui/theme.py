"""Cyborg color palette — half-human, half-machine."""
from rich.theme import Theme
from rich.style import Style

CYBORG_THEME = Theme({
    "primary":    "bold #00AAFF",
    "secondary":  "bold #00FFDD",
    "accent":     "bold #C0C0C0",
    "danger":     "bold #FF4444",
    "warning":    "bold #FFAA00",
    "success":    "bold #00FF88",
    "muted":      "#666699",
    "panel":      "on #0A0A1A",
    "highlight":  "bold white on #0033AA",
    "title":      "bold #00AAFF on #0A0A1A",
    "rule.line":  "#00AAFF",
    "allow":      "bold #00FF88",
    "block":      "bold #FF4444",
    "drop":       "bold #FF8800",
    "log":        "#888888",
})

BORDER_STYLE    = "bright_blue"
PANEL_STYLE     = "blue on black"
HEADER_STYLE    = "bold cyan on #0A0A1A"
