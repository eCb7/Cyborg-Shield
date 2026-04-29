"""Event logger — Cyborg never misses a trace."""
from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path


_LOG_DIR = Path(__file__).resolve().parents[2] / "logs"


def _log_path(name: str, ext: str) -> Path:
    _LOG_DIR.mkdir(exist_ok=True)
    today = datetime.now().strftime("%Y-%m-%d")
    return _LOG_DIR / f"{name}_{today}.{ext}"


# -------------------------------------------------------------------------- CSV
def log_event_csv(event: dict):
    path = _log_path("traffic", "csv")
    write_header = not path.exists()
    with open(path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=event.keys())
        if write_header:
            writer.writeheader()
        writer.writerow(event)


# -------------------------------------------------------------------------- JSON
def log_event_json(event: dict):
    path = _log_path("traffic", "jsonl")
    with open(path, "a") as f:
        f.write(json.dumps(event) + "\n")


# -------------------------------------------------------------------------- Audit
def audit(action: str, detail: str):
    path = _log_path("audit", "log")
    ts   = datetime.now().isoformat()
    with open(path, "a") as f:
        f.write(f"[{ts}] {action:12s} | {detail}\n")
