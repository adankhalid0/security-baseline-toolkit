"""Load the asset inventory that the audit runs against."""

from __future__ import annotations

import yaml


def load_inventory(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("assets", [])
