"""Configuration file support for Deploy Guard."""

import os
from pathlib import Path
from typing import Optional


# Default config filename
CONFIG_FILENAME = ".deploy-guard.yml"


def find_config(start_path: str) -> Optional[Path]:
    """Walk up from start_path to find .deploy-guard.yml."""
    current = Path(start_path).resolve()
    if current.is_file():
        current = current.parent

    for _ in range(20):  # max depth
        candidate = current / CONFIG_FILENAME
        if candidate.exists():
            return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def load_config(config_path: Optional[Path] = None) -> dict:
    """Load configuration from YAML file. Returns empty dict if no config found."""
    if config_path is None:
        return {}

    try:
        import yaml
    except ImportError:
        # If PyYAML not installed, try basic parsing
        return _parse_basic(config_path)

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _parse_basic(config_path: Path) -> dict:
    """Minimal config parser when PyYAML is not available."""
    config: dict = {}
    try:
        text = config_path.read_text(encoding="utf-8")
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if value.lower() == "true":
                    config[key] = True
                elif value.lower() == "false":
                    config[key] = False
                else:
                    config[key] = value
    except Exception:
        pass
    return config
