"""TOML configuration management."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("PERAPPPROXY_DIR", Path.home() / ".perappproxy"))
CONFIG_FILE = CONFIG_DIR / "config.toml"


@dataclass
class Rule:
    process: str
    upstream: str


@dataclass
class Config:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8080
    global_upstream: str = ""
    rules: list[Rule] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "proxy": {
                "listen_host": self.listen_host,
                "listen_port": self.listen_port,
                "global_upstream": self.global_upstream,
            },
            "rules": [{"process": r.process, "upstream": r.upstream} for r in self.rules],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        proxy = data.get("proxy", {})
        rules = [Rule(process=r["process"], upstream=r["upstream"]) for r in data.get("rules", [])]
        return cls(
            listen_host=proxy.get("listen_host", "127.0.0.1"),
            listen_port=proxy.get("listen_port", 8080),
            global_upstream=proxy.get("global_upstream", ""),
            rules=rules,
        )


def _write_toml(path: Path, data: dict) -> None:
    """Minimal TOML writer — no external dependency needed."""
    lines: list[str] = []

    def write_value(key: str, val) -> None:
        if isinstance(val, str):
            lines.append(f'{key} = "{val}"')
        elif isinstance(val, bool):
            lines.append(f"{key} = {'true' if val else 'false'}")
        else:
            lines.append(f"{key} = {val}")

    for section, content in data.items():
        if isinstance(content, dict):
            lines.append(f"[{section}]")
            for k, v in content.items():
                write_value(k, v)
            lines.append("")
        elif isinstance(content, list):
            for item in content:
                lines.append(f"[[{section}]]")
                for k, v in item.items():
                    write_value(k, v)
                lines.append("")

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def _read_toml(path: Path) -> dict:
    """Minimal TOML reader."""
    text = path.read_text(encoding="utf-8")
    result: dict = {}
    current_section: dict | list | None = None
    current_key: str = ""
    is_array = False

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("[[") and stripped.endswith("]]"):
            key = stripped[2:-2]
            is_array = True
            current_key = key
            if key not in result:
                result[key] = []
            current_section = {}
            result[key].append(current_section)
        elif stripped.startswith("[") and stripped.endswith("]"):
            key = stripped[1:-1]
            is_array = False
            current_key = key
            current_section = {}
            result[key] = current_section
        elif "=" in stripped and current_section is not None:
            k, v = stripped.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if v.lower() == "true":
                v = True
            elif v.lower() == "false":
                v = False
            else:
                try:
                    v = int(v)
                except ValueError:
                    try:
                        v = float(v)
                    except ValueError:
                        pass
            current_section[k] = v

    return result


def load_config() -> Config:
    if not CONFIG_FILE.exists():
        default = Config()
        save_config(default)
        return default
    data = _read_toml(CONFIG_FILE)
    return Config.from_dict(data)


def save_config(config: Config) -> None:
    _write_toml(CONFIG_FILE, config.to_dict())
