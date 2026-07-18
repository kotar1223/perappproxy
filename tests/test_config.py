"""Tests for config module."""

import tempfile
from pathlib import Path

from perappproxy.config import Config, Rule, _write_toml, _read_toml


def test_config_roundtrip():
    config = Config(
        listen_host="0.0.0.0",
        listen_port=9090,
        global_upstream="socks5://proxy:1080",
        rules=[
            Rule(process="chrome.exe", upstream="socks5://us:1080"),
            Rule(process="firefox.exe", upstream="socks5://eu:1080"),
        ],
    )

    with tempfile.NamedTemporaryFile(suffix=".toml", mode="w", delete=False) as f:
        path = Path(f.name)

    _write_toml(path, config.to_dict())
    data = _read_toml(path)
    restored = Config.from_dict(data)

    assert restored.listen_host == "0.0.0.0"
    assert restored.listen_port == 9090
    assert restored.global_upstream == "socks5://proxy:1080"
    assert len(restored.rules) == 2
    assert restored.rules[0].process == "chrome.exe"
    assert restored.rules[1].upstream == "socks5://eu:1080"

    path.unlink()


def test_config_defaults():
    config = Config()
    assert config.listen_host == "127.0.0.1"
    assert config.listen_port == 8080
    assert config.global_upstream == ""
    assert config.rules == []


def test_config_empty_rules():
    data = {
        "proxy": {"listen_host": "127.0.0.1", "listen_port": 8080, "global_upstream": ""},
        "rules": [],
    }
    config = Config.from_dict(data)
    assert len(config.rules) == 0


def test_proxy_server_parse():
    from perappproxy.proxy_server import ProxyServer

    assert ProxyServer._parse_proxy("socks5://proxy:1080") == ("proxy", 1080)
    assert ProxyServer._parse_proxy("http://proxy") == ("proxy", 8080)
    assert ProxyServer._parse_proxy("proxy:3128") == ("proxy", 3128)
    assert ProxyServer._parse_proxy("socks4://10.0.0.1:1080") == ("10.0.0.1", 1080)
