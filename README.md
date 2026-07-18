# PerAppProxy

**Per-application HTTP/HTTPS proxy router for Windows.**

Route different apps through different proxy servers — each app gets its own IP. Built-in free proxy pool with auto-fetch from public sources.

```
Chrome   → SOCKS5 US  → IP: 198.51.100.1
Firefox  → SOCKS5 EU  → IP: 203.0.113.42
DDNet    → SOCKS5 Asia → IP: 192.0.2.7
System   → SOCKS5 RU  → IP: 198.51.100.99
```

## Features

- **Per-app routing** — different process, different proxy, different IP
- **Free proxy pool** — fetch thousands of public SOCKS5/HTTP proxies
- **Auto-validate** — test which proxies are alive and measure latency
- **Quick assign** — pick a proxy from the pool in one command
- **System proxy toggle** — enable/disable Windows system-wide proxy
- **Connection scanner** — see which apps are online and where they connect
- **Lightweight** — pure Python, no kernel drivers, no VPN tunnel

## Install

```bash
pip install git+https://github.com/kotar1223/perappproxy.git
```

Or clone and install locally:

```bash
git clone https://github.com/kotar1223/perappproxy.git
cd perappproxy
pip install -e .
```

Requires **Python 3.11+** on **Windows 10/11**.

## Quick Start

```bash
# 1. Fetch free proxies
perappproxy pool fetch

# 2. Check which ones work
perappproxy pool check

# 3. See the fastest
perappproxy pool best

# 4. Assign proxies to apps
perappproxy quick chrome.exe --pool
perappproxy quick firefox.exe --pool
perappproxy quick DDNet1.exe --pool

# 5. Enable system proxy and start
perappproxy proxy-on
perappproxy start
```

## Commands

### Server

| Command | Description |
|---------|-------------|
| `perappproxy start` | Start the local proxy server |
| `perappproxy stop` | Stop the proxy server |
| `perappproxy status` | Show status, rules, and pool info |

### Rules

| Command | Description |
|---------|-------------|
| `perappproxy add <process> <proxy>` | Route app through proxy |
| `perappproxy rm <process>` | Remove routing rule |
| `perappproxy rules` | List all rules |
| `perappproxy set-global <proxy>` | Set default proxy |
| `perappproxy quick <process>` | Interactive proxy assignment |

### Proxy Pool

| Command | Description |
|---------|-------------|
| `perappproxy pool fetch` | Download free proxies from public sources |
| `perappproxy pool check` | Test which proxies are alive |
| `perappproxy pool list` | Show all proxies in pool |
| `perappproxy pool best` | Get fastest proxies |
| `perappproxy pool random` | Pick random alive proxy |
| `perappproxy pool add <addr>` | Add custom proxy |
| `perappproxy pool rm <addr>` | Remove proxy from pool |
| `perappproxy pool clear` | Clear entire pool |

### System

| Command | Description |
|---------|-------------|
| `perappproxy proxy-on` | Enable Windows system proxy |
| `perappproxy proxy-off` | Disable Windows system proxy |
| `perappproxy scan` | Show active connections with process names |

## Examples

### Route DDNet through different IPs

```bash
# Create multiple instances with different executables
# DDNet1.exe, DDNet2.exe, etc.

perappproxy pool fetch
perappproxy pool check -n 50
perappproxy pool best

perappproxy quick DDNet1.exe --pool   # Pick proxy 1
perappproxy quick DDNet2.exe --pool   # Pick proxy 2
perappproxy quick DDNet3.exe --pool   # Pick proxy 3

perappproxy proxy-on
perappproxy start
```

### Manual proxy assignment

```bash
perappproxy add chrome.exe "socks5://us-server.example.com:1080"
perappproxy add firefox.exe "socks5://eu-server.example.com:1080"
perappproxy set-global "socks5://fallback.example.com:1080"
perappproxy proxy-on
perappproxy start
```

### Use your own SOCKS5 proxies

```bash
perappproxy pool add 192.168.1.100:1080 -t socks5
perappproxy pool add 10.0.0.50:3128 -t http
perappproxy pool list
```

## Config

Config file: `~/.perappproxy/config.toml`

```toml
[proxy]
listen_host = "127.0.0.1"
listen_port = 8080
global_upstream = "socks5://127.0.0.1:1080"

[[rules]]
process = "chrome.exe"
upstream = "socks5://us-server:1080"

[[rules]]
process = "firefox.exe"
upstream = "socks5://eu-server:1080"
```

## How It Works

1. PerAppProxy runs a local HTTP/HTTPS proxy on `localhost:8080`
2. Windows system proxy routes all app traffic through it
3. For each connection, the proxy identifies the source process via Windows API (`GetExtendedTcpTable`)
4. Based on rules, it chains through the configured upstream proxy
5. Each app goes through its own proxy — different IPs, different locations

```
┌──────────┐     ┌────────────────────┐     ┌─────────────────┐
│  App A   │────▶│                    │────▶│  Proxy US       │
│  App B   │────▶│  PerAppProxy:8080  │────▶│  Proxy EU       │
│  App C   │────▶│  (rule routing)    │────▶│  Proxy Default  │
└──────────┘     └────────────────────┘     └─────────────────┘
```

## Use Cases

- **Multi-account gaming** — run multiple game clients with different IPs
- **Web scraping** — rotate IPs across different browser sessions
- **Privacy** — route sensitive apps through specific proxies
- **Testing** — simulate users from different countries
- **Bypass restrictions** — access region-locked content per app

## Requirements

- Windows 10/11
- Python 3.11+
- Admin rights (for system proxy changes)

## License

MIT
