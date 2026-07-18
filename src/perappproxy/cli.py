"""CLI interface using Click — with proxy pool management."""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from .config import Config, Rule, load_config, save_config, CONFIG_FILE
from .proxy_server import ProxyServer
from .route_resolver import RouteResolver
from .system_proxy import get_system_proxy, set_system_proxy, disable_system_proxy
from .scanner import scan_connections
from .proxy_pool import ProxyPool

console = Console()

PID_FILE = Path.home() / ".perappproxy" / "proxy.pid"


def _save_pid() -> None:
    PID_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()), encoding="utf-8")


def _read_pid() -> int | None:
    if not PID_FILE.exists():
        return None
    try:
        return int(PID_FILE.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def _remove_pid() -> None:
    if PID_FILE.exists():
        PID_FILE.unlink()


def _is_running() -> bool:
    pid = _read_pid()
    if not pid:
        return False
    try:
        import psutil
        return psutil.pid_exists(pid)
    except ImportError:
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False


# ─── MAIN GROUP ───────────────────────────────────────────────

@click.group()
@click.option("--debug", is_flag=True, help="Debug logging")
def cli(debug: bool) -> None:
    """PerAppProxy — per-application proxy router with free proxy pool."""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")


# ─── SERVER ───────────────────────────────────────────────────

@cli.command()
def start() -> None:
    """Start the proxy server."""
    if _is_running():
        console.print("[yellow]Already running. 'perappproxy stop' first.[/]")
        return

    config = load_config()
    resolver = RouteResolver(config)
    server = ProxyServer(config.listen_host, config.listen_port, resolver)

    console.print(Panel.fit(
        f"[bold green]Starting proxy on {config.listen_host}:{config.listen_port}[/]\n"
        f"Global: [cyan]{config.global_upstream or '(none)'}[/]  |  Rules: [cyan]{len(config.rules)}[/]",
        title="PerAppProxy",
    ))

    _save_pid()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    async def run() -> None:
        await server.start()
        stop_event = asyncio.Event()
        def _sig(): stop_event.set()
        for s in (signal.SIGINT, signal.SIGTERM):
            try: loop.add_signal_handler(s, _sig)
            except NotImplementedError: pass
        await stop_event.wait()
        await server.stop()

    try:
        loop.run_until_complete(run())
    except KeyboardInterrupt:
        loop.run_until_complete(server.stop())
    finally:
        loop.close()
        _remove_pid()
        console.print("[yellow]Stopped.[/]")


@cli.command()
def stop() -> None:
    """Stop the proxy server."""
    pid = _read_pid()
    if not pid:
        console.print("[yellow]Not running.[/]")
        return
    try:
        import psutil
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(timeout=5)
        console.print(f"[green]Stopped (PID {pid}).[/]")
    except Exception:
        try: os.kill(pid, signal.SIGTERM)
        except OSError: pass
        console.print(f"[green]Sent stop signal to PID {pid}.[/]")
    finally:
        _remove_pid()


@cli.command()
def status() -> None:
    """Show status, rules, and pool info."""
    config = load_config()
    running = _is_running()
    pool = ProxyPool()
    stats = pool.count()

    color = "green" if running else "red"
    state = "Running" if running else "Stopped"

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column(style="bold")
    t.add_column()
    t.add_row("State", f"[{color}]{state}[/]")
    t.add_row("Listen", f"{config.listen_host}:{config.listen_port}")
    t.add_row("Global", config.global_upstream or "(none)")
    t.add_row("Rules", str(len(config.rules)))
    t.add_row("Pool", f"[green]{stats['alive']} alive[/] / {stats['total']} total")

    console.print(Panel(t, title="PerAppProxy", border_style="blue"))

    if config.rules:
        rt = Table(title="Rules", border_style="dim")
        rt.add_column("#", style="dim")
        rt.add_column("Process", style="cyan")
        rt.add_column("Upstream", style="green")
        for i, r in enumerate(config.rules, 1):
            rt.add_row(str(i), r.process, r.upstream)
        console.print(rt)


# ─── RULES ────────────────────────────────────────────────────

@cli.command("set-global")
@click.argument("upstream")
def set_global(upstream: str) -> None:
    """Set default proxy (when no rule matches). Example: socks5://1.2.3.4:1080"""
    config = load_config()
    config.global_upstream = upstream
    save_config(config)
    console.print(f"[green]Global -> [cyan]{upstream}[/cyan][/]")


@cli.command("add")
@click.argument("process")
@click.argument("upstream")
def add_rule(process: str, upstream: str) -> None:
    """Add rule: process.exe -> proxy. Example: perappproxy add DDNet1.exe socks5://1.2.3.4:1080"""
    config = load_config()
    config.rules = [r for r in config.rules if r.process.lower() != process.lower()]
    config.rules.append(Rule(process=process, upstream=upstream))
    save_config(config)
    console.print(f"[green][cyan]{process}[/cyan] -> [cyan]{upstream}[/cyan][/]")


@cli.command("rm")
@click.argument("process")
def remove_rule(process: str) -> None:
    """Remove rule for process."""
    config = load_config()
    before = len(config.rules)
    config.rules = [r for r in config.rules if r.process.lower() != process.lower()]
    if len(config.rules) == before:
        console.print(f"[yellow]No rule for {process}[/]")
    else:
        save_config(config)
        console.print(f"[green]Removed {process}[/]")


@cli.command("rules")
def list_rules() -> None:
    """List all rules."""
    config = load_config()
    if not config.rules:
        console.print(f"[dim]No rules. Global: {config.global_upstream or '(none)'}[/]")
        return

    t = Table(title="Rules", border_style="blue")
    t.add_column("#", style="dim")
    t.add_column("Process", style="cyan")
    t.add_column("Upstream", style="green")
    for i, r in enumerate(config.rules, 1):
        t.add_row(str(i), r.process, r.upstream)
    console.print(t)
    console.print(f"[dim]Default: {config.global_upstream or '(none)'}[/]")


# ─── SYSTEM PROXY ─────────────────────────────────────────────

@cli.command("proxy-on")
def proxy_on_cmd() -> None:
    """Enable Windows system proxy."""
    config = load_config()
    set_system_proxy(config.listen_host, config.listen_port)
    console.print(f"[green]System proxy ON -> 127.0.0.1:{config.listen_port}[/]")


@cli.command("proxy-off")
def proxy_off_cmd() -> None:
    """Disable Windows system proxy."""
    disable_system_proxy()
    console.print("[green]System proxy OFF[/]")


# ─── SCAN ─────────────────────────────────────────────────────

@cli.command()
def scan() -> None:
    """Show active connections with process names."""
    conns = scan_connections()
    if not conns:
        console.print("[yellow]No active connections.[/]")
        return

    by_proc: dict[str, list[dict]] = {}
    for c in conns:
        by_proc.setdefault(c["process"], []).append(c)

    t = Table(title=f"Connections ({len(conns)})", border_style="blue")
    t.add_column("Process", style="cyan")
    t.add_column("#", justify="right")
    t.add_column("Remotes", style="dim")

    for proc, cl in sorted(by_proc.items()):
        remotes = [c["remote"] for c in cl[:3]]
        t.add_row(proc, str(len(cl)), ", ".join(remotes))
    console.print(t)
    console.print("[dim]Use process name with 'perappproxy add'[/]")


# ─── PROXY POOL ───────────────────────────────────────────────

@cli.group()
def pool() -> None:
    """Free proxy pool — fetch, check, and use public proxies."""
    pass


@pool.command("fetch")
def pool_fetch() -> None:
    """Download proxies from public sources."""
    pp = ProxyPool()
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
        task = prog.add_task("Fetching proxies...", total=None)
        proxies = pp.fetch_free_proxies(progress_callback=lambda m: prog.update(task, description=m))
        prog.update(task, description=f"Fetched {len(proxies)} new proxies")

    pp.proxies.extend(proxies)
    pp._save_cache()
    stats = pp.count()
    console.print(f"[green]Added {len(proxies)} proxies. Pool: {stats['total']} total[/]")


@pool.command("check")
@click.option("--limit", "-n", default=0, help="Check only first N proxies (0=all)")
def pool_check(limit: int) -> None:
    """Test which proxies are alive."""
    pp = ProxyPool()
    to_check = pp.proxies[:limit] if limit > 0 else pp.proxies
    if not to_check:
        console.print("[yellow]Pool empty. Run 'perappproxy pool fetch' first.[/]")
        return

    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
        task = prog.add_task(f"Testing {len(to_check)} proxies...", total=len(to_check))
        alive = pp.validate_proxies(to_check, progress_callback=lambda m: prog.update(task, description=m))
        prog.update(task, completed=len(to_check))

    pp._save_cache()
    stats = pp.count()
    console.print(f"[green]Alive: {stats['alive']} / {stats['total']}[/]")


@pool.command("list")
@click.option("--alive", "-a", is_flag=True, help="Show only alive proxies")
@click.option("--limit", "-n", default=30, help="Max entries to show")
def pool_list(alive: bool, limit: int) -> None:
    """List proxies in pool."""
    pp = ProxyPool()
    proxies = pp.list_alive() if alive else pp.list_all()
    if not proxies:
        console.print("[yellow]Pool empty.[/]")
        return

    # Sort by latency
    proxies.sort(key=lambda p: p.latency_ms if p.latency_ms > 0 else 99999)
    proxies = proxies[:limit]

    t = Table(title=f"Proxy Pool ({len(proxies)} shown)", border_style="blue")
    t.add_column("#", style="dim")
    t.add_column("Address", style="cyan")
    t.add_column("Type", style="yellow")
    t.add_column("Latency", justify="right")
    t.add_column("Status")

    for i, p in enumerate(proxies, 1):
        status = "[green]OK" if p.alive else "[red]DEAD"
        lat = f"{p.latency_ms:.0f}ms" if p.latency_ms > 0 else "-"
        t.add_row(str(i), p.address, p.protocol, lat, status)
    console.print(t)


@pool.command("add")
@click.argument("address")
@click.option("--type", "-t", "proto", default="socks5", help="Protocol: socks5, http, https")
def pool_add(address: str, proto: str) -> None:
    """Add custom proxy to pool. Example: perappproxy pool add 1.2.3.4:1080 -t socks5"""
    pp = ProxyPool()
    entry = pp.add_proxy(address, proto)
    pp._save_cache()
    console.print(f"[green]Added [cyan]{entry.url}[/cyan][/]")


@pool.command("rm")
@click.argument("address")
def pool_rm(address: str) -> None:
    """Remove proxy from pool."""
    pp = ProxyPool()
    if pp.remove_proxy(address):
        console.print(f"[green]Removed {address}[/]")
    else:
        console.print(f"[yellow]Not found: {address}[/]")


@pool.command("clear")
def pool_clear() -> None:
    """Clear entire proxy pool."""
    pp = ProxyPool()
    pp.clear()
    console.print("[green]Pool cleared.[/]")


@pool.command("random")
@click.option("--count", "-n", default=1, help="How many proxies to pick")
def pool_random(count: int) -> None:
    """Pick random alive proxy from pool."""
    pp = ProxyPool()
    picks = [pp.get_random() for _ in range(count)]
    picks = [p for p in picks if p]
    if not picks:
        console.print("[yellow]No alive proxies. Run 'pool check' first.[/]")
        return
    for p in picks:
        console.print(f"  [cyan]{p.url}[/]  ({p.latency_ms:.0f}ms)")


@pool.command("best")
@click.option("--count", "-n", default=3, help="How many fastest proxies")
def pool_best(count: int) -> None:
    """Get the fastest proxies from pool."""
    pp = ProxyPool()
    best = pp.get_best(count)
    if not best:
        console.print("[yellow]No alive proxies.[/]")
        return
    t = Table(title=f"Top {len(best)} Fastest", border_style="green")
    t.add_column("#", style="dim")
    t.add_column("Address", style="cyan")
    t.add_column("Latency", justify="right", style="green")
    for i, p in enumerate(best, 1):
        t.add_row(str(i), p.url, f"{p.latency_ms:.0f}ms")
    console.print(t)


# ─── QUICK ASSIGN ─────────────────────────────────────────────

@cli.command("quick")
@click.argument("process")
@click.option("--pool", "use_pool", is_flag=True, help="Auto-pick from proxy pool")
def quick_assign(process: str, use_pool: bool) -> None:
    """Quickly assign a proxy to an app. Interactive pick from pool or manual entry."""
    pp = ProxyPool()
    config = load_config()

    if use_pool:
        alive = pp.list_alive()
        if not alive:
            console.print("[yellow]Pool empty or no alive proxies. Run 'pool fetch' + 'pool check'[/]")
            return

        alive.sort(key=lambda p: p.latency_ms if p.latency_ms > 0 else 99999)
        t = Table(title="Pick a proxy", border_style="blue")
        t.add_column("#", style="dim")
        t.add_column("Address", style="cyan")
        t.add_column("Latency", style="green")
        for i, p in enumerate(alive[:20], 1):
            t.add_row(str(i), p.url, f"{p.latency_ms:.0f}ms")
        console.print(t)

        choice = console.input("[bold]Enter number (or 'r' for random): [/]")
        if choice.strip().lower() == "r":
            proxy = pp.get_random()
            if proxy:
                config.rules = [r for r in config.rules if r.process.lower() != process.lower()]
                config.rules.append(Rule(process=process, upstream=proxy.url))
                save_config(config)
                console.print(f"[green][cyan]{process}[/cyan] -> [cyan]{proxy.url}[/cyan] (random)[/]")
            return

        try:
            idx = int(choice.strip()) - 1
            if 0 <= idx < len(alive):
                proxy = alive[idx]
                config.rules = [r for r in config.rules if r.process.lower() != process.lower()]
                config.rules.append(Rule(process=process, upstream=proxy.url))
                save_config(config)
                console.print(f"[green][cyan]{process}[/cyan] -> [cyan]{proxy.url}[/cyan][/]")
        except (ValueError, IndexError):
            console.print("[red]Invalid choice[/]")
    else:
        proxy = console.input("[bold]Proxy address (socks5://host:port): [/]")
        if proxy.strip():
            config.rules = [r for r in config.rules if r.process.lower() != process.lower()]
            config.rules.append(Rule(process=process, upstream=proxy.strip()))
            save_config(config)
            console.print(f"[green][cyan]{process}[/cyan] -> [cyan]{proxy.strip()}[/cyan][/]")


@cli.command("config-path")
def config_path_cmd() -> None:
    """Show config file path."""
    console.print(str(CONFIG_FILE))


@cli.command()
def edit() -> None:
    """Open config in Notepad."""
    config = load_config()
    save_config(config)
    import subprocess
    subprocess.Popen(["notepad", str(CONFIG_FILE)])
    console.print(f"[dim]{CONFIG_FILE}[/]")


def main() -> None:
    cli()
