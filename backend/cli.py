import json
from datetime import datetime
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from db import init_db, get_conn
from scanner import run_scan, get_diff
from scope import check_scope
from firewall import audit_local_firewall, probe_firewall
from vulns import vuln_scan

app = typer.Typer(help="NetWatch - network security assessment CLI", no_args_is_help=True)
console = Console()

COLORS = {"critical": "bold red", "high": "red", "medium": "dark_orange",
          "low": "yellow", "info": "grey62"}
ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def save_findings(kind, target, findings):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO scans(target, started_at) VALUES (?,?)",
                (f"{kind}: {target}", datetime.now().isoformat()))
    sid = cur.lastrowid
    for f in findings:
        cur.execute(
            """INSERT INTO findings(scan_id, ip, port, category, severity, title, detail, fix)
               VALUES (?,?,?,?,?,?,?,?)""",
            (sid, f.get("ip", target), f.get("port"), kind,
             f["severity"], f["title"], f.get("detail", ""), f.get("fix", "")))
    conn.commit()
    conn.close()
    return sid


def guard(target: str, authorized: bool):
    if not authorized:
        console.print("[red]Refused:[/red] add --authorized to confirm you have "
                      "permission to test this target.")
        raise typer.Exit(1)
    try:
        check_scope(target)
    except ValueError as e:
        console.print(f"[red]Out of scope:[/red] {e}")
        raise typer.Exit(1)


def show_findings(findings, as_json=False, out: Optional[str] = None):
    findings = sorted(findings, key=lambda f: ORDER.get(f["severity"], 9))
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(findings, fh, indent=2)
        console.print(f"Saved report to [cyan]{out}[/cyan]")
    if as_json:
        print(json.dumps(findings, indent=2))
        return
    table = Table(show_lines=True)
    for col in ("Severity", "Host", "Finding", "Details", "Fix"):
        table.add_column(col, overflow="fold")
    for f in findings:
        host = f.get("ip", "") + (f":{f['port']}" if f.get("port") else "")
        style = COLORS.get(f["severity"], "")
        table.add_row(f"[{style}]{f['severity'].upper()}[/{style}]", host,
                      f["title"], f.get("detail", ""), f.get("fix", ""))
    console.print(table)


@app.command()
def scan(target: str = typer.Argument(..., help="IP or CIDR, e.g. 192.168.1.0/24"),
         authorized: bool = typer.Option(False, "--authorized", help="Confirm you have permission")):
    """Discover hosts and open ports, then show changes since the last scan."""
    guard(target, authorized)
    with console.status("Scanning..."):
        sid = run_scan(target)
    diff = get_diff(sid)
    conn = get_conn()
    hosts = conn.execute("SELECT * FROM hosts WHERE scan_id=?", (sid,)).fetchall()
    ports = conn.execute("SELECT * FROM ports WHERE scan_id=?", (sid,)).fetchall()
    conn.close()

    table = Table(title=f"Scan #{sid}", show_lines=True)
    table.add_column("IP"); table.add_column("Hostname"); table.add_column("Open ports")
    for h in hosts:
        plist = ", ".join(f"{p['port']}/{p['service']}" for p in ports if p["ip"] == h["ip"])
        table.add_row(h["ip"], h["hostname"] or "-", plist or "-")
    console.print(table)

    for ip in diff["new_hosts"]:
        console.print(f"[green]+ New device:[/green] {ip}")
    for ip in diff["gone_hosts"]:
        console.print(f"[yellow]- Device gone:[/yellow] {ip}")
    for p in diff["new_ports"]:
        console.print(f"[cyan]+ New port:[/cyan] {p['ip']}:{p['port']}")
    for r in diff["risky_ports"]:
        console.print(f"[red]! Risky:[/red] {r['ip']} has {r['service']} open (port {r['port']})")


@app.command("local-firewall")
def local_firewall(as_json: bool = typer.Option(False, "--json"),
                   out: Optional[str] = typer.Option(None, "--out", help="Save JSON to file")):
    """Audit the Windows Firewall on this machine."""
    f = audit_local_firewall()
    save_findings("local-firewall", "localhost", f)
    show_findings(f, as_json, out)


@app.command()
def firewall(target: str,
             authorized: bool = typer.Option(False, "--authorized"),
             as_json: bool = typer.Option(False, "--json"),
             out: Optional[str] = typer.Option(None, "--out")):
    """Probe a target to detect firewall filtering (SYN + ACK scans)."""
    guard(target, authorized)
    with console.status("Probing firewall..."):
        f = probe_firewall(target)
    save_findings("firewall", target, f)
    show_findings(f, as_json, out)


@app.command()
def vulns(target: str,
          authorized: bool = typer.Option(False, "--authorized"),
          as_json: bool = typer.Option(False, "--json"),
          out: Optional[str] = typer.Option(None, "--out")):
    """Match detected service versions to known CVEs."""
    guard(target, authorized)
    with console.status("Running vulnerability scan (can take a few minutes)..."):
        f = vuln_scan(target)
    if not f:
        console.print("No known CVEs matched.")
    save_findings("vulns", target, f)
    show_findings(f, as_json, out)


@app.command()
def history(limit: int = typer.Option(10, help="How many recent scans to show")):
    """List past scans."""
    conn = get_conn()
    rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    table = Table()
    table.add_column("ID"); table.add_column("Target"); table.add_column("Started")
    for r in rows:
        table.add_row(str(r["id"]), r["target"], r["started_at"])
    console.print(table)


@app.command()
def report(scan_id: int,
           as_json: bool = typer.Option(False, "--json"),
           out: Optional[str] = typer.Option(None, "--out")):
    """Show the saved findings of a past scan."""
    conn = get_conn()
    rows = [dict(r) for r in conn.execute("SELECT * FROM findings WHERE scan_id=?", (scan_id,))]
    conn.close()
    if not rows:
        console.print("No findings stored for that scan ID.")
        raise typer.Exit(1)
    show_findings(rows, as_json, out)


if __name__ == "__main__":
    init_db()
    app()