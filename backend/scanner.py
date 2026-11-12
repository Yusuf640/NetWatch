import nmap
from datetime import datetime
from db import get_conn

RISKY = {
       23:   ("Telnet ", "high"),
       21:   ("FTP ", "high"),
       3389: ("RDP ", "high"),
       5900: ("VNC ", "high"),
       445:  ("SMB ", "medium"),
       135:  ("RPC ", "medium"),
       3306: ("MySQL ", "medium"),
   }

def run_scan(target: str) -> int:
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sV --top-ports 100 -T4")
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("INSERT INTO scans(target, started_at) VALUES (?,?)",
                (target, datetime.now().isoformat()))
    scan_id = cur.lastrowid
    for ip in nm.all_hosts():
        host = nm[ip]
        cur.execute("INSERT INTO hosts(scan_id, ip, hostname, state) VALUES (?,?,?,?)",
                    (scan_id, ip, host.hostname(), host.state()))
        for proto in host.all_protocols():
            for port, info in host[proto].items():
                if info["state"] == "open":
                    cur.execute(
                        "INSERT INTO ports(scan_id, ip, port, protocol, service) VALUES (?,?,?,?,?)",
                        (scan_id, ip, port, proto, info.get("name", "")))
    conn.commit()
    conn.close()
    return scan_id

def get_diff(new_id: int):
    conn = get_conn()
    prev = conn.execute("SELECT id FROM scans WHERE id < ? ORDER BY id DESC LIMIT 1",
                        (new_id,)).fetchone()
    new_hosts = {r["ip"] for r in conn.execute("SELECT ip FROM hosts WHERE scan_id=?", (new_id,))}
    new_ports = {(r["ip"], r["port"]) for r in conn.execute(
        "SELECT ip, port FROM ports WHERE scan_id=?", (new_id,))}
    result = {"new_hosts": [], "gone_hosts": [], "new_ports": [], "risky_ports": []}
    if prev:
        old_hosts = {r["ip"] for r in conn.execute("SELECT ip FROM hosts WHERE scan_id=?", (prev["id"],))}
        old_ports = {(r["ip"], r["port"]) for r in conn.execute(
            "SELECT ip, port FROM ports WHERE scan_id=?", (prev["id"],))}
        result["new_hosts"] = sorted(new_hosts - old_hosts)
        result["gone_hosts"] = sorted(old_hosts - new_hosts)
        result["new_ports"] = [{"ip": i, "port": p} for i, p in sorted(new_ports - old_ports)]
    result["risky_ports"] = [{"ip": i, "port": p, "service": RISKY[p]}
                             for i, p in sorted(new_ports) if p in RISKY]
    conn.close()
    return result