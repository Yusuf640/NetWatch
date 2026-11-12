from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from db import init_db, get_conn
from scanner import run_scan, get_diff
from scope import check_scope
from firewall import audit_local_firewall, probe_firewall
from vulns import vuln_scan

app = FastAPI(title="NetWatch")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)
init_db()


class ScanRequest(BaseModel):
    target: str


class AuditRequest(BaseModel):
    target: str
    authorized: bool = False


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


def guard(req: AuditRequest):
    if not req.authorized:
        raise HTTPException(400, "You must confirm you are authorized to scan this target.")
    try:
        check_scope(req.target)
    except ValueError as e:
        raise HTTPException(403, str(e))


@app.post("/scan")
def start_scan(req: ScanRequest):
    return {"scan_id": run_scan(req.target)}


@app.get("/scans")
def list_scans():
    conn = get_conn()
    rows = [dict(r) for r in conn.execute("SELECT * FROM scans ORDER BY id DESC")]
    conn.close()
    return rows


@app.get("/scans/{scan_id}")
def scan_detail(scan_id: int):
    conn = get_conn()
    hosts = [dict(r) for r in conn.execute("SELECT * FROM hosts WHERE scan_id=?", (scan_id,))]
    ports = [dict(r) for r in conn.execute("SELECT * FROM ports WHERE scan_id=?", (scan_id,))]
    conn.close()
    return {"hosts": hosts, "ports": ports, "diff": get_diff(scan_id)}


@app.get("/audit/local-firewall")
def local_fw():
    f = audit_local_firewall()
    return {"scan_id": save_findings("local-firewall", "localhost", f), "findings": f}


@app.post("/audit/firewall")
def remote_fw(req: AuditRequest):
    guard(req)
    f = probe_firewall(req.target)
    return {"scan_id": save_findings("firewall", req.target, f), "findings": f}


@app.post("/audit/vulns")
def vulns(req: AuditRequest):
    guard(req)
    f = vuln_scan(req.target)
    return {"scan_id": save_findings("vulns", req.target, f), "findings": f}