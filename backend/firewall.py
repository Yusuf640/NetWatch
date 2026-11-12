import re, subprocess, platform
import xml.etree.ElementTree as ET
import nmap

# ---- Local Windows firewall audit ----
def audit_local_firewall():
    if platform.system() != "Windows":
        return [dict(severity="info", title="Local audit supports Windows only", detail="", fix="")]
    out = subprocess.run(["netsh", "advfirewall", "show", "allprofiles"],
                         capture_output=True, text=True).stdout
    findings = []
    parts = re.split(r"(\w+) Profile Settings:", out)
    for name, body in zip(parts[1::2], parts[2::2]):
        state = re.search(r"State\s+(\w+)", body)
        policy = re.search(r"Firewall Policy\s+(\S+)", body)
        if state and state.group(1).upper() != "ON":
            findings.append(dict(
                severity="high", title=f"{name} firewall profile is OFF",
                detail=f"State: {state.group(1)}",
                fix=f"Run: netsh advfirewall set {name.lower()}profile state on"))
        if policy and "BlockInbound" not in policy.group(1):
            findings.append(dict(
                severity="medium", title=f"{name} profile allows inbound by default",
                detail=f"Policy: {policy.group(1)}",
                fix="Set the default inbound action to Block."))
    if not findings:
        findings.append(dict(severity="info", title="Firewall enabled on all profiles",
                             detail="Default inbound action is Block.", fix=""))
    return findings

# ---- Remote firewall detection ----
def _probe(target, flags):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments=f"{flags} -Pn --top-ports 100 --reason -T4")
    root = ET.fromstring(nm.get_nmap_last_output())
    results = {}
    for h in root.findall("host"):
        ip = h.find("address").get("addr")
        counts, reasons, open_ports = {}, {}, []
        ports = h.find("ports")
        if ports is None:
            continue
        # Nmap collapses common states into <extraports>, so read them too
        for ep in ports.findall("extraports"):
            counts[ep.get("state")] = counts.get(ep.get("state"), 0) + int(ep.get("count"))
            for r in ep.findall("extrareasons"):
                reasons[r.get("reason")] = reasons.get(r.get("reason"), 0) + int(r.get("count"))
        for p in ports.findall("port"):
            st = p.find("state")
            counts[st.get("state")] = counts.get(st.get("state"), 0) + 1
            reasons[st.get("reason")] = reasons.get(st.get("reason"), 0) + 1
            if st.get("state") == "open":
                open_ports.append(int(p.get("portid")))
        results[ip] = dict(counts=counts, reasons=reasons, open=open_ports)
    return results

def probe_firewall(target):
    syn = _probe(target, "-sS")
    ack = _probe(target, "-sA")
    findings = []
    for ip, s in syn.items():
        total = sum(s["counts"].values()) or 1
        filtered = s["counts"].get("filtered", 0)
        a = ack.get(ip, {"counts": {}})
        ack_filtered = a["counts"].get("filtered", 0)
        a_total = sum(a["counts"].values()) or 1
        if filtered / total > 0.5:
            silent = s["reasons"].get("no-response", 0) > s["reasons"].get("admin-prohibited", 0)
            how = "silently dropping packets" if silent else "rejecting packets with ICMP"
            findings.append(dict(ip=ip, severity="info", title="Firewall detected",
                detail=f"{filtered}/{total} ports filtered; firewall is {how}.", fix=""))
        elif ack_filtered / a_total > 0.5:
            findings.append(dict(ip=ip, severity="info", title="Stateful firewall detected",
                detail="ACK probes are filtered even though SYN probes were answered.", fix=""))
        else:
            findings.append(dict(ip=ip, severity="medium", title="No firewall filtering detected",
                detail="Ports answer with resets instead of being filtered.",
                fix="Enable a host or network firewall and block unneeded inbound ports."))
        if s["open"]:
            findings.append(dict(ip=ip, severity="info", title="Ports reachable through the firewall",
                detail=", ".join(map(str, sorted(s["open"]))), fix="Confirm each one is intended."))
    return findings