import re
import nmap

CVE_LINE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d+\.\d)")

def _severity(score):
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"

def vuln_scan(target):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sV --script vulners --top-ports 100 -T4")
    findings = []
    for ip in nm.all_hosts():
        for proto in nm[ip].all_protocols():
            for port, info in nm[ip][proto].items():
                if info["state"] != "open":
                    continue
                product = f'{info.get("product","")} {info.get("version","")}'.strip()
                out = info.get("script", {}).get("vulners", "")
                cves = {c: float(s) for c, s in CVE_LINE.findall(out)}
                if cves:
                    top = max(cves.values())
                    worst = sorted(cves, key=cves.get, reverse=True)[:5]
                    findings.append(dict(
                        ip=ip, port=port, severity=_severity(top),
                        title=f"{product or info['name']}: {len(cves)} known CVEs",
                        detail=f"Highest CVSS {top}. Top: {', '.join(worst)}",
                        fix="Update this service to the latest patched version."))
    return findings