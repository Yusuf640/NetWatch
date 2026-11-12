# NetWatch

A network security assessment tool with a **web dashboard** and a **command-line interface**, both built on one shared scanning engine. NetWatch discovers hosts and open ports, detects changes between scans, audits Windows Firewall configuration, infers remote firewall behavior, and matches detected service versions to known CVEs with severity ratings and remediation advice.

> **Legal and ethical use:** Only scan systems you own or have explicit written permission to test. NetWatch includes a consent flag and a scope guard, but you are responsible for how you use it. Unauthorized scanning may be illegal.

![Dashboard](docs/screenshots/dashboard.png)

## Features

- **Host and port discovery** using Nmap, with scan history stored in SQLite
- **Change detection:** new devices, devices that disappeared, newly opened ports
- **Risky service alerts** (Telnet, FTP, RDP, SMB, VNC, RPC, MySQL)
- **Local firewall audit:** checks every Windows Firewall profile (state and default inbound policy) and gives the fix command
- **Remote firewall detection:** compares SYN and ACK scan results to tell whether a host is behind a stateful firewall, and whether it drops or rejects packets
- **Vulnerability matching:** maps service versions to CVEs through Nmap's `vulners` script, with CVSS-based severity (critical/high/medium/low)
- **Authorization guardrails:** every active test needs an explicit consent flag, and targets are limited to private/loopback ranges unless allow-listed
- **Two interfaces:** React dashboard and a Typer CLI with colored tables, JSON export, and history

## Architecture

```
React dashboard ──► FastAPI REST API ──┐
                                       ├──► scanner / firewall / vulns / scope ──► Nmap
Typer CLI ─────────────────────────────┘             │
                                                     ▼
                                                  SQLite
```

| File | Purpose |
|---|---|
| `backend/scanner.py` | Nmap host/port scan and diff between scans |
| `backend/firewall.py` | Local Windows Firewall audit and remote SYN/ACK analysis |
| `backend/vulns.py` | CVE matching and severity scoring |
| `backend/scope.py` | Target authorization guard |
| `backend/db.py` | SQLite schema and connection |
| `backend/main.py` | FastAPI endpoints |
| `backend/cli.py` | Command-line interface |
| `frontend/` | React (Vite) dashboard |

## Requirements

- Python 3.11+
- Node.js LTS (dashboard only)
- [Nmap](https://nmap.org/download) installed and on your PATH (includes Npcap on Windows)
- Administrator/root privileges for SYN and ACK scans

## Installation

```bash
git clone https://github.com/Yusuf640/netwatch.git
cd netwatch/backend
python -m venv venv
# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
# macOS/Linux
source venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage: CLI

Run from the `backend` folder, in a terminal with administrator rights:

```bash
python cli.py --help
python cli.py scan 192.168.56.0/24 --authorized
python cli.py local-firewall
python cli.py firewall 192.168.56.101 --authorized
python cli.py vulns 192.168.56.101 --authorized --out report.json
python cli.py history
python cli.py report 5
```

| Flag | Meaning |
|---|---|
| `--authorized` | Confirms you have permission to test the target (required for active tests) |
| `--json` | Print machine-readable JSON |
| `--out FILE` | Save findings to a JSON file |

![CLI](docs/screenshots/cli.png)

## Usage: Web dashboard

Terminal 1 (backend, as administrator):

```bash
cd backend
python -m uvicorn main:app --reload
```

Terminal 2 (frontend):

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. API docs are at `http://localhost:8000/docs`.

## API endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/scan` | Run a host/port scan |
| GET | `/scans` | List scan history |
| GET | `/scans/{id}` | Scan details and diff |
| GET | `/audit/local-firewall` | Audit local Windows Firewall |
| POST | `/audit/firewall` | Probe a target's firewall |
| POST | `/audit/vulns` | CVE matching scan |

## How firewall detection works

- **SYN scan (`-sS`):** closed ports reply with a reset, so no filtering. Ports that never reply, or return an ICMP "prohibited" message, are *filtered*, meaning a firewall is dropping or rejecting traffic.
- **ACK scan (`-sA`):** ports that respond are *unfiltered*. If ACK probes are filtered while SYN probes were answered, a stateful firewall is likely in place.

## Safe testing

Test against systems built for it:

- [Metasploitable 2](https://sourceforge.net/projects/metasploitable/) in VirtualBox on a **host-only** network
- DVWA, TryHackMe, Hack The Box
- Your own devices

`scanme.nmap.org` allows light port scanning only. Do not run the vulnerability scan against it.

## Limitations

- CVE matching is based on **version banners**. It can produce false positives when vendors backport patches without changing the version string, and false negatives when banners are hidden.
- The vulnerability scan needs internet access to query the vulners database.
- The local firewall audit supports Windows only.
- Firewall detection is an inference from scan behavior, not a rule-by-rule inspection of the remote device.
- NetWatch detects and reports. It does not exploit.

## Roadmap

- [ ] HTML/PDF report export
- [ ] Check Windows inbound firewall rules for risky ports
- [ ] AI-generated remediation summary
- [ ] Scheduled scans
- [ ] Docker support

## Tech stack

Python, FastAPI, Pydantic, Typer, Rich, python-nmap, SQLite, React, Vite, Nmap

## License

MIT. See [LICENSE](LICENSE).