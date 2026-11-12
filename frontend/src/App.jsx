import { useState, useEffect } from "react";
const API = "http://localhost:8000";
export default function App() {
  const [findings, setFindings] = useState([]);
const [authorized, setAuthorized] = useState(false);

const audit = async (path, method = "POST") => {
  setLoading(true);
  try {
    const res = await fetch(`${API}${path}`, {
      method,
      headers: { "Content-Type": "application/json" },
      body: method === "POST" ? JSON.stringify({ target, authorized }) : undefined,
    });
    if (!res.ok) throw new Error((await res.json()).detail || res.status);
    setFindings((await res.json()).findings);
  } catch (e) {
    alert("Failed: " + e.message);
  } finally {
    setLoading(false);
  }
};

const color = { critical: "#b00020", high: "crimson", medium: "darkorange", low: "goldenrod", info: "gray" };
  const [target, setTarget] = useState("192.168.1.0/24");
  const [scans, setScans] = useState([]);
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(false);

  const loadScans = async () => setScans(await (await fetch(`${API}/scans`)).json());
  const open = async (id) => setDetail(await (await fetch(`${API}/scans/${id}`)).json());
  useEffect(() => { loadScans(); }, []);

  const scan = async () => {
    setLoading(true);
    const res = await fetch(`${API}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target }),
    });
    const { scan_id } = await res.json();
    await loadScans();
    await open(scan_id);
    setLoading(false);
  };

  return (
    <div style={{ maxWidth: 900, margin: "2rem auto", fontFamily: "sans-serif" }}>
      <h1>NetWatch</h1>
      <input value={target} onChange={(e) => setTarget(e.target.value)} />
      <button onClick={scan} disabled={loading}>{loading ? "Scanning..." : "Run scan"}</button>
       <div style={{ margin: "1rem 0" }}>
  <label>
    <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
    {" "}I am authorized to test this target
  </label>
  <div>
    <button onClick={() => audit("/audit/local-firewall", "GET")} disabled={loading}>Audit my firewall</button>{" "}
    <button onClick={() => audit("/audit/firewall")} disabled={loading || !authorized}>Probe target firewall</button>{" "}
    <button onClick={() => audit("/audit/vulns")} disabled={loading || !authorized}>Vulnerability scan</button>
  </div>
</div>

{findings.length > 0 && (
  <table border="1" cellPadding="6">
    <thead><tr><th>Severity</th><th>Host</th><th>Finding</th><th>Details</th><th>Fix</th></tr></thead>
    <tbody>{findings.map((f, i) => (
      <tr key={i}>
        <td style={{ color: color[f.severity], fontWeight: "bold" }}>{f.severity.toUpperCase()}</td>
        <td>{f.ip}{f.port ? `:${f.port}` : ""}</td>
        <td>{f.title}</td><td>{f.detail}</td><td>{f.fix}</td>
      </tr>))}
    </tbody>
  </table>
)}
      <h3>History</h3>
      {scans.map((s) => (
        <div key={s.id}><a href="#" onClick={() => open(s.id)}>
          #{s.id} - {s.target} - {s.started_at}</a></div>
      ))}

      {detail && (<>
        <h3>Alerts</h3>
        {detail.diff.new_hosts.map((ip) => <p key={ip}>🆕 New device: {ip}</p>)}
        {detail.diff.gone_hosts.map((ip) => <p key={ip}>❌ Device gone: {ip}</p>)}
        {detail.diff.risky_ports.map((r) => (
          <p key={r.ip + r.port} style={{ color: "crimson" }}>
            ⚠️ {r.ip} has {r.service} open (port {r.port})</p>))}

        <h3>Hosts ({detail.hosts.length})</h3>
        <table border="1" cellPadding="6">
          <thead><tr><th>IP</th><th>Hostname</th><th>Open ports</th></tr></thead>
          <tbody>{detail.hosts.map((h) => (
            <tr key={h.ip}>
              <td>{h.ip}</td><td>{h.hostname}</td>
              <td>{detail.ports.filter((p) => p.ip === h.ip)
                    .map((p) => `${p.port}/${p.service}`).join(", ")}</td>
            </tr>))}
          </tbody>
        </table>
      </>)}
    </div>
  );
}
