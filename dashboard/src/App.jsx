
import { useEffect, useState } from "react";
import { BarChart, Bar, Cell, XAxis, YAxis, Tooltip, CartesianGrid, ResponsiveContainer } from "recharts";
import "./App.css";

const CATEGORY_META = {
  "SQL Injection": { color: "#ff5462", short: "SQLI" },
  XSS: { color: "#c26bff", short: "XSS" },
  LFI: { color: "#ffb020", short: "LFI" },
  "Directory Traversal": { color: "#4ea1ff", short: "TRAV" },
  "Command Injection": { color: "#ff7ab8", short: "CMDI" },
  "Rate Limit Exceeded": { color: "#8a94a6", short: "RATE" },
  "Banned IP": { color: "#ff2d3d", short: "BAN" },
};

const API_BASE = "https://sentinelshield-d7qb.onrender.com";

function App() {
  const [logs, setLogs] = useState([]);
  const [flagged, setFlagged] = useState({});
  const [now, setNow] = useState(new Date());

  const [testQuery, setTestQuery] = useState("");
  const [testUsername, setTestUsername] = useState("");
  const [testFile, setTestFile] = useState("");
  const [testResult, setTestResult] = useState(null);
  const [testLoading, setTestLoading] = useState(false);

  useEffect(() => {
    fetchData();
    const dataInterval = setInterval(fetchData, 5000);
    const clock = setInterval(() => setNow(new Date()), 1000);
    return () => {
      clearInterval(dataInterval);
      clearInterval(clock);
    };
  }, []);

  const fetchData = () => {
   fetch("https://sentinelshield-d7qb.onrender.com/api/logs")
      .then((res) => res.json())
      .then(setLogs)
      .catch((err) => console.error("Failed to fetch logs:", err));

      fetch("https://sentinelshield-d7qb.onrender.com/api/flagged")
      .then((res) => res.json())
      .then(setFlagged)
      .catch((err) => console.error("Failed to fetch flagged IPs:", err));
  };

  const runTest = async (type, value) => {
    setTestLoading(true);
    setTestResult(null);

    try {
      let res;

      if (type === "search") {
        res = await fetch(`${API_BASE}/search?q=${encodeURIComponent(value)}`);
      } else if (type === "file") {
        res = await fetch(`${API_BASE}/file?name=${encodeURIComponent(value)}`);
      } else if (type === "login") {
        res = await fetch(`${API_BASE}/login`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: `username=${encodeURIComponent(value)}&password=test`,
        });
      }

      const text = await res.text();

      setTestResult({
        status: res.status,
        text: text.slice(0, 200),
      });

      setTimeout(fetchData, 1000);
    } catch (err) {
      setTestResult({
        status: "error",
        text: "Could not reach backend — it may be waking up, try again in a few seconds.",
      });
    }

    setTestLoading(false);
  };

  const blockedLogs = logs.filter((l) => l.verdict === "blocked");
  const allowedLogs = logs.filter((l) => l.verdict === "allowed");
  const flaggedEntries = Object.entries(flagged);

  const categoryCounts = {};
  blockedLogs.forEach((l) => {
    const cat = l.category || "Unknown";
    categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
  });

  const chartData = Object.keys(categoryCounts).map((cat) => ({
    name: CATEGORY_META[cat]?.short || cat,
    fullName: cat,
    count: categoryCounts[cat],
    color: CATEGORY_META[cat]?.color || "#6b7685",
  }));

  const blockRate = logs.length ? ((blockedLogs.length / logs.length) * 100).toFixed(1) : "0.0";

  return (
    <div className="soc">
      <div className="soc-topbar">
        <div className="soc-brand">
          <span className="soc-mark" />
          <div>
            <div className="soc-title">SENTINELSHIELD</div>
            <div className="soc-subtitle">web protection console</div>
          </div>
        </div>
        <div className="soc-clock">
          <span className="soc-live">
            <span className="soc-live-dot" /> MONITORING
          </span>
          {now.toLocaleTimeString()}
        </div>
      </div>

      <div className="soc-stats">
        <div className="soc-stat">
          <div className="soc-stat-label">total requests</div>
          <div className="soc-stat-value">{logs.length}</div>
        </div>
        <div className="soc-stat accent-red">
          <div className="soc-stat-label">blocked</div>
          <div className="soc-stat-value">{blockedLogs.length}</div>
        </div>
        <div className="soc-stat accent-green">
          <div className="soc-stat-label">allowed</div>
          <div className="soc-stat-value">{allowedLogs.length}</div>
        </div>
        <div className="soc-stat accent-amber">
          <div className="soc-stat-label">flagged ips</div>
          <div className="soc-stat-value">{flaggedEntries.length}</div>
        </div>
        <div className="soc-stat">
          <div className="soc-stat-label">block rate</div>
          <div className="soc-stat-value">{blockRate}%</div>
        </div>
      </div>

      {/* TRY IT YOURSELF */}
      <div className="soc-panel">
        <div className="soc-panel-header">try it yourself — send a test request</div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: 12, marginBottom: 14 }}>

          <div>
            <div className="soc-empty" style={{ marginBottom: 6 }}>
              search (try: laptop, or &lt;script&gt;alert(1)&lt;/script&gt;)
            </div>

            <input
              value={testQuery}
              onChange={(e) => setTestQuery(e.target.value)}
              placeholder="search query"
              style={{
                width: "100%",
                background: "#0a0e14",
                border: "1px solid #1f2733",
                color: "#d5dce6",
                padding: 8,
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 12,
                marginBottom: 6,
                boxSizing: "border-box",
              }}
            />

            <button
              onClick={() => runTest("search", testQuery)}
              className="soc-tag tag-green"
              style={{ cursor: "pointer", border: "1px solid #2ecc8f55" }}
            >
              send search
            </button>
          </div>

          <div>
            <div className="soc-empty" style={{ marginBottom: 6 }}>
              login username (try: admin' OR '1'='1)
            </div>

            <input
              value={testUsername}
              onChange={(e) => setTestUsername(e.target.value)}
              placeholder="username"
              style={{
                width: "100%",
                background: "#0a0e14",
                border: "1px solid #1f2733",
                color: "#d5dce6",
                padding: 8,
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 12,
                marginBottom: 6,
                boxSizing: "border-box",
              }}
            />

            <button
              onClick={() => runTest("login", testUsername)}
              className="soc-tag tag-amber"
              style={{ cursor: "pointer", border: "1px solid #ffb02055" }}
            >
              send login
            </button>
          </div>

          <div>
            <div className="soc-empty" style={{ marginBottom: 6 }}>
              file lookup (try: readme.txt, or ../../etc/passwd)
            </div>

            <input
              value={testFile}
              onChange={(e) => setTestFile(e.target.value)}
              placeholder="filename"
              style={{
                width: "100%",
                background: "#0a0e14",
                border: "1px solid #1f2733",
                color: "#d5dce6",
                padding: 8,
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 12,
                marginBottom: 6,
                boxSizing: "border-box",
              }}
            />

            <button
              onClick={() => runTest("file", testFile)}
              className="soc-tag tag-red"
              style={{ cursor: "pointer", border: "1px solid #ff546255" }}
            >
              send file request
            </button>
          </div>

        </div>

        {testLoading && (
          <div className="soc-empty">sending request...</div>
        )}

        {testResult && (
          <div
            style={{
              marginTop: 10,
              padding: 10,
              background: "#0a0e14",
              border: "1px solid #1f2733",
              fontSize: 12,
            }}
          >
            <span
              className={`soc-tag ${
                testResult.status === 200
                  ? "tag-green"
                  : testResult.status === "error"
                  ? "tag-amber"
                  : "tag-red"
              }`}
            >
              status: {testResult.status}
            </span>

            <div style={{ marginTop: 8, color: "#8a94a6" }}>
              {testResult.text}
            </div>
          </div>
        )}
      </div>

      <div className="soc-panel">
        <div className="soc-panel-header">attack distribution by category</div>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={chartData} margin={{ top: 8, right: 12, left: -12, bottom: 0 }}>
            <CartesianGrid strokeDasharray="2 4" stroke="#1f2733" vertical={false} />
            <XAxis dataKey="name" tick={{ fill: "#6b7685", fontSize: 11, fontFamily: "JetBrains Mono, monospace" }} axisLine={{ stroke: "#1f2733" }} tickLine={false} />
            <YAxis allowDecimals={false} tick={{ fill: "#6b7685", fontSize: 11, fontFamily: "JetBrains Mono, monospace" }} axisLine={{ stroke: "#1f2733" }} tickLine={false} />
            <Tooltip
              contentStyle={{ background: "#11161f", border: "1px solid #1f2733", fontSize: 12, fontFamily: "JetBrains Mono, monospace" }}
              labelStyle={{ color: "#d5dce6" }}
              itemStyle={{ color: "#d5dce6" }}
              formatter={(value, name, props) => [value, props.payload.fullName]}
            />
            <Bar dataKey="count" radius={[2, 2, 0, 0]}>
              {chartData.map((entry, i) => (
                <Cell key={`cell-${i}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="soc-panel">
        <div className="soc-panel-header">flagged &amp; repeat offender ips</div>
        {flaggedEntries.length === 0 ? (
          <div className="soc-empty">no repeat offenders detected</div>
        ) : (
          <table className="soc-table">
            <thead>
              <tr>
                <th>ip address</th>
                <th>status</th>
                <th>violations</th>
                <th>attack types</th>
                <th>first seen</th>
                <th>last seen</th>
              </tr>
            </thead>
            <tbody>
              {flaggedEntries.map(([ip, info]) => (
                <tr key={ip}>
                  <td className="mono">{ip}</td>
                  <td>
                    <span className={`soc-tag ${info.status === "banned" ? "tag-red" : "tag-amber"}`}>
                      {info.status}
                    </span>
                  </td>
                  <td className="mono">{info.violation_count}</td>
                  <td className="mono">{[...new Set(info.categories)].join(", ")}</td>
                  <td className="mono dim">{info.first_seen}</td>
                  <td className="mono dim">{info.last_seen}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="soc-panel">
        <div className="soc-panel-header">recent events</div>
        <table className="soc-table">
          <thead>
            <tr>
              <th>time</th>
              <th>ip</th>
              <th>path</th>
              <th>verdict</th>
              <th>category</th>
            </tr>
          </thead>
          <tbody>
            {logs.slice().reverse().slice(0, 20).map((log, i) => (
              <tr key={i} className={log.verdict === "blocked" ? "row-flag" : ""}>
                <td className="mono dim">{log.timestamp}</td>
                <td className="mono">{log.ip}</td>
                <td className="mono">{log.path}</td>
                <td>
                  <span className={`soc-tag ${log.verdict === "blocked" ? "tag-red" : "tag-green"}`}>
                    {log.verdict}
                  </span>
                </td>
                <td>
                  {log.category ? (
                    <span className="soc-tag" style={{ color: CATEGORY_META[log.category]?.color || "#8a94a6", borderColor: (CATEGORY_META[log.category]?.color || "#8a94a6") + "55" }}>
                      {log.category}
                    </span>
                  ) : (
                    <span className="dim">—</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default App;

