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

function App() {
  const [logs, setLogs] = useState([]);
  const [flagged, setFlagged] = useState({});
  const [now, setNow] = useState(new Date());

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