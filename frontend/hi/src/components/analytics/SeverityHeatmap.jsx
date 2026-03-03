import React, { useMemo, useState, useEffect } from "react";
import { getDashboard } from "../../services/api";
import { useSocket } from "../../context/SocketContext";
import { sevColor } from "../../utils/formatters";

export default function SeverityHeatmap() {
  const [data, setData] = useState(null);
  const { feed } = useSocket();

  useEffect(() => {
    const load = async () => {
      try {
        const { data: d } = await getDashboard();
        setData(d);
      } catch (e) {
        console.error(e);
      }
    };
    load();
  }, []);

  const severities = ["critical", "high", "medium", "low", "none"];
  const liveDist = useMemo(() => {
    const acc = { critical: 0, high: 0, medium: 0, low: 0, none: 0 };
    for (const item of feed) {
      const raw = String(item?.severity || "none").toLowerCase();
      const sev = Object.prototype.hasOwnProperty.call(acc, raw) ? raw : "none";
      acc[sev] += 1;
    }
    return acc;
  }, [feed]);
  const dist = feed.length ? liveDist : (data?.severityDistribution || {});
  const total = Object.values(dist).reduce((a, b) => a + b, 0) || 1;
  const basisMessage = feed.length
    ? "Basis: Live traffic feed severity (realtime)"
    : "Basis: Dashboard API severity distribution";

  return (
    <div className="card">
      <div className="card-hdr">
        <span className="card-title">🌡️ Severity Distribution</span>
      </div>
      <div style={{ fontSize: "0.72rem", color: "var(--text-dim)", marginBottom: 10 }}>
        {basisMessage}
      </div>

      {!data ? (
        <div className="empty">
          <p>Loading...</p>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {severities.map((sev) => {
            const count = dist[sev] || 0;
            const pct = ((count / total) * 100).toFixed(1);
            const color = sevColor(sev);

            return (
              <div key={sev} style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span
                  style={{
                    minWidth: 65,
                    fontSize: "0.78rem",
                    fontWeight: 600,
                    textTransform: "uppercase",
                    color: color,
                  }}
                >
                  {sev}
                </span>
                <div
                  style={{
                    flex: 1,
                    height: 24,
                    background: "var(--border)",
                    borderRadius: 6,
                    overflow: "hidden",
                    position: "relative",
                  }}
                >
                  <div
                    style={{
                      width: `${pct}%`,
                      height: "100%",
                      background: `linear-gradient(90deg, ${color}55, ${color})`,
                      borderRadius: 6,
                      transition: "width 0.6s ease",
                      minWidth: count > 0 ? 4 : 0,
                    }}
                  />
                  <span
                    style={{
                      position: "absolute",
                      right: 8,
                      top: "50%",
                      transform: "translateY(-50%)",
                      fontSize: "0.7rem",
                      fontFamily: "var(--mono)",
                      fontWeight: 600,
                      color: "var(--text)",
                    }}
                  >
                    {count} ({pct}%)
                  </span>
                </div>
              </div>
            );
          })}

          <div
            style={{
              marginTop: 12,
              padding: "12px 16px",
              background: "rgba(0,0,0,0.15)",
              borderRadius: "var(--radius-sm)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <span style={{ fontSize: "0.78rem", color: "var(--text-dim)" }}>
              {feed.length ? "Live Stream Total" : "Total Alerts (7 days)"}
            </span>
            <span
              style={{
                fontSize: "1.2rem",
                fontWeight: 800,
                fontFamily: "var(--mono)",
                color: "var(--text)",
              }}
            >
              {Object.values(dist)
                .reduce((a, b) => a + b, 0)
                .toLocaleString()}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
