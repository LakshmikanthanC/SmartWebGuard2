import React, { useMemo } from "react";
import { useSocket } from "../../context/SocketContext";
import "./ThreatGauge.css";

export default function ThreatGauge({ level, stats }) {
  const { liveStats, feed } = useSocket();

  const computed = useMemo(() => {
    const critical = Number(stats?.severityDistribution?.critical || 0);
    const high = Number(stats?.severityDistribution?.high || 0);
    const medium = Number(stats?.severityDistribution?.medium || 0);
    const low = Number(stats?.severityDistribution?.low || 0);
    const safe = Number(stats?.severityDistribution?.safe || 0);
    const totalSeverity = critical + high + medium + low + safe;

    const severityScore = totalSeverity > 0
      ? (critical * 1 + high * 0.75 + medium * 0.45 + low * 0.2) / totalSeverity
      : 0;

    const liveTotal = Number(liveStats?.total || 0);
    const liveMalicious = Number(liveStats?.malicious || 0);
    const cumulativeMaliciousRatio = liveTotal > 0 ? liveMalicious / liveTotal : 0;
    const recentFeed = Array.isArray(feed) ? feed.slice(0, 60) : [];
    const recentMalicious = recentFeed.reduce(
      (acc, item) => acc + (item?.is_malicious ? 1 : 0),
      0
    );
    const recentMaliciousRatio = recentFeed.length > 0 ? recentMalicious / recentFeed.length : 0;

    const score = Math.max(
      0,
      Math.min(
        1,
        severityScore * 0.5 + cumulativeMaliciousRatio * 0.2 + recentMaliciousRatio * 0.3
      )
    );
    const pct = Math.round(score * 1000) / 10;

    const dynamicLevel =
      pct >= 80 ? "critical" : pct >= 60 ? "high" : pct >= 35 ? "medium" : pct >= 15 ? "low" : "safe";

    return { pct, dynamicLevel };
  }, [feed, liveStats?.malicious, liveStats?.total, stats?.severityDistribution]);

  const pct = computed.pct;
  const resolvedLevel = computed.dynamicLevel || level || "low";
  const colors = { low: "var(--green)", medium: "var(--orange)", high: "var(--red)", critical: "var(--purple)" };
  const color = colors[resolvedLevel] || "var(--green)";

  return (
    <div className="card threat-gauge-card">
      <div className="card-header"><span className="card-title"><span className="icon">🔥</span>Threat Level</span></div>
      <div className="gauge-container">
        <div className="gauge-ring">
          <svg viewBox="0 0 120 120" className="gauge-svg">
            <circle cx="60" cy="60" r="50" className="gauge-bg" />
            <circle
              cx="60" cy="60" r="50"
              className="gauge-fill"
              style={{
                strokeDasharray: `${pct * 3.14} ${314 - pct * 3.14}`,
                stroke: color,
                filter: `drop-shadow(0 0 8px ${color})`,
              }}
            />
          </svg>
          <div className="gauge-label">
            <span className="gauge-value" style={{ color }}>{pct}%</span>
            <span className="gauge-text">{resolvedLevel.toUpperCase()}</span>
          </div>
        </div>
      </div>
      <div className="gauge-details">
        <div className="gauge-detail"><span className="gd-dot" style={{ background: "var(--red)" }} /><span>Critical</span><span className="gd-val">{stats?.severityDistribution?.critical || 0}</span></div>
        <div className="gauge-detail"><span className="gd-dot" style={{ background: "var(--orange)" }} /><span>High</span><span className="gd-val">{stats?.severityDistribution?.high || 0}</span></div>
        <div className="gauge-detail"><span className="gd-dot" style={{ background: "var(--yellow)" }} /><span>Medium</span><span className="gd-val">{stats?.severityDistribution?.medium || 0}</span></div>
      </div>
    </div>
  );
}
