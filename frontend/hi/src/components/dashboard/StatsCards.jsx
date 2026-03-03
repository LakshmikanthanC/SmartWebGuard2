import React, { useEffect, useMemo, useRef } from "react";
import { fmtNum, sevColor } from "../../utils/formatters";
import { useSocket } from "../../context/SocketContext";
import "./StatsCards.css";

export default function StatsCards({ stats }) {
  const { liveStats, connectionError, feed } = useSocket();
  const baseOverviewRef = useRef(null);

  useEffect(() => {
    const incoming = stats?.overview;
    if (!incoming) return;

    if (!baseOverviewRef.current) {
      baseOverviewRef.current = {
        totalAlerts: Number(incoming.totalAlerts || 0),
        alerts24h: Number(incoming.alerts24h || 0),
        unacknowledged: Number(incoming.unacknowledged || 0),
      };
      return;
    }

    // If server-side counters reset/decrease, refresh the base snapshot.
    if (
      Number(incoming.totalAlerts || 0) < Number(baseOverviewRef.current.totalAlerts || 0) ||
      Number(incoming.alerts24h || 0) < Number(baseOverviewRef.current.alerts24h || 0)
    ) {
      baseOverviewRef.current = {
        totalAlerts: Number(incoming.totalAlerts || 0),
        alerts24h: Number(incoming.alerts24h || 0),
        unacknowledged: Number(incoming.unacknowledged || 0),
      };
    }
  }, [stats?.overview]);

  const liveOverview = useMemo(() => {
    const base = baseOverviewRef.current || {
      totalAlerts: Number(stats?.overview?.totalAlerts || 0),
      alerts24h: Number(stats?.overview?.alerts24h || 0),
      unacknowledged: Number(stats?.overview?.unacknowledged || 0),
    };

    const now = Date.now();
    const cutoff = now - 24 * 60 * 60 * 1000;
    const sessionAlerts24h = feed.reduce((count, item) => {
      const ts = Date.parse(item?.timestamp || "");
      const isMalicious = Boolean(item?.is_malicious);
      return Number.isFinite(ts) && ts >= cutoff && isMalicious ? count + 1 : count;
    }, 0);

    const totalAlerts = base.totalAlerts + Number(liveStats.malicious || 0);
    const alerts24h = base.alerts24h + sessionAlerts24h;
    const unacknowledged = base.unacknowledged + Number(liveStats.malicious || 0);
    const threatLevel =
      alerts24h > 100 ? "critical" : alerts24h > 50 ? "high" : alerts24h > 10 ? "medium" : "low";

    return { totalAlerts, alerts24h, unacknowledged, threatLevel };
  }, [feed, liveStats.malicious, stats?.overview]);

  const cards = [
    {
      icon: "🚨",
      label: "Total Alerts",
      value: fmtNum(liveOverview.totalAlerts),
      color: "var(--red)",
      sub: "All time (live)",
    },
    {
      icon: "⚡",
      label: "Last 24 Hours",
      value: fmtNum(liveOverview.alerts24h),
      color: "var(--orange)",
      sub: "Recent activity (live)",
    },
    {
      icon: "📡",
      label: "Live Packets",
      value: fmtNum(liveStats.total),
      color: connectionError ? "var(--red)" : "var(--cyan)",
      sub: connectionError ? connectionError : `${liveStats.normal} normal / ${liveStats.malicious} threats`,
    },
    {
      icon: "🎯",
      label: "Threat Level",
      value: liveOverview.threatLevel.toUpperCase(),
      color: sevColor(liveOverview.threatLevel),
      sub: `${fmtNum(liveOverview.unacknowledged)} unacknowledged`,
    },
  ];

  return (
    <div className="grid-4 mb-md">
      {cards.map((c, i) => (
        <div key={i} className="stat-card anim-fade-up" style={{ animationDelay: `${i * 80}ms` }}>
          <div className="stat-icon-wrap" style={{ background: c.color + "18" }}>
            <span className="stat-icon">{c.icon}</span>
          </div>
          <div className="stat-body">
            <span className="stat-value" style={{ color: c.color }}>
              {c.value || "0"}
            </span>
            <span className="stat-label">{c.label}</span>
            <span className="stat-sub">{c.sub}</span>
          </div>
          <div className="stat-glow" style={{ background: c.color }} />
        </div>
      ))}
    </div>
  );
}
