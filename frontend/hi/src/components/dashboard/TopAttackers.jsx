import React, { useMemo } from "react";
import { useSocket } from "../../context/SocketContext";
import "./TopAttackers.css";

export default function TopAttackers({ data: seedData = [] }) {
  const { feed } = useSocket();

  const data = useMemo(() => {
    const liveMap = {};

    for (const item of feed || []) {
      if (!item?.is_malicious) continue;
      const ip = item?.sourceIP || "Unknown";
      const type = String(item?.prediction || "unknown").toLowerCase();

      if (!liveMap[ip]) {
        liveMap[ip] = { _id: ip, count: 0, types: new Set() };
      }
      liveMap[ip].count += 1;
      liveMap[ip].types.add(type);
    }

    const liveData = Object.values(liveMap)
      .map((row) => ({ _id: row._id, count: row.count, types: Array.from(row.types) }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);

    return liveData.length ? liveData : (seedData || []);
  }, [feed, seedData]);

  if (!data.length) return null;

  const max = data[0]?.count || 1;

  return (
    <div className="card">
      <div className="card-header"><span className="card-title"><span className="icon">🏴‍☠️</span>Top Threat Sources</span></div>
      <div className="ta-list">
        {data.map((s, i) => (
          <div key={i} className="ta-row anim-fade-up" style={{ animationDelay: `${i * 50}ms` }}>
            <div className="ta-rank">#{i + 1}</div>
            <div className="ta-info">
              <div className="ta-ip">{s._id}</div>
              <div className="ta-types">{s.types?.join(", ")}</div>
            </div>
            <div className="ta-bar-wrap">
              <div className="ta-bar" style={{ width: `${(s.count / max) * 100}%` }} />
            </div>
            <div className="ta-count">{s.count}</div>
          </div>
        ))}
      </div>
    </div>
  );
}
