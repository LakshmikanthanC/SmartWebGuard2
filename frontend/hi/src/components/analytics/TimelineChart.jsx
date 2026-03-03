import React, { useMemo, useState, useEffect } from "react";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler,
} from "chart.js";
import { getTimeline } from "../../services/api";
import { useSocket } from "../../context/SocketContext";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
  Filler
);

const COLORS = {
  dos: "#ff4757",
  probe: "#ff9800",
  r2l: "#4d8dff",
  u2r: "#a855f7",
};

export default function TimelineChart() {
  const [data, setData] = useState([]);
  const [period, setPeriod] = useState("24h");
  const [loading, setLoading] = useState(true);
  const { feed } = useSocket();

  useEffect(() => {
    const load = async () => {
      setLoading(true);
      try {
        const { data: d } = await getTimeline(period);
        setData(d);
      } catch (e) {
        console.error(e);
      }
      setLoading(false);
    };
    load();
  }, [period]);

  const liveSeries = useMemo(() => {
    if (!feed.length) return [];

    const now = Date.now();
    const periodMsMap = {
      "1h": 60 * 60 * 1000,
      "24h": 24 * 60 * 60 * 1000,
      "7d": 7 * 24 * 60 * 60 * 1000,
      "30d": 30 * 24 * 60 * 60 * 1000,
    };
    const bucketMinutesMap = {
      "1h": 5,
      "24h": 60,
      "7d": 360,
      "30d": 1440,
    };
    const periodMs = periodMsMap[period] || periodMsMap["24h"];
    const bucketMs = (bucketMinutesMap[period] || 60) * 60 * 1000;
    const cutoff = now - periodMs;

    const buckets = new Map();
    const startBucket = Math.floor(cutoff / bucketMs) * bucketMs;
    const endBucket = Math.floor(now / bucketMs) * bucketMs;
    for (let t = startBucket; t <= endBucket; t += bucketMs) {
      buckets.set(t, { dos: 0, probe: 0, r2l: 0, u2r: 0 });
    }

    for (const item of feed) {
      const ts = Date.parse(item?.timestamp || "");
      if (!Number.isFinite(ts) || ts < cutoff) continue;
      const bucketTime = Math.floor(ts / bucketMs) * bucketMs;
      if (!buckets.has(bucketTime)) continue;
      const type = String(item?.prediction || "").toLowerCase();
      if (["dos", "probe", "r2l", "u2r"].includes(type)) {
        const row = buckets.get(bucketTime);
        row[type] += 1;
      }
    }

    return [...buckets.entries()]
      .sort((a, b) => a[0] - b[0])
      .map(([ts, row]) => ({
        time:
          period === "30d"
            ? new Date(ts).toLocaleDateString("en-US", { month: "short", day: "numeric" })
            : new Date(ts).toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit" }),
        ...row,
      }));
  }, [feed, period]);

  const seriesData = liveSeries.length ? liveSeries : data;

  if (loading && !seriesData.length) {
    return (
      <div className="card">
        <div className="card-hdr">
          <span className="card-title">📈 Attack Timeline</span>
        </div>
        <div className="empty">
          <p>Loading timeline...</p>
        </div>
      </div>
    );
  }

  if (!seriesData.length) {
    return (
      <div className="card">
        <div className="card-hdr">
          <span className="card-title">📈 Attack Timeline</span>
          <div className="card-actions">
            {["1h", "24h", "7d", "30d"].map((p) => (
              <button
                key={p}
                className={`btn btn-sm ${period === p ? "btn-primary" : "btn-ghost"}`}
                onClick={() => setPeriod(p)}
              >
                {p}
              </button>
            ))}
          </div>
        </div>
        <div className="empty">
          <div className="empty-icon">📉</div>
          <p>No data for this period</p>
        </div>
      </div>
    );
  }

  const labels = seriesData.map((d) => d.time);
  const types = ["dos", "probe", "r2l", "u2r"];
  const datasets = types.map((t) => ({
    label: t.toUpperCase(),
    data: seriesData.map((r) => r[t] || 0),
    borderColor: COLORS[t],
    backgroundColor: COLORS[t] + "18",
    fill: true,
    tension: 0.4,
    pointRadius: 3,
    pointHoverRadius: 7,
    borderWidth: 2.5,
    pointBackgroundColor: COLORS[t],
    pointBorderColor: "#111640",
    pointBorderWidth: 2,
  }));

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: "index", intersect: false },
    plugins: {
      legend: {
        position: "top",
        labels: {
          color: "#8f96b8",
          usePointStyle: true,
          padding: 16,
          font: { family: "Inter", size: 11.5 },
        },
      },
      tooltip: {
        backgroundColor: "#1a2055",
        titleColor: "#e4e7f1",
        bodyColor: "#8f96b8",
        borderColor: "#2a3370",
        borderWidth: 1,
        cornerRadius: 10,
        padding: 12,
        titleFont: { weight: "bold" },
      },
    },
    scales: {
      x: {
        grid: { color: "rgba(30,37,90,0.4)", lineWidth: 0.5 },
        ticks: {
          color: "#5c6490",
          font: { family: "JetBrains Mono", size: 10 },
          maxRotation: 45,
        },
      },
      y: {
        grid: { color: "rgba(30,37,90,0.4)", lineWidth: 0.5 },
        ticks: {
          color: "#5c6490",
          font: { family: "JetBrains Mono", size: 10 },
        },
        beginAtZero: true,
      },
    },
  };

  return (
    <div className="card">
      <div className="card-hdr">
        <span className="card-title">📈 Attack Timeline</span>
        <div className="card-actions">
          {["1h", "24h", "7d", "30d"].map((p) => (
            <button
              key={p}
              className={`btn btn-sm ${period === p ? "btn-primary" : "btn-ghost"}`}
              onClick={() => setPeriod(p)}
            >
              {p}
            </button>
          ))}
        </div>
      </div>
      <div style={{ height: 380 }}>
        <Line data={{ labels, datasets }} options={options} />
      </div>
    </div>
  );
}
