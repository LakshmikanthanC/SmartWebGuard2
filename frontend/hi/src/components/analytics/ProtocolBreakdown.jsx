import React, { useMemo, useState, useEffect } from "react";
import { Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Tooltip,
  Legend,
} from "chart.js";
import { getAlerts } from "../../services/api";
import { useSocket } from "../../context/SocketContext";

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

export default function ProtocolBreakdown() {
  const [seedAlerts, setSeedAlerts] = useState([]);
  const { feed } = useSocket();

  useEffect(() => {
    const load = async () => {
      try {
        const { data } = await getAlerts({ limit: 500, page: 1 });
        setSeedAlerts(data.alerts || []);
      } catch (e) {
        console.error(e);
      }
    };
    load();
  }, []);

  const chartData = useMemo(() => {
    const source = feed.length
      ? feed.map((f) => ({
          protocol: f.protocol || "tcp",
          attackType: f.prediction || "unknown",
        }))
      : seedAlerts;

    const protoCounts = {};
    const protoAttacks = {};

    source.forEach((a) => {
      const proto = String(a.protocol || "tcp").toUpperCase();
      const type = String(a.attackType || "unknown").toLowerCase();
      if (type === "normal") return;

      if (!protoCounts[proto]) protoCounts[proto] = 0;
      protoCounts[proto] += 1;

      if (!protoAttacks[proto]) protoAttacks[proto] = {};
      if (!protoAttacks[proto][type]) protoAttacks[proto][type] = 0;
      protoAttacks[proto][type] += 1;
    });

    const protocols = Object.keys(protoCounts).sort((a, b) => protoCounts[b] - protoCounts[a]);
    const attackTypes = [...new Set(source.map((a) => String(a.attackType || "").toLowerCase()))]
      .filter((t) => t && t !== "normal");

    const colors = {
      dos: "#ff4757",
      probe: "#ff9800",
      r2l: "#4d8dff",
      u2r: "#a855f7",
    };

    const datasets = attackTypes.map((type) => ({
      label: type.toUpperCase(),
      data: protocols.map((p) => protoAttacks[p]?.[type] || 0),
      backgroundColor: (colors[type] || "#5c6490") + "80",
      borderColor: colors[type] || "#5c6490",
      borderWidth: 1.5,
      borderRadius: 4,
    }));

    return { labels: protocols, datasets };
  }, [feed, seedAlerts]);

  if (!chartData) {
    return (
      <div className="card">
        <div className="card-hdr">
          <span className="card-title">🔌 Protocol Breakdown</span>
        </div>
        <div className="empty">
          <div className="empty-icon">🔌</div>
          <p>Loading protocol data...</p>
        </div>
      </div>
    );
  }

  if (!chartData.labels?.length) {
    return (
      <div className="card">
        <div className="card-hdr">
          <span className="card-title">🔌 Protocol Breakdown</span>
        </div>
        <div className="empty">
          <div className="empty-icon">📡</div>
          <p>Waiting for live protocol traffic...</p>
        </div>
      </div>
    );
  }

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "top",
        labels: {
          color: "#8f96b8",
          usePointStyle: true,
          padding: 14,
          font: { family: "Inter", size: 11 },
        },
      },
      tooltip: {
        backgroundColor: "#1a2055",
        titleColor: "#e4e7f1",
        bodyColor: "#8f96b8",
        borderColor: "#2a3370",
        borderWidth: 1,
        cornerRadius: 8,
      },
    },
    scales: {
      x: {
        stacked: true,
        grid: { color: "rgba(30,37,90,0.4)" },
        ticks: {
          color: "#5c6490",
          font: { family: "JetBrains Mono", size: 11, weight: "bold" },
        },
      },
      y: {
        stacked: true,
        grid: { color: "rgba(30,37,90,0.4)" },
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
        <span className="card-title">🔌 Protocol Breakdown</span>
      </div>
      <div style={{ height: 320 }}>
        <Bar data={chartData} options={options} />
      </div>
    </div>
  );
}
