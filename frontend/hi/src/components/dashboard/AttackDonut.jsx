import React, { useMemo } from "react";
import { Doughnut } from "react-chartjs-2";
import { Chart as ChartJS, ArcElement, Tooltip, Legend } from "chart.js";
import { atkColor, fmtNum } from "../../utils/formatters";
import { useSocket } from "../../context/SocketContext";

ChartJS.register(ArcElement, Tooltip, Legend);

export default function AttackDonut({ distribution }) {
  const { feed } = useSocket();

  const liveDistribution = useMemo(() => {
    const map = {};
    for (const item of feed || []) {
      if (!item?.is_malicious) continue;
      const type = String(item?.prediction || "unknown").toLowerCase();
      map[type] = (map[type] || 0) + 1;
    }
    return map;
  }, [feed]);

  const finalDistribution =
    Object.keys(liveDistribution).length > 0 ? liveDistribution : (distribution || {});

  if (!Object.keys(finalDistribution).length) {
    return (
      <div className="card">
        <div className="card-header">
          <span className="card-title">
            <span className="icon">🎯</span>
            Attack Distribution
          </span>
        </div>
        <div className="empty-state">
          <div className="empty-icon">🎯</div>
          <p>No data yet</p>
        </div>
      </div>
    );
  }

  const labels = Object.keys(finalDistribution).map((k) => k.toUpperCase());
  const values = Object.values(finalDistribution);
  const colors = Object.keys(finalDistribution).map((k) => atkColor(k));
  const total = values.reduce((a, b) => a + b, 0);

  const data = {
    labels,
    datasets: [
      {
        data: values,
        backgroundColor: colors.map((c) => c + "30"),
        borderColor: colors,
        borderWidth: 2,
        hoverOffset: 6,
      },
    ],
  };

  const opts = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "68%",
    plugins: {
      legend: {
        position: "bottom",
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
        callbacks: {
          label: (ctx) => {
            const pct = ((ctx.parsed / total) * 100).toFixed(1);
            return ` ${ctx.label}: ${ctx.parsed} (${pct}%)`;
          },
        },
      },
    },
  };

  return (
    <div className="card">
      <div className="card-header">
        <span className="card-title">
          <span className="icon">🎯</span>
          Attack Distribution
        </span>
      </div>
      <div style={{ height: 280, position: "relative" }}>
        <Doughnut data={data} options={opts} />
        <div
          style={{
            position: "absolute",
            top: "40%",
            left: "50%",
            transform: "translate(-50%,-50%)",
            textAlign: "center",
          }}
        >
          <div
            style={{
              fontSize: "1.6rem",
              fontWeight: 800,
              fontFamily: "var(--mono)",
              color: "var(--text)",
            }}
          >
            {fmtNum(total)}
          </div>
          <div
            style={{
              fontSize: ".65rem",
              color: "var(--text-dim)",
              textTransform: "uppercase",
              letterSpacing: "1px",
            }}
          >
            Total
          </div>
        </div>
      </div>
    </div>
  );
}
