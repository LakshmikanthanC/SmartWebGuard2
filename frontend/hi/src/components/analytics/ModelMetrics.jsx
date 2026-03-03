import React, { useCallback, useEffect, useState } from "react";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
} from "chart.js";
import { getModelInfo } from "../../services/api";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend
);

export default function ModelMetrics() {
  const [info, setInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);

  const load = useCallback(async () => {
    try {
      const { data } = await getModelInfo();
      setInfo(data);
      setLastUpdated(new Date());
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const iv = setInterval(load, 10000);
    return () => clearInterval(iv);
  }, [load]);

  if (loading) {
    return (
      <div className="card">
        <div className="card-hdr">
          <span className="card-title">🧠 Model Performance</span>
        </div>
        <div className="empty">
          <p>Loading model info...</p>
        </div>
      </div>
    );
  }

  if (!info?.metrics) {
    return (
      <div className="card">
        <div className="card-hdr">
          <span className="card-title">🧠 Model Performance</span>
        </div>
        <div className="empty">
          <div className="empty-icon">🧠</div>
          <p>No model metrics available. Train the model first.</p>
        </div>
      </div>
    );
  }

  const m = info.metrics;
  const hasMetrics = !!info?.metrics;
  const modelStatus = info?.model_loaded
    ? { label: "Loaded", color: "var(--green)" }
    : hasMetrics
      ? { label: "Demo Mode", color: "var(--orange)" }
      : { label: "Not Loaded", color: "var(--red)" };

  const metricCards = [
    { label: "Accuracy", value: m.accuracy, color: "var(--green)" },
    { label: "Precision", value: m.precision, color: "var(--blue)" },
    { label: "Recall", value: m.recall, color: "var(--orange)" },
    { label: "F1 Score", value: m.f1_score, color: "var(--purple)" },
  ];

  let trainingChart = null;
  if (m.training_history) {
    const h = m.training_history;
    const epochs = h.accuracy.map((_, i) => `${i + 1}`);

    trainingChart = {
      labels: epochs,
      datasets: [
        {
          label: "Train Accuracy",
          data: h.accuracy,
          borderColor: "var(--green)",
          backgroundColor: "transparent",
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 1,
        },
        {
          label: "Val Accuracy",
          data: h.val_accuracy,
          borderColor: "var(--blue)",
          backgroundColor: "transparent",
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 1,
          borderDash: [5, 5],
        },
        {
          label: "Train Loss",
          data: h.loss,
          borderColor: "var(--red)",
          backgroundColor: "transparent",
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 1,
        },
        {
          label: "Val Loss",
          data: h.val_loss,
          borderColor: "var(--orange)",
          backgroundColor: "transparent",
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 1,
          borderDash: [5, 5],
        },
      ],
    };
  }

  const chartOpts = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "top",
        labels: {
          color: "#8f96b8",
          usePointStyle: true,
          padding: 14,
          font: { family: "Inter", size: 10.5 },
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
        grid: { color: "rgba(30,37,90,0.3)" },
        ticks: {
          color: "#5c6490",
          font: { family: "JetBrains Mono", size: 9 },
        },
        title: {
          display: true,
          text: "Epoch",
          color: "#5c6490",
          font: { size: 11 },
        },
      },
      y: {
        grid: { color: "rgba(30,37,90,0.3)" },
        ticks: {
          color: "#5c6490",
          font: { family: "JetBrains Mono", size: 9 },
        },
        beginAtZero: true,
        max: 1.05,
      },
    },
  };

  return (
    <div className="card">
      <div className="card-hdr">
        <span className="card-title">🧠 Model Performance</span>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "flex-end", gap: 2 }}>
          <span
            style={{
              fontSize: "0.72rem",
              color: modelStatus.color,
              fontFamily: "var(--mono)",
              fontWeight: 600,
            }}
          >
            {`Status: ${modelStatus.label}`}
          </span>
          <span style={{ fontSize: "0.66rem", color: "var(--text-dim)", fontFamily: "var(--mono)" }}>
            {lastUpdated ? `Updated: ${lastUpdated.toLocaleTimeString()}` : "Updated: --"}
          </span>
        </div>
      </div>

      {/* Metric Summary Cards */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: 12,
          marginBottom: 22,
        }}
      >
        {metricCards.map((mc) => (
          <div
            key={mc.label}
            style={{
              background: "rgba(0,0,0,0.15)",
              borderRadius: "var(--radius-sm)",
              padding: "14px 10px",
              textAlign: "center",
            }}
          >
            <div
              style={{
                fontSize: "1.4rem",
                fontWeight: 800,
                fontFamily: "var(--mono)",
                color: mc.color,
              }}
            >
              {(mc.value * 100).toFixed(1)}%
            </div>
            <div
              style={{
                fontSize: "0.65rem",
                color: "var(--text-dim)",
                textTransform: "uppercase",
                letterSpacing: "0.5px",
                marginTop: 3,
              }}
            >
              {mc.label}
            </div>
          </div>
        ))}
      </div>

      {/* Training History Chart */}
      {trainingChart && (
        <>
          <h4
            style={{
              fontSize: "0.85rem",
              fontWeight: 600,
              color: "var(--text-sec)",
              marginBottom: 12,
            }}
          >
            Training History
          </h4>
          <div style={{ height: 280 }}>
            <Line data={trainingChart} options={chartOpts} />
          </div>
        </>
      )}

      {/* Class Names */}
      {m.class_names && (
        <div
          style={{
            marginTop: 18,
            display: "flex",
            alignItems: "center",
            gap: 8,
            flexWrap: "wrap",
          }}
        >
          <span
            style={{
              fontSize: "0.75rem",
              color: "var(--text-dim)",
              fontWeight: 600,
            }}
          >
            Trained Classes:
          </span>
          {m.class_names.map((c) => (
            <span
              key={c}
              style={{
                padding: "3px 10px",
                background: "var(--bg-hover)",
                border: "1px solid var(--border)",
                borderRadius: 50,
                fontSize: "0.72rem",
                fontWeight: 600,
                color: "var(--text-sec)",
              }}
            >
              {c.toUpperCase()}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}
