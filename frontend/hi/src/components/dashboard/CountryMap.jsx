import React, { useEffect, useState, useMemo } from "react";
import { Bar } from "react-chartjs-2";
import { Chart as ChartJS, CategoryScale, LinearScale, BarElement, Tooltip, Legend } from "chart.js";
import { fmtNum } from "../../utils/formatters";
import { getCountryDistribution } from "../../services/api";
import { useSocket } from "../../context/SocketContext";

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip, Legend);

const regionNames = new Intl.DisplayNames(["en"], { type: "region" });
const getCountryName = (code) => {
  const normalized = String(code || "").toUpperCase();
  if (!normalized || normalized === "UNKNOWN" || normalized === "ZZ") return "Unknown";
  return regionNames.of(normalized) || normalized;
};

const hashCode = (value) => {
  let hash = 0;
  const text = String(value || "");
  for (let i = 0; i < text.length; i += 1) {
    hash = (hash << 5) - hash + text.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
};
const getCountryColor = (code) => {
  const hue = hashCode(code) % 360;
  return `hsl(${hue}, 70%, 55%)`;
};

export default function CountryMap() {
  const { countryStats } = useSocket();
  const [countryData, setCountryData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [period, setPeriod] = useState("24h");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const res = await getCountryDistribution(period, 0);
        setCountryData(res.data);
      } catch (err) {
        console.error("Failed to fetch country data:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
    const interval = setInterval(fetchData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, [period]);

  // Merge real-time country stats with historical data - must be called before any early returns
  const mergedData = useMemo(() => {
    const mergedMap = {};

    // Historical data from API.
    (countryData?.countries || []).forEach((c) => {
      const key = c.country || "Unknown";
      if (!mergedMap[key]) mergedMap[key] = { country: key, count: 0, types: [] };
      mergedMap[key].count += Number(c.count || 0);
      const incomingTypes = Array.isArray(c.types) ? c.types : [];
      mergedMap[key].types = [...new Set([...(mergedMap[key].types || []), ...incomingTypes])];
    });

    // Live socket increments.
    Object.entries(countryStats).forEach(([country, count]) => {
      const key = country || "Unknown";
      if (!mergedMap[key]) mergedMap[key] = { country: key, count: 0, types: [] };
      mergedMap[key].count += Number(count || 0);
    });

    return Object.values(mergedMap).sort((a, b) => b.count - a.count);
  }, [countryData, countryStats]);

  if (loading) {
    return (
      <div className="card">
        <div className="card-header">
          <span className="card-title"><span className="icon">🌍</span>Attack Sources by Country</span>
        </div>
        <div className="loading-state">Loading...</div>
      </div>
    );
  }

  if (mergedData.length === 0) {
    return (
      <div className="card">
        <div className="card-header">
          <span className="card-title"><span className="icon">🌍</span>Attack Sources by Country</span>
        </div>
        <div className="empty-state">
          <div className="empty-icon">🌍</div>
          <p>No country data available</p>
        </div>
      </div>
    );
  }

  const countries = mergedData;
  const total = countryData?.total || 0;
  const realtimeTotal = Object.values(countryStats).reduce((a, b) => a + b, 0);
  const displayTotal = total + realtimeTotal;

  const labels = countries.map((c) => getCountryName(c.country));
  const values = countries.map((c) => c.count);
  const colors = countries.map((c) => getCountryColor(c.country));
  const chartHeight = Math.max(320, countries.length * 24);

  const data = {
    labels,
    datasets: [{
      label: "Attacks",
      data: values,
      backgroundColor: colors.map((c) => c + "80"),
      borderColor: colors,
      borderWidth: 1,
      borderRadius: 4,
      barThickness: 12,
      maxBarThickness: 18,
      categoryPercentage: 0.8,
      barPercentage: 0.9,
    }],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    indexAxis: "y",
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: "#1a2055",
        titleColor: "#e4e7f1",
        bodyColor: "#8f96b8",
        borderColor: "#2a3370",
        borderWidth: 1,
        cornerRadius: 8,
        callbacks: {
          title: (items) => getCountryName(items[0].label),
          label: (ctx) => ` ${fmtNum(ctx.parsed.x)} attacks`,
        },
      },
    },
    scales: {
      x: {
        grid: { color: "#2a3370" },
        ticks: { color: "#8f96b8" },
      },
      y: {
        grid: { display: false },
        ticks: { color: "#8f96b8", font: { size: 11 } },
      },
    },
  };

  return (
    <div className="card">
      <div className="card-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span className="card-title"><span className="icon">🌍</span>Attack Sources by Country</span>
        <select
          value={period}
          onChange={(e) => setPeriod(e.target.value)}
          style={{ background: "#1a2055", color: "#8f96b8", border: "1px solid #2a3370", padding: "4px 8px", borderRadius: "4px", fontSize: "0.75rem" }}
        >
          <option value="1h">Last Hour</option>
          <option value="24h">Last 24 Hours</option>
          <option value="7d">Last 7 Days</option>
          <option value="30d">Last 30 Days</option>
        </select>
      </div>
      <div style={{ maxHeight: 420, overflowY: "auto", position: "relative" }}>
        <div style={{ height: chartHeight }}>
          <Bar data={data} options={options} />
        </div>
      </div>
      <div style={{ padding: "12px 0 0", borderTop: "1px solid #2a3370", marginTop: "8px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem", color: "#8f96b8" }}>
          <span>Total: <strong style={{ color: "#e4e7f1" }}>{fmtNum(displayTotal)}</strong> attacks</span>
          <span>Top: <strong style={{ color: "#e4e7f1" }}>{countries[0]?.country ? getCountryName(countries[0].country) : "N/A"}</strong></span>
        </div>
      </div>
    </div>
  );
}
