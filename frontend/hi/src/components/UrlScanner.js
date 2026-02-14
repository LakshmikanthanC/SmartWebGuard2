import React, { useState, useEffect, useCallback } from "react";
import {
  scanUrl,
  getUrlHistory,
  getUrlStats,
  deleteUrlScan,
} from "../services/api";
import { fmtDate, sevColor, sevBg } from "../utils/formatters";
import { generatePDF, generateExcel } from "../utils/reportGenerator";
import "./UrlScanner.css";

export default function UrlScanner() {
  // ============================================================
  // STATE
  // ============================================================
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState(null);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyPg, setHistoryPg] = useState({});
  const [activeTab, setActiveTab] = useState("scan");
  const [downloading, setDownloading] = useState(null);

  // ============================================================
  // DATA LOADERS
  // ============================================================
  const loadHistory = useCallback(async () => {
    try {
      const { data } = await getUrlHistory({ page: historyPage, limit: 10 });
      setHistory(data.scans || []);
      setHistoryPg(data.pagination || {});
    } catch (e) {
      console.error(e);
    }
  }, [historyPage]);

  const loadStats = useCallback(async () => {
    try {
      const { data } = await getUrlStats();
      setStats(data);
    } catch (e) {
      console.error(e);
    }
  }, []);

  useEffect(() => {
    loadHistory();
    loadStats();
  }, [loadHistory, loadStats]);

  // ============================================================
  // HANDLE SCAN
  // ============================================================
  const handleScan = async (deep = true) => {
    if (!url.trim()) {
      setError("Please enter a URL to scan");
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const { data } = await scanUrl(url.trim(), deep);
      setResult(data);
      loadHistory();
      loadStats();
    } catch (e) {
      setError(e.response?.data?.error || e.message || "Scan failed");
    }
    setLoading(false);
  };

  // ============================================================
  // REPORT DOWNLOAD
  // ============================================================
  const handleDownload = async (format) => {
    if (!result) return;
    setDownloading(format);
    try {
      if (format === "pdf") {
        await generatePDF(result);
      } else {
        await generateExcel(result);
      }
    } catch (e) {
      console.error("Download error:", e);
      setError(`Failed to generate ${format.toUpperCase()} report`);
    }
    setDownloading(null);
  };

  // ============================================================
  // EVENT HANDLERS
  // ============================================================
  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !loading) handleScan(true);
  };

  const handleDeleteScan = async (id) => {
    try {
      await deleteUrlScan(id);
      setHistory((h) => h.filter((s) => s._id !== id));
      loadStats();
    } catch (e) {
      console.error(e);
    }
  };

  // ============================================================
  // QUICK TEST URLs
  // ============================================================
  const quickUrls = [
    { label: "✅ Google", url: "https://www.google.com" },
    { label: "✅ GitHub", url: "https://github.com" },
    {
      label: "⚠️ Suspicious",
      url: "http://192.168.1.1/admin/login.php?user=admin",
    },
    {
      label: "🚨 Phishing",
      url: "http://secure-paypal-login.tk/verify?account=locked",
    },
    {
      label: "🚨 Malware",
      url: "http://free-crack-download.xyz/photoshop-crack.exe",
    },
  ];

  // ============================================================
  // HELPERS
  // ============================================================
  const getRiskGradient = (score) => {
    if (score >= 70) return "linear-gradient(90deg, #ff4757, #ff6b81)";
    if (score >= 50) return "linear-gradient(90deg, #ff9800, #ffb74d)";
    if (score >= 30) return "linear-gradient(90deg, #fbbf24, #fcd34d)";
    if (score >= 15) return "linear-gradient(90deg, #8bc34a, #aed581)";
    return "linear-gradient(90deg, #00e67a, #69f0ae)";
  };

  const getRiskEmoji = (level) =>
    ({
      safe: "✅",
      low: "🟢",
      medium: "🟡",
      high: "🟠",
      critical: "🔴",
    }[level] || "❓");

  const getSevStyle = (sev) => {
    const map = {
      critical: {
        bg: "rgba(168,85,247,0.08)",
        border: "var(--purple)",
        icon: "🔴",
      },
      high: {
        bg: "rgba(255,71,87,0.08)",
        border: "var(--red)",
        icon: "🟠",
      },
      medium: {
        bg: "rgba(255,152,0,0.08)",
        border: "var(--orange)",
        icon: "🟡",
      },
      low: {
        bg: "rgba(139,195,74,0.08)",
        border: "#8bc34a",
        icon: "🟢",
      },
      info: {
        bg: "rgba(77,141,255,0.08)",
        border: "var(--blue)",
        icon: "🔵",
      },
    };
    return map[sev] || map.info;
  };

  // ============================================================
  // RENDER
  // ============================================================
  return (
    <div className="us-container">
      {/* ==================== HEADER ==================== */}
      <div className="us-header">
        <h2 className="us-title">🔗 URL Safety Scanner</h2>
        <p className="us-subtitle">
          Analyze any URL for phishing, malware, viruses, and security threats
        </p>
      </div>

      {/* ==================== STATS BAR ==================== */}
      {stats && (
        <div className="us-stats-bar">
          <div className="us-stat">
            <span className="us-stat-val">{stats.total}</span>
            <span className="us-stat-label">Total Scans</span>
          </div>
          <div className="us-stat">
            <span className="us-stat-val" style={{ color: "var(--green)" }}>
              {stats.safe}
            </span>
            <span className="us-stat-label">Safe</span>
          </div>
          <div className="us-stat">
            <span className="us-stat-val" style={{ color: "var(--red)" }}>
              {stats.unsafe}
            </span>
            <span className="us-stat-label">Unsafe</span>
          </div>
          {stats.riskDistribution &&
            Object.entries(stats.riskDistribution).map(([level, count]) => (
              <div key={level} className="us-stat">
                <span
                  className="us-stat-val"
                  style={{ color: sevColor(level) }}
                >
                  {count}
                </span>
                <span className="us-stat-label">{level}</span>
              </div>
            ))}
        </div>
      )}

      {/* ==================== TABS ==================== */}
      <div className="us-tabs">
        <button
          className={`us-tab ${activeTab === "scan" ? "us-tab-active" : ""}`}
          onClick={() => setActiveTab("scan")}
        >
          🔍 Scan URL
        </button>
        <button
          className={`us-tab ${
            activeTab === "history" ? "us-tab-active" : ""
          }`}
          onClick={() => setActiveTab("history")}
        >
          📜 Scan History ({stats?.total || 0})
        </button>
      </div>

      {/* ============================================================ */}
      {/*                        SCAN TAB                               */}
      {/* ============================================================ */}
      {activeTab === "scan" && (
        <div className="us-scan-section">
          {/* ---------- INPUT CARD ---------- */}
          <div className="card us-input-card">
            <div className="us-input-row">
              <div className="us-input-icon">🌐</div>
              <input
                type="text"
                className="us-input"
                placeholder="Enter URL to scan (e.g., https://example.com)"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={loading}
              />
              <button
                className="btn btn-ghost us-scan-btn"
                onClick={() => handleScan(false)}
                disabled={loading}
                title="Quick scan — URL analysis only, no content fetch"
              >
                ⚡ Quick
              </button>
              <button
                className="btn btn-primary us-scan-btn"
                onClick={() => handleScan(true)}
                disabled={loading}
                title="Deep scan — fetches and analyzes page content"
              >
                {loading ? (
                  <>
                    <span className="us-spinner" /> Scanning...
                  </>
                ) : (
                  "🔍 Deep Scan"
                )}
              </button>
            </div>

            {/* Quick Test URLs */}
            <div className="us-quick">
              <span className="us-quick-label">Quick Test:</span>
              {quickUrls.map((q) => (
                <button
                  key={q.url}
                  className="us-quick-btn"
                  onClick={() => {
                    setUrl(q.url);
                    setResult(null);
                    setError(null);
                  }}
                >
                  {q.label}
                </button>
              ))}
            </div>

            {error && <div className="us-error">❌ {error}</div>}
          </div>

          {/* ==================== RESULTS ==================== */}
          {result && (
            <div className="us-result anim-up">
              {/* ===== 1. VERDICT CARD ===== */}
              <div
                className="card us-verdict-card"
                style={{
                  borderColor: result.safe ? "var(--green)" : "var(--red)",
                }}
              >
                <div className="us-verdict-top">
                  <div className="us-verdict-icon-wrap">
                    <span className="us-verdict-emoji">
                      {result.safe ? "✅" : "🚨"}
                    </span>
                  </div>
                  <div className="us-verdict-info">
                    <div
                      className="us-verdict-status"
                      style={{
                        color: result.safe ? "var(--green)" : "var(--red)",
                      }}
                    >
                      {result.safe ? "SAFE" : "UNSAFE"}
                    </div>
                    <div className="us-verdict-url">{result.url}</div>
                    <div style={{ display: "flex", gap: 6, marginTop: 4 }}>
                      {result.cached && (
                        <span className="us-cached-badge">
                          📦 Cached Result
                        </span>
                      )}
                      {result.scanType && (
                        <span
                          className="us-cached-badge"
                          style={{
                            background: "rgba(168,85,247,0.12)",
                            color: "var(--purple)",
                          }}
                        >
                          {result.scanType === "deep"
                            ? "🔬 Deep Scan"
                            : "⚡ Quick Scan"}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="us-risk-circle">
                    <svg viewBox="0 0 120 120" className="us-risk-svg">
                      <circle
                        cx="60"
                        cy="60"
                        r="50"
                        className="us-risk-bg"
                      />
                      <circle
                        cx="60"
                        cy="60"
                        r="50"
                        className="us-risk-fill"
                        style={{
                          strokeDasharray: `${result.riskScore * 3.14} ${
                            314 - result.riskScore * 3.14
                          }`,
                          stroke: sevColor(result.riskLevel),
                        }}
                      />
                    </svg>
                    <div className="us-risk-label">
                      <span
                        className="us-risk-num"
                        style={{ color: sevColor(result.riskLevel) }}
                      >
                        {result.riskScore}
                      </span>
                      <span className="us-risk-text">/ 100</span>
                    </div>
                  </div>
                </div>

                {/* Risk Bar */}
                <div className="us-risk-bar-section">
                  <div className="us-risk-bar-track">
                    <div
                      className="us-risk-bar-fill"
                      style={{
                        width: `${result.riskScore}%`,
                        background: getRiskGradient(result.riskScore),
                      }}
                    />
                    <div
                      className="us-risk-bar-marker"
                      style={{ left: `${result.riskScore}%` }}
                    />
                  </div>
                  <div className="us-risk-bar-labels">
                    <span style={{ color: "var(--green)" }}>Safe</span>
                    <span style={{ color: "var(--yellow)" }}>Low</span>
                    <span style={{ color: "var(--orange)" }}>Medium</span>
                    <span style={{ color: "var(--red)" }}>High</span>
                    <span style={{ color: "var(--purple)" }}>Critical</span>
                  </div>
                </div>

                {/* Download Buttons */}
                <div className="us-download-bar">
                  <span className="us-download-label">
                    📥 Download Report:
                  </span>
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={() => handleDownload("pdf")}
                    disabled={downloading === "pdf"}
                  >
                    {downloading === "pdf"
                      ? "⏳ Generating..."
                      : "📄 PDF Report"}
                  </button>
                  <button
                    className="btn btn-ghost btn-sm us-excel-btn"
                    onClick={() => handleDownload("excel")}
                    disabled={downloading === "excel"}
                  >
                    {downloading === "excel"
                      ? "⏳ Generating..."
                      : "📊 Excel Report"}
                  </button>
                </div>
              </div>

              {/* ===== 2. FINDING SUMMARY BAR ===== */}
              {result.findings?.length > 0 && (
                <div className="us-findings-summary">
                  <span className="us-fs-label">Findings:</span>
                  {[
                    {
                      key: "critical",
                      label: "Critical",
                      color: "var(--purple)",
                    },
                    { key: "high", label: "High", color: "var(--red)" },
                    {
                      key: "medium",
                      label: "Medium",
                      color: "var(--orange)",
                    },
                    { key: "low", label: "Low", color: "#8bc34a" },
                    { key: "info", label: "Info", color: "var(--blue)" },
                  ].map(({ key, label, color }) => (
                    <div key={key} className="us-fs-item">
                      <span
                        className="us-fs-dot"
                        style={{ background: color }}
                      />
                      <span className="us-fs-name">{label}:</span>
                      <span
                        className="us-fs-count"
                        style={{ color: color }}
                      >
                        {result.finding_summary?.[key] || 0}
                      </span>
                    </div>
                  ))}
                  <span className="us-fs-categories">
                    Categories:{" "}
                    {(result.categories_detected || []).join(", ") || "None"}
                  </span>
                </div>
              )}

              {/* ===== 3. THREATS / WARNINGS / INFO / RECS GRID ===== */}
              <div className="us-details-grid">
                {result.threats?.length > 0 && (
                  <div className="card us-detail-card">
                    <div className="card-hdr">
                      <span className="card-title">🚨 Threats</span>
                      <span
                        className="badge"
                        style={{
                          background: "rgba(255,71,87,0.12)",
                          color: "var(--red)",
                        }}
                      >
                        {result.threats.length}
                      </span>
                    </div>
                    <div className="us-list">
                      {result.threats.map((t, i) => (
                        <div
                          key={i}
                          className="us-list-item us-item-threat"
                        >
                          <span className="us-item-icon">🔴</span>
                          <span>{t}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.warnings?.length > 0 && (
                  <div className="card us-detail-card">
                    <div className="card-hdr">
                      <span className="card-title">⚠️ Warnings</span>
                      <span
                        className="badge"
                        style={{
                          background: "rgba(255,152,0,0.12)",
                          color: "var(--orange)",
                        }}
                      >
                        {result.warnings.length}
                      </span>
                    </div>
                    <div className="us-list">
                      {result.warnings.map((w, i) => (
                        <div
                          key={i}
                          className="us-list-item us-item-warning"
                        >
                          <span className="us-item-icon">🟡</span>
                          <span>{w}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.info?.length > 0 && (
                  <div className="card us-detail-card">
                    <div className="card-hdr">
                      <span className="card-title">ℹ️ Information</span>
                    </div>
                    <div className="us-list">
                      {result.info.map((inf, i) => (
                        <div
                          key={i}
                          className="us-list-item us-item-info"
                        >
                          <span className="us-item-icon">🔵</span>
                          <span>{inf}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {result.recommendations?.length > 0 && (
                  <div className="card us-detail-card">
                    <div className="card-hdr">
                      <span className="card-title">💡 Recommendations</span>
                    </div>
                    <div className="us-list">
                      {result.recommendations.map((r, i) => (
                        <div key={i} className="us-list-item us-item-rec">
                          <span className="us-item-icon">💡</span>
                          <span>{r}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* ===== 4. MALWARE & PHISHING INDICATORS ===== */}
              {(result.malwareIndicators?.length > 0 ||
                result.phishingIndicators?.length > 0) && (
                <div className="us-details-grid">
                  {result.malwareIndicators?.length > 0 && (
                    <div className="card us-detail-card">
                      <div className="card-hdr">
                        <span className="card-title">
                          🦠 Malware Indicators
                        </span>
                        <span
                          className="badge"
                          style={{
                            background: "rgba(255,71,87,0.12)",
                            color: "var(--red)",
                          }}
                        >
                          {result.malwareIndicators.length}
                        </span>
                      </div>
                      <div className="us-list">
                        {result.malwareIndicators.map((m, i) => (
                          <div
                            key={i}
                            className="us-list-item us-item-threat"
                          >
                            <span className="us-item-icon">🦠</span>
                            <span>{m}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {result.phishingIndicators?.length > 0 && (
                    <div className="card us-detail-card">
                      <div className="card-hdr">
                        <span className="card-title">
                          🎣 Phishing Indicators
                        </span>
                        <span
                          className="badge"
                          style={{
                            background: "rgba(255,152,0,0.12)",
                            color: "var(--orange)",
                          }}
                        >
                          {result.phishingIndicators.length}
                        </span>
                      </div>
                      <div className="us-list">
                        {result.phishingIndicators.map((p, i) => (
                          <div
                            key={i}
                            className="us-list-item us-item-warning"
                          >
                            <span className="us-item-icon">🎣</span>
                            <span>{p}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ===== 5. DETAILED FINDINGS ===== */}
              {result.findings?.length > 0 && (
                <div className="card" style={{ marginBottom: 18 }}>
                  <div className="card-hdr">
                    <span className="card-title">
                      🔎 Detailed Findings ({result.findings.length})
                    </span>
                    <div style={{ display: "flex", gap: 6 }}>
                      {["critical", "high", "medium", "low", "info"].map(
                        (sev) =>
                          (result.finding_summary?.[sev] || 0) > 0 && (
                            <span
                              key={sev}
                              className="badge"
                              style={{
                                background: sevBg(
                                  sev === "info" ? "none" : sev
                                ),
                                color: sevColor(
                                  sev === "info" ? "none" : sev
                                ),
                              }}
                            >
                              {result.finding_summary[sev]} {sev}
                            </span>
                          )
                      )}
                    </div>
                  </div>

                  <div className="us-findings-list">
                    {result.findings.map((f, i) => {
                      const sc = getSevStyle(f.severity);
                      return (
                        <div
                          key={i}
                          className="us-finding-card anim-up"
                          style={{
                            animationDelay: `${i * 30}ms`,
                            background: sc.bg,
                            borderLeft: `4px solid ${sc.border}`,
                          }}
                        >
                          {/* Finding Header */}
                          <div className="us-finding-header">
                            <div className="us-finding-title-row">
                              <span className="us-finding-icon">
                                {sc.icon}
                              </span>
                              <span className="us-finding-name">
                                {f.name}
                              </span>
                            </div>
                            <div className="us-finding-badges">
                              <span
                                className="badge"
                                style={{
                                  background: sc.bg,
                                  color: sc.border,
                                  border: `1px solid ${sc.border}`,
                                }}
                              >
                                {f.severity}
                              </span>
                              <span className="us-finding-cat">
                                {f.category}
                              </span>
                              {f.risk_points !== 0 && (
                                <span
                                  className="us-finding-pts"
                                  style={{
                                    color:
                                      f.risk_points > 0
                                        ? "var(--red)"
                                        : "var(--green)",
                                  }}
                                >
                                  {f.risk_points > 0 ? "+" : ""}
                                  {f.risk_points} pts
                                </span>
                              )}
                            </div>
                          </div>

                          {/* Description */}
                          <div className="us-finding-desc">
                            {f.description}
                          </div>

                          {/* Evidence */}
                          {f.evidence && (
                            <div className="us-finding-evidence">
                              📎 {f.evidence}
                            </div>
                          )}

                          {/* Recommendation */}
                          {f.recommendation && (
                            <div className="us-finding-rec">
                              <span>💡</span>
                              <span>{f.recommendation}</span>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* ===== 6. MALICIOUS SCRIPT PATTERNS ===== */}
              {result.analysis?.scripts?.malicious_patterns?.length > 0 && (
                <div className="card" style={{ marginBottom: 18 }}>
                  <div className="card-hdr">
                    <span className="card-title">
                      ⚠️ Malicious Script Patterns
                    </span>
                  </div>
                  <div className="us-list">
                    {result.analysis.scripts.malicious_patterns.map(
                      (p, i) => (
                        <div
                          key={i}
                          className="us-list-item us-item-threat"
                        >
                          <span className="us-item-icon">💀</span>
                          <span>
                            <strong>{p.pattern}</strong> — found {p.count}{" "}
                            time(s)
                          </span>
                        </div>
                      )
                    )}
                  </div>
                </div>
              )}

              {/* ===== 7. REDIRECT CHAIN ===== */}
              {result.analysis?.redirects?.count > 0 && (
                <div className="card" style={{ marginBottom: 18 }}>
                  <div className="card-hdr">
                    <span className="card-title">
                      🔀 Redirect Chain ({result.analysis.redirects.count}{" "}
                      redirects)
                    </span>
                  </div>
                  <div className="us-list">
                    {result.analysis.redirects.chain?.map((r, i) => (
                      <div
                        key={i}
                        className="us-list-item us-item-info"
                      >
                        <span className="us-item-icon">
                          {i ===
                          result.analysis.redirects.chain.length - 1
                            ? "🏁"
                            : "➡️"}
                        </span>
                        <span>
                          <strong>{r.status}</strong>{" "}
                          <span className="us-chain-url">{r.url}</span>
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* ===== 8. SECURITY HEADERS ===== */}
              {result.analysis?.headers?.security_headers_present && (
                <div className="card" style={{ marginBottom: 18 }}>
                  <div className="card-hdr">
                    <span className="card-title">🔒 Security Headers</span>
                  </div>
                  <div className="us-headers-grid">
                    <div>
                      <h4 className="us-hdr-title us-hdr-present">
                        ✅ Present
                      </h4>
                      {result.analysis.headers.security_headers_present
                        .length === 0 ? (
                        <span className="us-hdr-none">None</span>
                      ) : (
                        result.analysis.headers.security_headers_present.map(
                          (h) => (
                            <div key={h} className="us-hdr-item us-hdr-ok">
                              {h}
                            </div>
                          )
                        )
                      )}
                    </div>
                    <div>
                      <h4 className="us-hdr-title us-hdr-missing">
                        ❌ Missing
                      </h4>
                      {(
                        result.analysis.headers.security_headers_missing ||
                        []
                      ).map((h) => (
                        <div key={h} className="us-hdr-item us-hdr-bad">
                          {h}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* ===== 9. TECHNICAL ANALYSIS ===== */}
              {result.analysis && (
                <div className="card us-tech-card">
                  <div className="card-hdr">
                    <span className="card-title">🔬 Technical Analysis</span>
                  </div>

                  <div className="us-tech-grid">
                    {/* Domain */}
                    {result.analysis.domain && (
                      <div className="us-tech-section">
                        <h4>🌐 Domain</h4>
                        <div className="us-tech-rows">
                          <div className="us-tech-row">
                            <span>Domain</span>
                            <span className="us-tech-val us-mono us-cyan">
                              {result.analysis.domain.name}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Length</span>
                            <span className="us-tech-val">
                              {result.analysis.domain.length} chars
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>IP Address</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color: result.analysis.domain.is_ip
                                  ? "var(--red)"
                                  : "var(--green)",
                              }}
                            >
                              {result.analysis.domain.is_ip
                                ? "Yes ⚠️"
                                : "No ✓"}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Subdomains</span>
                            <span className="us-tech-val">
                              {result.analysis.domain.subdomain_count}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Suspicious TLD</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color: result.analysis.domain.suspicious_tld
                                  ? "var(--red)"
                                  : "var(--green)",
                              }}
                            >
                              {result.analysis.domain.suspicious_tld
                                ? "Yes ⚠️"
                                : "No ✓"}
                            </span>
                          </div>
                          {result.analysis.domain.resolved_ip && (
                            <div className="us-tech-row">
                              <span>Resolved IP</span>
                              <span className="us-tech-val us-mono">
                                {result.analysis.domain.resolved_ip}
                              </span>
                            </div>
                          )}
                          <div className="us-tech-row">
                            <span>Trusted</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color: result.analysis.reputation?.trusted
                                  ? "var(--green)"
                                  : "var(--text-dim)",
                              }}
                            >
                              {result.analysis.reputation?.trusted
                                ? "Yes ✓"
                                : "Unknown"}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* SSL */}
                    {result.analysis.ssl && (
                      <div className="us-tech-section">
                        <h4>🔒 SSL / TLS</h4>
                        <div className="us-tech-rows">
                          <div className="us-tech-row">
                            <span>Protocol</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color:
                                  result.analysis.ssl.protocol === "https"
                                    ? "var(--green)"
                                    : "var(--red)",
                              }}
                            >
                              {result.analysis.ssl.protocol?.toUpperCase()}
                            </span>
                          </div>
                          {result.analysis.ssl.checked && (
                            <>
                              <div className="us-tech-row">
                                <span>Certificate</span>
                                <span
                                  className="us-tech-val"
                                  style={{
                                    color: result.analysis.ssl.valid
                                      ? "var(--green)"
                                      : "var(--red)",
                                  }}
                                >
                                  {result.analysis.ssl.valid
                                    ? "Valid ✓"
                                    : "Invalid ✖"}
                                </span>
                              </div>
                              {result.analysis.ssl.issuer && (
                                <div className="us-tech-row">
                                  <span>Issuer</span>
                                  <span className="us-tech-val">
                                    {result.analysis.ssl.issuer}
                                  </span>
                                </div>
                              )}
                              {result.analysis.ssl.expires && (
                                <div className="us-tech-row">
                                  <span>Expires</span>
                                  <span className="us-tech-val">
                                    {result.analysis.ssl.expires}
                                  </span>
                                </div>
                              )}
                            </>
                          )}
                        </div>
                      </div>
                    )}

                    {/* URL Structure */}
                    {result.analysis.url_structure && (
                      <div className="us-tech-section">
                        <h4>🔗 URL Structure</h4>
                        <div className="us-tech-rows">
                          <div className="us-tech-row">
                            <span>Length</span>
                            <span className="us-tech-val">
                              {result.analysis.url_structure.total_length ||
                                result.analysis.url_structure.url_length}{" "}
                              chars
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Path Depth</span>
                            <span className="us-tech-val">
                              {result.analysis.url_structure.path_depth}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Query Params</span>
                            <span className="us-tech-val">
                              {result.analysis.url_structure.query_params}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Encoded Chars</span>
                            <span className="us-tech-val">
                              {result.analysis.url_structure.encoded_chars}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Non-std Port</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color: result.analysis.url_structure
                                  .non_standard_port
                                  ? "var(--orange)"
                                  : "var(--green)",
                              }}
                            >
                              {result.analysis.url_structure.non_standard_port
                                ? "Yes ⚠️"
                                : "No ✓"}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Content Analysis */}
                    {result.analysis.content && (
                      <div className="us-tech-section">
                        <h4>📋 Content</h4>
                        <div className="us-tech-rows">
                          {result.analysis.content.deep_scan && (
                            <>
                              {result.analysis.content.links !== undefined && (
                                <div className="us-tech-row">
                                  <span>Links</span>
                                  <span className="us-tech-val">
                                    {result.analysis.content.links}
                                  </span>
                                </div>
                              )}
                              {result.analysis.content
                                .external_domain_count !== undefined && (
                                <div className="us-tech-row">
                                  <span>External Domains</span>
                                  <span className="us-tech-val">
                                    {
                                      result.analysis.content
                                        .external_domain_count
                                    }
                                  </span>
                                </div>
                              )}
                              {result.analysis.content.phishing_score !==
                                undefined && (
                                <div className="us-tech-row">
                                  <span>Phishing Score</span>
                                  <span
                                    className="us-tech-val"
                                    style={{
                                      color:
                                        result.analysis.content
                                          .phishing_score >= 3
                                          ? "var(--red)"
                                          : "var(--green)",
                                    }}
                                  >
                                    {result.analysis.content.phishing_score}
                                  </span>
                                </div>
                              )}
                            </>
                          )}
                          {result.analysis.content.has_redirect_param !==
                            undefined && (
                            <div className="us-tech-row">
                              <span>Redirect Param</span>
                              <span
                                className="us-tech-val"
                                style={{
                                  color: result.analysis.content
                                    .has_redirect_param
                                    ? "var(--orange)"
                                    : "var(--green)",
                                }}
                              >
                                {result.analysis.content.has_redirect_param
                                  ? "Yes ⚠️"
                                  : "No ✓"}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Scripts */}
                    {result.analysis.scripts?.total !== undefined && (
                      <div className="us-tech-section">
                        <h4>📜 Scripts</h4>
                        <div className="us-tech-rows">
                          <div className="us-tech-row">
                            <span>Total</span>
                            <span className="us-tech-val">
                              {result.analysis.scripts.total}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>External</span>
                            <span className="us-tech-val">
                              {result.analysis.scripts.external}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Inline</span>
                            <span className="us-tech-val">
                              {result.analysis.scripts.inline}
                            </span>
                          </div>
                          {result.analysis.scripts.obfuscation_score !==
                            undefined && (
                            <div className="us-tech-row">
                              <span>Obfuscation</span>
                              <span
                                className="us-tech-val"
                                style={{
                                  color:
                                    result.analysis.scripts
                                      .obfuscation_score >= 3
                                      ? "var(--red)"
                                      : result.analysis.scripts
                                          .obfuscation_score >= 1
                                      ? "var(--orange)"
                                      : "var(--green)",
                                }}
                              >
                                {result.analysis.scripts.obfuscation_score}
                              </span>
                            </div>
                          )}
                          {result.analysis.scripts.cryptominer_detected !==
                            undefined && (
                            <div className="us-tech-row">
                              <span>Cryptominer</span>
                              <span
                                className="us-tech-val"
                                style={{
                                  color: result.analysis.scripts
                                    .cryptominer_detected
                                    ? "var(--red)"
                                    : "var(--green)",
                                }}
                              >
                                {result.analysis.scripts.cryptominer_detected
                                  ? "DETECTED 🚨"
                                  : "None ✓"}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Forms */}
                    {result.analysis.forms?.total !== undefined && (
                      <div className="us-tech-section">
                        <h4>📋 Forms</h4>
                        <div className="us-tech-rows">
                          <div className="us-tech-row">
                            <span>Total</span>
                            <span className="us-tech-val">
                              {result.analysis.forms.total}
                            </span>
                          </div>
                          <div className="us-tech-row">
                            <span>Password Fields</span>
                            <span
                              className="us-tech-val"
                              style={{
                                color:
                                  result.analysis.forms.has_password_field &&
                                  !result.analysis.reputation?.trusted
                                    ? "var(--orange)"
                                    : "var(--text)",
                              }}
                            >
                              {result.analysis.forms.password_fields}
                            </span>
                          </div>
                          {result.analysis.forms.suspicious?.length > 0 && (
                            <div className="us-tech-row">
                              <span>Suspicious</span>
                              <span
                                className="us-tech-val"
                                style={{ color: "var(--red)" }}
                              >
                                {result.analysis.forms.suspicious.length} ⚠️
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Iframes */}
                    {result.analysis.iframes?.total !== undefined && (
                      <div className="us-tech-section">
                        <h4>🖼️ Iframes</h4>
                        <div className="us-tech-rows">
                          <div className="us-tech-row">
                            <span>Total</span>
                            <span className="us-tech-val">
                              {result.analysis.iframes.total}
                            </span>
                          </div>
                          {result.analysis.iframes.hidden_count !==
                            undefined && (
                            <div className="us-tech-row">
                              <span>Hidden</span>
                              <span
                                className="us-tech-val"
                                style={{
                                  color:
                                    result.analysis.iframes.hidden_count > 0
                                      ? "var(--red)"
                                      : "var(--green)",
                                }}
                              >
                                {result.analysis.iframes.hidden_count}
                                {result.analysis.iframes.hidden_count > 0
                                  ? " 🚨"
                                  : " ✓"}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Page Metadata */}
                  {result.analysis.metadata?.title && (
                    <div className="us-metadata">
                      <div className="us-meta-label">Page Title</div>
                      <div className="us-meta-val">
                        {result.analysis.metadata.title}
                      </div>
                      {result.analysis.metadata.description && (
                        <>
                          <div
                            className="us-meta-label"
                            style={{ marginTop: 8 }}
                          >
                            Description
                          </div>
                          <div className="us-meta-desc">
                            {result.analysis.metadata.description}
                          </div>
                        </>
                      )}
                    </div>
                  )}

                  {/* Scan Meta */}
                  <div className="us-scan-meta">
                    <span>
                      Duration:{" "}
                      <strong>{result.scanDuration || "N/A"}ms</strong>
                    </span>
                    <span>
                      Scanned:{" "}
                      <strong>{fmtDate(result.timestamp)}</strong>
                    </span>
                    <span>
                      Type:{" "}
                      <strong>
                        {result.scanType === "deep"
                          ? "Deep Scan"
                          : "Quick Scan"}
                      </strong>
                    </span>
                    <span>
                      Findings: <strong>{result.findings?.length || 0}</strong>
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Empty State */}
          {!result && !loading && !error && (
            <div className="card">
              <div className="empty">
                <div className="empty-icon">🔗</div>
                <p>
                  Enter a URL above and click <strong>Deep Scan</strong> or{" "}
                  <strong>Quick Scan</strong>
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ============================================================ */}
      {/*                       HISTORY TAB                             */}
      {/* ============================================================ */}
      {activeTab === "history" && (
        <div className="card">
          <div className="card-hdr">
            <span className="card-title">📜 Scan History</span>
            <button
              className="btn btn-ghost btn-sm"
              onClick={loadHistory}
            >
              ↻ Refresh
            </button>
          </div>

          {!history.length ? (
            <div className="empty">
              <div className="empty-icon">📜</div>
              <p>No scan history yet. Scan a URL to get started.</p>
            </div>
          ) : (
            <>
              <div className="us-history-list">
                {history.map((scan, i) => (
                  <div
                    key={scan._id}
                    className="us-history-item anim-up"
                    style={{ animationDelay: `${i * 40}ms` }}
                  >
                    <div className="us-hist-left">
                      <span className="us-hist-emoji">
                        {getRiskEmoji(scan.riskLevel)}
                      </span>
                      <div>
                        <div className="us-hist-url">{scan.url}</div>
                        <div className="us-hist-meta">
                          <span>{fmtDate(scan.createdAt)}</span>
                          {scan.scanDuration && (
                            <span>{scan.scanDuration}ms</span>
                          )}
                          {scan.scanType && (
                            <span style={{ color: "var(--purple)" }}>
                              {scan.scanType}
                            </span>
                          )}
                          {scan.threats?.length > 0 && (
                            <span style={{ color: "var(--red)" }}>
                              {scan.threats.length} threat(s)
                            </span>
                          )}
                          {scan.warnings?.length > 0 && (
                            <span style={{ color: "var(--orange)" }}>
                              {scan.warnings.length} warning(s)
                            </span>
                          )}
                          {scan.malwareIndicators?.length > 0 && (
                            <span style={{ color: "var(--red)" }}>
                              🦠 {scan.malwareIndicators.length}
                            </span>
                          )}
                          {scan.phishingIndicators?.length > 0 && (
                            <span style={{ color: "var(--orange)" }}>
                              🎣 {scan.phishingIndicators.length}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="us-hist-right">
                      <div className="us-hist-score">
                        <span
                          className="us-hist-score-num"
                          style={{ color: sevColor(scan.riskLevel) }}
                        >
                          {scan.riskScore}
                        </span>
                        <span className="us-hist-score-label">/100</span>
                      </div>
                      <span
                        className="badge"
                        style={{
                          background: sevBg(scan.riskLevel),
                          color: sevColor(scan.riskLevel),
                        }}
                      >
                        {scan.riskLevel}
                      </span>
                      <button
                        className="btn btn-danger btn-sm"
                        onClick={() => handleDeleteScan(scan._id)}
                      >
                        ✕
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              {historyPg.pages > 1 && (
                <div className="at-pag">
                  <button
                    className="btn btn-ghost btn-sm"
                    disabled={historyPage <= 1}
                    onClick={() => setHistoryPage((p) => p - 1)}
                  >
                    ← Prev
                  </button>
                  <span className="at-pag-info">
                    Page {historyPg.page} of {historyPg.pages}
                  </span>
                  <button
                    className="btn btn-ghost btn-sm"
                    disabled={historyPage >= historyPg.pages}
                    onClick={() => setHistoryPage((p) => p + 1)}
                  >
                    Next →
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}