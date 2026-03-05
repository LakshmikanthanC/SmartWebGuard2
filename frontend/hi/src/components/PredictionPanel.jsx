import React, { useEffect, useState } from "react";
import { postPredict, getModelInfo } from "../services/api";
import { sevColor, sevBg, atkIcon, atkColor, fmtPct } from "../utils/formatters";
import "./PredictionPanel.css";

const SAMPLE_NORMAL = {
  duration: 12,
  protocol_type: "tcp",
  service: "http",
  flag: "SF",
  src_bytes: 520,
  dst_bytes: 1032,
  land: 0,
  wrong_fragment: 0,
  urgent: 0,
  hot: 0,
  num_failed_logins: 0,
  logged_in: 1,
  num_compromised: 0,
  root_shell: 0,
  su_attempted: 0,
  num_root: 0,
  num_file_creations: 0,
  num_shells: 0,
  num_access_files: 0,
  num_outbound_cmds: 0,
  is_host_login: 0,
  is_guest_login: 0,
  count: 12,
  srv_count: 10,
  serror_rate: 0.0,
  srv_serror_rate: 0.0,
  rerror_rate: 0.0,
  srv_rerror_rate: 0.0,
  same_srv_rate: 1.0,
  diff_srv_rate: 0.0,
  srv_diff_host_rate: 0.0,
  dst_host_count: 120,
  dst_host_srv_count: 60,
  dst_host_same_srv_rate: 0.9,
  dst_host_diff_srv_rate: 0.04,
  dst_host_same_src_port_rate: 0.1,
  dst_host_srv_diff_host_rate: 0.02,
  dst_host_serror_rate: 0.0,
  dst_host_srv_serror_rate: 0.0,
  dst_host_rerror_rate: 0.01,
  dst_host_srv_rerror_rate: 0.01,
};

const SAMPLE_DOS = {
  duration: 0,
  protocol_type: "tcp",
  service: "http",
  flag: "S0",
  src_bytes: 0,
  dst_bytes: 0,
  land: 0,
  wrong_fragment: 0,
  urgent: 0,
  hot: 0,
  num_failed_logins: 0,
  logged_in: 0,
  num_compromised: 0,
  root_shell: 0,
  su_attempted: 0,
  num_root: 0,
  num_file_creations: 0,
  num_shells: 0,
  num_access_files: 0,
  num_outbound_cmds: 0,
  is_host_login: 0,
  is_guest_login: 0,
  count: 500,
  srv_count: 2,
  serror_rate: 1.0,
  srv_serror_rate: 1.0,
  rerror_rate: 0.0,
  srv_rerror_rate: 0.0,
  same_srv_rate: 0.08,
  diff_srv_rate: 0.92,
  srv_diff_host_rate: 0.85,
  dst_host_count: 255,
  dst_host_srv_count: 4,
  dst_host_same_srv_rate: 0.03,
  dst_host_diff_srv_rate: 0.95,
  dst_host_same_src_port_rate: 0.98,
  dst_host_srv_diff_host_rate: 0.85,
  dst_host_serror_rate: 1.0,
  dst_host_srv_serror_rate: 1.0,
  dst_host_rerror_rate: 0.0,
  dst_host_srv_rerror_rate: 0.0,
};

const SAMPLE_PROBE = {
  duration: 0,
  protocol_type: "icmp",
  service: "ecr_i",
  flag: "SF",
  src_bytes: 8,
  dst_bytes: 0,
  land: 0,
  wrong_fragment: 0,
  urgent: 0,
  hot: 0,
  num_failed_logins: 0,
  logged_in: 0,
  num_compromised: 0,
  root_shell: 0,
  su_attempted: 0,
  num_root: 0,
  num_file_creations: 0,
  num_shells: 0,
  num_access_files: 0,
  num_outbound_cmds: 0,
  is_host_login: 0,
  is_guest_login: 0,
  count: 300,
  srv_count: 300,
  serror_rate: 0.0,
  srv_serror_rate: 0.0,
  rerror_rate: 0.0,
  srv_rerror_rate: 0.0,
  same_srv_rate: 1.0,
  diff_srv_rate: 0.0,
  srv_diff_host_rate: 1.0,
  dst_host_count: 255,
  dst_host_srv_count: 255,
  dst_host_same_srv_rate: 1.0,
  dst_host_diff_srv_rate: 0.0,
  dst_host_same_src_port_rate: 1.0,
  dst_host_srv_diff_host_rate: 0.0,
  dst_host_serror_rate: 0.0,
  dst_host_srv_serror_rate: 0.0,
  dst_host_rerror_rate: 0.0,
  dst_host_srv_rerror_rate: 0.0,
};

const SAMPLE_R2L = {
  duration: 200,
  protocol_type: "tcp",
  service: "ftp",
  flag: "SF",
  src_bytes: 300,
  dst_bytes: 4500,
  land: 0,
  wrong_fragment: 0,
  urgent: 0,
  hot: 3,
  num_failed_logins: 4,
  logged_in: 1,
  num_compromised: 0,
  root_shell: 0,
  su_attempted: 0,
  num_root: 0,
  num_file_creations: 2,
  num_shells: 0,
  num_access_files: 1,
  num_outbound_cmds: 0,
  is_host_login: 0,
  is_guest_login: 0,
  count: 5,
  srv_count: 5,
  serror_rate: 0.0,
  srv_serror_rate: 0.0,
  rerror_rate: 0.0,
  srv_rerror_rate: 0.0,
  same_srv_rate: 1.0,
  diff_srv_rate: 0.0,
  srv_diff_host_rate: 0.0,
  dst_host_count: 50,
  dst_host_srv_count: 25,
  dst_host_same_srv_rate: 0.5,
  dst_host_diff_srv_rate: 0.1,
  dst_host_same_src_port_rate: 0.2,
  dst_host_srv_diff_host_rate: 0.05,
  dst_host_serror_rate: 0.0,
  dst_host_srv_serror_rate: 0.0,
  dst_host_rerror_rate: 0.0,
  dst_host_srv_rerror_rate: 0.0,
};

export default function PredictionPanel() {
  const [featureValues, setFeatureValues] = useState({ ...SAMPLE_NORMAL });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [modelInfo, setModelInfo] = useState(null);
  const [modelLoading, setModelLoading] = useState(false);

  const runPredict = async (values) => {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const { data } = await postPredict(values);
      if (data.error) {
        const err = data.error;
        const errMsg = typeof err === 'object' ? err.message || JSON.stringify(err) : err;
        setError(errMsg);
      } else {
        setResult(data);
      }
    } catch (e) {
      const err = e.response?.data?.error;
      const errMsg = typeof err === 'object' ? err.message || JSON.stringify(err) : err || e.message || "Prediction failed";
      setError(errMsg);
    }
    setLoading(false);
  };

  const handlePredict = async () => {
    await runPredict(featureValues);
  };

  const loadModelInfo = async () => {
    setModelLoading(true);
    try {
      const { data } = await getModelInfo();
      if (data.error) {
        const err = data.error;
        const errMsg = typeof err === 'object' ? err.message || JSON.stringify(err) : err;
        setModelInfo({ error: errMsg });
      } else {
        setModelInfo(data);
      }
    } catch (e) {
      setModelInfo({ error: "Could not load model info" });
    }
    setModelLoading(false);
  };

  const loadSample = (sample, name) => {
    setFeatureValues({ ...sample });
    setResult(null);
    setError(null);
  };

  const handleFieldChange = (field, value) => {
    setFeatureValues(prev => ({
      ...prev,
      [field]: value
    }));
  };

  useEffect(() => {
    const initialSample = { ...SAMPLE_NORMAL };
    setFeatureValues(initialSample);
  }, []);

  // Get all keys from the sample object for consistent ordering
  const fieldKeys = Object.keys(SAMPLE_NORMAL);

  return (
    <div className="pp-container">
      <div className="pp-header">
        <h2 className="pp-title">🤖 AI Traffic Prediction</h2>
        <p className="pp-subtitle">
          Submit network traffic features to classify as Normal or Malicious
        </p>
      </div>

      <div className="pp-layout">
        {/* Left Panel — Input */}
        <div className="pp-input-panel">
          <div className="card">
            <div className="card-hdr">
              <span className="card-title">📝 Traffic Features</span>
            </div>

            <div className="pp-samples">
              <span className="pp-samples-label">Load Sample:</span>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => loadSample(SAMPLE_NORMAL, "Normal")}
              >
                ✅ Normal
              </button>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => loadSample(SAMPLE_DOS, "DoS")}
              >
                🔥 DoS
              </button>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => loadSample(SAMPLE_PROBE, "Probe")}
              >
                🔍 Probe
              </button>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => loadSample(SAMPLE_R2L, "R2L")}
              >
                🔓 R2L
              </button>
            </div>

            <div className="pp-table-wrapper">
              <table className="pp-features-table">
                <thead>
                  <tr>
                    <th>Field</th>
                    <th>Value</th>
                  </tr>
                </thead>
                <tbody>
                  {fieldKeys.map((key) => (
                    <tr key={key}>
                      <td className="pp-field-name">{key}</td>
                      <td className="pp-field-value">
                        <input
                          type="text"
                          className="pp-field-input"
                          value={featureValues[key]}
                          onChange={(e) => handleFieldChange(key, e.target.value)}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="pp-actions">
              <button
                className="btn btn-primary"
                onClick={handlePredict}
                disabled={loading}
              >
                {loading ? "⏳ Analyzing..." : "🚀 Predict"}
              </button>
              <button
                className="btn btn-ghost"
                onClick={loadModelInfo}
                disabled={modelLoading}
              >
                {modelLoading ? "Loading..." : "📊 Model Info"}
              </button>
            </div>

            {error && <div className="pp-error">❌ {error}</div>}
          </div>
        </div>

        {/* Right Panel — Results */}
        <div className="pp-result-panel">
          {result && (
            <div className="card anim-up pp-result-card">
              <div className="card-hdr">
                <span className="card-title">📋 Prediction Result</span>
              </div>

              <div
                className="pp-verdict"
                style={{
                  borderColor: result.is_malicious
                    ? "var(--red)"
                    : "var(--green)",
                }}
              >
                <div className="pp-verdict-icon">
                  {result.is_malicious ? "🚨" : "✅"}
                </div>
                <div className="pp-verdict-text">
                  <div
                    className="pp-verdict-label"
                    style={{
                      color: result.is_malicious
                        ? "var(--red)"
                        : "var(--green)",
                    }}
                  >
                    {result.is_malicious
                      ? "MALICIOUS TRAFFIC DETECTED"
                      : "NORMAL TRAFFIC"}
                  </div>
                  <div className="pp-verdict-type">
                    {atkIcon(result.prediction)}{" "}
                    {result.prediction?.toUpperCase()}
                  </div>
                </div>
              </div>

              <div className="pp-details-grid">
                <div className="pp-detail">
                  <span className="pp-detail-label">Classification</span>
                  <span
                    className="pp-detail-val"
                    style={{ color: atkColor(result.prediction) }}
                  >
                    {result.prediction?.toUpperCase()}
                  </span>
                </div>
                <div className="pp-detail">
                  <span className="pp-detail-label">Confidence</span>
                  <span className="pp-detail-val">
                    {fmtPct(result.confidence)}
                  </span>
                </div>
                <div className="pp-detail">
                  <span className="pp-detail-label">Severity</span>
                  <span
                    className="badge"
                    style={{
                      background: sevBg(result.severity),
                      color: sevColor(result.severity),
                    }}
                  >
                    {result.severity}
                  </span>
                </div>
                <div className="pp-detail">
                  <span className="pp-detail-label">Malicious</span>
                  <span
                    className="pp-detail-val"
                    style={{
                      color: result.is_malicious
                        ? "var(--red)"
                        : "var(--green)",
                    }}
                  >
                    {result.is_malicious ? "YES" : "NO"}
                  </span>
                </div>
              </div>

              {result.probabilities &&
                Object.keys(result.probabilities).length > 0 && (
                  <div className="pp-probs">
                    <h4>Class Probabilities</h4>
                    {Object.entries(result.probabilities)
                      .sort(([, a], [, b]) => b - a)
                      .map(([cls, prob]) => (
                        <div key={cls} className="pp-prob-row">
                          <span className="pp-prob-icon">
                            {atkIcon(cls)}
                          </span>
                          <span className="pp-prob-name">
                            {cls.toUpperCase()}
                          </span>
                          <div className="pp-prob-bar-wrap">
                            <div
                              className="pp-prob-bar"
                              style={{
                                width: `${prob * 100}%`,
                                background: atkColor(cls),
                              }}
                            />
                          </div>
                          <span className="pp-prob-val">
                            {(prob * 100).toFixed(2)}%
                          </span>
                        </div>
                      ))}
                  </div>
                )}
            </div>
          )}

          {modelInfo && (
            <div className="card anim-up" style={{ marginTop: 18 }}>
              <div className="card-hdr">
                <span className="card-title">📊 Model Information</span>
              </div>
              {modelInfo.error ? (
                <div className="pp-error">{modelInfo.error}</div>
              ) : (
                <div className="pp-model-info">
                  {(() => {
                    const hasMetrics = !!modelInfo.metrics;
                    const statusLabel = modelInfo.model_loaded
                      ? "Loaded"
                      : hasMetrics
                        ? "Demo Mode"
                        : "Not Loaded";
                    return (
                  <div className="pp-model-status">
                    <span className="pp-ms-dot" />
                    Model:{" "}
                    {statusLabel}
                  </div>
                    );
                  })()}
                  {modelInfo.metrics && (
                    <div className="pp-metrics-grid">
                      <div className="pp-metric">
                        <span className="pp-metric-val">
                          {(modelInfo.metrics.accuracy * 100).toFixed(2)}%
                        </span>
                        <span className="pp-metric-label">Accuracy</span>
                      </div>
                      <div className="pp-metric">
                        <span className="pp-metric-val">
                          {(modelInfo.metrics.precision * 100).toFixed(2)}%
                        </span>
                        <span className="pp-metric-label">Precision</span>
                      </div>
                      <div className="pp-metric">
                        <span className="pp-metric-val">
                          {(modelInfo.metrics.recall * 100).toFixed(2)}%
                        </span>
                        <span className="pp-metric-label">Recall</span>
                      </div>
                      <div className="pp-metric">
                        <span className="pp-metric-val">
                          {(modelInfo.metrics.f1_score * 100).toFixed(2)}%
                        </span>
                        <span className="pp-metric-label">F1 Score</span>
                      </div>
                    </div>
                  )}
                  {modelInfo.metrics?.class_names && (
                    <div className="pp-classes">
                      <span className="pp-classes-label">Classes:</span>
                      {modelInfo.metrics.class_names.map((c) => (
                        <span key={c} className="pp-class-tag">
                          {atkIcon(c)} {c.toUpperCase()}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {!result && !modelInfo && (
            <div className="card">
              <div className="empty">
                <div className="empty-icon">🤖</div>
                <p>
                  Default sample is auto-loaded and predicted.
                  Edit fields or load another sample, then click Predict.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
