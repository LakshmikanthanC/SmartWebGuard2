const mongoose = require("mongoose");

const ALLOWED_SEVERITIES = new Set(["none", "low", "medium", "high", "critical"]);
const ALLOWED_PROTOCOLS = new Set(["tcp", "udp", "icmp", "other"]);

function normalizeSeverity(value) {
  const v = String(value || "").toLowerCase();
  if (ALLOWED_SEVERITIES.has(v)) return v;
  return "medium";
}

function normalizeProtocol(value) {
  const v = String(value || "").toLowerCase();
  if (ALLOWED_PROTOCOLS.has(v)) return v;
  return "other";
}

const alertSchema = new mongoose.Schema(
  {
    timestamp: { type: Date, default: Date.now, index: true },
    sourceIP: { type: String, required: true },
    destinationIP: { type: String, required: true },
    sourcePort: { type: Number, default: 0 },
    destinationPort: { type: Number, default: 0 },
    protocol: {
      type: String,
      enum: ["tcp", "udp", "icmp", "other"],
      default: "tcp",
      set: normalizeProtocol,
    },
    attackType: { type: String, required: true, index: true },
    severity: {
      type: String,
      enum: ["none", "low", "medium", "high", "critical"],
      default: "medium",
      set: normalizeSeverity,
    },
    confidence: { type: Number, min: 0, max: 1 },
    probabilities: { type: mongoose.Schema.Types.Mixed },
    rawFeatures: { type: mongoose.Schema.Types.Mixed },
    acknowledged: { type: Boolean, default: false },
    notes: { type: String, default: "" },
    explanation: { type: String, default: "" },
    recommendations: [String],
  },
  { timestamps: true }
);

alertSchema.index({ severity: 1, timestamp: -1 });
alertSchema.index({ acknowledged: 1 });

module.exports = mongoose.model("Alert", alertSchema);
