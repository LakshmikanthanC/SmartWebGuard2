const router = require("express").Router();
const geoip = require("geoip-lite");
const bridge = require("../services/pythonBridge");
const Alert = require("../models/Alert");
const { emitAlert } = require("../services/socketService");
const { randIP, randPort } = require("../utils/helpers");
const ALLOWED_SEVERITIES = new Set(["none", "low", "medium", "high", "critical"]);
const ALLOWED_PROTOCOLS = new Set(["tcp", "udp", "icmp", "other"]);

const getCountry = (ip) => {
  try {
    const geo = geoip.lookup(ip);
    return geo ? geo.country : "Unknown";
  } catch (e) {
    return "Unknown";
  }
};

const normalizeSeverity = (severity, predictionLabel) => {
  const value = String(severity || "").toLowerCase();
  if (ALLOWED_SEVERITIES.has(value)) return value;
  const predicted = String(predictionLabel || "").toLowerCase();
  return predicted === "normal" ? "none" : "medium";
};

const normalizeProtocol = (protocol) => {
  const value = String(protocol || "").toLowerCase();
  return ALLOWED_PROTOCOLS.has(value) ? value : "other";
};

router.post("/", async (req, res, next) => {
  try {
    const features = req.body;
    if (!features || !Object.keys(features).length)
      return res.status(400).json({ error: "No features provided" });

    const prediction = await bridge.predict(features);

    const safeSeverity = normalizeSeverity(prediction.severity, prediction.prediction);
    const safeProtocol = normalizeProtocol(features.protocol_type || "tcp");
    prediction.severity = safeSeverity;

    if (prediction.is_malicious) {
      const sourceIP = features.source_ip || randIP();
      const destinationIP = features.dest_ip || randIP();
      const sourceCountry = getCountry(sourceIP);
      const destinationCountry = getCountry(destinationIP);

      const alert = await Alert.create({
        sourceIP,
        destinationIP,
        sourceCountry,
        destinationCountry,
        sourcePort: features.source_port || randPort(),
        destinationPort: features.dest_port || randPort(),
        protocol: safeProtocol,
        attackType: prediction.prediction,
        severity: safeSeverity,
        confidence: prediction.confidence,
        probabilities: prediction.probabilities,
        rawFeatures: features,
      });
      emitAlert({
        _id: alert._id, timestamp: alert.timestamp,
        sourceIP: alert.sourceIP, destinationIP: alert.destinationIP,
        sourceCountry: alert.sourceCountry, destinationCountry: alert.destinationCountry,
        attackType: alert.attackType, severity: alert.severity,
        confidence: alert.confidence,
      });
    }
    res.json(prediction);
  } catch (err) { next(err); }
});

router.get("/health", async (req, res) => {
  res.json(await bridge.healthCheck());
});

router.get("/model-info", async (req, res, next) => {
  try { res.json(await bridge.getModelInfo()); }
  catch (err) { next(err); }
});

router.post("/train", async (req, res, next) => {
  try { res.json(await bridge.triggerTraining()); }
  catch (err) { next(err); }
});

module.exports = router;
