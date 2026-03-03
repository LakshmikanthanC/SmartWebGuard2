const router = require("express").Router();
const Alert = require("../models/Alert");

router.get("/dashboard", async (req, res, next) => {
  try {
    const now = new Date();
    const h24 = new Date(now - 864e5);
    const d7 = new Date(now - 6048e5);

    const [totalAlerts, alerts24h, bySeverity, byType, recent, hourly, unack] = await Promise.all([
      Alert.countDocuments(),
      Alert.countDocuments({ timestamp: { $gte: h24 } }),
      Alert.aggregate([{ $match: { timestamp: { $gte: d7 } } }, { $group: { _id: "$severity", count: { $sum: 1 } } }]),
      Alert.aggregate([{ $match: { timestamp: { $gte: d7 } } }, { $group: { _id: "$attackType", count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
      Alert.find().sort({ timestamp: -1 }).limit(10).select("timestamp attackType severity sourceIP confidence destinationIP protocol").lean(),
      Alert.aggregate([
        { $match: { timestamp: { $gte: h24 } } },
        { $group: { _id: { $dateToString: { format: "%H:00", date: "$timestamp" } }, count: { $sum: 1 }, avgConf: { $avg: "$confidence" } } },
        { $sort: { _id: 1 } },
      ]),
      Alert.countDocuments({ acknowledged: false }),
    ]);

    const sevDist = {};
    bySeverity.forEach((i) => (sevDist[i._id] = i.count));
    const atkDist = {};
    byType.forEach((i) => (atkDist[i._id] = i.count));

    res.json({
      overview: {
        totalAlerts, alerts24h, unacknowledged: unack,
        threatLevel: alerts24h > 100 ? "critical" : alerts24h > 50 ? "high" : alerts24h > 10 ? "medium" : "low",
      },
      severityDistribution: sevDist,
      attackDistribution: atkDist,
      recentAlerts: recent,
      hourlyTrend: hourly,
    });
  } catch (err) { next(err); }
});

router.get("/attack-timeline", async (req, res, next) => {
  try {
    const { period = "24h" } = req.query;
    const ms = { "1h": 36e5, "24h": 864e5, "7d": 6048e5, "30d": 2592e6 };
    const fmt = { "1h": "%H:%M", "24h": "%H:00", "7d": "%m-%d", "30d": "%m-%d" };
    const windowMs = ms[period] || 864e5;
    let end = new Date();
    let since = new Date(end.getTime() - windowMs);

    // If there are no recent alerts in the requested window, anchor on latest alert
    // so timeline still visualizes existing data instead of a flat zero chart.
    const hasRecent = await Alert.exists({ timestamp: { $gte: since } });
    if (!hasRecent) {
      const latest = await Alert.findOne().sort({ timestamp: -1 }).select("timestamp").lean();
      if (latest?.timestamp) {
        end = new Date(latest.timestamp);
        since = new Date(end.getTime() - windowMs);
      }
    }

    const data = await Alert.aggregate([
      { $match: { timestamp: { $gte: since, $lte: end } } },
      { $group: { _id: { t: { $dateToString: { format: fmt[period] || "%H:00", date: "$timestamp" } }, type: "$attackType" }, count: { $sum: 1 } } },
      { $sort: { "_id.t": 1 } },
    ]);

    const pad2 = (n) => String(n).padStart(2, "0");
    const toLabel = (d) => {
      if (period === "1h") return `${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
      if (period === "24h") return `${pad2(d.getHours())}:00`;
      return `${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
    };

    const stepMs =
      period === "1h" ? 60e3 :
      period === "24h" ? 36e5 :
      864e5;

    const types = ["dos", "probe", "r2l", "u2r"];
    const map = {};
    for (let t = since.getTime(); t <= end.getTime(); t += stepMs) {
      const label = toLabel(new Date(t));
      if (!map[label]) {
        map[label] = { time: label };
        types.forEach((k) => { map[label][k] = 0; });
      }
    }

    data.forEach(({ _id, count }) => {
      if (!map[_id.t]) {
        map[_id.t] = { time: _id.t };
        types.forEach((k) => { map[_id.t][k] = 0; });
      }
      map[_id.t][_id.type] = count;
    });

    res.json(Object.values(map));
  } catch (err) { next(err); }
});

router.get("/top-sources", async (req, res, next) => {
  try {
    const top = await Alert.aggregate([
      { $group: { _id: "$sourceIP", count: { $sum: 1 }, types: { $addToSet: "$attackType" }, last: { $max: "$timestamp" } } },
      { $sort: { count: -1 } }, { $limit: +(req.query.limit || 10) },
    ]);
    res.json(top);
  } catch (err) { next(err); }
});

router.get("/country-distribution", async (req, res, next) => {
  try {
    const { period = "24h" } = req.query;
    const limit = Math.max(parseInt(req.query.limit || "0", 10), 0);
    const ms = { "1h": 36e5, "24h": 864e5, "7d": 6048e5, "30d": 2592e6 };
    const windowMs = ms[period] || 864e5;
    const since = new Date(Date.now() - windowMs);

    const pipeline = [
      { $match: { timestamp: { $gte: since } } },
      { $group: { _id: "$sourceCountry", count: { $sum: 1 }, types: { $addToSet: "$attackType" } } },
      { $sort: { count: -1 } },
    ];
    if (limit > 0) {
      pipeline.push({ $limit: limit });
    }

    const countryData = await Alert.aggregate(pipeline);

    const distribution = {};
    countryData.forEach((item) => {
      distribution[item._id || "Unknown"] = item.count;
    });

    res.json({
      countries: countryData.map((c) => ({
        country: c._id || "Unknown",
        count: c.count,
        types: c.types,
      })),
      distribution,
      total: countryData.reduce((sum, c) => sum + c.count, 0),
    });
  } catch (err) { next(err); }
});

module.exports = router;
