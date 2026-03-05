const router = require("express").Router();
const axios = require("axios");
const dns = require("dns").promises;
const net = require("net");
const UrlScan = require("../models/UrlScan");

const AI_URL = process.env.AI_ENGINE_URL || "http://localhost:5000";
const GEOIPIFY_API_KEY = process.env.GEOIPIFY_API_KEY || "";
const IPGEOLOCATION_API_KEY = process.env.IPGEOLOCATION_API_KEY || "";
const IPINFO_TOKEN = process.env.IPINFO_TOKEN || "";
const parsedAiScanTimeout = parseInt(process.env.AI_SCAN_TIMEOUT_MS || "25000", 10);
const AI_SCAN_TIMEOUT_MS = Number.isFinite(parsedAiScanTimeout)
  ? Math.min(Math.max(parsedAiScanTimeout, 5000), 25000)
  : 25000;
const AI_BATCH_TIMEOUT_MS = Math.max(parseInt(process.env.AI_BATCH_TIMEOUT_MS || "180000", 10), 10000);
const parsedAiQuickRetryTimeout = parseInt(process.env.AI_QUICK_RETRY_TIMEOUT_MS || "10000", 10);
const AI_QUICK_RETRY_TIMEOUT_MS = Number.isFinite(parsedAiQuickRetryTimeout)
  ? Math.min(Math.max(parsedAiQuickRetryTimeout, 3000), 10000)
  : 10000;
const GEO_RESOLVE_TIMEOUT_MS = Math.max(parseInt(process.env.GEO_RESOLVE_TIMEOUT_MS || "1200", 10), 300);
const RISK_RANK = { safe: 0, low: 1, medium: 2, high: 3, critical: 4 };
const LEGACY_RECOMMENDATION_PATTERNS = [
  /leave this website immediately/i,
  /do not interact with any elements/i,
];

function sanitizeRecommendations(recommendations, riskLevel = "unknown") {
  const incoming = Array.isArray(recommendations) ? recommendations : [];
  const filtered = incoming
    .map((r) => (typeof r === "string" ? r.trim() : ""))
    .filter((r) => r && !LEGACY_RECOMMENDATION_PATTERNS.some((p) => p.test(r)));

  if (filtered.length > 0) {
    return [...new Set(filtered)].slice(0, 6);
  }

  if (riskLevel === "critical" || riskLevel === "high") {
    return [
      "Block this domain immediately, avoid any interaction, and investigate endpoint/browser activity before reopening.",
    ];
  }
  if (riskLevel === "medium") {
    return [
      "Open only in an isolated environment and verify redirects/domain ownership before entering any data.",
    ];
  }
  return [
    "No immediate high-risk indicators in this scan; continue standard domain and certificate verification.",
  ];
}

function normalizeHostname(rawUrl) {
  if (!rawUrl || typeof rawUrl !== "string") return null;
  const clean = rawUrl.trim();
  if (!clean) return null;
  try {
    const normalized = /^https?:\/\//i.test(clean) ? clean : `https://${clean}`;
    return new URL(normalized).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

function isGoogleHostname(hostname) {
  if (!hostname) return false;
  return hostname === "google.com" || hostname.endsWith(".google.com");
}

function hasReputationThreat(result) {
  const rep = result?.analysis?.reputation || {};
  const vtMalicious = Number(rep?.virustotal?.malicious || 0);
  const gsb = rep?.google_safe_browsing || {};
  const gsbThreat =
    Boolean(gsb?.matches) ||
    Boolean(gsb?.threat_types?.length) ||
    Boolean(gsb?.threats?.length);
  return vtMalicious > 0 || gsbThreat;
}

function countryCodeToFlagEmoji(code) {
  if (!code || typeof code !== "string" || code.length !== 2) return "GL";
  const upper = code.toUpperCase();
  return String.fromCodePoint(...[...upper].map((c) => 127397 + c.charCodeAt(0)));
}

function countryCodeToName(code) {
  if (!code || typeof code !== "string") return "Unknown";
  const upper = code.toUpperCase();
  try {
    const display = new Intl.DisplayNames(["en"], { type: "region" });
    return display.of(upper) || "Unknown";
  } catch {
    return "Unknown";
  }
}

function isPrivateIpv4(ip) {
  if (net.isIP(ip) !== 4) return false;
  const [a, b] = ip.split(".").map(Number);
  if (a === 10 || a === 127) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  return false;
}

function fallbackCountryFromHostname(hostname) {
  if (!hostname) return null;
  const tld = hostname.split(".").pop();
  if (tld && /^[a-z]{2}$/i.test(tld)) {
    const code = tld.toUpperCase();
    const countryName = countryCodeToName(code);
    if (countryName && countryName !== "Unknown") {
      return {
        countryCode: code,
        countryName,
        countryFlag: countryCodeToFlagEmoji(code),
        geoSource: "tld",
        resolvedIP: null,
      };
    }
  }
  return {
    countryCode: "GL",
    countryName: "Global / Unknown",
    countryFlag: "GL",
    geoSource: "unknown",
    resolvedIP: null,
  };
}

async function resolveCountryFromUrl(rawUrl) {
  const hostname = normalizeHostname(rawUrl);
  if (!hostname) return null;

  let ip = hostname;
  if (!net.isIP(hostname)) {
    try {
      const resolved = await dns.lookup(hostname, { family: 4 });
      ip = resolved.address;
    } catch {
      try {
        const resolvedAny = await dns.lookup(hostname);
        ip = resolvedAny.address;
      } catch {
        return null;
      }
    }
  }

  if (isPrivateIpv4(ip)) {
    return null;
  }

  if (GEOIPIFY_API_KEY) {
    try {
      const { data } = await axios.get("https://geo.ipify.org/api/v2/country", {
        params: { apiKey: GEOIPIFY_API_KEY, ipAddress: ip },
        timeout: 8000,
      });
      const code = data?.location?.country;
      if (code) {
        const upper = String(code).toUpperCase();
        return {
          countryCode: upper,
          countryName: countryCodeToName(upper),
          countryFlag: countryCodeToFlagEmoji(upper),
          resolvedIP: data?.ip || ip,
          geoSource: "geoip",
        };
      }
    } catch {}
  }

  if (IPGEOLOCATION_API_KEY) {
    try {
      const { data } = await axios.get("https://api.ipgeolocation.io/ipgeo", {
        params: { apiKey: IPGEOLOCATION_API_KEY, ip },
        timeout: 8000,
      });
      if (data?.country_code2) {
        const code = String(data.country_code2).toUpperCase();
        return {
          countryCode: code,
          countryName: data.country_name || "Unknown",
          countryFlag: countryCodeToFlagEmoji(code),
          resolvedIP: data.ip || ip,
          geoSource: "geoip",
        };
      }
    } catch {}
  }

  if (IPINFO_TOKEN) {
    try {
      const { data } = await axios.get(`https://ipinfo.io/${encodeURIComponent(ip)}/json`, {
        params: { token: IPINFO_TOKEN },
        timeout: 8000,
      });
      if (data?.country) {
        const code = String(data.country).toUpperCase();
        return {
          countryCode: code,
          countryName: countryCodeToName(code),
          countryFlag: countryCodeToFlagEmoji(code),
          resolvedIP: data.ip || ip,
          geoSource: "geoip",
        };
      }
    } catch {}
  }

  try {
    const { data } = await axios.get(`https://ipwho.is/${encodeURIComponent(ip)}`, { timeout: 8000 });
    if (data && data.success !== false && data.country_code) {
      const code = String(data.country_code).toUpperCase();
      return {
        countryCode: code,
        countryName: countryCodeToName(code),
        countryFlag: countryCodeToFlagEmoji(code),
        resolvedIP: ip,
        geoSource: "geoip",
      };
    }
  } catch {}

  try {
    const { data } = await axios.get(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,query`,
      { timeout: 8000 }
    );
    if (data && data.status === "success" && data.countryCode) {
      const code = String(data.countryCode).toUpperCase();
      return {
        countryCode: code,
        countryName: countryCodeToName(code),
        countryFlag: countryCodeToFlagEmoji(code),
        resolvedIP: data.query || ip,
        geoSource: "geoip",
      };
    }
  } catch {}

  return null;
}

// POST /api/url/scan
router.post("/scan", async (req, res, next) => {
  try {
    const { url, deep_scan: requestedDeepScan } = req.body || {};
    const deep_scan = requestedDeepScan === true;

    if (!url || !url.trim()) {
      return res.status(400).json({ error: "URL is required" });
    }

    const cleanUrl = url.trim();
    const hostname = normalizeHostname(cleanUrl);

    // Cache check (1 hour) - scoped by scan type
    const cached = await UrlScan.findOne({
      url: cleanUrl,
      scanType: deep_scan ? "deep" : "quick",
      createdAt: { $gte: new Date(Date.now() - 3600000) },
    })
      .sort({ createdAt: -1 })
      .lean();

    if (cached) {
      const sanitizedRecommendations = sanitizeRecommendations(
        cached.recommendations,
        cached.riskLevel
      );
      const cachedReplay = await UrlScan.create({
        url: cached.url,
        urlHash: cached.urlHash,
        scanType: cached.scanType,
        safe: cached.safe,
        riskScore: cached.riskScore,
        riskLevel: cached.riskLevel,
        threats: cached.threats || [],
        warnings: cached.warnings || [],
        info: cached.info || [],
        recommendations: sanitizedRecommendations,
        analysis: cached.analysis || {},
        malwareIndicators: cached.malwareIndicators || [],
        phishingIndicators: cached.phishingIndicators || [],
        scanDuration: cached.scanDuration || 0,
        countryCode: cached.countryCode || null,
        countryName: cached.countryName || null,
        countryFlag: cached.countryFlag || null,
        resolvedIP: cached.resolvedIP || null,
        geoSource: cached.geoSource || "unknown",
      });

      return res.json({ ...cachedReplay.toObject(), cached: true });
    }

    const endpoint = "/api/url/scan";
    const quickEndpoint = "/api/url/quick";
    const startTime = Date.now();
    const countryPromise = resolveCountryFromUrl(cleanUrl).catch(() => null);

    let result;
    let effectiveDeepScan = deep_scan;
    try {
      const { data } = await axios.post(
        `${AI_URL}${endpoint}`,
        { url: cleanUrl, deep_scan },
        { timeout: AI_SCAN_TIMEOUT_MS }
      );
      result = data;
    } catch (scanErr) {
      const timedOut =
        scanErr?.code === "ECONNABORTED" || /timeout/i.test(String(scanErr?.message || ""));
      if (timedOut) {
        try {
          const { data } = await axios.post(
            `${AI_URL}${quickEndpoint}`,
            { url: cleanUrl },
            { timeout: AI_QUICK_RETRY_TIMEOUT_MS }
          );
          result = data;
          effectiveDeepScan = false;
        } catch (quickErr) {
          throw quickErr;
        }
      } else {
        throw scanErr;
      }
    }

    if (isGoogleHostname(hostname) && !hasReputationThreat(result)) {
      result.safe = true;
      result.risk_score = Math.min(Number(result.risk_score || 0), 10);
      result.risk_level = "safe";
      result.threats = [];
      result.warnings = [];
      result.malware_indicators = [];
      result.phishing_indicators = [];
      if (!Array.isArray(result.info)) result.info = [];
      result.info.push("Trusted domain override applied for Google domain.");
    }

    const scanDuration = Date.now() - startTime;
    const sanitizedRecommendations = sanitizeRecommendations(
      result.recommendations,
      result.risk_level
    );
    const resolvedCountry =
      (await Promise.race([
        countryPromise,
        new Promise((resolve) => setTimeout(() => resolve(null), GEO_RESOLVE_TIMEOUT_MS)),
      ])) ||
      fallbackCountryFromHostname(hostname);

    const scan = await UrlScan.create({
      url: cleanUrl,
      urlHash: result.url_hash,
      scanType: result.scan_type || (effectiveDeepScan ? "deep" : "quick"),
      safe: result.safe,
      riskScore: result.risk_score,
      riskLevel: result.risk_level,
      threats: result.threats,
      warnings: result.warnings,
      info: result.info,
      recommendations: sanitizedRecommendations,
      analysis: result.analysis,
      malwareIndicators: result.malware_indicators,
      phishingIndicators: result.phishing_indicators,
      scanDuration: result.scan_duration_ms || scanDuration,
      countryCode: resolvedCountry.countryCode,
      countryName: resolvedCountry.countryName,
      countryFlag: resolvedCountry.countryFlag,
      resolvedIP: resolvedCountry.resolvedIP,
      geoSource: resolvedCountry.geoSource,
    });

    res.json({
      _id: scan._id,
      url: scan.url,
      scanType: scan.scanType,
      safe: scan.safe,
      riskScore: scan.riskScore,
      riskLevel: scan.riskLevel,
      threats: scan.threats,
      warnings: scan.warnings,
      info: scan.info,
      recommendations: scan.recommendations,
      analysis: scan.analysis,
      malwareIndicators: scan.malwareIndicators,
      phishingIndicators: scan.phishingIndicators,
      scanDuration: scan.scanDuration,
      countryCode: scan.countryCode,
      countryName: scan.countryName,
      countryFlag: scan.countryFlag,
      geoSource: scan.geoSource,
      timestamp: scan.createdAt,
      fallbackToQuick: deep_scan && !effectiveDeepScan,
      cached: false,
    });
  } catch (err) {
    if (err.code === "ECONNREFUSED") {
      return res.status(503).json({ error: "AI Engine offline. Start ai-engine first." });
    }
    if (err.code === "ECONNABORTED" || /timeout/i.test(String(err.message || ""))) {
      return res.status(504).json({
        error: "Scan timed out. Please try Quick Scan or try again in a few moments.",
      });
    }
    next(err);
  }
});

// POST /api/url/batch — Batch scan
router.post("/batch", async (req, res, next) => {
  try {
    const { urls, deep_scan = false } = req.body;
    if (!urls || !urls.length) {
      return res.status(400).json({ error: "URLs required" });
    }

    const { data } = await axios.post(
      `${AI_URL}/api/url/batch`,
      { urls: urls.slice(0, 20), deep_scan },
      { timeout: AI_BATCH_TIMEOUT_MS }
    );

    await Promise.all(
      data.results.map(async (r) => {
        const hostname = normalizeHostname(r.url);
        const resolvedCountry =
          (await Promise.race([
            resolveCountryFromUrl(r.url),
            new Promise((resolve) => setTimeout(() => resolve(null), GEO_RESOLVE_TIMEOUT_MS)),
          ])) ||
          fallbackCountryFromHostname(hostname);

        await UrlScan.create({
          url: r.url,
          urlHash: r.url_hash,
          scanType: r.scan_type,
          safe: r.safe,
          riskScore: r.risk_score,
          riskLevel: r.risk_level,
          threats: r.threats,
          warnings: r.warnings,
          info: r.info,
          recommendations: r.recommendations,
          analysis: r.analysis,
          malwareIndicators: r.malware_indicators,
          phishingIndicators: r.phishing_indicators,
          scanDuration: r.scan_duration_ms,
          countryCode: resolvedCountry.countryCode,
          countryName: resolvedCountry.countryName,
          countryFlag: resolvedCountry.countryFlag,
          resolvedIP: resolvedCountry.resolvedIP,
          geoSource: resolvedCountry.geoSource,
        });
      })
    );

    res.json(data);
  } catch (err) {
    next(err);
  }
});

// GET /api/url/history
router.get("/history", async (req, res, next) => {
  try {
    const { page = 1, limit = 20, riskLevel, safe, scanType } = req.query;
    const filter = {};
    if (riskLevel) filter.riskLevel = riskLevel;
    if (safe !== undefined) filter.safe = safe === "true";
    if (scanType) filter.scanType = scanType;

    const [scans, total] = await Promise.all([
      UrlScan.find(filter)
        .sort({ createdAt: -1 })
        .skip((+page - 1) * +limit)
        .limit(+limit)
        .select("url safe riskScore riskLevel scanType threats warnings malwareIndicators phishingIndicators scanDuration createdAt")
        .lean(),
      UrlScan.countDocuments(filter),
    ]);

    res.json({
      scans,
      pagination: { page: +page, limit: +limit, total, pages: Math.ceil(total / +limit) },
    });
  } catch (err) {
    next(err);
  }
});

// GET /api/url/stats
router.get("/stats", async (req, res, next) => {
  try {
    const [total, safe, unsafe, byRisk, byType, recent] = await Promise.all([
      UrlScan.countDocuments(),
      UrlScan.countDocuments({ safe: true }),
      UrlScan.countDocuments({ safe: false }),
      UrlScan.aggregate([{ $group: { _id: "$riskLevel", count: { $sum: 1 } } }]),
      UrlScan.aggregate([{ $group: { _id: "$scanType", count: { $sum: 1 } } }]),
      UrlScan.find().sort({ createdAt: -1 }).limit(5).select("url safe riskScore riskLevel scanType createdAt").lean(),
    ]);

    const riskDist = {};
    byRisk.forEach((r) => (riskDist[r._id] = r.count));
    const typeDist = {};
    byType.forEach((t) => (typeDist[t._id] = t.count));

    res.json({ total, safe, unsafe, riskDistribution: riskDist, scanTypes: typeDist, recentScans: recent });
  } catch (err) {
    next(err);
  }
});

// GET /api/url/analytics
router.get("/analytics", async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit || "1000", 10), 100), 5000);
    const countryLimit = Math.max(parseInt(req.query.countryLimit || "0", 10), 0);

    const scans = await UrlScan.find()
      .sort({ createdAt: -1 })
      .limit(limit)
      .select("url riskLevel createdAt countryCode countryName countryFlag geoSource analysis.content.mentioned_countries")
      .lean();

    const countryCounts = {};
    const marketCountryCounts = {};
    const linkCounts = {};

    scans.forEach((scan) => {
      const hostname = normalizeHostname(scan.url);
      if (!hostname) return;

      const fallback = fallbackCountryFromHostname(hostname);
      const code = (scan.countryCode || fallback.countryCode || "GL").toUpperCase();
      const key = code.toLowerCase();
      const countryName = scan.countryName || fallback.countryName || "Global / Unknown";
      const countryFlag = scan.countryFlag || fallback.countryFlag || "🌐";

      if (!countryCounts[key]) {
        countryCounts[key] = { code, flag: countryFlag, name: countryName, count: 0 };
      }
      countryCounts[key].count += 1;

      if (!linkCounts[hostname]) {
        linkCounts[hostname] = { url: hostname, hits: 0, risk: scan.riskLevel || "safe" };
      }
      linkCounts[hostname].hits += 1;

      const current = RISK_RANK[linkCounts[hostname].risk] || 0;
      const incoming = RISK_RANK[scan.riskLevel] || 0;
      if (incoming > current) linkCounts[hostname].risk = scan.riskLevel;

      const mentioned = scan?.analysis?.content?.mentioned_countries;
      if (Array.isArray(mentioned)) {
        mentioned.forEach((m) => {
          const name = (m?.name || "").trim();
          const count = Math.max(parseInt(m?.count || "0", 10), 0);
          if (!name || !count) return;
          if (!marketCountryCounts[name]) {
            marketCountryCounts[name] = { name, count: 0 };
          }
          marketCountryCounts[name].count += count;
        });
      }
    });

    const total = Object.values(countryCounts).reduce((sum, c) => sum + c.count, 0) || 1;
    const allCountries = Object.values(countryCounts)
      .sort((a, b) => b.count - a.count)
      .map((c) => ({ ...c, percent: Number(((c.count / total) * 100).toFixed(1)) }));
    const countries = countryLimit > 0 ? allCountries.slice(0, countryLimit) : allCountries;

    const totalMarketMentions = Object.values(marketCountryCounts).reduce((sum, c) => sum + c.count, 0) || 1;
    const marketCountries = Object.values(marketCountryCounts)
      .sort((a, b) => b.count - a.count)
      .map((c) => ({ ...c, percent: Number(((c.count / totalMarketMentions) * 100).toFixed(1)) }));

    const topLinks = Object.values(linkCounts).sort((a, b) => b.hits - a.hits).slice(0, 12);

    res.json({
      updatedAt: new Date().toISOString(),
      sampleSize: scans.length,
      totalCountries: allCountries.length,
      countries,
      marketCountries,
      topLinks,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/url/backfill-geo
router.post("/backfill-geo", async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.body?.limit || "200", 10), 1), 1000);

    const scans = await UrlScan.find({
      $or: [
        { countryCode: { $exists: false } },
        { countryCode: null },
        { countryCode: "" },
        { geoSource: { $in: ["unknown", null] } },
      ],
    })
      .sort({ createdAt: -1 })
      .limit(limit)
      .select("_id url countryCode geoSource")
      .lean();

    let updated = 0;
    let skipped = 0;

    for (const scan of scans) {
      const resolved =
        (await resolveCountryFromUrl(scan.url)) ||
        fallbackCountryFromHostname(normalizeHostname(scan.url));

      if (!resolved) {
        skipped += 1;
        continue;
      }

      await UrlScan.updateOne(
        { _id: scan._id },
        { $set: { countryCode: resolved.countryCode, countryName: resolved.countryName, countryFlag: resolved.countryFlag, resolvedIP: resolved.resolvedIP, geoSource: resolved.geoSource } }
      );
      updated += 1;
    }

    res.json({ scanned: scans.length, updated, skipped, message: "Geo backfill completed" });
  } catch (err) {
    next(err);
  }
});

// GET /api/url/:id
router.get("/:id", async (req, res, next) => {
  try {
    const scan = await UrlScan.findById(req.params.id).lean();
    if (!scan) return res.status(404).json({ error: "Not found" });
    res.json(scan);
  } catch (err) {
    next(err);
  }
});

// DELETE /api/url/:id
router.delete("/:id", async (req, res, next) => {
  try {
    await UrlScan.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted" });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
