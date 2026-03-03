require("dotenv").config();
const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const morgan = require("morgan");
const geoip = require("geoip-lite");
const connectDB = require("./config/db");
const errorHandler = require("./middleware/errorHandler");
const socketService = require("./services/socketService");
const { genTraffic, randIP, randPort } = require("./utils/helpers");
const bridge = require("./services/pythonBridge");
const Alert = require("./models/Alert");
const { getRecommendations } = require("./services/recommendation");
const chatProvider = require("./services/chatProvider");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: process.env.FRONTEND_URL || "http://localhost:3000", methods: ["GET", "POST"] },
});
socketService.init(io);

const parseCountryWeights = () => {
  const raw = String(process.env.SIM_COUNTRY_WEIGHTS || "").trim();
  if (!raw) return [];

  if (raw.startsWith("[")) {
    try {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        return parsed
          .map((item) => ({
            code: String(item?.code || "").toUpperCase(),
            weight: Number(item?.weight || 0),
          }))
          .filter((item) => /^[A-Z]{2}$/.test(item.code) && item.weight > 0);
      }
    } catch {
      return [];
    }
  }

  return raw
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const [codeRaw, weightRaw] = entry.split(":");
      return {
        code: String(codeRaw || "").toUpperCase(),
        weight: Number(weightRaw || 0),
      };
    })
    .filter((item) => /^[A-Z]{2}$/.test(item.code) && item.weight > 0);
};

const COUNTRIES = parseCountryWeights();
const COUNTRY_WEIGHTS = COUNTRIES.reduce((acc, c) => acc + c.weight, 0);
const SIM_DEFAULT_COUNTRY = String(process.env.SIM_DEFAULT_COUNTRY || "ZZ").toUpperCase();
const SIM_MIN_MALICIOUS_RATE = Math.min(
  1,
  Math.max(0, Number(process.env.SIM_MIN_MALICIOUS_RATE || 0.18))
);

const getCountryFromIP = (ip) => {
  try {
    // Check if it's a private IP
    const parts = ip.split(".").map(Number);
    if (parts[0] === 10 || parts[0] === 127) return null;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return null;
    if (parts[0] === 192 && parts[1] === 168) return null;
    
    const geo = geoip.lookup(ip);
    if (geo && geo.country) {
      return geo.country;
    }
  } catch (e) {
    // Ignore errors
  }
  return null;
};

const getRandomCountry = () => {
  if (!COUNTRIES.length || COUNTRY_WEIGHTS <= 0) {
    return SIM_DEFAULT_COUNTRY;
  }
  // Use weighted random selection
  let r = Math.random() * COUNTRY_WEIGHTS;
  for (const c of COUNTRIES) {
    r -= c.weight;
    if (r <= 0) return c.code;
  }
  return SIM_DEFAULT_COUNTRY;
};

const toSqlType = (name) => {
  const n = String(name || "").toLowerCase();
  if (n.includes("id")) return "INT";
  if (n.includes("email")) return "VARCHAR(255)";
  if (n.includes("date") || n.includes("time")) return "TIMESTAMP";
  if (n.includes("count") || n.includes("qty") || n.includes("age")) return "INT";
  if (n.includes("price") || n.includes("amount") || n.includes("total")) return "DECIMAL(10,2)";
  return "VARCHAR(255)";
};

const buildSqlCreateTableReply = (text) => {
  const input = String(text || "");
  const lower = input.toLowerCase();
  const tableMatch = lower.match(/(?:create\s+table|table)\s+([a-z_][a-z0-9_]*)/i);
  const tableName = tableMatch?.[1] || "my_table";

  let cols = [];
  const withMatch = input.match(/\bwith\s+(.+)$/i);
  if (withMatch?.[1]) {
    cols = withMatch[1]
      .split(/,| and /i)
      .map((s) => s.trim().toLowerCase().replace(/[^a-z0-9_ ]/g, "").replace(/\s+/g, "_"))
      .filter(Boolean);
  }
  if (!cols.length) cols = ["name", "email"];

  const seen = new Set(["id"]);
  const fields = cols
    .filter((c) => {
      if (!c || seen.has(c)) return false;
      seen.add(c);
      return true;
    })
    .map((c) => `  ${c} ${toSqlType(c)}${c === "email" ? " NOT NULL UNIQUE" : ""},`);

  return [
    "Use this SQL command:",
    `CREATE TABLE ${tableName} (`,
    "  id INT PRIMARY KEY AUTO_INCREMENT,",
    ...fields,
    "  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
    ");",
  ].join("\n");
};

const extractTopicFromPrompt = (input) => {
  const text = String(input || "").trim();
  const patterns = [
    /(?:what is|what's)\s+(.+)\??$/i,
    /(?:explain|about|define)\s+(.+)$/i,
    /(?:topic|subject)\s*:\s*(.+)$/i,
  ];
  for (const rx of patterns) {
    const m = text.match(rx);
    if (m?.[1]) return m[1].trim().replace(/[?.!]+$/, "");
  }
  if (text.split(/\s+/).length <= 6) return text.replace(/[?.!]+$/, "");
  return "";
};

const buildTopicExplanation = (topic) => {
  const t = String(topic || "").trim();
  if (!t) return "";
  return [
    `${t} is a concept/topic that refers to its core idea and practical use in real-world systems.`,
    `In simple terms: ${t} helps solve a specific problem by giving a clear method or approach.`,
    "Why it matters:",
    "1. It improves understanding and decision-making.",
    "2. It is commonly used in implementation and troubleshooting.",
    "3. Learning it helps you build and debug faster.",
    "",
    `If you want, I can explain "${t}" with a beginner example or advanced version.`
  ].join("\n");
};

app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(morgan("dev"));

app.use("/api/url", require("./routes/urlscan"));
app.use("/api/predict", require("./routes/predict"));
app.use("/api/alerts", require("./routes/alerts"));
app.use("/api/analytics", require("./routes/analytics"));

app.get("/api/health", async (req, res) => {
  const ai = await bridge.healthCheck();
  res.json({ status: "healthy", ai_engine: ai, uptime: process.uptime() });
});

const buildContextAwareReply = (message, history = []) => {
  const text = String(message || "").trim();
  const lower = text.toLowerCase();
  const recentUserTurns = (Array.isArray(history) ? history : [])
    .filter((m) => m && (m.role === "user" || m.sender === "user"))
    .map((m) => String(m.content || m.text || "").trim())
    .filter(Boolean)
    .slice(-4);

  const hasCode = /```|const |let |function |class |import |return |=>/.test(text);
  const asksDebug = /bug|error|fix|issue|not working|fails|crash|exception|trace/.test(lower);
  const asksExplain = /what is|explain|difference|compare|why/.test(lower);
  const asksSecurity = /phish|malware|ransomware|mfa|2fa|password|vpn|security|cyber|owasp/.test(lower);
  const asksReact = /react|jsx|vite|useeffect|state|props|hook/.test(lower);
  const asksGeneralCode = /code|coding|api|function|class|python|javascript|node|sql|java|c\+\+/.test(lower);
  const asksCreateTable = /(create\s+table|sql\s+table|table\s+schema)/.test(lower);

  if (/^(hi|hello|hey)\b/.test(lower)) {
    return "Hi. Ask me coding, security, or general questions. Include your exact error or goal for a better answer.";
  }

  if (asksExplain && extractedTopic) {
    return buildTopicExplanation(extractedTopic);
  }

  if (asksReact) {
    return [
      "React quick fix checklist:",
      "1. Verify `useEffect` dependencies are complete and stable.",
      "2. Ensure async state updates are guarded on unmount.",
      "3. Check stale closure issues in callbacks/timers.",
      "4. Confirm conditional rendering does not unmount your chat unexpectedly.",
      "5. Inspect console for key warnings and runtime errors.",
      "",
      "If you share the component code and error, I can give an exact patch."
    ].join("\n");
  }

  if (asksSecurity) {
    return [
      "Security quick guidance:",
      "1. Verify URL/domain before login.",
      "2. Use MFA and unique passwords.",
      "3. Keep OS/packages updated.",
      "4. Avoid unknown links/attachments.",
      "5. Back up critical data regularly."
    ].join("\n");
  }

  if (asksCreateTable) {
    return buildSqlCreateTableReply(text);
  }

  if (hasCode || asksDebug || asksGeneralCode) {
    const contextLine = recentUserTurns.length
      ? `Recent context: ${recentUserTurns.join(" | ")}`
      : "No previous context provided.";
    return [
      "I can help debug this quickly.",
      "Please share:",
      "1. Language/framework",
      "2. Exact error/output",
      "3. Expected vs actual behavior",
      "4. Minimal reproducible code snippet",
      "",
      contextLine
    ].join("\n");
  }

  if (asksExplain) {
    return "I can explain it clearly. Tell me the exact topic and your level (beginner/intermediate/advanced), and I will tailor the explanation.";
  }

  return "I can help with coding, cybersecurity, and general questions. For better output, include your exact task and any error details.";
};

const splitTextForStream = (text, targetChunkSize = 48) => {
  const normalized = String(text || "").replace(/\s+/g, " ").trim();
  if (!normalized) return [];
  const words = normalized.split(" ");
  const chunks = [];
  let current = [];
  let len = 0;
  for (const w of words) {
    const nextLen = len + (current.length ? 1 : 0) + w.length;
    if (current.length && nextLen > targetChunkSize) {
      chunks.push(current.join(" "));
      current = [w];
      len = w.length;
    } else {
      current.push(w);
      len = nextLen;
    }
  }
  if (current.length) {
    chunks.push(current.join(" "));
  }
  return chunks;
};

// Fast AI chat endpoint - real LLM only, no local fallback
app.post("/api/ai/chat", async (req, res) => {
  try {
    const message = String(req.body?.message || "").trim();
    const history = req.body?.history;
    if (!message) {
      return res.status(400).json({ error: "message is required" });
    }
    if (!chatProvider.hasProviderConfig()) {
      return res.status(503).json({ 
        error: "provider_not_configured", 
        message: "AI provider not configured. Please set OPENAI_API_KEY in the backend .env file." 
      });
    }
    try {
      const reply = await chatProvider.getReply(message, history);
      if (reply) {
        return res.json({ reply, source: "provider", latency_ms: 0 });
      }
      return res.status(500).json({ 
        error: "empty_response", 
        message: "AI provider returned an empty response. Please try again." 
      });
    } catch (providerErr) {
      console.error("AI provider chat failed:", providerErr?.message || providerErr);
      const errMsg = String(providerErr?.message || providerErr || "");
      return res.status(502).json({ 
        error: "provider_request_failed", 
        message: `AI provider error: ${errMsg}` 
      });
    }
  } catch (e) {
    console.error("Chat endpoint error:", e);
    return res.status(500).json({ error: "chat_failed", message: e?.message || "Unknown error" });
  }
});

app.post("/api/ai/chat/stream", async (req, res) => {
  try {
    const message = String(req.body?.message || "").trim();
    const history = req.body?.history;
    if (!message) {
      return res.status(400).json({ error: "message is required" });
    }

    if (!chatProvider.hasProviderConfig()) {
      return res.status(503).json({ 
        error: "provider_not_configured", 
        message: "AI provider not configured. Please set OPENAI_API_KEY in the backend .env file." 
      });
    }

    res.setHeader("Content-Type", "text/event-stream; charset=utf-8");
    res.setHeader("Cache-Control", "no-cache, no-transform");
    res.setHeader("Connection", "keep-alive");
    if (typeof res.flushHeaders === "function") {
      res.flushHeaders();
    }

    try {
      await chatProvider.streamReply(
        message,
        history,
        (delta) => {
          try {
            res.write(`data: ${JSON.stringify({ type: "chunk", delta })}\n\n`);
          } catch (writeErr) {
            // Client disconnected, ignore write errors
          }
        },
        null
      );
      try {
        res.write(`data: ${JSON.stringify({ type: "done", source: "provider" })}\n\n`);
      } catch {}
      return res.end();
    } catch (providerErr) {
      console.error("AI provider stream failed:", providerErr?.message || providerErr);
      const errMsg = String(providerErr?.message || providerErr || "");
      // Send error as SSE event
      res.write(`data: ${JSON.stringify({ type: "error", error: "provider_stream_failed", message: `AI provider error: ${errMsg}` })}\n\n`);
      return res.end();
    }
  } catch (e) {
    console.error("Chat stream endpoint error:", e);
    if (!res.headersSent) {
      return res.status(500).json({ error: "chat_stream_failed", message: e?.message || "Unknown error" });
    }
    return res.end();
  }
});

// Simulation
let simTimer = null;
const startSim = () => {
  if (simTimer) return;
  simTimer = setInterval(async () => {
    try {
      const feat = genTraffic();
      feat.source_ip = randIP(); 
      feat.dest_ip = randIP();
      feat.source_port = randPort(); 
      feat.dest_port = randPort();
      
      // Try geoip lookup first, fallback to random country
      let sourceCountry = getCountryFromIP(feat.source_ip);
      let destCountry = getCountryFromIP(feat.dest_ip);
      
      // Fallback to weighted random country if lookup failed
      if (!sourceCountry) sourceCountry = getRandomCountry();
      if (!destCountry) destCountry = getRandomCountry();
      
      feat.source_country = sourceCountry;
      feat.dest_country = destCountry;
      
      let pred;
      try { pred = await bridge.predict(feat); } catch {
        const types = ["normal", "dos", "probe", "r2l", "u2r"];
        const w = [0.6, 0.18, 0.12, 0.06, 0.04];
        let r = Math.random(), c = 0, s = "normal";
        for (let i = 0; i < types.length; i++) { c += w[i]; if (r <= c) { s = types[i]; break; } }
        const sev = { normal: "none", dos: "high", probe: "medium", r2l: "high", u2r: "critical" };
        pred = { prediction: s, confidence: 0.7 + Math.random() * 0.29, severity: sev[s], is_malicious: s !== "normal", probabilities: {} };
      }

      // Keep dashboard populated in demo mode even if model predicts mostly normal traffic.
      if (!pred.is_malicious && Math.random() < SIM_MIN_MALICIOUS_RATE) {
        const forced = ["dos", "probe", "r2l", "u2r"][Math.floor(Math.random() * 4)];
        const sev = { dos: "high", probe: "medium", r2l: "high", u2r: "critical" };
        pred = {
          ...pred,
          prediction: forced,
          confidence: Math.max(Number(pred.confidence || 0), 0.62),
          severity: sev[forced],
          is_malicious: true,
        };
      }
      socketService.emitTraffic({
        timestamp: new Date().toISOString(), 
        sourceIP: feat.source_ip, 
        destinationIP: feat.dest_ip,
        sourcePort: feat.source_port, 
        destinationPort: feat.dest_port,
        sourceCountry: feat.source_country, 
        destinationCountry: feat.dest_country,
        protocol: feat.protocol_type, 
        prediction: pred.prediction,
        confidence: pred.confidence, 
        is_malicious: pred.is_malicious, 
        severity: pred.severity,
      });
      if (pred.is_malicious) {
        const alert = await Alert.create({
          sourceIP: feat.source_ip, 
          destinationIP: feat.dest_ip,
          sourceCountry: feat.source_country, 
          destinationCountry: feat.dest_country,
          sourcePort: feat.source_port, 
          destinationPort: feat.dest_port,
          protocol: feat.protocol_type, 
          attackType: pred.prediction,
          severity: pred.severity, 
          confidence: pred.confidence,
          probabilities: pred.probabilities, 
          rawFeatures: feat,
          recommendations: getRecommendations(pred.prediction),
        });
        socketService.emitAlert({
          _id: alert._id, 
          timestamp: alert.timestamp, 
          sourceIP: alert.sourceIP,
          destinationIP: alert.destinationIP, 
          sourceCountry: alert.sourceCountry,
          destinationCountry: alert.destinationCountry, 
          sourcePort: alert.sourcePort,
          destinationPort: alert.destinationPort, 
          attackType: alert.attackType,
          severity: alert.severity, 
          confidence: alert.confidence,
        });
        // Emit country stats for real-time updates
        socketService.emitCountryStats({
          sourceCountry: alert.sourceCountry,
          count: 1,
        });
      }
    } catch {}
  }, 1500);
};

app.post("/api/simulation/start", (_, res) => { startSim(); res.json({ status: "started" }); });
app.post("/api/simulation/stop", (_, res) => { clearInterval(simTimer); simTimer = null; res.json({ status: "stopped" }); });
app.get("/api/simulation/status", (_, res) => res.json({ running: !!simTimer }));
app.use(errorHandler);

const PORT = process.env.PORT || 4000;
(async () => {
  await connectDB();
  server.listen(PORT, () => {
    console.log(`\n  🛡️  AI-NIDS Backend on port ${PORT}\n`);
    startSim();
  });
})();
