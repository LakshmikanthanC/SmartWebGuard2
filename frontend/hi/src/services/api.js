import axios from "axios";

// Use relative path to go through Vite proxy
const API = import.meta.env.VITE_API_URL || "/api";
const API_TIMEOUT_MS = Number(import.meta.env.VITE_API_TIMEOUT_MS || 120000);
const URL_SCAN_TIMEOUT_MS = Number(import.meta.env.VITE_URL_SCAN_TIMEOUT_MS || 90000);
const URL_QUICK_SCAN_TIMEOUT_MS = Number(
  import.meta.env.VITE_URL_QUICK_SCAN_TIMEOUT_MS || 30000
);
const CHAT_TIMEOUT_MS = Number(import.meta.env.VITE_CHAT_TIMEOUT_MS || 60000);
const CHAT_STREAM_TIMEOUT_MS = Number(
  import.meta.env.VITE_CHAT_STREAM_TIMEOUT_MS || 120000
);
const api = axios.create({ baseURL: API, timeout: API_TIMEOUT_MS });

export const getDashboard = () => api.get("/analytics/dashboard");
export const getAlerts = (p) => api.get("/alerts", { params: p });
export const getRecentAlerts = (n = 20) => api.get(`/alerts/recent?limit=${n}`);
export const ackAlert = (id, notes) => api.patch(`/alerts/${id}/acknowledge`, { notes });
export const deleteAlert = (id) => api.delete(`/alerts/${id}`);
export const getTimeline = (p = "24h") => api.get(`/analytics/attack-timeline?period=${p}`);
export const getTopSources = (n = 10) => api.get(`/analytics/top-sources?limit=${n}`);
export const getCountryDistribution = (period = "24h", limit = 0) =>
  api.get(`/analytics/country-distribution?period=${period}&limit=${limit}`);
export const postPredict = (f) => api.post("/predict", f);
export const getModelInfo = () => api.get("/predict/model-info");
export const getAIHealth = () => api.get("/predict/health");
export const getHealth = () => api.get("/health");
export const startSim = () => api.post("/simulation/start");
export const stopSim = () => api.post("/simulation/stop");
export const getSimStatus = () => api.get("/simulation/status");

// URL Scanner - Deep & Quick
export const scanUrl = (url, deep = true) =>
  api.post("/url/scan", { url, deep_scan: deep }, { timeout: URL_SCAN_TIMEOUT_MS });
export const quickScanUrl = (url) =>
  api.post("/url/scan", { url, deep_scan: false }, { timeout: URL_QUICK_SCAN_TIMEOUT_MS });
export const batchScanUrls = (urls, deep = false) =>
  api.post("/url/batch", { urls, deep_scan: deep });
export const getUrlHistory = (params) =>
  api.get("/url/history", { params });
export const getUrlStats = () => api.get("/url/stats");
export const getUrlAnalytics = (params) =>
  api.get("/url/analytics", { params });
export const getUrlScan = (id) => api.get(`/url/${id}`);
export const deleteUrlScan = (id) => api.delete(`/url/${id}`);

// AI Assistant (optional backend endpoint)
export const askAssistant = (message, history = []) =>
  api.post("/ai/chat", { message, history }, { timeout: CHAT_TIMEOUT_MS });

export const askAssistantStream = async (
  message,
  history = [],
  { onChunk, signal, timeoutMs = CHAT_STREAM_TIMEOUT_MS } = {}
) => {
  console.log("[API] askAssistantStream called, message:", message);
  const base = (API || "").replace(/\/$/, "");
  const url = `${base}/ai/chat/stream`;
  console.log("[API] Fetching URL:", url);
  const timeoutController = new AbortController();
  const timer = setTimeout(
    () => timeoutController.abort(new Error("chat_stream_timeout")),
    Math.max(1000, timeoutMs)
  );
  const linkedSignal = signal
    ? AbortSignal.any([signal, timeoutController.signal])
    : timeoutController.signal;
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message, history }),
    signal: linkedSignal,
  }).finally(() => clearTimeout(timer));

  console.log("[API] Response status:", response.status, response.ok);

  if (!response.ok) {
    throw new Error(`chat_stream_failed_${response.status}`);
  }
  if (!response.body) {
    throw new Error("chat_stream_unavailable");
  }

  console.log("[API] Starting to read stream...");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let fullText = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });

    const events = buffer.split("\n\n");
    buffer = events.pop() || "";

    for (const evt of events) {
      const line = evt
        .split("\n")
        .find((l) => l.startsWith("data:"));
      if (!line) continue;
      const raw = line.slice(5).trim();
      if (!raw) continue;
      let payload;
      try {
        payload = JSON.parse(raw);
      } catch {
        continue;
      }
      if (payload.type === "chunk" && payload.delta) {
        fullText += payload.delta;
        if (onChunk) onChunk(payload.delta, fullText);
      }
      if (payload.type === "error") {
        throw new Error(payload.message || payload.error || "AI stream error");
      }
      if (payload.type === "done") {
        return fullText.trim();
      }
    }
  }

  return fullText.trim();
};

export default api;
