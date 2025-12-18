require("dotenv").config();
const express = require("express");
const axios = require("axios");
const path = require("path");

const app = express();

/* ================= CONFIG ================= */
const PORT = process.env.PORT || 3000;
const OPENSEARCH_URL = process.env.OPENSEARCH_URL;
const OPENSEARCH_USER = process.env.OPENSEARCH_USER;
const OPENSEARCH_PASS = process.env.OPENSEARCH_PASS;

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; // self-signed cert

const os = axios.create({
  baseURL: OPENSEARCH_URL,
  auth: {
    username: OPENSEARCH_USER,
    password: OPENSEARCH_PASS,
  },
  headers: { "Content-Type": "application/json" },
});

/* ================= STATIC FRONTEND ================= */
app.use(express.static(path.join(__dirname, "public")));

/* ================= HELPERS ================= */
const index = "wazuh-alerts-*";

/* ================= API ================= */

// Health check
app.get("/api/health", (_, res) => res.json({ status: "ok" }));

// Total alerts (all time & last 24h)
app.get("/api/alerts", async (_, res) => {
  try {
    const [last24h, allTime] = await Promise.all([
      os.post(`/${index}/_count`, {
        query: { range: { "@timestamp": { gte: "now-24h", lte: "now" } } },
      }),
      os.post(`/${index}/_count`),
    ]);
    res.json({
      last24h: last24h.data.count,
      allTime: allTime.data.count,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Alerts by severity
app.get("/api/alerts/severity", async (_, res) => {
  try {
    const r = await os.post(`/${index}/_search`, {
      size: 0,
      aggs: {
        severity: {
          terms: { field: "rule.level", order: { _key: "desc" } },
        },
      },
    });
    res.json(r.data.aggregations.severity.buckets);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Critical alerts (>=12)
app.get("/api/alerts/critical", async (_, res) => {
  try {
    const r = await os.post(`/${index}/_count`, {
      query: { range: { "rule.level": { gte: 12 } } },
    });
    res.json({ critical: r.data.count });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Timeline last 24h
app.get("/api/alerts/timeline", async (_, res) => {
  try {
    const r = await os.post(`/${index}/_search`, {
      size: 0,
      query: { range: { "@timestamp": { gte: "now-24h", lte: "now" } } },
      aggs: {
        timeline: { date_histogram: { field: "@timestamp", fixed_interval: "1h" } },
      },
    });
    res.json(r.data.aggregations.timeline.buckets);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Top attacker IP
app.get("/api/threats/top-attackers", async (_, res) => {
  try {
    const r = await os.post(`/${index}/_search`, {
      size: 0,
      aggs: { attackers: { terms: { field: "data.srcip", size: 10 } } },
    });
    res.json(r.data.aggregations.attackers.buckets);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// MITRE ATT&CK
app.get("/api/threats/mitre", async (_, res) => {
  try {
    const r = await os.post(`/${index}/_search`, {
      size: 0,
      aggs: { mitre: { terms: { field: "rule.mitre.id", size: 10 } } },
    });
    res.json(r.data.aggregations.mitre.buckets);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Top hosts
app.get("/api/assets/top-hosts", async (_, res) => {
  try {
    const r = await os.post(`/${index}/_search`, {
      size: 0,
      aggs: { hosts: { terms: { field: "agent.name.keyword", size: 10 } } },
    });
    res.json(r.data.aggregations.hosts.buckets);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Failed logins / brute force
app.get("/api/auth/failed-logins", async (_, res) => {
  try {
    const r = await os.post(`/${index}/_search`, {
      size: 0,
      query: { match: { "rule.groups": "authentication_failed" } },
      aggs: { sources: { terms: { field: "data.srcip", size: 10 } } },
    });
    res.json(r.data.aggregations.sources.buckets);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ================= START SERVER ================= */
app.listen(PORT, () =>
  console.log(`🚀 SOC Dashboard API running on http://localhost:${PORT}`)
);
