/**
 * LendTech HTTP Proxy v1.0.0
 *
 * Unified REST proxy for LendTech partner portals.
 * Supports BHB Funding and Funders Group (same software, different URLs).
 *
 * Auth uses axios (matching the proven BHB MCP server pattern).
 * Report downloads stream binary via fetch for zero-corruption.
 */

import express from "express";
import axios from "axios";
import { Readable } from "stream";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.LENDTECH_API_KEY || "";

// ── Portal Configuration ────────────────────────────────────────────────────

const PORTALS = {
  bhb: {
    name: "BHB Funding",
    baseUrl: "https://bhbfunding.lendtech.io/partner",
    username: process.env.BHB_USERNAME || "",
    password: process.env.BHB_PASSWORD || "",
    defaultSyndicatorId: 157, // Beechwood Fund
  },
  fg: {
    name: "Funders Group",
    baseUrl: "https://funderzgroup.lendtech.io/partner",
    username: process.env.FG_USERNAME || "",
    password: process.env.FG_PASSWORD || "",
    defaultSyndicatorId: 109, // Beechwood Fund
  },
};

// ── Session Store ───────────────────────────────────────────────────────────

const sessions = new Map();
let sessionCounter = 0;

// ── Auth Middleware ──────────────────────────────────────────────────────────

function requireApiKey(req, res, next) {
  if (!API_KEY) return next();
  const auth = req.headers.authorization || "";
  if (auth !== `Bearer ${API_KEY}`) {
    return res.status(401).json({ error: "Invalid or missing API key" });
  }
  next();
}

function requireSession(req, res, next) {
  const sid = req.headers["x-session-id"];
  if (!sid || !sessions.has(sid)) {
    return res.status(401).json({ error: "Invalid or missing session. Call /api/auto-login first." });
  }
  req.portalSession = sessions.get(sid);
  req.sessionId = sid;
  next();
}

// ── Cookie Helpers (axios-style, matching BHB MCP client) ───────────────────

function extractCookies(resp) {
  // Try multiple approaches — axios + Node versions handle set-cookie differently
  let setCookies;
  // Method 1: axios typically exposes set-cookie as an array
  setCookies = resp.headers["set-cookie"];
  // Method 2: raw headers via getSetCookie() (Node 20+)
  if ((!setCookies || (Array.isArray(setCookies) && setCookies.length === 0)) && resp.headers?.raw) {
    try { setCookies = resp.headers.raw()["set-cookie"]; } catch {}
  }
  if (!setCookies) return "";
  const arr = Array.isArray(setCookies) ? setCookies : [setCookies];
  const result = arr.map((c) => c.split(";")[0]).join("; ");
  console.error(`extractCookies: found ${arr.length} cookie(s): ${arr.map(c => c.split("=")[0]).join(", ")}`);
  return result;
}

function mergeCookies(existing, newCookies) {
  if (!newCookies) return existing;
  const combined = existing ? `${existing}; ${newCookies}` : newCookies;
  const map = new Map();
  combined.split(";").forEach((pair) => {
    const trimmed = pair.trim();
    const eq = trimmed.indexOf("=");
    if (eq > 0) map.set(trimmed.slice(0, eq).trim(), trimmed);
  });
  return [...map.values()].join("; ");
}

// ── Health ───────────────────────────────────────────────────────────────────

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    version: "1.0.0",
    portals: Object.entries(PORTALS).map(([key, p]) => ({
      key,
      name: p.name,
      baseUrl: p.baseUrl,
      credentialsSet: !!(p.username && p.password),
    })),
    activeSessions: sessions.size,
    apiKeyRequired: !!API_KEY,
  });
});

// ── Auto-Login (axios-based, matching BHB MCP client exactly) ───────────────

app.post("/api/auto-login", requireApiKey, async (req, res) => {
  try {
    const portalKey = (req.body.portal || req.query.portal || "bhb").toLowerCase();
    const portal = PORTALS[portalKey];
    if (!portal) {
      return res.status(400).json({ error: `Unknown portal: ${portalKey}. Use "bhb" or "fg".` });
    }
    if (!portal.username || !portal.password) {
      return res.status(500).json({
        error: `Credentials not configured for ${portal.name}. Set ${portalKey.toUpperCase()}_USERNAME and ${portalKey.toUpperCase()}_PASSWORD env vars.`,
      });
    }

    // Step 1: GET /login — use native fetch, follow redirects manually to capture all cookies
    let cookieJar = "";
    let loginUrl = portal.baseUrl + "/login";
    let html = "";
    for (let i = 0; i < 5; i++) {
      const resp = await fetch(loginUrl, {
        headers: { Accept: "text/html", ...(cookieJar ? { Cookie: cookieJar } : {}) },
        redirect: "manual",
      });
      const respCookies = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
      if (respCookies.length) {
        const nc = respCookies.map(c => c.split(";")[0]).join("; ");
        cookieJar = mergeCookies(cookieJar, nc);
        console.error(`Step 1 redirect ${i}: ${resp.status}, got ${respCookies.length} cookie(s)`);
      }
      if (resp.status >= 300 && resp.status < 400) {
        const loc = resp.headers.get("location") || "";
        loginUrl = loc.startsWith("http") ? loc : portal.baseUrl + loc;
        continue;
      }
      html = await resp.text();
      break;
    }
    console.error("Login page HTML length:", html.length, "title:", (html.match(/<title>([^<]*)<\/title>/) || [])[1] || "none");
    const csrfMatch = html.match(/name="_csrf_token"\s+value="([^"]+)"/);
    if (!csrfMatch) {
      console.error("HTML snippet:", html.substring(0, 500));
      return res.status(500).json({ error: "Could not extract CSRF token from login page", cookieCount: cookieJar.split(";").length });
    }
    const csrfToken = csrfMatch[1];
    console.error("After step 1: CSRF found, cookies:", cookieJar.split(";").length);
    // Also log the login_check redirect to see if it goes to /login (fail) or / (success)


    // Step 2: POST /login_check with base64-encoded password
    // Use native fetch for reliable set-cookie header access
    const encodedPassword = Buffer.from(portal.password).toString("base64");
    const loginBody = `_username=${encodeURIComponent(portal.username)}&_password=${encodeURIComponent(encodedPassword)}&_csrf_token=${encodeURIComponent(csrfToken)}`;
    console.error("login_check body (redacted):", `_username=${portal.username}&_password=[base64]&_csrf_token=[token]`);
    const checkResp = await fetch(portal.baseUrl + "/login_check", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Origin": portal.baseUrl.replace("/partner", ""),
        "Referer": portal.baseUrl + "/login",
        ...(cookieJar ? { Cookie: cookieJar } : {}),
      },
      body: loginBody,
      redirect: "manual",
    });
    // Extract cookies from fetch response using getSetCookie()
    const checkCookies = checkResp.headers.getSetCookie ? checkResp.headers.getSetCookie() : [];
    const checkLocation = checkResp.headers.get("location") || "";
    console.error("login_check: status=", checkResp.status, "location=", checkLocation, "cookies=", checkCookies.length);
    // If login failed (redirect to /login), try to read the error from the redirect page
    if (checkLocation.includes("login")) {
      console.error("LOGIN FAILED — redirected back to login page");
    }
    if (checkCookies.length) {
      const newCookies = checkCookies.map(c => c.split(";")[0]).join("; ");
      cookieJar = mergeCookies(cookieJar, newCookies);
    }
    console.error("After step 2 (POST /login_check):", `${cookieJar.split(";").length} cookies`);

    // Step 3: Follow redirect manually to collect remaining cookies
    if (checkResp.status >= 300 && checkResp.status < 400 && checkLocation) {
      const redirectUrl = checkLocation.startsWith("http") ? checkLocation : portal.baseUrl + checkLocation;
      const redirectResp = await fetch(redirectUrl, {
        headers: { Cookie: cookieJar },
        redirect: "manual",
      });
      const redirCookies = redirectResp.headers.getSetCookie ? redirectResp.headers.getSetCookie() : [];
      if (redirCookies.length) {
        const rc = redirCookies.map(c => c.split(";")[0]).join("; ");
        cookieJar = mergeCookies(cookieJar, rc);
      }
    }
    console.error("After step 3 (redirect):", `${cookieJar.split(";").length} cookies`);

    if (!cookieJar) {
      return res.status(500).json({ error: "No session cookie received after login" });
    }

    // Step 4: Verify session using native fetch (axios drops cookies on Railway)
    console.error("Cookie jar before verify:", cookieJar.substring(0, 200));
    try {
      const verifyResp = await fetch(portal.baseUrl + "/dashboard/partner_syn_stats", {
        headers: { Cookie: cookieJar, Accept: "application/json" },
        redirect: "manual",
      });
      const verifyStatus = verifyResp.status;
      const ct = verifyResp.headers.get("content-type") || "";
      console.error(`Verify: status=${verifyStatus}, ct=${ct}`);
      if (verifyStatus >= 300 && verifyStatus < 400) {
        const loc = verifyResp.headers.get("location") || "";
        console.error("Verify redirect to:", loc);
        if (loc.includes("login")) {
          return res.status(500).json({ error: "Session not authenticated. Login may have failed.", debug: { cookies: cookieJar.split(";").length, redirectTo: loc } });
        }
      }
    } catch (verifyErr) {
      console.error("Verify failed:", verifyErr.message, "- proceeding anyway");
    }

    // Store session
    const sid = `lendtech-${portalKey}-${++sessionCounter}-${Date.now()}`;
    sessions.set(sid, {
      portal: portalKey,
      portalName: portal.name,
      baseUrl: portal.baseUrl,
      defaultSyndicatorId: portal.defaultSyndicatorId,
      cookies: cookieJar,
      createdAt: new Date().toISOString(),
    });

    res.json({
      authenticated: true,
      sessionId: sid,
      portal: portalKey,
      portalName: portal.name,
      defaultSyndicatorId: portal.defaultSyndicatorId,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Portal Fetch (binary-safe streaming via fetch API) ──────────────────────

async function portalFetch(session, path, queryParams = null) {
  let url = session.baseUrl + path;
  if (queryParams && Object.keys(queryParams).length) {
    url += "?" + new URLSearchParams(queryParams).toString();
  }
  const resp = await fetch(url, {
    headers: {
      Cookie: session.cookies,
      Accept: "*/*",
    },
    redirect: "manual",
  });
  const location = resp.headers.get("location") || "";
  if ((resp.status === 302 || resp.status === 301) && location.toLowerCase().includes("login")) {
    session.cookies = null;
    throw new Error("Session expired. Call /api/auto-login again.");
  }
  return resp;
}

// ── Report Downloads (binary-safe streaming) ────────────────────────────────

app.get("/api/reports/closing", requireApiKey, requireSession, async (req, res) => {
  try {
    const syndicatorId = req.query.syndicatorId || req.portalSession.defaultSyndicatorId;
    const startDate = req.query.startDate;
    const endDate = req.query.endDate;
    const includeAll = req.query.includeAll || "false";
    const view = req.query.view || "Main";

    if (!startDate || !endDate) {
      return res.status(400).json({ error: "startDate and endDate required (YYYY-MM-DD)" });
    }

    const portalResp = await portalFetch(req.portalSession, "/reports/closing/report.csv", {
      report_id: syndicatorId,
      allDeals: includeAll,
      viewType: view,
      start: startDate,
      end: endDate,
    });

    const ct = portalResp.headers.get("content-type");
    const cd = portalResp.headers.get("content-disposition");
    if (ct) res.set("content-type", ct);
    if (cd) res.set("content-disposition", cd);
    Readable.fromWeb(portalResp.body).pipe(res);
  } catch (e) {
    res.status(e.message.includes("expired") ? 401 : 500).json({ error: e.message });
  }
});

app.get("/api/reports/wallet", requireApiKey, requireSession, async (req, res) => {
  try {
    const syndicatorId = req.query.syndicatorId || req.portalSession.defaultSyndicatorId;
    const amStatusId = req.query.amStatusId || "";
    const startDate = req.query.startDate || "";
    const endDate = req.query.endDate || "";
    const view = req.query.view || "Syndication";

    // Wallet URL builds query string differently: amStatusId= and syndicatorId= as prefix params
    const params = {};
    if (amStatusId) params.amStatusId = amStatusId;
    params.syndicatorId = syndicatorId;
    params.start = startDate;
    params.end = endDate;
    params.viewType = view;
    const portalResp = await portalFetch(req.portalSession, "/reports/wallet/export.csv", params);

    const ct = portalResp.headers.get("content-type");
    const cd = portalResp.headers.get("content-disposition");
    if (ct) res.set("content-type", ct);
    if (cd) res.set("content-disposition", cd);
    Readable.fromWeb(portalResp.body).pipe(res);
  } catch (e) {
    res.status(e.message.includes("expired") ? 401 : 500).json({ error: e.message });
  }
});

app.get("/api/reports/portfolio", requireApiKey, requireSession, async (req, res) => {
  try {
    const syndicatorId = req.query.syndicatorId || req.portalSession.defaultSyndicatorId;
    const amStatusId = req.query.amStatusId || "0";
    const portalResp = await portalFetch(req.portalSession, `/deals/portfolio/syndicated/csv/${syndicatorId}/${amStatusId}`);
    const ct = portalResp.headers.get("content-type");
    const cd = portalResp.headers.get("content-disposition");
    if (ct) res.set("content-type", ct);
    if (cd) res.set("content-disposition", cd);
    Readable.fromWeb(portalResp.body).pipe(res);
  } catch (e) {
    res.status(e.message.includes("expired") ? 401 : 500).json({ error: e.message });
  }
});

app.get("/api/reports/payouts", requireApiKey, requireSession, async (req, res) => {
  try {
    const partnerId = req.query.partnerId || req.portalSession.defaultSyndicatorId;
    const partnerType = req.query.partnerType || "SYN";
    const startDate = req.query.startDate;
    const endDate = req.query.endDate;
    if (!startDate || !endDate) {
      return res.status(400).json({ error: "startDate and endDate required (YYYY-MM-DD)" });
    }
    const portalResp = await portalFetch(req.portalSession, "/syndication/payout/report.csv", {
      partner_id: partnerId, partner_type: partnerType, start: startDate, end: endDate,
    });
    const ct = portalResp.headers.get("content-type");
    const cd = portalResp.headers.get("content-disposition");
    if (ct) res.set("content-type", ct);
    if (cd) res.set("content-disposition", cd);
    Readable.fromWeb(portalResp.body).pipe(res);
  } catch (e) {
    res.status(e.message.includes("expired") ? 401 : 500).json({ error: e.message });
  }
});

// ── JSON Data Endpoints ─────────────────────────────────────────────────────

app.get("/api/portfolio", requireApiKey, requireSession, async (req, res) => {
  try {
    const syndicatorId = req.query.syndicatorId || req.portalSession.defaultSyndicatorId;
    const amStatusId = req.query.amStatusId || "";
    const portalResp = await portalFetch(req.portalSession, "/deals/portfolio/syndicated", { id: syndicatorId, amStatusId });
    const ct = portalResp.headers.get("content-type") || "application/json";
    res.set("content-type", ct);
    Readable.fromWeb(portalResp.body).pipe(res);
  } catch (e) {
    res.status(e.message.includes("expired") ? 401 : 500).json({ error: e.message });
  }
});

app.get("/api/payouts", requireApiKey, requireSession, async (req, res) => {
  try {
    const partnerId = req.query.partnerId || req.portalSession.defaultSyndicatorId;
    const partnerType = req.query.partnerType || "SYN";
    const startDate = req.query.startDate;
    const endDate = req.query.endDate;
    if (!startDate || !endDate) {
      return res.status(400).json({ error: "startDate and endDate required (YYYY-MM-DD)" });
    }
    const portalResp = await portalFetch(req.portalSession, "/syndication/payout", {
      partner_id: partnerId, partner_type: partnerType, start: startDate, end: endDate, payment_status: req.query.paymentStatus || "", order: "", type: "",
    });
    const ct = portalResp.headers.get("content-type") || "application/json";
    res.set("content-type", ct);
    Readable.fromWeb(portalResp.body).pipe(res);
  } catch (e) {
    res.status(e.message.includes("expired") ? 401 : 500).json({ error: e.message });
  }
});

app.get("/api/stats", requireApiKey, requireSession, async (req, res) => {
  try {
    const portalResp = await portalFetch(req.portalSession, "/dashboard/partner_syn_stats");
    const ct = portalResp.headers.get("content-type") || "application/json";
    res.set("content-type", ct);
    Readable.fromWeb(portalResp.body).pipe(res);
  } catch (e) {
    res.status(e.message.includes("expired") ? 401 : 500).json({ error: e.message });
  }
});

// ── Generic Proxy (binary-safe) ─────────────────────────────────────────────

app.get("/api/proxy", requireApiKey, requireSession, async (req, res) => {
  try {
    const path = req.query.path;
    if (!path) return res.status(400).json({ error: "path query param required" });
    const params = {};
    for (const [k, v] of Object.entries(req.query)) {
      if (k !== "path") params[k] = v;
    }
    const portalResp = await portalFetch(req.portalSession, path, Object.keys(params).length ? params : null);
    const ct = portalResp.headers.get("content-type");
    const cd = portalResp.headers.get("content-disposition");
    if (ct) res.set("content-type", ct);
    if (cd) res.set("content-disposition", cd);
    Readable.fromWeb(portalResp.body).pipe(res);
  } catch (e) {
    res.status(e.message.includes("expired") ? 401 : 500).json({ error: e.message });
  }
});

// ── Start ───────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`LendTech HTTP Proxy v1.0.0`);
  console.log(`  Port     : ${PORT}`);
  console.log(`  Portals  : ${Object.entries(PORTALS).map(([k, p]) => `${k} (${p.baseUrl})`).join(", ")}`);
  console.log(`  API Key  : ${API_KEY ? "required" : "NOT SET (open access)"}`);
  console.log(`  Endpoints:`);
  console.log(`    POST /api/auto-login       — Authenticate with a portal`);
  console.log(`    GET  /api/reports/closing   — Closing report (collections CSV)`);
  console.log(`    GET  /api/reports/wallet    — Wallet ledger (cash txns CSV)`);
  console.log(`    GET  /api/reports/portfolio — Portfolio export (deals CSV)`);
  console.log(`    GET  /api/reports/payouts   — Payouts export (payments CSV)`);
  console.log(`    GET  /api/portfolio         — Portfolio deals JSON`);
  console.log(`    GET  /api/payouts           — Payout history JSON`);
  console.log(`    GET  /api/stats             — Syndicator stats JSON`);
  console.log(`    GET  /api/proxy             — Generic binary-safe proxy`);
  console.log(`    GET  /health                — Health check`);
});
