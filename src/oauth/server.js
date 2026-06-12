import express from "express";
import cookieParser from "cookie-parser";
import { nanoid } from "nanoid";
import {
  createOAuthSession,
  destroyOAuthSession,
  getOAuthSession,
  getUserById,
  verifyUserCredentials,
  storeAuthCode,
  consumeAuthCode,
  listMembershipsByUser,
  getTenantById,
} from "../shared/datastore.js";
import { signAuthToken } from "../shared/jwt.js";

const OAUTH_COOKIE_NAME = "oauth_session";
const DEFAULT_PORT = 4000;
const CLIENT_ID = process.env.CLIENT_ID || "task-app";
const CLIENT_NAME = process.env.CLIENT_NAME || "Task Manager";
const DEFAULT_APP_BASE_URL = "http://localhost:3000";

function escapeRegex(value) {
  return value.replace(/\\/g, "\\\\").replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function sanitizeAndDecodeUrl(url) {
  try {
    // First sanitize by creating a URL object (this validates the URL)
    const urlObj = new URL(url);
    // Return the sanitized URL
    return urlObj.toString();
  } catch (error) {
    // If URL parsing fails, try to decode and parse again
    try {
      const decodedUrl = decodeURIComponent(url);
      const urlObj = new URL(decodedUrl);
      return urlObj.toString();
    } catch (decodeError) {
      throw new Error("Invalid URL format");
    }
  }
}

// VULNERABLE: This function validates the URL but doesn't decode it
// This allows URL-encoded characters to pass validation but get decoded later
function validateRedirectUri(url) {
  try {
    // First try to validate the URL as-is (with encoded characters)
    const urlObj = new URL(url);
    return urlObj.toString();
  } catch (error) {
    // If URL parsing fails, try to decode and parse again
    try {
      const decodedUrl = decodeURIComponent(url);
      const urlObj = new URL(decodedUrl);
      return urlObj.toString();
    } catch (decodeError) {
      throw new Error("Invalid URL format");
    }
  }
}

function buildRedirectPatternFromBase(baseUrl) {
  const input = (baseUrl || "").toString().trim();
  const raw = input || DEFAULT_APP_BASE_URL;
  const sanitized = raw.replace(/\/+$/, "");

  let domain;
  try {
    const url = new URL(sanitized);
    domain = url.hostname;
  } catch (error) {
    console.warn("Failed to parse base URL for redirect pattern:", baseUrl, error);
    domain = "localhost";
  }

  const patternSource = `^https?://((.*\\.)?${escapeRegex(
    domain
  )}(:[0-9]+)?|${escapeRegex(domain)}(:[0-9]+)?)/oauth/.*$`;
  try {
    return new RegExp(patternSource);
  } catch (error) {
    console.warn("Failed to build redirect pattern, falling back to localhost.", error);
    return new RegExp(
      `^https?://((.*\\.)?${escapeRegex("localhost")}(:[0-9]+)?|${escapeRegex(
        "localhost"
      )}(:[0-9]+)?)/oauth/.*$`
    );
  }
}

function isValidBase64String(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!trimmed) return false;
  // Normalize base64url to base64
  let b64 = trimmed.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding as needed
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  else if (pad !== 0) return false;
  try {
    const buf = Buffer.from(b64, "base64");
    // Re-encode and compare normalized (ignore padding differences)
    const re = buf.toString("base64").replace(/=+$/, "");
    const norm = b64.replace(/=+$/, "");
    return re === norm;
  } catch (_e) {
    return false;
  }
}

// In-memory OAuth Dashboard storage (intentionally simple and insecure for demo)
const DASHBOARD_USERS = [];
const DASHBOARD_SESSIONS = new Map(); // sessionId -> userId

// Simple helper to create a dashboard session
function createDashboardSession(userId) {
  const id = nanoid(24);
  DASHBOARD_SESSIONS.set(id, userId);
  return id;
}

function getDashboardSession(id) {
  const userId = DASHBOARD_SESSIONS.get(id);
  if (!userId) return null;
  const user = DASHBOARD_USERS.find((u) => u.id === userId) || null;
  if (!user) return null;
  return { id, user };
}

function destroyDashboardSession(id) {
  DASHBOARD_SESSIONS.delete(id);
}

// Clients registered via dashboard live alongside the built-in demo client
const CLIENTS = [
  {
    id: CLIENT_ID,
    name: CLIENT_NAME,
    client_secret: process.env.CLIENT_SECRET || "task-secret",
    // Built-in demo client keeps legacy env-based redirect pattern
    baseUrl: process.env.APP_BASE_URL || DEFAULT_APP_BASE_URL,
    redirectUriPattern: buildRedirectPatternFromBase(process.env.APP_BASE_URL || DEFAULT_APP_BASE_URL),
    ownerId: null, // built-in
    redirectRules: [], // dashboard-created clients can populate this
    allowedScopes: ["name", "email"],
  },
];

function findClient(clientId) {
  return CLIENTS.find((client) => client.id === clientId) || null;
}

// Check redirect URI against per-client rules (exact or regex),
// falling back to legacy pattern-based validation when no rules are set.
function clientRedirectAllowed(client, encodedRedirectUri) {
  const decoded = (() => {
    try {
      return decodeURIComponent(encodedRedirectUri);
    } catch (_e) {
      return encodedRedirectUri;
    }
  })();

  if (Array.isArray(client.redirectRules) && client.redirectRules.length > 0) {
    for (const rule of client.redirectRules) {
      if (!rule || !rule.type || !rule.value) continue;
      if (rule.type === "exact" && decoded === rule.value) {
        return true;
      }
      if (rule.type === "regex") {
        try {
          const rx = new RegExp(rule.value);
          if (rx.test(decoded)) return true;
        } catch (_e) {
          // invalid regex provided by client; ignore
        }
      }
    }
    return false;
  }

  // For the built-in demo client only, fall back to its legacy pattern
  if (client.ownerId === null && client.redirectUriPattern instanceof RegExp) {
    return client.redirectUriPattern.test(decoded);
  }
  return false;
}

function buildErrorResponse(res, redirectUri, responseMode, error, state) {
  if (!redirectUri) {
    res.status(400).send(`<h1>OAuth Error</h1><p>${error}</p>`);
    return;
  }

  const target = new URL(redirectUri);
  const params = new URLSearchParams();
  params.set("error", error);
  if (state) {
    params.set("state", state);
  }

  if (responseMode === "fragment") {
    target.hash = params.toString();
  } else {
    params.forEach((value, key) => {
      target.searchParams.set(key, value);
    });
  }
  res.redirect(target.toString());
}

function buildSuccessRedirect({
  redirectUri,
  responseMode,
  includeCode,
  includeToken,
  code,
  token,
  state,
}) {
  const target = new URL(redirectUri);

  const payload = {};
  if (includeCode) {
    payload.code = code;
  }
  if (includeToken) {
    payload.token = token;
  }
  if (state) {
    payload.state = state;
  }

  if (responseMode) {
    if (responseMode === "fragment") {
      const fragmentParams = new URLSearchParams(payload);
      target.hash = fragmentParams.toString();
    } else {
      Object.entries(payload).forEach(([key, value]) => {
        target.searchParams.set(key, value);
      });
    }
    return target.toString();
  }

  if (includeCode && includeToken) {
    target.searchParams.set("code", code);
    if (state) {
      target.searchParams.set("state", state);
    }
    const fragmentParams = new URLSearchParams();
    fragmentParams.set("token", token);
    target.hash = fragmentParams.toString();
    return target.toString();
  }

  if (includeCode) {
    target.searchParams.set("code", code);
    if (state) {
      target.searchParams.set("state", state);
    }
    return target.toString();
  }

  const fragmentParams = new URLSearchParams();
  fragmentParams.set("token", token);
  if (state) {
    fragmentParams.set("state", state);
  }
  target.hash = fragmentParams.toString();
  return target.toString();
}

function ensureLoggedIn(req, res, next) {
  const sessionId = req.cookies[OAUTH_COOKIE_NAME];
  if (!sessionId) {
    return next();
  }
  const session = getOAuthSession(sessionId);
  if (!session) {
    return next();
  }
  const user = getUserById(session.userId);
  if (!user) {
    destroyOAuthSession(sessionId);
    return next();
  }
  req.oauthUser = user;
  req.oauthSessionId = sessionId;
  return next();
}

function renderLoginPage({ returnTo, error }) {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>OAuth Login</title>
    <style>
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }
      
      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
      }
      
      .container {
        background: white;
        border-radius: 16px;
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        padding: 40px;
        width: 100%;
        max-width: 400px;
        backdrop-filter: blur(10px);
      }
      
      .logo {
        text-align: center;
        margin-bottom: 32px;
      }
      
      .logo h1 {
        color: #1a202c;
        font-size: 28px;
        font-weight: 700;
        margin-bottom: 8px;
      }
      
      .logo p {
        color: #718096;
        font-size: 16px;
      }
      
      .form-group {
        margin-bottom: 24px;
      }
      
      label {
        display: block;
        color: #2d3748;
        font-weight: 600;
        margin-bottom: 8px;
        font-size: 14px;
      }
      
      input {
        width: 100%;
        padding: 16px;
        border: 2px solid #e2e8f0;
        border-radius: 12px;
        font-size: 16px;
        transition: all 0.2s ease;
        background: #f7fafc;
      }
      
      input:focus {
        outline: none;
        border-color: #667eea;
        background: white;
        box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
      }
      
      .error {
        background: #fed7d7;
        color: #c53030;
        padding: 12px 16px;
        border-radius: 8px;
        margin-bottom: 24px;
        border-left: 4px solid #e53e3e;
        font-size: 14px;
      }
      
      .btn {
        width: 100%;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 16px;
        border-radius: 12px;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s ease;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }
      
      .btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
      }
      
      .btn:active {
        transform: translateY(0);
      }
      
      .footer {
        text-align: center;
        margin-top: 24px;
        color: #718096;
        font-size: 14px;
      }
      
      @media (max-width: 480px) {
        .container {
          padding: 24px;
          margin: 10px;
        }
        
        .logo h1 {
          font-size: 24px;
        }
      }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="logo">
        <h1>Welcome Back</h1>
        <p>Sign in to continue to your account</p>
      </div>
      
      ${error ? `<div class="error">${error}</div>` : ""}
      
      <form method="post" action="/login">
        <input type="hidden" name="returnTo" value="${returnTo ?? ""}" />
        
        <div class="form-group">
          <label for="email">Email Address</label>
          <input type="email" id="email" name="email" required placeholder="Enter your email" />
        </div>
        
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" required placeholder="Enter your password" />
        </div>
        
        <button type="submit" class="btn">Sign In</button>
      </form>
      
      <div class="footer">
        <p>Secure OAuth Authentication</p>
      </div>
    </div>
  </body>
</html>`;
}

function renderConsentPage({ client, params, user }) {
  const hiddenInputs = Object.entries(params)
    .map(
      ([key, value]) => `<input type="hidden" name="${key}" value="${value}" />`
    )
    .join("\n");

  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Authorize ${client.name}</title>
    <style>
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }
      
      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
      }
      
      .container {
        background: white;
        border-radius: 16px;
        box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
        padding: 40px;
        width: 100%;
        max-width: 500px;
        backdrop-filter: blur(10px);
      }
      
      .header {
        text-align: center;
        margin-bottom: 32px;
      }
      
      .header h1 {
        color: #1a202c;
        font-size: 28px;
        font-weight: 700;
        margin-bottom: 8px;
      }
      
      .header p {
        color: #718096;
        font-size: 16px;
      }
      
      .app-info {
        background: #f7fafc;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 32px;
        border-left: 4px solid #667eea;
      }
      
      .app-name {
        font-size: 20px;
        font-weight: 600;
        color: #2d3748;
        margin-bottom: 8px;
      }
      
      .app-description {
        color: #4a5568;
        font-size: 16px;
        line-height: 1.5;
        margin-bottom: 16px;
      }
      
      .user-info {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 16px;
        background: #edf2f7;
        border-radius: 8px;
        margin-bottom: 24px;
      }
      
      .user-avatar {
        width: 40px;
        height: 40px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-weight: 600;
        font-size: 16px;
      }
      
      .user-details {
        flex: 1;
      }
      
      .user-label {
        font-size: 12px;
        color: #718096;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 2px;
      }
      
      .user-email {
        font-weight: 600;
        color: #2d3748;
      }
      
      .permissions {
        background: #f0fff4;
        border: 1px solid #9ae6b4;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 32px;
      }
      
      .permissions h3 {
        color: #22543d;
        font-size: 14px;
        font-weight: 600;
        margin-bottom: 8px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }
      
      .permissions ul {
        list-style: none;
        color: #2f855a;
      }
      
      .permissions li {
        padding: 4px 0;
        font-size: 14px;
      }
      
      .permissions li:before {
        content: "✓";
        color: #38a169;
        font-weight: bold;
        margin-right: 8px;
      }
      
      .actions {
        display: flex;
        gap: 16px;
        margin-top: 24px;
      }
      
      .btn {
        flex: 1;
        padding: 16px;
        border: none;
        border-radius: 12px;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s ease;
        text-transform: uppercase;
        letter-spacing: 0.5px;
      }
      
      .btn-primary {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
      }
      
      .btn-primary:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
      }
      
      .btn-secondary {
        background: #e2e8f0;
        color: #4a5568;
        border: 2px solid #cbd5e0;
      }
      
      .btn-secondary:hover {
        background: #cbd5e0;
        transform: translateY(-1px);
      }
      
      .btn:active {
        transform: translateY(0);
      }
      
      .footer {
        text-align: center;
        margin-top: 24px;
        color: #718096;
        font-size: 12px;
      }
      
      @media (max-width: 480px) {
        .container {
          padding: 24px;
          margin: 10px;
        }
        
        .header h1 {
          font-size: 24px;
        }
        
        .actions {
          flex-direction: column;
        }
        
        .btn {
          width: 100%;
        }
      }
    </style>
  </head>
  <body>
    <div class="container">
      <div class="header">
        <h1>Authorization Request</h1>
        <p>Review and approve the following request</p>
      </div>
      
      <div class="app-info">
        <div class="app-name">${client.name}</div>
        <div class="app-description">
          This application is requesting permission to access your account information.
        </div>
      </div>
      
      <div class="user-info">
        <div class="user-avatar">
          ${user.email.charAt(0).toUpperCase()}
        </div>
        <div class="user-details">
          <div class="user-label">Signed in as</div>
          <div class="user-email">${user.email}</div>
        </div>
      </div>
      
      <div class="permissions">
        <h3>Requested Permissions</h3>
        <ul>
          <li>Access your basic profile information</li>
          <li>Read your account details</li>
          <li>Manage tasks on your behalf</li>
        </ul>
      </div>
      
      <div class="actions">
        <form method="post" action="/authorize" style="flex: 1;">
          ${hiddenInputs}
          <input type="hidden" name="decision" value="approve" />
          <button type="submit" class="btn btn-primary">Authorize</button>
        </form>
        <form method="post" action="/authorize" style="flex: 1;">
          ${hiddenInputs}
          <input type="hidden" name="decision" value="deny" />
          <button type="submit" class="btn btn-secondary">Deny</button>
        </form>
      </div>
      
      <div class="footer">
        <p>You can revoke this access at any time in your account settings</p>
      </div>
    </div>
  </body>
</html>`;
}

function buildTokenPayload(user, requestedScopes = []) {
  const scopes = Array.isArray(requestedScopes) ? requestedScopes : [];
  const memberships = listMembershipsByUser(user.id).map((membership) => ({
    tenantId: membership.tenantId,
    role: membership.role,
    tenantName: getTenantById(membership.tenantId)?.name ?? null,
  }));

  const payload = {
    sub: user.id,
    memberships,
    scope: scopes.join(" "),
  };
  if (scopes.includes("email")) payload.email = user.email;
  if (scopes.includes("name")) payload.name = user.name;
  return payload;
}

export async function startOAuthServer({ port = DEFAULT_PORT } = {}) {
  const app = express();
  app.use((req, res, next) => {
    res.removeHeader("X-Frame-Options");
    res.setHeader("Content-Security-Policy", "frame-ancestors *");
    next();
  });
  app.use(cookieParser());
  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());
  app.use(ensureLoggedIn);

  // ----- OAuth Dashboard (JSON-based, intentionally simple) -----
  const DASH_COOKIE = "oauth_dashboard_session";

  function wantsHtml(req) {
    const ct = (req.headers["content-type"] || "").toLowerCase();
    const accept = (req.headers["accept"] || "").toLowerCase();
    return ct.includes("application/x-www-form-urlencoded") || accept.includes("text/html");
  }

  function ensureDashboardAuth(req, res, next) {
    const sid = req.cookies[DASH_COOKIE];
    if (!sid) return res.status(401).json({ error: "unauthorized" });
    const session = getDashboardSession(sid);
    if (!session) return res.status(401).json({ error: "unauthorized" });
    req.dashboardUser = session.user;
    req.dashboardSessionId = sid;
    next();
  }

  app.post("/dashboard/register", (req, res) => {
    const { email, password, name } = req.body || {};
    if (!email || !password) {
      if (wantsHtml(req)) {
        return res.status(400).send(renderDashboardRegisterPage({ error: "Email and password required" }));
      }
      return res.status(400).json({ error: "email_and_password_required" });
    }
    const exists = DASHBOARD_USERS.find((u) => u.email === email);
    if (exists) {
      if (wantsHtml(req)) {
        return res.status(400).send(renderDashboardRegisterPage({ error: "Email already registered" }));
      }
      return res.status(400).json({ error: "email_taken" });
    }
    const user = { id: nanoid(16), email, password, name: name || null };
    DASHBOARD_USERS.push(user);
    const sid = createDashboardSession(user.id);
    res.cookie(DASH_COOKIE, sid, { httpOnly: true, sameSite: "lax" });
    if (wantsHtml(req)) return res.redirect("/dashboard");
    res.json({ id: user.id, email: user.email });
  });

  app.post("/dashboard/login", (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) {
      if (wantsHtml(req)) {
        return res.status(400).send(renderDashboardLoginPage({ error: "Email and password required" }));
      }
      return res.status(400).json({ error: "email_and_password_required" });
    }
    const user = DASHBOARD_USERS.find(
      (u) => u.email === email && u.password === password
    );
    if (!user) {
      if (wantsHtml(req)) {
        return res.status(401).send(renderDashboardLoginPage({ error: "Invalid credentials" }));
      }
      return res.status(401).json({ error: "invalid_credentials" });
    }
    const sid = createDashboardSession(user.id);
    res.cookie(DASH_COOKIE, sid, { httpOnly: true, sameSite: "lax" });
    if (wantsHtml(req)) return res.redirect("/dashboard");
    res.json({ id: user.id, email: user.email });
  });

  app.post("/dashboard/logout", (req, res) => {
    const sid = req.cookies[DASH_COOKIE];
    if (sid) destroyDashboardSession(sid);
    res.clearCookie(DASH_COOKIE);
    if (wantsHtml(req)) return res.redirect("/dashboard/login");
    res.json({ success: true });
  });

  app.get("/dashboard/logout", (req, res) => {
    const sid = req.cookies[DASH_COOKIE];
    if (sid) destroyDashboardSession(sid);
    res.clearCookie(DASH_COOKIE);
    res.redirect("/dashboard/login");
  });

  function renderPageShell({ title, body }) {
    return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${title}</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; background:#f6f7fb; margin:0; padding:24px; }
      .card { max-width: 800px; margin: 0 auto; background:#fff; border-radius:12px; padding:24px; box-shadow: 0 6px 24px rgba(0,0,0,0.07); }
      h1 { margin:0 0 12px 0; font-size:22px; }
      h2 { margin-top:24px; font-size:18px; }
      label { display:block; font-size:14px; margin:12px 0 6px; color:#333; }
      input[type=text], input[type=password], input[type=email] { width:100%; padding:10px 12px; border:1px solid #ccd3e0; border-radius:8px; }
      .row { display:flex; gap:12px; }
      .row > div { flex:1; }
      .btn { display:inline-block; background:#4f46e5; color:#fff; border:none; padding:10px 14px; border-radius:8px; cursor:pointer; text-decoration:none; }
      .btn.secondary { background:#e5e7eb; color:#111827; }
      .error { background:#fee2e2; color:#991b1b; padding:10px 12px; border-radius:8px; margin:10px 0; }
      .muted { color:#6b7280; font-size:13px; }
      .client { border:1px solid #e5e7eb; border-radius:8px; padding:12px; margin:12px 0; }
      .rules { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size:12px; background:#f9fafb; padding:8px; border-radius:6px; }
      form.inline { display:inline; }
    </style>
  </head>
  <body>
    <div class="card">${body}</div>
  </body>
</html>`;
  }

  function renderDashboardLoginPage({ error } = {}) {
    return renderPageShell({
      title: "OAuth Dashboard – Login",
      body: `
        <h1>Dashboard Login</h1>
        ${error ? `<div class=\"error\">${error}</div>` : ""}
        <form method="post" action="/dashboard/login">
          <label>Email</label>
          <input type="email" name="email" required />
          <label>Password</label>
          <input type="password" name="password" required />
          <div style="margin-top:12px">
            <button class="btn" type="submit">Login</button>
            <a class="btn secondary" href="/dashboard/register" style="margin-left:8px">Register</a>
          </div>
        </form>
      `,
    });
  }

  function renderDashboardRegisterPage({ error } = {}) {
    return renderPageShell({
      title: "OAuth Dashboard – Register",
      body: `
        <h1>Create Dashboard Account</h1>
        ${error ? `<div class=\"error\">${error}</div>` : ""}
        <form method="post" action="/dashboard/register">
          <label>Name</label>
          <input type="text" name="name" />
          <label>Email</label>
          <input type="email" name="email" required />
          <label>Password</label>
          <input type="password" name="password" required />
          <div style="margin-top:12px">
            <button class="btn" type="submit">Create Account</button>
            <a class="btn secondary" href="/dashboard/login" style="margin-left:8px">Back to Login</a>
          </div>
        </form>
      `,
    });
  }

  function renderDashboardHomePage({ user, clients, message } = {}) {
    const list = (clients || []).map((c) => {
      const rulesList = (c.redirect_rules || []).map((r, idx) => `
          <div style="display:flex; align-items:center; justify-content:space-between; gap:8px; margin:4px 0;">
            <div class="rules" style="flex:1; white-space:pre;">${(r.type + ": " + r.value).replace(/&/g,'&amp;').replace(/</g,'&lt;')}</div>
            <form class="inline" method="post" action="/dashboard/clients/${c.id}/redirects/edit">
              <input type="hidden" name="index" value="${idx}" />
              <select name="type">
                <option value="exact" ${r.type === 'exact' ? 'selected' : ''}>exact</option>
                <option value="regex" ${r.type === 'regex' ? 'selected' : ''}>regex</option>
              </select>
              <input type="text" name="value" value="${r.value.replace(/&/g,'&amp;').replace(/"/g,'&quot;')}" style="width:260px" />
              <button class="btn" type="submit">Update</button>
            </form>
            <form class="inline" method="post" action="/dashboard/clients/${c.id}/redirects/delete">
              <input type="hidden" name="index" value="${idx}" />
              <button class="btn secondary" type="submit">Delete</button>
            </form>
          </div>
        `).join("") || "<div class=\"muted\">(no redirect rules)</div>";
      return `
        <div class="client">
          <div><strong>${c.name}</strong></div>
          <div class="muted">Client ID: <code>${c.id}</code></div>
          ${c.id === CLIENT_ID || c.client_secret ? `<div class="muted">Client Secret: <code>${(c.client_secret || '').replace(/&/g,'&amp;').replace(/</g,'&lt;')}</code></div>` : ''}
          <div style="margin-top:8px">
            <form class="inline" method="post" action="/dashboard/clients/${c.id}/response">
              <label>Allowed Response Types</label>
              <label style="margin-right:8px"><input type="checkbox" name="allowed_response_types" value="code" ${c.allowed_response_types?.includes('code') ? 'checked' : ''}/> code</label>
              <label style="margin-right:8px"><input type="checkbox" name="allowed_response_types" value="token" ${c.allowed_response_types?.includes('token') ? 'checked' : ''}/> token</label>
              <br/>
              <label>Allowed Response Modes</label>
              <label style="margin-right:8px"><input type="checkbox" name="allowed_response_modes" value="query" ${c.allowed_response_modes?.includes('query') ? 'checked' : ''}/> query</label>
              <label style="margin-right:8px"><input type="checkbox" name="allowed_response_modes" value="fragment" ${c.allowed_response_modes?.includes('fragment') ? 'checked' : ''}/> fragment</label>
              <button class="btn" type="submit" style="margin-left:8px">Update Response Options</button>
            </form>
          </div>
          <div style="margin-top:8px">
            <form class="inline" method="post" action="/dashboard/clients/${c.id}/scopes">
              <label>Allowed Scopes</label>
              <label style="margin-right:8px"><input type="checkbox" name="allowed_scopes" value="name" ${c.allowed_scopes?.includes('name') ? 'checked' : ''}/> name</label>
              <label style="margin-right:8px"><input type="checkbox" name="allowed_scopes" value="email" ${c.allowed_scopes?.includes('email') ? 'checked' : ''}/> email</label>
              <button class="btn" type="submit" style="margin-left:8px">Update Scopes</button>
            </form>
          </div>
          <div style="margin-top:8px">
            ${rulesList}
          </div>
          <div style="margin-top:8px">
            <form class="inline" method="post" action="/dashboard/clients/${c.id}/redirects">
              <label>Add Redirect Rule</label>
              <div class="row">
                <div>
                  <select name="type">
                    <option value="exact">exact</option>
                    <option value="regex">regex</option>
                  </select>
                </div>
                <div><input type="text" name="value" placeholder="http://localhost:3000/oauth/callback or ^https://.*\\.example\\.com/oauth/.*$" /></div>
                <div><button class="btn" type="submit">Add</button></div>
              </div>
            </form>
          </div>
        </div>
      `;
    }).join("");

    return renderPageShell({
      title: "OAuth Dashboard",
      body: `
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <h1>OAuth Dashboard</h1>
          <div>
            <span class="muted">${user?.email || "anonymous"}</span>
            ${user ? `<a class="btn secondary" style="margin-left:8px" href="/dashboard/logout">Logout</a>` : ''}
          </div>
        </div>
        ${message ? `<div class="muted" style="margin:8px 0">${message}</div>` : ''}
        ${user ? `
          <h2>Create Client</h2>
          <form method="post" action="/dashboard/clients">
            <label>App Name</label>
            <input type="text" name="name" placeholder="My App" required />
            <label>Allowed Scopes</label>
            <div>
              <label><input type="checkbox" name="allowed_scopes" value="name" checked /> name</label>
              <label><input type="checkbox" name="allowed_scopes" value="email" checked /> email</label>
            </div>
            <label>Redirect Rule</label>
            <div class="row">
              <div>
                <select name="redirect_mode">
                  <option value="exact" selected>exact</option>
                  <option value="regex">regex</option>
                </select>
              </div>
              <div>
                <input type="text" name="redirect_value" placeholder="http://localhost:3000/oauth/login" />
              </div>
            </div>
            <div style="margin-top:12px">
              <button class="btn" type="submit">Create</button>
            </div>
          </form>

          <h2>Your Clients</h2>
          ${list || '<div class="muted">No clients yet</div>'}
        ` : `
          <p class="muted">Sign in to create and manage OAuth clients.</p>
          <div style="margin-top:12px">
            <a class="btn" href="/dashboard/login">Login</a>
            <a class="btn secondary" href="/dashboard/register" style="margin-left:8px">Register</a>
          </div>
        `}
      `,
    });
  }

  function getDashboardUser(req) {
    const sid = req.cookies[DASH_COOKIE];
    if (!sid) return null;
    const session = getDashboardSession(sid);
    return session?.user || null;
  }

  app.get("/dashboard", (req, res) => {
    const user = getDashboardUser(req);
    const clients = user
      ? CLIENTS.filter((c) => c.ownerId === user.id || c.id === CLIENT_ID).map((c) => ({
          id: c.id,
          name: c.name,
          client_secret: c.client_secret || null,
          allowed_scopes: c.allowedScopes || [],
          allowed_response_types: c.allowedResponseTypes || [],
          allowed_response_modes: c.allowedResponseModes || [],
          redirect_rules: c.redirectRules || [],
        }))
      : [];
    res.send(renderDashboardHomePage({ user, clients }));
  });

  app.get("/dashboard/login", (req, res) => {
    const user = getDashboardUser(req);
    if (user) return res.redirect("/dashboard");
    res.send(renderDashboardLoginPage());
  });

  app.get("/dashboard/register", (req, res) => {
    const user = getDashboardUser(req);
    if (user) return res.redirect("/dashboard");
    res.send(renderDashboardRegisterPage());
  });

  // Create a new OAuth client for the dashboard user
  // Accepts either {name, redirect_mode, redirect_value}
  // or {name, redirect_rules: [{type: 'exact'|'regex', value: string}, ...]}
  app.post("/dashboard/clients", ensureDashboardAuth, (req, res) => {
    const { name, redirect_mode, redirect_value, redirect_rules, allowed_scopes } = req.body || {};
    if (!name) return res.status(400).json({ error: "name_required" });

    const rules = Array.isArray(redirect_rules)
      ? redirect_rules
      : redirect_mode && redirect_value
      ? [{ type: String(redirect_mode), value: String(redirect_value) }]
      : [];

    const client = {
      id: `client_${nanoid(12)}`,
      client_secret: `secret_${nanoid(24)}`,
      name,
      ownerId: req.dashboardUser.id,
      redirectRules: rules.filter(
        (r) => r && (r.type === "exact" || r.type === "regex") && typeof r.value === "string"
      ),
      // No server-derived pattern for dashboard clients; they must supply exact or regex rules
      redirectUriPattern: null,
      allowedScopes: Array.isArray(allowed_scopes)
        ? allowed_scopes.filter((s) => s === "name" || s === "email")
        : ["name", "email"],
    };
    CLIENTS.push(client);
    if (wantsHtml(req)) return res.redirect("/dashboard");
    res.json({
      id: client.id,
      client_secret: client.client_secret,
      name: client.name,
      redirect_rules: client.redirectRules,
      allowed_scopes: client.allowedScopes,
    });
  });

  // Update allowed scopes (HTML form convenience)
  app.post("/dashboard/clients/:id/scopes", ensureDashboardAuth, (req, res) => {
    const c = CLIENTS.find((x) => x.id === req.params.id && (x.ownerId === req.dashboardUser.id || x.id === CLIENT_ID));
    if (!c) {
      if (wantsHtml(req)) return res.redirect("/dashboard");
      return res.status(404).json({ error: "not_found" });
    }
    let scopes = req.body.allowed_scopes;
    if (typeof scopes === 'string') scopes = [scopes];
    if (!Array.isArray(scopes)) scopes = [];
    c.allowedScopes = scopes.filter((s) => s === 'name' || s === 'email');
    if (wantsHtml(req)) return res.redirect("/dashboard");
    res.json({ allowed_scopes: c.allowedScopes });
  });

  // Edit an existing redirect rule by index
  app.post("/dashboard/clients/:id/redirects/edit", ensureDashboardAuth, (req, res) => {
    const c = CLIENTS.find((x) => x.id === req.params.id && (x.ownerId === req.dashboardUser.id || x.id === CLIENT_ID));
    if (!c) {
      if (wantsHtml(req)) return res.redirect("/dashboard");
      return res.status(404).json({ error: "not_found" });
    }
    const idx = Number.parseInt(req.body.index, 10);
    const type = String(req.body.type || '').trim();
    const value = String(req.body.value || '').trim();
    if (!Number.isFinite(idx) || idx < 0 || idx >= (c.redirectRules?.length || 0)) {
      if (wantsHtml(req)) return res.redirect("/dashboard");
      return res.status(400).json({ error: "invalid_index" });
    }
    if (!(type === 'exact' || type === 'regex') || !value) {
      if (wantsHtml(req)) return res.redirect("/dashboard");
      return res.status(400).json({ error: "invalid_rule" });
    }
    c.redirectRules[idx] = { type, value };
    if (wantsHtml(req)) return res.redirect("/dashboard");
    res.json({ redirect_rules: c.redirectRules });
  });

  // Update allowed response types/modes
  app.post("/dashboard/clients/:id/response", ensureDashboardAuth, (req, res) => {
    const c = CLIENTS.find((x) => x.id === req.params.id && (x.ownerId === req.dashboardUser.id || x.id === CLIENT_ID));
    if (!c) {
      if (wantsHtml(req)) return res.redirect("/dashboard");
      return res.status(404).json({ error: "not_found" });
    }
    let types = req.body.allowed_response_types;
    if (typeof types === 'string') types = [types];
    if (!Array.isArray(types)) types = [];
    c.allowedResponseTypes = types.filter((t) => t === 'code' || t === 'token');

    let modes = req.body.allowed_response_modes;
    if (typeof modes === 'string') modes = [modes];
    if (!Array.isArray(modes)) modes = [];
    c.allowedResponseModes = modes.filter((m) => m === 'query' || m === 'fragment');

    if (wantsHtml(req)) return res.redirect("/dashboard");
    res.json({ allowed_response_types: c.allowedResponseTypes, allowed_response_modes: c.allowedResponseModes });
  });

  // Delete an existing redirect rule by index
  app.post("/dashboard/clients/:id/redirects/delete", ensureDashboardAuth, (req, res) => {
    const c = CLIENTS.find((x) => x.id === req.params.id && (x.ownerId === req.dashboardUser.id || x.id === CLIENT_ID));
    if (!c) {
      if (wantsHtml(req)) return res.redirect("/dashboard");
      return res.status(404).json({ error: "not_found" });
    }
    const idx = Number.parseInt(req.body.index, 10);
    if (!Number.isFinite(idx) || idx < 0 || idx >= (c.redirectRules?.length || 0)) {
      if (wantsHtml(req)) return res.redirect("/dashboard");
      return res.status(400).json({ error: "invalid_index" });
    }
    c.redirectRules.splice(idx, 1);
    if (wantsHtml(req)) return res.redirect("/dashboard");
    res.json({ redirect_rules: c.redirectRules });
  });

  app.get("/dashboard/clients", ensureDashboardAuth, (req, res) => {
    const list = CLIENTS.filter((c) => c.ownerId === req.dashboardUser.id || c.id === CLIENT_ID).map((c) => ({
      id: c.id,
      name: c.name,
      redirect_rules: c.redirectRules || [],
      allowed_scopes: c.allowedScopes || [],
    }));
    res.json({ clients: list });
  });

  app.get("/dashboard/clients/:id", ensureDashboardAuth, (req, res) => {
    const c = CLIENTS.find((x) => x.id === req.params.id && (x.ownerId === req.dashboardUser.id || x.id === CLIENT_ID));
    if (!c) return res.status(404).json({ error: "not_found" });
    res.json({
      id: c.id,
      name: c.name,
      client_secret: c.client_secret,
      redirect_rules: c.redirectRules || [],
      allowed_scopes: c.allowedScopes || [],
    });
  });

  app.put("/dashboard/clients/:id", ensureDashboardAuth, (req, res) => {
    const c = CLIENTS.find((x) => x.id === req.params.id && (x.ownerId === req.dashboardUser.id || x.id === CLIENT_ID));
    if (!c) return res.status(404).json({ error: "not_found" });
    const { name, redirect_rules, allowed_scopes } = req.body || {};
    if (typeof name === "string") c.name = name;
    if (Array.isArray(redirect_rules)) {
      c.redirectRules = redirect_rules.filter(
        (r) => r && (r.type === "exact" || r.type === "regex") && typeof r.value === "string"
      );
    }
    if (Array.isArray(allowed_scopes)) {
      c.allowedScopes = allowed_scopes.filter((s) => s === "name" || s === "email");
    }
    res.json({
      id: c.id,
      name: c.name,
      redirect_rules: c.redirectRules || [],
      allowed_scopes: c.allowedScopes || [],
    });
  });

  app.post("/dashboard/clients/:id/redirects", ensureDashboardAuth, (req, res) => {
    const c = CLIENTS.find((x) => x.id === req.params.id && (x.ownerId === req.dashboardUser.id || x.id === CLIENT_ID));
    if (!c) return res.status(404).json({ error: "not_found" });
    const { type, value } = req.body || {};
    if (!type || !value) return res.status(400).json({ error: "invalid_rule" });
    if (!(type === "exact" || type === "regex")) {
      return res.status(400).json({ error: "invalid_type" });
    }
    c.redirectRules = c.redirectRules || [];
    c.redirectRules.push({ type, value: String(value) });
    if (wantsHtml(req)) return res.redirect("/dashboard");
    res.json({ redirect_rules: c.redirectRules });
  });

  app.get("/health", (req, res) => {
    res.json({ status: "ok" });
  });

  app.get("/login", (req, res) => {
    if (req.oauthUser) {
      const returnTo = req.query.returnTo || "/";
      return res.redirect(returnTo);
    }
    res.send(renderLoginPage({ returnTo: req.query.returnTo }));
  });

  app.post("/login", (req, res) => {
    const { email, password, returnTo } = req.body;
    const user = verifyUserCredentials(email, password);
    if (!user) {
      return res.status(401).send(
        renderLoginPage({
          returnTo,
          error: "Invalid email or password",
        })
      );
    }
    const sessionId = createOAuthSession(user.id);
    res.cookie(OAUTH_COOKIE_NAME, sessionId, {
      httpOnly: true,
      sameSite: "lax",
    });
    res.redirect(returnTo || "/authorize");
  });

  app.post("/logout", (req, res) => {
    const sessionId = req.cookies[OAUTH_COOKIE_NAME];
    if (sessionId) {
      destroyOAuthSession(sessionId);
    }
    res.clearCookie(OAUTH_COOKIE_NAME);
    res.json({ success: true });
  });

  app.get("/logout", (req, res) => {
    const sessionId = req.cookies[OAUTH_COOKIE_NAME];
    if (sessionId) {
      destroyOAuthSession(sessionId);
    }
    res.clearCookie(OAUTH_COOKIE_NAME);
    const returnTo = req.query.returnTo || "/login";
    res.redirect(returnTo);
  });

  app.get("/authorize", (req, res) => {
    const {
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: responseType,
      state,
      response_mode: responseMode,
      prompt = "user_interaction",
      scope: scopeParam,
    } = req.query;

    const client = findClient(clientId);
    if (!client) {
      return res.status(400).send("Unknown client");
    }
    if (!redirectUri) {
      return res.status(400).send("Invalid redirect_uri");
    }

    // VULNERABLE: Validate redirect URI without decoding
    let validatedRedirectUri;
    try {
      validatedRedirectUri = validateRedirectUri(redirectUri);
    } catch (error) {
      return res.status(400).send("Invalid redirect_uri format");
    }

    // First enforce any client-configured rules (exact or regex); fallback to legacy pattern
    if (!clientRedirectAllowed(client, redirectUri)) {
      return res.status(400).send("Invalid redirect_uri");
    }
    if (!responseType) {
      return res.status(400).send("Missing response_type");
    }

    // Scopes: parse requested, validate against client allowed scopes (if any)
    const requestedScopes = (typeof scopeParam === "string" && scopeParam.trim())
      ? scopeParam.trim().split(/\s+/)
      : [];
    const allowedScopes = Array.isArray(client.allowedScopes) ? client.allowedScopes : ["name", "email"];
    const invalidRequested = requestedScopes.filter((s) => !allowedScopes.includes(s));
    if (invalidRequested.length > 0) {
      return buildErrorResponse(
        res,
        redirectUri,
        responseMode,
        "invalid_scope",
        state
      );
    }

    const sessionId = req.cookies[OAUTH_COOKIE_NAME];
    const session = sessionId ? getOAuthSession(sessionId) : null;
    if (!session) {
      if (prompt === "none") {
        return buildErrorResponse(
          res,
          redirectUri,
          responseMode,
          "login_required",
          state
        );
      }
      const returnTo = `/authorize?${new URLSearchParams(
        req.query
      ).toString()}`;
      return res.redirect(
        `/login?${new URLSearchParams({ returnTo }).toString()}`
      );
    }

    const user = getUserById(session.userId);
    if (!user) {
      destroyOAuthSession(sessionId);
      const returnTo = `/authorize?${new URLSearchParams(
        req.query
      ).toString()}`;
      return res.redirect(
        `/login?${new URLSearchParams({ returnTo }).toString()}`
      );
    }

    const responseTypes = responseType.split(",").map((type) => type.trim());
    const allowedTypes = Array.isArray(client.allowedResponseTypes) ? client.allowedResponseTypes : ["code", "token"];
    if (!responseTypes.every((type) => allowedTypes.includes(type))) {
      return res.status(400).send("Unsupported response_type");
    }

    if (responseMode) {
      const allowedModes = Array.isArray(client.allowedResponseModes) ? client.allowedResponseModes : ["query", "fragment"];
      if (!allowedModes.includes(responseMode)) {
        return res.status(400).send("Unsupported response_mode");
      }
    }

    if (prompt === "user_interaction" && req.query.decision !== "skip") {
      const params = {
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: responseType,
      };
      if (state) params.state = state;
      if (responseMode) params.response_mode = responseMode;
      if (requestedScopes.length) params.scope = requestedScopes.join(" ");
      params.prompt = "none";
      return res.send(renderConsentPage({ client, params, user }));
    }

    const includeCode = responseTypes.includes("code");
    const includeToken = responseTypes.includes("token");
    let code;
    if (includeCode) {
      code = nanoid(32);
      storeAuthCode({
        code,
        userId: user.id,
        clientId,
        redirectUri: validatedRedirectUri,
        scope: requestedScopes,
      });
    }

    let token;
    if (includeToken) {
      token = signAuthToken(buildTokenPayload(user, requestedScopes));
    }

    const redirectTarget = buildSuccessRedirect({
      redirectUri: redirectUri, // VULNERABLE: Use original encoded URI for redirect
      responseMode,
      includeCode,
      includeToken,
      code,
      token,
      state,
    });

    return res.redirect(redirectTarget);
  });

  app.post("/authorize", (req, res) => {
    const {
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: responseType,
      state,
      response_mode: responseMode,
      prompt,
      decision,
      scope,
    } = req.body;

    if (decision !== "approve") {
      return buildErrorResponse(
        res,
        redirectUri,
        responseMode,
        "access_denied",
        state
      );
    }

    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: responseType,
      prompt: prompt ?? "none",
    });
    if (state) params.set("state", state);
    if (responseMode) params.set("response_mode", responseMode);
    if (scope) params.set("scope", scope);

    return res.redirect(`/authorize?${params.toString()}&decision=skip`);
  });

  app.post("/token", (req, res) => {
    const { code, client_id: clientId, client_secret: clientSecret } = req.body;
    if (!code || !clientId) {
      return res.status(400).json({ error: "invalid_request" });
    }

    const client = findClient(clientId);
    if (!client) {
      return res.status(400).json({ error: "invalid_client" });
    }

    // If the client has a secret configured, require it in the request
    if (client.client_secret) {
      if (!clientSecret || clientSecret !== client.client_secret) {
        return res.status(400).json({ error: "invalid_client" });
      }
    }

    // NOTE: No redirect_uri validation at token exchange time per demo requirements.

    const record = consumeAuthCode(code);
    if (!record) {
      return res.status(400).json({ error: "invalid_code" });
    }
    // Do not enforce redirect_uri matching during token exchange.

    const user = getUserById(record.userId);
    if (!user) {
      return res.status(400).json({ error: "user_not_found" });
    }

    const token = signAuthToken(buildTokenPayload(user, record.scope || []));
    res.json({ token, token_type: "Bearer" });
  });

  return new Promise((resolve) => {
    const server = app.listen(port, () => resolve(server));
  });
}
