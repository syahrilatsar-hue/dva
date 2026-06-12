import express from "express";
import cookieParser from "cookie-parser";
import multer from "multer";
import path from "path";
import fs from "fs";
import { nanoid } from "nanoid";
import { createRequire } from "module";
import {
  createInvitation,
  createMembership,
  createTask,
  createTenant,
  createUser,
  deleteTask,
  getInvitationByToken,
  getTenantById,
  getUserById,
  getUserByUsername,
  listInvitationsByTenant,
  listTasksByTenant,
  listTenantMembers,
  listMembershipsByUser,
  markInvitationUsed,
  setUserAboutMe,
  toggleTaskCompletion,
  updateUserIdentifiers,
  verifyUserCredentialsByUsername,
} from "../shared/datastore.js";
import { signAuthToken, verifyAuthToken } from "../shared/jwt.js";
import crypto from "crypto";

const APP_COOKIE_NAME = "task_auth_token";
const DEFAULT_PORT = 3000;
const OAUTH_BASE_URL = process.env.OAUTH_BASE_URL || "http://localhost:4000";
const APP_BASE_URL = process.env.APP_BASE_URL || "http://localhost:3000";
const CLIENT_ID = process.env.CLIENT_ID || "task-app";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "task-secret";
const CSRF_COOKIE_NAME = "task_csrf_token";

const require = createRequire(import.meta.url);
const mmmagic = require("mmmagic");
const Magic = mmmagic.Magic;
const magicMimeDetector = new Magic(mmmagic.MAGIC_MIME_TYPE);

const ALLOWED_MAGIC_MIME_TYPES = new Map([
  ["application/pdf", "pdf"],
  ["application/x-pdf", "pdf"],
  ["image/jpeg", "jpeg"],
  ["image/jpg", "jpeg"],
  ["image/pjpeg", "jpeg"],
  ["image/png", "png"],
  ["image/webp", "webp"],
]);
// Allow switching config at runtime for demo purposes
let ACTIVE_CLIENT_ID = CLIENT_ID;
let ACTIVE_CLIENT_SECRET = CLIENT_SECRET;
let ACTIVE_APP_BASE_URL = APP_BASE_URL;
let ACTIVE_OAUTH_BASE_URL = OAUTH_BASE_URL;

function sanitizeBaseUrl(maybeUrl) {
  if (typeof maybeUrl !== "string" || !maybeUrl.trim()) return null;
  try {
    const u = new URL(maybeUrl.trim());
    // strip trailing slash for consistency
    return u.toString().replace(/\/+$/, "");
  } catch (_e) {
    return null;
  }
}

function resolveAppBaseUrl(req) {
  // Prefer runtime override
  if (ACTIVE_APP_BASE_URL) return ACTIVE_APP_BASE_URL;
  // Derive from request when behind proxy
  try {
    const proto = req.protocol;
    const host = req.get("host");
    if (proto && host) return `${proto}://${host}`;
  } catch (_e) {}
  return APP_BASE_URL;
}

function resolveOAuthBaseUrl() {
  return ACTIVE_OAUTH_BASE_URL || OAUTH_BASE_URL;
}

function genStateBase64(bytes = 12) {
  return crypto.randomBytes(bytes).toString("base64");
}

function generateCsrfToken() {
  return crypto.randomBytes(24).toString("hex");
}

function setCsrfCookie(res, token = generateCsrfToken()) {
  res.cookie(CSRF_COOKIE_NAME, token, {
    httpOnly: false,
    sameSite: "lax",
  });
  return token;
}

function detectMimeTypeFromFile(filePath) {
  return new Promise((resolve) => {
    magicMimeDetector.detectFile(filePath, (err, result) => {
      if (err || typeof result !== "string") {
        return resolve(null);
      }
      const value = result.toLowerCase().trim();
      return resolve(value || null);
    });
  });
}

async function validateUploadedFile(file) {
  if (!file) {
    return { ok: false, error: "missing_file" };
  }
  const detectedMime = await detectMimeTypeFromFile(file.path);
  if (!detectedMime) {
    return { ok: false, error: "invalid_magic_bytes" };
  }
  const normalizedMime = detectedMime.split(";")[0].trim();
  const allowedName = ALLOWED_MAGIC_MIME_TYPES.get(normalizedMime);
  if (!allowedName) {
    return { ok: false, error: "unsupported_magic_type" };
  }
  return { ok: true, type: allowedName };
}

const isPlainObject = (value) =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function isValidBase64String(value) {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!trimmed) return false;
  let b64 = trimmed.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  else if (pad !== 0) return false;
  try {
    const buf = Buffer.from(b64, "base64");
    const re = buf.toString("base64").replace(/=+$/, "");
    const norm = b64.replace(/=+$/, "");
    return re === norm;
  } catch {
    return false;
  }
}
const UPLOAD_DIR =
  process.env.UPLOAD_DIR || path.join(process.cwd(), "uploads");
const DEFAULT_TRACKER_BASE_URL = "http://localhost:5002";
const TRACKER_BASE_URL =
  (process.env.TRACKER_BASE_URL || DEFAULT_TRACKER_BASE_URL).trim() ||
  DEFAULT_TRACKER_BASE_URL;
const TRACKER_IFRAME_URL = (() => {
  const explicit = process.env.TRACKER_IFRAME_URL;
  if (typeof explicit === "string" && explicit.trim()) {
    return explicit.trim();
  }
  return `${TRACKER_BASE_URL.replace(/\/+$/, "")}/collector`;
})();

const CLIENT_BUILD_DIR = path.join(process.cwd(), "client", "dist");
const CLIENT_INDEX_FILE = path.join(CLIENT_BUILD_DIR, "index.html");

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const uniqueName = `${Date.now()}-${nanoid()}-${file.originalname}`;
    cb(null, uniqueName);
  },
});

const upload = multer({ storage });

const parseFlexibleJsonBody = (() => {
  const parser = express.json({ type: () => true });
  return (req, res, next) => {
    if (isPlainObject(req.body) && Object.keys(req.body).length > 0) {
      return next();
    }
    parser(req, res, (err) => {
      if (err) {
        return res.status(400).json({ error: "Invalid JSON payload." });
      }
      if (!isPlainObject(req.body)) {
        req.body = {};
      }
      next();
    });
  };
})();

function buildAuthorizeUrl(req, {
  responseType,
  prompt = "user_interaction",
  state,
}) {
  const appBase = resolveAppBaseUrl(req);
  const oauthBase = resolveOAuthBaseUrl();
  const query = new URLSearchParams({
    client_id: ACTIVE_CLIENT_ID,
    redirect_uri: responseType.includes("token")
      ? `${appBase}/oauth/token`
      : `${appBase}/oauth/login`,
    response_type: responseType,
    prompt,
  });
  // Require both scopes from OAuth server
  query.set("scope", "name email");
  query.set("state", state || genStateBase64());
  return `${oauthBase}/authorize?${query.toString()}`;
}

function listUserMemberships(userId) {
  return listMembershipsByUser(userId).map((membership) => ({
    id: membership.id,
    tenantId: membership.tenantId,
    role: membership.role,
    tenantName: getTenantById(membership.tenantId)?.name ?? null,
  }));
}

function buildAdminOverviewPayload(user, membership) {
  const tenant = getTenantById(membership.tenantId);
  const members = listTenantMembers(membership.tenantId).map((member) => {
    const memberUser = getUserById(member.userId);
    return {
      id: member.id,
      role: member.role,
      joinedAt: member.createdAt,
      user: memberUser
        ? {
            id: memberUser.id,
            name: memberUser.name,
            email: memberUser.email,
            username: memberUser.username,
          }
        : null,
    };
  });

  const invitations = listInvitationsByTenant(membership.tenantId).map(
    (invitation) => ({
      id: invitation.id,
      email: invitation.email,
      token: invitation.token,
      createdAt: invitation.createdAt,
      usedAt: invitation.usedAt,
      inviteLink: `${APP_BASE_URL}/invite/${invitation.token}`,
    })
  );

  return {
    tenant,
    members,
    invitations,
    aboutMe: user.aboutMe || "",
    inviteLinkBase: `${APP_BASE_URL}/invite/`,
  };
}

function buildLocalTokenPayload(user) {
  return {
    sub: user.id,
    email: user.email,
    name: user.name,
    memberships: listUserMemberships(user.id),
  };
}

function formatUser(user, activeMembership) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    username: user.username,
    aboutMe: user.aboutMe,
    isAdmin: activeMembership?.role === "admin" || false,
  };
}

function ensureUserMembership(user) {
  const memberships = listMembershipsByUser(user.id);
  if (memberships.length > 0) {
    return memberships[0];
  }
  const tenantName = user.name
    ? `${user.name}'s Workspace`
    : `${user.username}'s Workspace`;
  const tenant = createTenant({ name: tenantName, ownerId: user.id });
  return createMembership({
    tenantId: tenant.id,
    userId: user.id,
    role: "admin",
  });
}

function attachAuth(req, res, next) {
  const token = req.cookies[APP_COOKIE_NAME];
  if (!token) {
    return next();
  }
  const payload = verifyAuthToken(token);
  if (!payload) {
    res.clearCookie(APP_COOKIE_NAME);
    return next();
  }
  const user = getUserById(payload.sub);
  if (!user) {
    res.clearCookie(APP_COOKIE_NAME);
    return next();
  }
  const memberships = listUserMemberships(user.id);
  const activeMembership = memberships[0] || null;
  req.auth = {
    user,
    memberships,
    activeMembership,
  };
  next();
}

function ensureCsrfToken(req, res, next) {
  const cookieToken = req.cookies[CSRF_COOKIE_NAME];
  if (req.auth?.user) {
    if (!cookieToken) {
      req.csrfToken = setCsrfCookie(res);
    } else {
      req.csrfToken = cookieToken;
    }
  } else {
    req.csrfToken = null;
  }
  next();
}

function requireAuthJson(req, res, next) {
  if (!req.auth?.user) {
    return res.status(401).json({ error: "unauthenticated" });
  }
  return next();
}

function requireAdminJson(req, res, next) {
  if (
    !req.auth?.activeMembership ||
    req.auth.activeMembership.role !== "admin"
  ) {
    return res.status(403).json({ error: "forbidden" });
  }
  return next();
}

function getRequestCsrfToken(req) {
  const headerToken = req.get("x-csrf-token");
  if (typeof headerToken === "string" && headerToken.trim()) {
    return headerToken.trim();
  }
  const bodyToken = req.body && typeof req.body.csrfToken === "string" ? req.body.csrfToken.trim() : "";
  return bodyToken || null;
}

function requireCsrfToken(req, res, next) {
  const cookieToken = req.cookies[CSRF_COOKIE_NAME];
  const requestToken = getRequestCsrfToken(req);
  if (!cookieToken || !requestToken || cookieToken !== requestToken) {
    return res.status(403).json({ error: "invalid_csrf_token" });
  }
  return next();
}

// OAuth API auth using Bearer token
function attachOAuthApiAuth(req, res, next) {
  const header = req.headers["authorization"] || "";
  const m = header.match(/^Bearer\s+(.+)$/i);
  if (!m) return next();
  const token = m[1];
  const payload = verifyAuthToken(token);
  if (!payload) return next();
  const user = getUserById(payload.sub);
  if (!user) return next();
  const memberships = listUserMemberships(user.id);
  req.apiAuth = { user, memberships };
  next();
}

function requireOAuthAdminForTenant(req, res, next) {
  const tenantId = req.query.tenantId || req.body?.tenantId;
  if (!tenantId) {
    return res.status(400).json({ error: "tenantId_required" });
  }
  if (!req.apiAuth?.user) {
    return res.status(401).json({ error: "invalid_or_missing_token" });
  }
  const membership = (req.apiAuth.memberships || []).find(
    (m) => m.tenantId === tenantId && m.role === "admin"
  );
  if (!membership) {
    return res.status(403).json({ error: "forbidden" });
  }
  req.apiAuth.tenantId = tenantId;
  req.apiAuth.activeMembership = membership;
  next();
}

function buildSessionPayload(req) {
  if (!req.auth?.user) {
    return {
      authenticated: false,
      user: null,
      memberships: [],
      csrfToken: req.csrfToken || null,
      oauthAuthorizeUrl: buildAuthorizeUrl(req, { responseType: "code", state: genStateBase64() }),
      trackerIframeUrl: TRACKER_IFRAME_URL,
      appBaseUrl: resolveAppBaseUrl(req),
      oauthBaseUrl: resolveOAuthBaseUrl(),
    };
  }
  const { user, memberships, activeMembership } = req.auth;
  return {
    authenticated: true,
    user: formatUser(user, activeMembership),
    memberships,
    activeMembership,
    csrfToken: req.csrfToken || null,
    oauthAuthorizeUrl: buildAuthorizeUrl(req, { responseType: "code", state: genStateBase64() }),
    trackerIframeUrl: TRACKER_IFRAME_URL,
    appBaseUrl: resolveAppBaseUrl(req),
    oauthBaseUrl: resolveOAuthBaseUrl(),
  };
}

function sendAppShell(res) {
  if (fs.existsSync(CLIENT_INDEX_FILE)) {
    return res.sendFile(CLIENT_INDEX_FILE);
  }
  return res
    .status(200)
    .send(
      "Client build not found. Run `npm run build:client` to generate the React bundle."
    );
}

export async function startTaskApp({ port = DEFAULT_PORT } = {}) {
  const app = express();
  if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  }

  app.use(cookieParser());
  // Respect X-Forwarded-* when running behind a proxy / container ingress
  app.set("trust proxy", true);
  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());
  app.use(attachAuth);
  app.use(ensureCsrfToken);
  app.use(attachOAuthApiAuth);

  app.use(
    "/uploads",
    express.static(UPLOAD_DIR, {
      setHeaders: (res, filePath) => {
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="${path.basename(filePath)}"`
        );
      },
    })
  );

  // API routes
  // Public API helper: implicit flow authorize URL for tokens (response_type=token)
  app.get("/api/v1/oauth/authorize-url", (req, res) => {
    const url = buildAuthorizeUrl(req, { responseType: "token", state: genStateBase64() });
    res.json({ authorizeUrl: url, responseType: "token" });
  });

  // OAuth-protected admin API for tasks (Bearer token)
  app.get("/api/v1/tasks", requireOAuthAdminForTenant, (req, res) => {
    const tenantId = req.apiAuth.tenantId;
    const tenant = getTenantById(tenantId);
    if (!tenant) return res.status(404).json({ error: "tenant_not_found" });
    const tasks = listTasksByTenant(tenantId);
    res.json({ tenant, tasks });
  });

  // Helper: API docs + token fetcher (implicit flow)
  app.get("/oauth/token-helper", (req, res) => {
    res.send(`<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Task Admin API – Docs & Token</title>
    <style>
      body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; background:#f6f7fb; margin:0; padding:24px; }
      .card { max-width: 920px; margin: 0 auto; background:#fff; border-radius:12px; padding:24px; box-shadow: 0 6px 24px rgba(0,0,0,0.07); }
      h1 { margin:0 0 12px 0; font-size:22px; }
      h2 { margin:18px 0 8px; font-size:18px; }
      .muted { color:#6b7280; font-size:13px; }
      textarea { width:100%; height:120px; padding:10px; border:1px solid #ccd3e0; border-radius:8px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
      pre { background:#0b1020; color:#e5e7eb; padding:12px; border-radius:8px; overflow:auto; font-size:13px; }
      .row { display:flex; gap:12px; margin-top:12px; flex-wrap: wrap; }
      .btn { background:#4f46e5; color:#fff; border:none; padding:10px 14px; border-radius:8px; cursor:pointer; }
      .btn.secondary { background:#e5e7eb; color:#111827; }
      code { background:#f3f4f6; padding:2px 6px; border-radius:4px; }
      .k { color:#93c5fd; }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Task Admin API – Docs & Token</h1>
      <p class="muted">Use this page to fetch an OAuth token (implicit flow) and test the Task Admin API. Your OAuth client must allow <code>response_type=token</code> and include a redirect rule for this page.</p>

      <h2>Your Token</h2>
      <div id="status" class="muted" style="margin:8px 0"></div>
      <label>Token</label>
      <textarea id="token" readonly placeholder="Click 'Get Token' to start the OAuth flow..."></textarea>
      <div class="row">
        <button class="btn" id="get">Get Token</button>
        <button class="btn" id="copy">Copy Token</button>
        <button class="btn secondary" id="clear">Clear</button>
        <button class="btn secondary" id="home">Back to App</button>
      </div>

      <h2>Endpoints</h2>
      <ul>
        <li><code>GET /api/v1/tasks?tenantId=&lt;id&gt;</code> – list tasks (admin)</li>
        <li><code>POST /api/v1/tasks</code> – create task (admin). Body: <code>{"tenantId":"...","title":"...","description":"..."}</code></li>
        <li><code>DELETE /api/v1/tasks/:taskId?tenantId=&lt;id&gt;</code> – delete task (admin)</li>
      </ul>
      <p class="muted">Send your token in the header <code>Authorization: Bearer &lt;token&gt;</code>.</p>

      <h2>Examples</h2>
      <pre><span class="k"># Get tasks</span>
curl -H 'Authorization: Bearer &lt;token&gt;' \
  '${resolveAppBaseUrl(req)}/api/v1/tasks?tenantId=&lt;tenant-id&gt;'

<span class="k"># Create task</span>
curl -X POST -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer &lt;token&gt;' \
  -d '{"tenantId":"&lt;tenant-id&gt;","title":"Test task"}' \
  '${resolveAppBaseUrl(req)}/api/v1/tasks'

<span class="k"># Delete task</span>
curl -X DELETE -H 'Authorization: Bearer &lt;token&gt;' \
  '${resolveAppBaseUrl(req)}/api/v1/tasks/&lt;task-id&gt;?tenantId=&lt;tenant-id&gt;'
      </pre>
    </div>
    <script>
      (function(){
        var params = new URLSearchParams(window.location.hash.replace(/^#/, ''));
        var token = params.get('token');
        var scope = params.get('scope');
        var state = params.get('state');
        var el = document.getElementById('token');
        var status = document.getElementById('status');
        function setToken(t) { el.value = t || ''; }
        function setStatus(msg) { status.textContent = msg || ''; }
        if (token) {
          setToken(token);
          setStatus('Token received.' + (scope ? (' Scope: ' + scope) : ''));
          history.replaceState(null, document.title, window.location.pathname + window.location.search);
        } else {
          // If OAuth returned an error via query string (prompt=none can yield login_required)
          var q = new URLSearchParams(window.location.search);
          var err = q.get('error');
          if (err) {
            setStatus('OAuth error: ' + err + '. You may need to sign in to the OAuth server and try again.');
          } else {
            setStatus('No token yet. Click Get Token to start the OAuth flow.');
          }
        }

        document.getElementById('get').addEventListener('click', function(){
          fetch('/api/v1/oauth/authorize-url/helper')
            .then(function(r){ return r.json(); })
            .then(function(data){
              var url = (data && (data.loginUrl || data.authorizeUrl)) || null;
              if (url) {
                window.location.assign(url);
              } else {
                setStatus('Unable to obtain authorize URL.');
              }
            })
            .catch(function(){ setStatus('Unable to obtain authorize URL.'); });
        });
        document.getElementById('copy').addEventListener('click', function(){
          el.select();
          document.execCommand('copy');
          setStatus('Token copied to clipboard.');
        });
        document.getElementById('clear').addEventListener('click', function(){ setToken(''); setStatus(''); });
        document.getElementById('home').addEventListener('click', function(){ window.location.href = '/'; });
      })();
    </script>
  </body>
  </html>`);
  });

  // Helper: provide an authorize URL that returns token to the helper page (response_type=token)
  app.get("/api/v1/oauth/authorize-url/helper", (req, res) => {
    const appBase = resolveAppBaseUrl(req);
    const oauthBase = resolveOAuthBaseUrl();
    const q = new URLSearchParams({
      client_id: ACTIVE_CLIENT_ID,
      redirect_uri: `${appBase}/oauth/token-helper`,
      response_type: "token",
      prompt: "none",
      scope: "name email",
      state: genStateBase64()
    });
    const authorize = `${oauthBase}/authorize?${q.toString()}`;
    const loginUrl = `${oauthBase}/login?${new URLSearchParams({ returnTo: authorize }).toString()}`;
    res.json({ authorizeUrl: authorize, loginUrl, responseType: 'token', redirect: `${appBase}/oauth/token-helper` });
  });

  app.post("/api/v1/tasks", requireOAuthAdminForTenant, (req, res) => {
    const tenantId = req.apiAuth.tenantId;
    const { title, description } = req.body || {};
    if (!title) return res.status(400).json({ error: "title_required" });
    const task = createTask({ tenantId, createdBy: req.apiAuth.user.id, title, description });
    res.status(201).json({ task });
  });

  app.delete("/api/v1/tasks/:taskId", requireOAuthAdminForTenant, (req, res) => {
    const tenantId = req.apiAuth.tenantId;
    const ok = deleteTask(req.params.taskId, tenantId);
    if (!ok) return res.status(404).json({ error: "task_not_found" });
    res.json({ success: true });
  });
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok" });
  });

  app.get("/api/config", (req, res) => {
    res.json({
      oauthAuthorizeUrl: buildAuthorizeUrl(req, { responseType: "code", state: genStateBase64() }),
      trackerIframeUrl: TRACKER_IFRAME_URL,
      appBaseUrl: resolveAppBaseUrl(req),
      oauthBaseUrl: resolveOAuthBaseUrl(),
      clientId: ACTIVE_CLIENT_ID,
    });
  });

  app.get("/api/session", (req, res) => {
    res.json(buildSessionPayload(req));
  });

  // Demo endpoint to update OAuth client id and base URLs at runtime (intentionally open)
  app.post("/api/config/oauth", (req, res) => {
    const { clientId, clientSecret, appBaseUrl, oauthBaseUrl } = req.body || {};
    if (typeof clientId === "string" && clientId.trim()) {
      ACTIVE_CLIENT_ID = clientId.trim();
    }
    if (typeof clientSecret === "string" && clientSecret.trim()) {
      ACTIVE_CLIENT_SECRET = clientSecret.trim();
    }
    const appSan = sanitizeBaseUrl(appBaseUrl);
    if (appSan) ACTIVE_APP_BASE_URL = appSan;
    const oauthSan = sanitizeBaseUrl(oauthBaseUrl);
    if (oauthSan) ACTIVE_OAUTH_BASE_URL = oauthSan;
    res.json({
      success: true,
      clientId: ACTIVE_CLIENT_ID,
      appBaseUrl: resolveAppBaseUrl(req),
      oauthBaseUrl: resolveOAuthBaseUrl(),
      oauthAuthorizeUrl: buildAuthorizeUrl(req, { responseType: "code", state: genStateBase64() }),
    });
  });

  app.post("/api/auth/local/signup", async (req, res) => {
    const { name, email, username, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required." });
    }
    try {
      const user = createUser({ name, email, password, username });
      const membership = ensureUserMembership(user);
      const token = signAuthToken(buildLocalTokenPayload(user));
      res.cookie(APP_COOKIE_NAME, token, {
        httpOnly: true,
        sameSite: "lax",
      });
      const csrfToken = setCsrfCookie(res);
      res.json({
        success: true,
        user: formatUser(user, membership),
        memberships: listUserMemberships(user.id),
        csrfToken,
        redirect: "/home",
      });
    } catch (error) {
      res
        .status(400)
        .json({ error: error.message || "Unable to create account" });
    }
  });

  app.post("/api/auth/local/login", parseFlexibleJsonBody, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required." });
    }
    const user = verifyUserCredentialsByUsername(username, password);
    if (!user) {
      return res.status(401).json({ error: "Invalid username or password." });
    }
    const membership = ensureUserMembership(user);
    const token = signAuthToken(buildLocalTokenPayload(user));
    res.cookie(APP_COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: "lax",
    });
    const csrfToken = setCsrfCookie(res);
    res.json({
      success: true,
      user: formatUser(user, membership),
      memberships: listUserMemberships(user.id),
      csrfToken,
      redirect: "/home",
    });
  });

  app.post(
    "/api/auth/change-email",
    parseFlexibleJsonBody,
    requireAuthJson,
    requireCsrfToken,
    (req, res) => {
      const { email, username } = req.body || {};
      if (
        (typeof email !== "string" || !email.trim()) &&
        (typeof username !== "string" || !username.trim())
      ) {
        return res.status(400).json({
          error: "Provide a new email or username.",
        });
      }
      try {
        const update = {};
        if (typeof email === "string" && email.trim()) {
          update.email = email;
        }
        if (typeof username === "string" && username.trim()) {
          update.username = username;
        }
        const updatedUser = updateUserIdentifiers(req.auth.user.id, update);
        const memberships = listUserMemberships(updatedUser.id);
        const activeMembership =
          memberships.find((m) => m.id === req.auth.activeMembership?.id) ||
          memberships[0] ||
          null;
        req.auth.user = updatedUser;
        req.auth.memberships = memberships;
        req.auth.activeMembership = activeMembership;
        const newToken = signAuthToken(buildLocalTokenPayload(updatedUser));
        res.cookie(APP_COOKIE_NAME, newToken, {
          httpOnly: true,
          sameSite: "lax",
        });
        res.json({
          success: true,
          user: formatUser(updatedUser, activeMembership),
          memberships,
          csrfToken: req.cookies[CSRF_COOKIE_NAME] || null,
        });
      } catch (error) {
        res.status(400).json({
          error: error.message || "Unable to update user",
        });
      }
    }
  );

  app.post("/api/auth/admin/signup", (req, res) => {
    const { name, email, password, organization, username } = req.body;
    if (!name || !email || !password || !organization) {
      return res.status(400).json({ error: "All fields are required." });
    }
    try {
      const user = createUser({ name, email, password, username });
      const tenant = createTenant({ name: organization, ownerId: user.id });
      createMembership({ tenantId: tenant.id, userId: user.id, role: "admin" });
      const memberships = listUserMemberships(user.id);
      const activeMembership = memberships[0] || null;
      const token = signAuthToken(buildLocalTokenPayload(user));
      res.cookie(APP_COOKIE_NAME, token, {
        httpOnly: true,
        sameSite: "lax",
      });
      const csrfToken = setCsrfCookie(res);
      res.json({
        success: true,
        user: formatUser(user, activeMembership),
        memberships,
        csrfToken,
        redirect: "/home",
      });
    } catch (error) {
      res
        .status(400)
        .json({ error: error.message || "Unable to create admin" });
    }
  });

  app.post("/api/auth/logout", (req, res) => {
    res.clearCookie(APP_COOKIE_NAME);
    res.clearCookie(CSRF_COOKIE_NAME);
    const params = new URLSearchParams({ returnTo: APP_BASE_URL });
    const appLogoutUrl = `${APP_BASE_URL}/logout?${params.toString()}`;
    res.json({ success: true, logoutUrl: appLogoutUrl });
  });

  app.get("/logout", (req, res) => {
    res.clearCookie(APP_COOKIE_NAME);
    res.clearCookie(CSRF_COOKIE_NAME);
    const returnTo =
      typeof req.query.returnTo === "string" && req.query.returnTo.trim()
        ? req.query.returnTo
        : APP_BASE_URL;
    res.redirect(302, returnTo);
  });

  app.get("/api/tasks", requireAuthJson, (req, res) => {
    const membership = req.auth.activeMembership;
    if (!membership) {
      return res.status(400).json({ error: "No tenant membership" });
    }
    const tenant = getTenantById(membership.tenantId);
    const tasks = listTasksByTenant(membership.tenantId);
    res.json({ tenant, tasks });
  });

  app.post("/api/tasks", requireAuthJson, (req, res) => {
    const membership = req.auth.activeMembership;
    if (!membership) {
      return res.status(400).json({ error: "No tenant membership" });
    }
    const { title, description } = req.body;
    if (!title) {
      return res.status(400).json({ error: "Title is required" });
    }
    const task = createTask({
      tenantId: membership.tenantId,
      createdBy: req.auth.user.id,
      title,
      description,
    });
    res.status(201).json({ task });
  });

  app.post("/api/tasks/:taskId/toggle", requireAuthJson, (req, res) => {
    const membership = req.auth.activeMembership;
    if (!membership) {
      return res.status(400).json({ error: "No tenant membership" });
    }
    try {
      const task = toggleTaskCompletion(
        req.params.taskId,
        membership.tenantId,
        req.auth.user.id
      );
      res.json({ task });
    } catch (error) {
      res.status(404).json({ error: "Task not found" });
    }
  });

  app.get(
    "/api/admin/overview",
    requireAuthJson,
    requireAdminJson,
    (req, res) => {
      const membership = req.auth.activeMembership;
      res.json(buildAdminOverviewPayload(req.auth.user, membership));
    }
  );

  app.post(
    "/api/admin/invitations",
    requireAuthJson,
    requireAdminJson,
    (req, res) => {
      const { email } = req.body;
      if (!email) {
        return res.status(400).json({ error: "Email is required" });
      }
      const membership = req.auth.activeMembership;
      const invitation = createInvitation({
        tenantId: membership.tenantId,
        email,
      });
      res.status(201).json({
        invitation: {
          id: invitation.id,
          email: invitation.email,
          token: invitation.token,
          createdAt: invitation.createdAt,
          inviteLink: `${APP_BASE_URL}/invite/${invitation.token}`,
        },
      });
    }
  );

  app.post(
    "/api/admin/about",
    requireAuthJson,
    requireAdminJson,
    (req, res) => {
      const aboutMe =
        typeof req.body.aboutMe === "string" ? req.body.aboutMe : "";
      const user = setUserAboutMe(req.auth.user.id, aboutMe);
      res.json({ success: true, aboutMe: user.aboutMe });
    }
  );

  app.post(
    "/api/admin/upload",
    requireAuthJson,
    requireAdminJson,
    upload.single("attachment"),
    async (req, res) => {
      if (!req.file) {
        return res.status(400).json({ error: "Upload failed" });
      }
      const validation = await validateUploadedFile(req.file);
      if (!validation.ok) {
        try {
          await fs.promises.unlink(req.file.path);
        } catch (_error) {}
        const messageMap = {
          invalid_magic_bytes: "Unable to determine file type from magic bytes.",
          unsupported_magic_type: "Unsupported file type. Allowed: pdf, jpg, webp, png.",
        };
        const errorMessage =
          messageMap[validation.error] || "Invalid file upload.";
        return res.status(400).json({ error: errorMessage });
      }
      const fileUrl = `${APP_BASE_URL}/uploads/${encodeURIComponent(
        req.file.filename
      )}`;
      res.json({ success: true, fileUrl });
    }
  );

  app.get(/^\/api\/(.+)\/details$/, requireAuthJson, (req, res) => {
    const rawSegment = req.params[0] || "";
    let decodedUsername = rawSegment;
    try {
      decodedUsername = decodeURIComponent(rawSegment);
    } catch (_error) {
      decodedUsername = rawSegment;
    }
    const requestedUsername = decodedUsername.trim().toLowerCase();
    const authUsername = (req.auth.user?.username || "").trim().toLowerCase();
    if (!authUsername || requestedUsername !== authUsername) {
      return res.status(403).json({ error: "forbidden" });
    }
    const membership = req.auth.activeMembership;
    if (!membership) {
      return res.status(400).json({ error: "No tenant membership" });
    }
    res.json(buildAdminOverviewPayload(req.auth.user, membership));
  });

  app.get("/api/invitations/:token", (req, res) => {
    if (req.auth?.user) {
      return res.status(400).json({ error: "Already authenticated" });
    }
    const invitation = getInvitationByToken(req.params.token);
    if (!invitation || invitation.usedAt) {
      return res
        .status(404)
        .json({ error: "Invitation invalid or already used" });
    }
    const tenant = getTenantById(invitation.tenantId);
    res.json({
      token: invitation.token,
      email: invitation.email,
      tenantName: tenant?.name || "workspace",
    });
  });

  app.post("/api/invitations/:token", (req, res) => {
    const invitation = getInvitationByToken(req.params.token);
    if (!invitation || invitation.usedAt) {
      return res
        .status(404)
        .json({ error: "Invitation invalid or already used" });
    }
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }
    try {
      const user = createUser({ name, email, password });
      createMembership({
        tenantId: invitation.tenantId,
        userId: user.id,
        role: "user",
      });
      markInvitationUsed(invitation.token);
      const token = signAuthToken(buildLocalTokenPayload(user));
      res.cookie(APP_COOKIE_NAME, token, {
        httpOnly: true,
        sameSite: "lax",
      });
      const csrfToken = setCsrfCookie(res);
      res.json({ success: true, redirect: "/home", csrfToken });
    } catch (error) {
      res
        .status(400)
        .json({ error: error.message || "Unable to accept invitation" });
    }
  });

  // OAuth callback flows (unchanged in behaviour)
  app.get("/oauth/login", async (req, res) => {
    const { code, state } = req.query;
    if (!state || !isValidBase64String(String(state))) {
      return res.status(400).send('OAuth error: invalid state. <a href="/">Return home</a>');
    }
    if (!code) {
      return res
        .status(400)
        .send('Missing authorization code. <a href="/">Return home</a>');
    }
    try {
      const response = await fetch(`${resolveOAuthBaseUrl()}/token`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          code,
          client_id: ACTIVE_CLIENT_ID,
          client_secret: ACTIVE_CLIENT_SECRET,
          redirect_uri: `${resolveAppBaseUrl(req)}/oauth/login`,
        }),
      });
      if (!response.ok) {
        throw new Error("Token exchange failed");
      }
      const result = await response.json();
      const payload = verifyAuthToken(result.token);
      if (!payload) {
        throw new Error("Invalid token received");
      }
      // Enforce required scopes on OAuth tokens
      const scopeStr = typeof payload.scope === "string" ? payload.scope : "";
      const scopes = scopeStr.split(/\s+/).filter(Boolean);
      if (!(scopes.includes("name") && scopes.includes("email"))) {
        throw new Error("Required scopes not granted");
      }
      res.cookie(APP_COOKIE_NAME, result.token, {
        httpOnly: true,
        sameSite: "lax",
      });
      setCsrfCookie(res);
      res.redirect("/home");
    } catch (error) {
      res
        .status(400)
        .send(`OAuth error: ${error.message}. <a href=\"/\">Return home</a>`);
    }
  });

  app.get("/oauth/token", async (req, res) => {
    let exchangeError = null;
    const { code } = req.query;
    const hasCode = Boolean(code);
    if (code) {
      try {
        const response = await fetch(`${resolveOAuthBaseUrl()}/token`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            code,
            client_id: ACTIVE_CLIENT_ID,
            client_secret: ACTIVE_CLIENT_SECRET,
            redirect_uri: `${resolveAppBaseUrl(req)}/oauth/token`,
          }),
        });
        if (!response.ok) {
          throw new Error("Token exchange failed");
        }
        const result = await response.json();
        const payload = verifyAuthToken(result.token);
        if (!payload) {
          throw new Error("Invalid token received");
        }
        // Enforce required scopes on OAuth tokens
        var scopeStr = typeof payload.scope === "string" ? payload.scope : "";
        var scopes = scopeStr.split(/\s+/).filter(Boolean);
        if (!(scopes.includes("name") && scopes.includes("email"))) {
          throw new Error("Required scopes not granted");
        }
        res.cookie(APP_COOKIE_NAME, result.token, {
          httpOnly: true,
          sameSite: "lax",
        });
        setCsrfCookie(res);
      } catch (error) {
        exchangeError = error;
      }
    }

    res.send(`<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Processing token...</title>
  </head>
  <body>
    <p>${
      exchangeError
        ? `Error: ${exchangeError.message}. <a href="/">Return home</a>`
        : "Processing token..."
    }</p>
    <script>
      (function() {
        var fragment = window.location.hash.substring(1);
        var params = new URLSearchParams(fragment);
        var token = params.get('token');
        if (!token) {
          if (${hasCode ? "true" : "false"}) {
            window.location.replace('/home');
            return;
          }
          document.body.innerHTML = '<p>Missing token. <a href="/">Return home</a></p>';
          return;
        }
        fetch('/oauth/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: token })
        }).then(function() {
          window.location.replace('/home');
        }).catch(function() {
          document.body.innerHTML = '<p>Unable to store token. <a href="/">Return home</a></p>';
        });
      })();
    </script>
  </body>
</html>`);
  });

  app.post("/oauth/token", (req, res) => {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: "Missing token" });
    }
    const payload = verifyAuthToken(token);
    if (!payload) {
      return res.status(400).json({ error: "Invalid token" });
    }
    // Enforce required scopes on OAuth tokens coming from implicit flow
    const scopeStr = typeof payload.scope === "string" ? payload.scope : "";
    const scopes = scopeStr.split(/\s+/).filter(Boolean);
    if (!(scopes.includes("name") && scopes.includes("email"))) {
      return res.status(400).json({ error: "insufficient_scope" });
    }
    res.cookie(APP_COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: "lax",
    });
    setCsrfCookie(res);
    res.json({ success: true });
  });

  if (fs.existsSync(CLIENT_BUILD_DIR)) {
    app.use(express.static(CLIENT_BUILD_DIR));
  }

  const spaRoutes = [
    "/",
    "/home",
    "/login",
    "/signup",
    "/local/login",
    "/local/signup",
    "/admin",
  ];

  spaRoutes.forEach((route) => {
    app.get(route, (req, res) => sendAppShell(res));
  });

  app.get("/invite/:token", (req, res) => sendAppShell(res));

  app.get("*", (req, res, next) => {
    if (
      req.path.startsWith("/api") ||
      req.path.startsWith("/uploads") ||
      req.path.startsWith("/oauth")
    ) {
      return next();
    }
    return sendAppShell(res);
  });

  return new Promise((resolve) => {
    const server = app.listen(port, () => resolve(server));
  });
}
