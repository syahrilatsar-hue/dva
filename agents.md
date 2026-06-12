# Project Identity
- A deliberately vulnerable multi-app demo showcasing a custom OAuth flow and a tenant-scoped task manager.
- Everything runs under Node.js/Express with in-memory persistence.
- Security hardening is explicitly *not* the goal; many surfaces (framing, messaging, redirect handling) are intentionally lax for demonstration/testing.

# App Surfaces
## 1. OAuth Server (`src/oauth/server.js`)
- GET-driven authorize endpoint with `response_type` values `code`, `token`, or `code,token` (comma-separated) and optional `response_mode=query|fragment`.
- `state` parameter accepted but ignored; persists purely for parity.
- Supports `prompt=user_interaction|none`. `user_interaction` shows a consent page unless `decision=skip`; `none` skips UI and errors with `login_required` if no session.
- Issues one-time authorization codes stored in-memory and JWT access tokens signed via `JWT_SECRET`.
- Redirect validation allows the configured `APP_BASE_URL` and any subdomain under `/oauth/...`. Incoming `redirect_uri` values are URL-decoded before comparison.
- OAuth session maintained with `oauth_session` cookie; logout clears both server state and cookie.
- All pages disable `X-Frame-Options` and set `Content-Security-Policy: frame-ancestors *` so the UI is universally frameable.

## 2. Task Manager App (`src/app/server.js` + `client/` React SPA)
- Express now exposes JSON APIs consumed by the React frontend (`client/src`).
- Session bootstrap lives at `/api/session`; React handles routing (`/`, `/login`, `/home`, `/admin`, `/invite/:token`, etc.).
- `/oauth/login?code=` exchanges codes for JWTs; `/oauth/token` handles implicit tokens received via fragment. The SPA links users to these endpoints when needed.
- Password flows:
  - `/api/auth/local/signup` / `/api/auth/local/login` create or authenticate username/password users and issue the JWT cookie.
  - `/api/auth/admin/signup` mirrors the former server-rendered admin signup flow, creating a tenant + admin membership.
- Admin JSON APIs live under `/api/admin/*` for members, invitations, uploads, and profile content.
- Tracker iframe config is delivered via the session payload; the SPA renders the hidden iframe and posts `{ type: 'parent-location', href }` once on load.

### Redirect Helper
- `/redirect?path=...` still performs an unvalidated 302 to the provided path **only if** the user already has an authenticated session; the SPA relies on this helper after local and invitation logins.

## 3. Tracker Iframe App (`src/tracker/server.js`)
- Standalone Express server used when running locally.
- Receives `postMessage` calls, records parent URLs + origins in `localStorage`, and displays them.
- Also frameable to ensure it can sit inside the main app or elsewhere.
- Start-up honours `TRACKER_RUN_SERVER` – default `true`, set to `false` to skip bundling the tracker when delegating to an external host.

# Environment & Deployment Notes
- `APP_BASE_URL` and `OAUTH_BASE_URL` must reflect public origins; the OAuth server derives allowed redirects from `APP_BASE_URL` and its subdomains.
- `TRACKER_IFRAME_URL` should be pointed at the domain/subdomain that should capture parent locations; omit to use the bundled tracker (`TRACKER_BASE_URL` + `/collector`).
- `TRACKER_BASE_URL`/`TRACKER_PORT` matter only when hosting the helper locally; remote trackers ignore these.
- Default ports: OAuth `4000`, Task app `3000`, Tracker `5002`.
- All persistence is memory-only; restarts reset users/tenants/tasks/invites/codes.

# Intended LLM Perspective
- Treat the project as a testbed for discussing OAuth flows, weak framing policies, redirect validation edge cases, and cross-origin messaging.
- The exposed vulnerabilities (e.g., universal framing, location exfiltration, lax state handling) are intentional and should not be “fixed” unless explicitly requested.
- When reasoning about auth, remember: codes tied to sanitized redirect URIs, tokens stored in cookies, and state values have no protective effect.
- When extending features, maintain compatibility with the described OAuth contract and the tracker integration.
