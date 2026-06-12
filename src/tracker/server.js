import express from "express";

const DEFAULT_PORT = 5002;

function renderIndexPage() {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Tracker Index</title>
  </head>
  <body>
    <h1>Tracker Index</h1>
    <script>
      let redirectParams = new URLSearchParams(window.location.search);
      let redirectUrl = redirectParams.get("redirect_url");
      if (redirectUrl) {
        window.location.href = redirectUrl;
      }
    </script>
  </body>
</html>`;
}

function renderCollectorPage() {
  return `<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Tracker Frame</title>
    <style>
      body {
        margin: 0;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: #0f172a;
        color: #e2e8f0;
        display: flex;
        align-items: center;
        justify-content: center;
        min-height: 100vh;
      }

      .card {
        background: rgba(15, 23, 42, 0.8);
        border-radius: 12px;
        padding: 24px;
        width: min(420px, 90vw);
        box-shadow: 0 20px 45px rgba(15, 23, 42, 0.5);
        border: 1px solid rgba(148, 163, 184, 0.2);
      }

      h1 {
        margin: 0 0 12px;
        font-size: 20px;
        font-weight: 600;
        letter-spacing: 0.5px;
      }

      p {
        margin: 0 0 16px;
        font-size: 14px;
        color: #94a3b8;
        line-height: 1.6;
      }

      ul {
        list-style: none;
        margin: 0;
        padding: 0;
        display: grid;
        gap: 12px;
        max-height: 220px;
        overflow-y: auto;
      }

      li {
        background: rgba(15, 23, 42, 0.6);
        border-radius: 8px;
        padding: 12px;
        font-size: 13px;
        line-height: 1.5;
        border: 1px solid rgba(148, 163, 184, 0.15);
      }

      .entry-origin {
        color: #38bdf8;
        font-weight: 600;
      }

      .entry-time {
        display: block;
        color: #94a3b8;
        margin-top: 4px;
        font-size: 12px;
      }
    </style>
  </head>
  <body>
    <div class="card">
      <h1>Tracker Iframe</h1>
      <p>Capturing the parent frame URL and persisting it locally.</p>
      <div id="tracker-log"></div>
    </div>
    <script>
      (function () {
        var STORAGE_KEY = "tracker.parentUrl";
        var logElement = document.getElementById("tracker-log");

        function readValue() {
          try {
            var raw = localStorage.getItem(STORAGE_KEY);
            return typeof raw === "string" ? raw : "";
          } catch (error) {
            return "";
          }
        }

        function writeValue(value) {
          try {
            localStorage.setItem(STORAGE_KEY, value);
          } catch (error) {
            // Ignore storage quota issues.
          }
        }

        function render(value) {
          if (!logElement) {
            return;
          }
          if (!value) {
            logElement.innerHTML = '<div>No capture stored.</div>';
            return;
          }
          var escapedHref = String(value)
            // .replace(/&/g, "&amp;")
            // .replace(/</g, "&lt;")
            // .replace(/>/g, "&gt;");
          logElement.innerHTML = '<div><strong>Stored URL:</strong><br />' + escapedHref + '</div>';
        }

        function handleMessage(event) {
          var data = event.data || {};
          if (typeof data !== "object" || data.type !== "parent-location") {
            return;
          }
          if (!data.href) {
            return;
          }
          var urlValue = String(data.href);
          writeValue(urlValue);
          render(urlValue);
        }

        window.addEventListener("message", handleMessage);
        render(readValue());
        try {
          window.parent.postMessage({ type: "tracker-ready" }, "*");
        } catch (error) {
          // Ignore cross-origin errors when notifying parent
        }
      })();
    </script>
  </body>
</html>`;
}

export async function startTrackerServer({ port = DEFAULT_PORT } = {}) {
  const app = express();

  app.use((req, res, next) => {
    res.removeHeader("X-Frame-Options");
    res.setHeader("Content-Security-Policy", "frame-ancestors *");
    next();
  });

  app.get("/health", (req, res) => {
    res.json({ status: "ok" });
  });

  app.get("/collector", (req, res) => {
    res.send(renderCollectorPage());
  });

  app.get("/", (req, res) => {
    res.send(renderIndexPage());
  });

  return new Promise((resolve) => {
    const server = app.listen(port, () => resolve(server));
  });
}
