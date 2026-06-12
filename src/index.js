import { startOAuthServer } from './oauth/server.js';
import { startTaskApp } from './app/server.js';
import { startTrackerServer } from './tracker/server.js';

function parsePort(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

async function main() {
  const oauthPort = parsePort(process.env.OAUTH_PORT, 4000);
  const appPort = parsePort(process.env.APP_PORT, 3000);
  const trackerPort = parsePort(process.env.TRACKER_PORT, 5002);

  await startOAuthServer({ port: oauthPort });
  await startTaskApp({ port: appPort });

  const trackerBaseEnv = process.env.TRACKER_BASE_URL?.trim();
  const trackerIframeEnv = process.env.TRACKER_IFRAME_URL?.trim();
  const trackerBaseFallback = `http://localhost:${trackerPort}`;
  const trackerBase = trackerBaseEnv || trackerBaseFallback;

  let trackerStarted = false;
  const trackerRunSetting = process.env.TRACKER_RUN_SERVER?.trim().toLowerCase();
  const shouldStartLocalTracker = trackerRunSetting !== 'false';
  if (shouldStartLocalTracker) {
    await startTrackerServer({ port: trackerPort });
    trackerStarted = true;
  }

  const oauthBase = process.env.OAUTH_BASE_URL || `http://localhost:${oauthPort}`;
  const appBase = process.env.APP_BASE_URL || `http://localhost:${appPort}`;
  console.log(`OAuth server running on ${oauthBase}`);
  console.log(`Task manager app running on ${appBase}`);
  const trackerTarget = trackerIframeEnv || trackerBase;
  if (trackerStarted) {
    console.log(`Tracker iframe app running on ${trackerTarget}`);
  } else {
    console.log(`Tracker iframe app disabled (configured for ${trackerTarget})`);
  }
}

main().catch((error) => {
  console.error('Failed to start servers', error);
  process.exit(1);
});
