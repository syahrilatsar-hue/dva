import React, {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import { apiGet, apiPost } from "./api.js";
import LandingPage from "./components/LandingPage.jsx";
import HomePage from "./components/HomePage.jsx";
import LocalLoginPage from "./components/LocalLoginPage.jsx";
import LocalSignupPage from "./components/LocalSignupPage.jsx";
import AdminSignupPage from "./components/AdminSignupPage.jsx";
import AdminDashboard from "./components/AdminDashboard.jsx";
import InviteAcceptPage from "./components/InviteAcceptPage.jsx";
import OAuthEntryPage from "./components/OAuthEntryPage.jsx";

const SessionContext = createContext(null);

export function useSession() {
  return useContext(SessionContext);
}

const TRACKER_IFRAME_NAME = "tracking-iframe";
const TRACKER_IFRAME_DATA_VALUE = "collector";

function TrackerFrame({ trackerUrl }) {
  const frameRef = React.useRef(null);
  const routeLocation = useLocation();

  const postParentLocation = React.useCallback(() => {
    if (!trackerUrl) {
      return;
    }
    const payload = { type: "parent-location", href: window.location.href };

    const targets = [];
    try {
      if (TRACKER_IFRAME_NAME && window.frames[TRACKER_IFRAME_NAME]) {
        targets.push(window.frames[TRACKER_IFRAME_NAME]);
      }
    } catch (_error) {}

    try {
      const total = window.frames.length;
      for (let index = 0; index < total; index += 1) {
        const candidate = window.frames[index];
        if (!candidate || targets.includes(candidate)) {
          continue;
        }
        try {
          const element = candidate.frameElement;
          if (element?.dataset?.trackerFrame === TRACKER_IFRAME_DATA_VALUE) {
            targets.unshift(candidate);
            continue;
          }
        } catch (_innerError) {}
        targets.push(candidate);
      }
    } catch (_error) {}

    targets.forEach((target) => {
      if (!target || typeof target.postMessage !== "function") {
        return;
      }
      try {
        target.postMessage(payload, "*");
      } catch (_error) {}
    });
  }, [trackerUrl]);

  React.useEffect(() => {
    if (!trackerUrl) {
      return undefined;
    }

    const frameNode = frameRef.current;
    if (frameNode) {
      frameNode.setAttribute("name", TRACKER_IFRAME_NAME);
      frameNode.dataset.trackerFrame = TRACKER_IFRAME_DATA_VALUE;
      const duplicates = document.querySelectorAll(
        `iframe[data-tracker-frame="${TRACKER_IFRAME_DATA_VALUE}"]`
      );
      duplicates.forEach((node) => {
        if (node !== frameNode && node.parentNode) {
          node.parentNode.removeChild(node);
        }
      });
    }

    const trackerOrigin = (() => {
      try {
        return new URL(trackerUrl).origin;
      } catch (_error) {
        return "*";
      }
    })();

    const handleMessage = (event) => {
      if (!event?.data) {
        return;
      }
      if (trackerOrigin !== "*" && event.origin !== trackerOrigin) {
        return;
      }
      if (event.data.type === "tracker-ready") {
        postParentLocation();
      }
    };

    const handleLoad = () => {
      postParentLocation();
    };

    window.addEventListener("message", handleMessage);
    frameNode?.addEventListener("load", handleLoad);

    postParentLocation();
    const t1 = setTimeout(postParentLocation, 100);
    const t2 = setTimeout(postParentLocation, 500);
    const t3 = setTimeout(postParentLocation, 1500);
    const raf = requestAnimationFrame(() => postParentLocation());

    const onWindowLoad = () => postParentLocation();
    const addedWindowLoadListener = document.readyState !== "complete";
    if (addedWindowLoadListener) {
      window.addEventListener("load", onWindowLoad, { once: true });
    }
    const onPageShow = () => postParentLocation();
    window.addEventListener("pageshow", onPageShow);
    const onVisibility = () => {
      if (!document.hidden) {
        postParentLocation();
      }
    };
    document.addEventListener("visibilitychange", onVisibility);

    return () => {
      window.removeEventListener("message", handleMessage);
      frameNode?.removeEventListener("load", handleLoad);
      if (addedWindowLoadListener) {
        window.removeEventListener("load", onWindowLoad);
      }
      window.removeEventListener("pageshow", onPageShow);
      document.removeEventListener("visibilitychange", onVisibility);
      clearTimeout(t1);
      clearTimeout(t2);
      clearTimeout(t3);
      cancelAnimationFrame(raf);
    };
  }, [trackerUrl, postParentLocation]);

  React.useEffect(() => {
    if (!trackerUrl) {
      return;
    }
    postParentLocation();
  }, [trackerUrl, routeLocation, postParentLocation]);

  if (!trackerUrl) {
    return null;
  }

  return (
    <iframe
      ref={frameRef}
      src={trackerUrl}
      id="tracking-iframe"
      name={TRACKER_IFRAME_NAME}
      data-tracker-frame={TRACKER_IFRAME_DATA_VALUE}
      style={{
        width: 1,
        height: 1,
        border: 0,
        position: "absolute",
        opacity: 0,
        pointerEvents: "none",
      }}
      tabIndex={-1}
      aria-hidden="true"
    />
  );
}

function AppShell({ children }) {
  const { session, loading, logout } = useSession();
  const location = useLocation();
  const navigate = useNavigate();
  const isAuth = session?.authenticated;
  const user = session?.user;
  const adminPath = user?.username
    ? `/admin/${encodeURIComponent(user.username)}`
    : "/admin";

  return (
    <div className="app-shell">
      <header>
        <div className="logo">Task Manager</div>
        <nav>
          {isAuth && user ? (
            <>
              <div className="user-info">
                <div className="user-avatar">
                  {(user.name || user.email || "?").charAt(0).toUpperCase()}
                </div>
                <span>{user.name || user.email}</span>
              </div>
              <a
                href="/home"
                onClick={(e) => {
                  e.preventDefault();
                  if (location.pathname !== "/home") {
                    navigate("/home");
                  }
                }}
              >
                Home
              </a>
              {user.isAdmin ? (
                <>
                  <a
                    href={adminPath}
                    onClick={(e) => {
                      e.preventDefault();
                      if (location.pathname !== adminPath) {
                        navigate(adminPath);
                      }
                    }}
                  >
                    Admin
                  </a>
                  <a href="/oauth/token-helper">API Docs & Token</a>
                </>
              ) : null}
              <a
                href="/logout"
                onClick={(event) => {
                  event.preventDefault();
                  logout();
                }}
              >
                Logout
              </a>
            </>
          ) : (
            <a
              href="/login"
              onClick={(e) => {
                e.preventDefault();
                if (location.pathname !== "/login") {
                  navigate("/login");
                }
              }}
            >
              Login
            </a>
          )}
        </nav>
      </header>
      <main>
        {loading ? (
          <div className="card">
            <p>Loading...</p>
          </div>
        ) : (
          children
        )}
      </main>
    </div>
  );
}

function ProtectedRoute({ children }) {
  const { session, loading } = useSession();
  if (loading) {
    return (
      <div className="card">
        <p>Loading...</p>
      </div>
    );
  }
  if (!session?.authenticated) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

function AdminRoute({ children }) {
  const { session, loading } = useSession();
  if (loading) {
    return (
      <div className="card">
        <p>Loading...</p>
      </div>
    );
  }
  if (!session?.authenticated) {
    return <Navigate to="/login" replace />;
  }
  if (!session?.user?.isAdmin) {
    return <Navigate to="/home" replace />;
  }
  return children;
}

function AdminRedirect() {
  const { session } = useSession();
  const username = session?.user?.username || "";
  if (!username) {
    return (
      <div className="card">
        <div className="error">Admin username unavailable.</div>
      </div>
    );
  }
  const adminPath = `/admin/${encodeURIComponent(username)}`;
  return <Navigate to={adminPath} replace />;
}

export default function App() {
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [trackerMessage, setTrackerMessage] = useState("");
  const navigate = useNavigate();

  const refreshSession = React.useCallback(async () => {
    setLoading(true);
    try {
      const data = await apiGet("/api/session");
      setSession(data);
      setError(null);
    } catch (err) {
      setSession(null);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refreshSession();
  }, []);

  useEffect(() => {
    const trackerOrigin = (() => {
      if (!session?.trackerIframeUrl) {
        return null;
      }
      try {
        return new URL(session.trackerIframeUrl).origin;
      } catch (_error) {
        return null;
      }
    })();

    if (!trackerOrigin) {
      return;
    }

    const handleTrackerMessage = (event) => {
      // Origin check - ONLY trust the tracker iframe origin
      if (event.origin !== trackerOrigin) {
        return;
      }

      if (!event.data) {
        return;
      }

      // Parse JSON string if needed
      let data = event.data;
      if (typeof data === "string") {
        try {
          data = JSON.parse(data);
        } catch (_error) {
          return;
        }
      }

      // Check for message property and dangerously set it
      if (data.message !== undefined) {
        setTrackerMessage(data.message);
      }
    };

    window.addEventListener("message", handleTrackerMessage);

    return () => {
      window.removeEventListener("message", handleTrackerMessage);
    };
  }, [session?.trackerIframeUrl]);

  const logout = React.useCallback(async () => {
    try {
      const response = await apiPost("/api/auth/logout");
      await refreshSession();
      if (response?.logoutUrl) {
        window.location.href = response.logoutUrl;
        return;
      }
      navigate("/login");
    } catch (err) {
      console.error(err);
    }
  }, [navigate, refreshSession]);

  const contextValue = useMemo(
    () => ({ session, setSession, refreshSession, loading, error, logout }),
    [session, loading, error, logout, refreshSession]
  );

  return (
    <SessionContext.Provider value={contextValue}>
      <TrackerFrame trackerUrl={session?.trackerIframeUrl} />
      {trackerMessage && (
        <div
          id="tracker-message-display"
          dangerouslySetInnerHTML={{ __html: trackerMessage }}
          style={{
            position: "fixed",
            bottom: "20px",
            right: "20px",
            padding: "10px",
            backgroundColor: "#fff",
            border: "1px solid #ccc",
            borderRadius: "4px",
            boxShadow: "0 2px 8px rgba(0,0,0,0.1)",
            maxWidth: "300px",
            zIndex: 9999,
          }}
        />
      )}
      <AppShell>
        <Routes>
          <Route index element={<LandingPage />} />
          <Route path="/login" element={<OAuthEntryPage />} />
          <Route path="/local/login" element={<LocalLoginPage />} />
          <Route path="/local/signup" element={<LocalSignupPage />} />
          <Route path="/signup" element={<AdminSignupPage />} />
          <Route
            path="/home"
            element={
              <ProtectedRoute>
                <HomePage />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin"
            element={
              <AdminRoute>
                <AdminRedirect />
              </AdminRoute>
            }
          />
          <Route
            path="/admin/:username"
            element={
              <AdminRoute>
                <AdminDashboard />
              </AdminRoute>
            }
          />
          <Route path="/invite/:token" element={<InviteAcceptPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell>
    </SessionContext.Provider>
  );
}
