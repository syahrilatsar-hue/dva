import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useSession } from '../App.jsx';

export default function OAuthEntryPage() {
  const { session, loading } = useSession();
  const navigate = useNavigate();

  if (loading) {
    return <div className="card"><p>Loading...</p></div>;
  }

  if (session?.authenticated) {
    navigate('/home', { replace: true });
    return null;
  }

  const authorizeUrl = session?.oauthAuthorizeUrl;

  function handleContinue(e) {
    e.preventDefault();
    if (!authorizeUrl) return;
    try {
      const u = new URL(authorizeUrl);
      const state = u.searchParams.get('state') || '';
      // Store state in a cookie so the backend can validate on redirect
      // SameSite=Lax so it will be sent on the first-party redirect back
      document.cookie = `oauth_state=${encodeURIComponent(state)}; Path=/; SameSite=Lax`;
    } catch (_e) {}
    window.location.assign(authorizeUrl);
  }

  return (
    <div className="card">
      <h1>Sign in with OAuth</h1>
      <p>Authenticate via the OAuth provider.</p>
      <p>
        <button type="button" disabled={!authorizeUrl} onClick={handleContinue}>
          Continue with OAuth
        </button>
      </p>
      <p className="helper-text">
        Prefer username/password?{' '}
        <a
          href="/local/login"
          onClick={(e) => {
            e.preventDefault();
            navigate('/local/login');
          }}
        >
          Use the password flow
        </a>
      </p>
    </div>
  );
}
