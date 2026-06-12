import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSession } from '../App.jsx';

export default function LandingPage() {
  const { session, loading } = useSession();
  const navigate = useNavigate();

  useEffect(() => {
    if (!loading && session?.authenticated) {
      navigate('/home', { replace: true });
    }
  }, [loading, session, navigate]);

  if (loading) {
    return <div className="card"><p>Loading...</p></div>;
  }

  return (
    <div className="card">
      <h1>Stay on top of tasks across your team</h1>
      <p>Create an organization, invite teammates, and track progress.</p>
      <p>
        <button type="button" onClick={() => navigate('/signup')}>
          Create admin account
        </button>
      </p>
      <p>
        Already have an account?{' '}
        <a
          href="/login"
          onClick={(e) => {
            e.preventDefault();
            navigate('/login');
          }}
        >
          Sign in with OAuth
        </a>
      </p>
      <p>
        Prefer username/password?{' '}
        <a
          href="/local/login"
          onClick={(e) => {
            e.preventDefault();
            navigate('/local/login');
          }}
        >
          Use password login
        </a>
      </p>
      <p>
        Need to create a password-only account?{' '}
        <a
          href="/local/signup"
          onClick={(e) => {
            e.preventDefault();
            navigate('/local/signup');
          }}
        >
          Sign up with username/password
        </a>
      </p>
    </div>
  );
}
