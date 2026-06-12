import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiPost } from '../api.js';
import { useSession } from '../App.jsx';

export default function LocalLoginPage() {
  const { session, loading, refreshSession } = useSession();
  const navigate = useNavigate();
  const [form, setForm] = useState({ username: '', password: '' });
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  if (!loading && session?.authenticated) {
    navigate('/home', { replace: true });
    return null;
  }

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const response = await apiPost('/api/auth/local/login', form);
      await refreshSession();
      navigate(response.redirect || '/home');
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="card">
      <h1>Password sign-in</h1>
      {error ? <div className="error">{error}</div> : null}
      <p className="helper-text">Enter your username and password to continue.</p>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <input
            id="username"
            name="username"
            type="text"
            value={form.username}
            onChange={handleChange}
            autoComplete="username"
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            value={form.password}
            onChange={handleChange}
            autoComplete="current-password"
            required
          />
        </div>
        <button type="submit" disabled={submitting}>
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
      <p>
        Need an account?{' '}
        <a
          href="/local/signup"
          onClick={(e) => {
            e.preventDefault();
            navigate('/local/signup');
          }}
        >
          Create one with username/password
        </a>
      </p>
      <p>
        Prefer OAuth?{' '}
        <a
          href="/login"
          onClick={(e) => {
            e.preventDefault();
            navigate('/login');
          }}
        >
          Use the OAuth flow
        </a>
      </p>
    </div>
  );
}
