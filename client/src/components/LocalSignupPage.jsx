import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiPost } from '../api.js';
import { useSession } from '../App.jsx';

export default function LocalSignupPage() {
  const { session, loading, refreshSession } = useSession();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: '', email: '', username: '', password: '' });
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
      const response = await apiPost('/api/auth/local/signup', form);
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
      <h1>Create password account</h1>
      {error ? <div className="error">{error}</div> : null}
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="name">Full name</label>
          <input id="name" name="name" type="text" value={form.name} onChange={handleChange} required />
        </div>
        <div className="form-group">
          <label htmlFor="email">Email</label>
          <input id="email" name="email" type="email" value={form.email} onChange={handleChange} required />
        </div>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <input
            id="username"
            name="username"
            type="text"
            value={form.username}
            onChange={handleChange}
            required
          />
          <div className="helper-text">Lowercase letters and numbers only; collisions auto-resolve.</div>
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            id="password"
            name="password"
            type="password"
            value={form.password}
            onChange={handleChange}
            required
          />
        </div>
        <button type="submit" disabled={submitting}>
          {submitting ? 'Creating…' : 'Create account'}
        </button>
      </form>
      <p>
        Already registered?{' '}
        <a
          href="/local/login"
          onClick={(e) => {
            e.preventDefault();
            navigate('/local/login');
          }}
        >
          Sign in with password
        </a>
      </p>
      <p>
        Need to create an admin organization?{' '}
        <a
          href="/signup"
          onClick={(e) => {
            e.preventDefault();
            navigate('/signup');
          }}
        >
          Use the admin signup flow
        </a>
      </p>
    </div>
  );
}
