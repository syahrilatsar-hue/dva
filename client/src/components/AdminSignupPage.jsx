import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiPost } from '../api.js';
import { useSession } from '../App.jsx';

export default function AdminSignupPage() {
  const { session, loading, refreshSession } = useSession();
  const navigate = useNavigate();
  const [form, setForm] = useState({ name: '', email: '', password: '', organization: '', username: '' });
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
      const response = await apiPost('/api/auth/admin/signup', form);
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
      <h1>Create an admin account</h1>
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
          <input id="username" name="username" type="text" value={form.username} onChange={handleChange} />
          <div className="helper-text">Leave blank to auto-generate.</div>
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input id="password" name="password" type="password" value={form.password} onChange={handleChange} required />
        </div>
        <div className="form-group">
          <label htmlFor="organization">Organization name</label>
          <input
            id="organization"
            name="organization"
            type="text"
            value={form.organization}
            onChange={handleChange}
            required
          />
        </div>
        <button type="submit" disabled={submitting}>
          {submitting ? 'Creating…' : 'Create organization'}
        </button>
      </form>
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
    </div>
  );
}
