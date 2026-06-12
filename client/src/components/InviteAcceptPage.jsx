import React, { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { apiGet, apiPost } from '../api.js';
import { useSession } from '../App.jsx';

export default function InviteAcceptPage() {
  const { token } = useParams();
  const { session, loading, refreshSession } = useSession();
  const navigate = useNavigate();
  const [invite, setInvite] = useState(null);
  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const [error, setError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (!loading && session?.authenticated) {
      navigate('/home', { replace: true });
    }
  }, [loading, session, navigate]);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await apiGet(`/api/invitations/${token}`);
        setInvite(data);
        setForm((prev) => ({ ...prev, email: data.email || '' }));
        setLoaded(true);
      } catch (err) {
        setError(err.message);
        setLoaded(true);
      }
    };
    load();
  }, [token]);

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const response = await apiPost(`/api/invitations/${token}`, form);
      await refreshSession();
      navigate(response.redirect || '/home', { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  if (!loaded) {
    return <div className="card"><p>Loading invitation…</p></div>;
  }

  if (error) {
    return <div className="card"><div className="error">{error}</div></div>;
  }

  if (!invite) {
    return <div className="card"><p>Invitation not found.</p></div>;
  }

  return (
    <div className="card">
      <h1>Join {invite.tenantName || 'workspace'}</h1>
      <p>Complete your profile to join.</p>
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
          <label htmlFor="password">Password</label>
          <input id="password" name="password" type="password" value={form.password} onChange={handleChange} required />
        </div>
        <button type="submit" disabled={submitting}>
          {submitting ? 'Joining…' : 'Create account'}
        </button>
      </form>
    </div>
  );
}
