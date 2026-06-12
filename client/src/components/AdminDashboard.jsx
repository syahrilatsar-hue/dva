import React, { useCallback, useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { apiGet, apiPost } from '../api.js';
import { useSession } from '../App.jsx';

export default function AdminDashboard() {
  const { session } = useSession();
  const params = useParams();
  const routeUsername = params.username || '';
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [overview, setOverview] = useState(null);
  const [inviteEmail, setInviteEmail] = useState('');
  const [aboutMe, setAboutMe] = useState('');
  const [uploadResult, setUploadResult] = useState(null);
  const [message, setMessage] = useState(null);
  useEffect(() => {
    if (!message) return undefined;
    const id = setTimeout(() => setMessage(null), 4000);
    return () => clearTimeout(id);
  }, [message]);

  const encodeHtml = useCallback((value) =>
    String(value ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;')
      .replace(/\//g, '&#47;'),
  []);

  const decodeHtml = useCallback((value) => {
    if (!value) {
      return '';
    }
    return String(value)
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, '\'')
      .replace(/&#47;/g, '/')
      .replace(/&amp;/g, '&');
  }, []);

  const load = useCallback(async (usernameValue) => {
    if (!usernameValue) {
      setError('User not specified');
      setOverview(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      let decoded = usernameValue;
      try {
        decoded = decodeURIComponent(usernameValue);
      } catch (_error) {
        // keep original if decoding fails
      }
      const data = await apiGet(`/api/${decoded}/details`);
      setOverview(data);
      setAboutMe(decodeHtml(data.aboutMe || ''));
      setError(null);
      setMessage(null);
    } catch (err) {
      setOverview(null);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [decodeHtml]);

  useEffect(() => {
    if (!session?.user?.username) {
      return;
    }
    if (!routeUsername) {
      setOverview(null);
      setError('User not specified');
      setLoading(false);
      return;
    }
    setError(null);
    load(routeUsername);
  }, [routeUsername, load, session?.user?.username]);

  const submitInvite = async (event) => {
    event.preventDefault();
    if (!inviteEmail.trim()) {
      return;
    }
    try {
      const response = await apiPost('/api/admin/invitations', { email: inviteEmail.trim() });
      setInviteEmail('');
      setMessage(`Invitation created: ${response.invitation.inviteLink}`);
      if (routeUsername) {
        await load(routeUsername);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const submitAbout = async (event) => {
    event.preventDefault();
    try {
      await apiPost('/api/admin/about', { aboutMe: encodeHtml(aboutMe) });
      setMessage('About me updated');
      if (routeUsername) {
        await load(routeUsername);
      }
    } catch (err) {
      setError(err.message);
    }
  };

  const submitUpload = async (event) => {
    event.preventDefault();
    const file = event.target.elements.attachment.files[0];
    if (!file) {
      setError('Please choose a file');
      return;
    }
    const formData = new FormData();
    formData.append('attachment', file);
    try {
      const response = await apiPost('/api/admin/upload', formData);
      setUploadResult(response.fileUrl);
      setMessage('File uploaded successfully');
    } catch (err) {
      setError(err.message);
    }
  };

  if (loading) {
    return <div className="card"><p>Loading admin dashboard...</p></div>;
  }

  if (error) {
    return <div className="card"><div className="error">{error}</div></div>;
  }

  if (!overview) {
    return <div className="card"><p>No data available.</p></div>;
  }

  return (
    <div>
      {message ? <div className="success">{message}</div> : null}
      <div className="card">
        <h1>{overview.tenant?.name || 'Workspace'} admin</h1>
        <p>Invite teammates, upload resources, and customize your profile.</p>
      </div>

      <div className="card">
        <h2>Invite teammates</h2>
        <form onSubmit={submitInvite}>
          <div className="form-group">
            <label htmlFor="inviteEmail">Email address</label>
            <input
              id="inviteEmail"
              name="inviteEmail"
              type="email"
              value={inviteEmail}
              onChange={(event) => setInviteEmail(event.target.value)}
              required
            />
          </div>
          <button type="submit">Generate invite link</button>
        </form>
        {overview.invitations?.length ? (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Created</th>
                  <th>Status</th>
                  <th>Invite link</th>
                </tr>
              </thead>
              <tbody>
                {overview.invitations.map((invitation) => (
                  <tr key={invitation.id}>
                    <td>{invitation.email}</td>
                    <td>{new Date(invitation.createdAt).toLocaleString()}</td>
                    <td>{invitation.usedAt ? 'Used' : 'Pending'}</td>
                    <td>
                      {invitation.inviteLink ? <code>{invitation.inviteLink}</code> : '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p>No pending invites.</p>
        )}
      </div>

      <div className="card">
      <h2>About me</h2>
      <div
        className="about-display"
        dangerouslySetInnerHTML={{ __html: overview.aboutMe || '' }}
      />
      <form onSubmit={submitAbout}>
        <div className="form-group">
          <label htmlFor="aboutMe">Profile blurb</label>
          <textarea
              id="aboutMe"
              name="aboutMe"
              className="rich-editor"
              rows={6}
              value={aboutMe}
              onChange={(event) => setAboutMe(event.target.value)}
            />
          </div>
          <button type="submit">Save profile</button>
        </form>
      </div>

      <div className="card">
        <h2>Upload asset</h2>
        <form onSubmit={submitUpload}>
          <div className="form-group">
            <label htmlFor="attachment">Attachment</label>
            <input id="attachment" name="attachment" type="file" accept="image/*" />
          </div>
          <button type="submit">Upload file</button>
        </form>
        {uploadResult ? (
          <p>
            Uploaded file URL: <code>{uploadResult}</code>
          </p>
        ) : null}
      </div>

      <div className="card">
        <h2>Members</h2>
        {overview.members?.length ? (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Email</th>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Joined</th>
                </tr>
              </thead>
              <tbody>
                {overview.members.map((member) => (
                  <tr key={member.id}>
                    <td>{member.user?.name || '—'}</td>
                    <td>{member.user?.email || '—'}</td>
                    <td>{member.user?.username || '—'}</td>
                    <td>{member.role}</td>
                    <td>{new Date(member.joinedAt).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p>No members yet.</p>
        )}
      </div>
    </div>
  );
}
