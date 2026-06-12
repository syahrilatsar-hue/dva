import React, { useEffect, useState } from "react";
import { apiGet, apiPost } from "../api.js";
import { useSession } from "../App.jsx";

export default function HomePage() {
  const { session, setSession } = useSession();
  const [tasks, setTasks] = useState([]);
  const [tenant, setTenant] = useState(null);
  const [error, setError] = useState(null);
  const [form, setForm] = useState({ title: "", description: "" });
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [accountForm, setAccountForm] = useState({ email: "", username: "" });
  const [accountError, setAccountError] = useState(null);
  const [accountSuccess, setAccountSuccess] = useState(null);
  const [accountSubmitting, setAccountSubmitting] = useState(false);

  useEffect(() => {
    const load = async () => {
      try {
        const data = await apiGet("/api/tasks");
        setTasks(data.tasks || []);
        setTenant(data.tenant || null);
        setError(null);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };
    load();
  }, []);

  useEffect(() => {
    setAccountForm({
      email: session?.user?.email || "",
      username: session?.user?.username || "",
    });
  }, [session?.user?.email, session?.user?.username]);

  // Note: Tracking iframe functionality is now handled by the TrackerFrame component in App.jsx
  // This ensures the tracker URL is dynamically configured from the server session

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleAccountChange = (event) => {
    const { name, value } = event.target;
    setAccountForm((prev) => ({ ...prev, [name]: value }));
    setAccountSuccess(null);
  };

  const handleAccountSubmit = async (event) => {
    event.preventDefault();
    setAccountError(null);
    setAccountSuccess(null);
    if (!session?.csrfToken) {
      setAccountError("CSRF token missing. Refresh the page and try again.");
      return;
    }
    if (
      (!accountForm.email || !accountForm.email.trim()) &&
      (!accountForm.username || !accountForm.username.trim())
    ) {
      setAccountError("Provide a new email or username.");
      return;
    }
    setAccountSubmitting(true);
    try {
      const response = await apiPost("/api/auth/change-email", {
        email: accountForm.email,
        username: accountForm.username,
        csrfToken: session.csrfToken,
      });
      setAccountSuccess("Account updated.");
      setSession((prev) => ({
        ...(prev || {}),
        user: response.user,
        memberships: response.memberships,
        csrfToken: response.csrfToken || session.csrfToken,
      }));
      setAccountForm({
        email: response.user?.email || "",
        username: response.user?.username || "",
      });
    } catch (err) {
      setAccountError(err.message);
    } finally {
      setAccountSubmitting(false);
    }
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!form.title.trim()) {
      setError("Title is required");
      return;
    }
    setSubmitting(true);
    try {
      const response = await apiPost("/api/tasks", form);
      setTasks((prev) => [response.task, ...prev]);
      setForm({ title: "", description: "" });
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  };

  const toggleTask = async (taskId) => {
    try {
      const response = await apiPost(`/api/tasks/${taskId}/toggle`);
      setTasks((prev) =>
        prev.map((task) =>
          task.id === taskId ? { ...task, ...response.task } : task
        )
      );
    } catch (err) {
      setError(err.message);
    }
  };

  if (loading) {
    return (
      <div className="card">
        <p>Loading tasks...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card">
        <div className="error">{error}</div>
      </div>
    );
  }

  return (
    <div>
      <div className="card">
        <h1>{tenant?.name || "Workspace"} Tasks</h1>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="title">Task title</label>
            <input
              id="title"
              name="title"
              type="text"
              value={form.title}
              onChange={handleChange}
              placeholder="Enter task title"
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="description">Description</label>
            <textarea
              id="description"
              name="description"
              rows={3}
              value={form.description}
              onChange={handleChange}
              placeholder="Enter task description (optional)"
            />
          </div>
          <button type="submit" disabled={submitting}>
            {submitting ? "Adding…" : "Add task"}
          </button>
        </form>
      </div>

      <div className="card">
        <h2>Account settings</h2>
        <form onSubmit={handleAccountSubmit}>
          <div className="form-group">
            <label htmlFor="account-email">Login email</label>
            <input
              id="account-email"
              name="email"
              type="email"
              value={accountForm.email}
              onChange={handleAccountChange}
              placeholder="name@example.com"
            />
          </div>
          <div className="form-group">
            <label htmlFor="account-username">Username</label>
            <input
              id="account-username"
              name="username"
              type="text"
              value={accountForm.username}
              onChange={handleAccountChange}
              placeholder="letters and numbers only"
            />
          </div>
          {accountError ? <div className="error">{accountError}</div> : null}
          {accountSuccess ? (
            <div className="success">{accountSuccess}</div>
          ) : null}
          <button
            type="submit"
            disabled={accountSubmitting || !session?.csrfToken}
          >
            {accountSubmitting ? "Saving…" : "Save changes"}
          </button>
          <p className="helper-text">
            Update the email or username used to sign in. Leave a field
            unchanged to keep the current value.
          </p>
        </form>
      </div>

      <div className="card">
        <h2>Current tasks</h2>
        {tasks.length === 0 ? (
          <p>No tasks yet.</p>
        ) : (
          <ul>
            {tasks.map((task) => (
              <li
                key={task.id}
                className={task.completed ? "task-completed" : ""}
              >
                <strong>{task.title}</strong>
                {task.description ? ` – ${task.description}` : ""}
                <form
                  onSubmit={(event) => {
                    event.preventDefault();
                    toggleTask(task.id);
                  }}
                  style={{ display: "inline" }}
                >
                  <button type="submit" className="secondary">
                    {task.completed ? "Mark incomplete" : "Mark complete"}
                  </button>
                </form>
                {task.completed && task.completedAt ? (
                  <div className="completion-time">
                    Completed at {new Date(task.completedAt).toLocaleString()}
                  </div>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
