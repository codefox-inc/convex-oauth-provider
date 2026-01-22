import { useAuthActions } from "@convex-dev/auth/react";
import { Authenticated, Unauthenticated, useQuery, useMutation } from "convex/react";
import { api } from "../convex/_generated/api";
import { useState } from "react";
import "./App.css";

type Task = {
  _id: string;
  title: string;
  description?: string;
  status: "pending" | "in_progress" | "done";
  priority?: "low" | "medium" | "high";
  dueDate?: string;
  createdAt: number;
};

function SignIn() {
  const { signIn } = useAuthActions();
  const [isLoading, setIsLoading] = useState(false);

  const handleSignIn = async () => {
    setIsLoading(true);
    try {
      await signIn("anonymous");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="auth-section">
      <h2>OAuth Provider Example</h2>
      <p>Sign in to manage your tasks via web UI or MCP.</p>
      <button onClick={handleSignIn} disabled={isLoading}>
        {isLoading ? "Signing in..." : "Sign in anonymously"}
      </button>
    </div>
  );
}

function TaskManager() {
  const { signOut } = useAuthActions();
  const tasks = useQuery(api.tasks.list) as Task[] | undefined;
  const createTask = useMutation(api.tasks.create);
  const updateTask = useMutation(api.tasks.update);
  const removeTask = useMutation(api.tasks.remove);

  const [newTitle, setNewTitle] = useState("");
  const [newDescription, setNewDescription] = useState("");

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    await createTask({ title: newTitle, description: newDescription || undefined });
    setNewTitle("");
    setNewDescription("");
  };

  const handleStatusChange = async (taskId: string, status: Task["status"]) => {
    await updateTask({ taskId: taskId as any, status });
  };

  const handleDelete = async (taskId: string) => {
    if (confirm("Delete this task?")) {
      await removeTask({ taskId: taskId as any });
    }
  };

  return (
    <div className="task-manager">
      <div className="header">
        <h1>Task Manager</h1>
        <button onClick={() => signOut()}>Sign Out</button>
      </div>

      <form className="create-form" onSubmit={handleCreate}>
        <input
          type="text"
          placeholder="Task title"
          value={newTitle}
          onChange={(e) => setNewTitle(e.target.value)}
          required
        />
        <input
          type="text"
          placeholder="Description (optional)"
          value={newDescription}
          onChange={(e) => setNewDescription(e.target.value)}
        />
        <button type="submit">Add Task</button>
      </form>

      <div className="task-list">
        {tasks?.map((task) => (
          <div key={task._id} className={`task-item ${task.status}`}>
            <div className="task-content">
              <h3>{task.title}</h3>
              {task.description && <p>{task.description}</p>}
            </div>
            <div className="task-actions">
              <select
                value={task.status}
                onChange={(e) =>
                  handleStatusChange(task._id, e.target.value as Task["status"])
                }
              >
                <option value="pending">Pending</option>
                <option value="in_progress">In Progress</option>
                <option value="done">Done</option>
              </select>
              <button className="delete-btn" onClick={() => handleDelete(task._id)}>
                Delete
              </button>
            </div>
          </div>
        ))}
        {tasks?.length === 0 && (
          <p className="no-tasks">No tasks yet. Create one above!</p>
        )}
      </div>

      <OAuthSection />
    </div>
  );
}

type Authorization = {
  _id: string;
  clientId: string;
  clientName: string;
  clientLogoUrl?: string;
  clientWebsite?: string;
  scopes: string[];
  authorizedAt: number;
  lastUsedAt?: number;
};

function OAuthSection() {
  const authorizations = useQuery(api.oauth.listMyAuthorizations) as Authorization[] | undefined;
  const revokeAuth = useMutation(api.oauth.revokeAuthorization);
  const [revoking, setRevoking] = useState<string | null>(null);

  const handleRevoke = async (clientId: string) => {
    if (!confirm("Revoke access for this app? It will need to re-authorize.")) {
      return;
    }
    setRevoking(clientId);
    try {
      await revokeAuth({ clientId });
    } finally {
      setRevoking(null);
    }
  };

  const formatDate = (timestamp: number) => {
    return new Date(timestamp).toLocaleDateString("ja-JP", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div className="oauth-section">
      <h2>Connected Apps</h2>

      <div className="authorizations-list">
        {authorizations && authorizations.length > 0 ? (
          authorizations.map((auth) => (
            <div key={auth._id} className="authorization-item">
              <div className="auth-info">
                {auth.clientLogoUrl && (
                  <img src={auth.clientLogoUrl} alt="" className="client-logo" />
                )}
                <div className="auth-details">
                  <h4>{auth.clientName}</h4>
                  <p className="scopes">Scopes: {auth.scopes.join(", ")}</p>
                  <p className="dates">
                    Authorized: {formatDate(auth.authorizedAt)}
                    {auth.lastUsedAt && ` • Last used: ${formatDate(auth.lastUsedAt)}`}
                  </p>
                </div>
              </div>
              <button
                className="revoke-btn"
                onClick={() => handleRevoke(auth.clientId)}
                disabled={revoking === auth.clientId}
              >
                {revoking === auth.clientId ? "Revoking..." : "Revoke"}
              </button>
            </div>
          ))
        ) : (
          <p className="no-apps">No connected apps yet.</p>
        )}
      </div>

    </div>
  );
}

function App() {
  return (
    <div className="app">
      <Authenticated>
        <TaskManager />
      </Authenticated>
      <Unauthenticated>
        <SignIn />
      </Unauthenticated>
    </div>
  );
}

export default App;
