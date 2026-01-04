import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchAdminUsers } from "../api/auth";

export default function AdminUsers() {
  const [q, setQ] = useState("");
  const [role, setRole] = useState("");
  const [locked, setLocked] = useState("");
  const [mfaEnabled, setMfaEnabled] = useState("");
  const [page, setPage] = useState(1);

  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [data, setData] = useState({ users: [], total: 0, hasMore: false, limit: 50 });

  async function load(p = 1) {
    setLoading(true);
    setStatus(null);

    try {
      const res = await fetchAdminUsers({
        q: q || undefined,
        role: role || undefined,
        locked: locked || undefined,
        mfaEnabled: mfaEnabled || undefined,
        page: p,
        limit: 50,
      });

      setData(res.data);
      setPage(p);
    } catch (err) {
      const code = err.response?.status;
      setStatus({
        type: "error",
        message:
          code === 401 || code === 403
            ? "Admin access required."
            : "Failed to load users.",
      });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load(1);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Admin – Users</h1>

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
        <input
          placeholder="Search email..."
          value={q}
          onChange={(e) => setQ(e.target.value)}
          style={{ padding: "8px 10px", minWidth: 240 }}
        />

        <select value={role} onChange={(e) => setRole(e.target.value)} style={{ padding: "8px 10px" }}>
          <option value="">Role (any)</option>
          <option value="user">user</option>
          <option value="admin">admin</option>
        </select>

        <select value={locked} onChange={(e) => setLocked(e.target.value)} style={{ padding: "8px 10px" }}>
          <option value="">Locked (any)</option>
          <option value="true">locked</option>
          <option value="false">not locked</option>
        </select>

        <select value={mfaEnabled} onChange={(e) => setMfaEnabled(e.target.value)} style={{ padding: "8px 10px" }}>
          <option value="">MFA (any)</option>
          <option value="true">enabled</option>
          <option value="false">disabled</option>
        </select>

        <button
          type="button"
          onClick={() => load(1)}
          disabled={loading}
          style={{ padding: "8px 12px" }}
        >
          {loading ? "Loading..." : "Apply"}
        </button>
      </div>

      {status && (
        <p style={{ color: "crimson", marginBottom: 12 }}>{status.message}</p>
      )}

      <p style={{ opacity: 0.8, marginBottom: 12 }}>
        Showing {data.users.length} of {data.total}
      </p>

      <div style={{ overflowX: "auto" }}>
        <table style={{ borderCollapse: "collapse", minWidth: 900, fontSize: 14 }}>
          <thead>
            <tr>
              <th style={th}>Email</th>
              <th style={th}>Role</th>
              <th style={th}>MFA</th>
              <th style={th}>Failed Logins</th>
              <th style={th}>Locked Until</th>
              <th style={th}>Created</th>
              <th style={th}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {data.users.map((u) => (
              <tr key={u._id}>
                <td style={td}>
                  <Link to={`/admin/users/${u._id}`}>{u.email}</Link>
                </td>
                <td style={td}>{u.role}</td>
                <td style={td}>{u.mfaEnabled ? "✅" : "—"}</td>
                <td style={td}>{u.failedLoginCount ?? 0}</td>
                <td style={td}>
                  {u.lockoutUntil ? new Date(u.lockoutUntil).toLocaleString() : "—"}
                </td>
                <td style={td}>{new Date(u.createdAt).toLocaleDateString()}</td>
                <td style={td}>
                  <Link to={`/admin/users/${u._id}`}>View</Link>
                </td>
              </tr>
            ))}
            {data.users.length === 0 && !loading && (
              <tr>
                <td style={td} colSpan={7}>No users found.</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div style={{ display: "flex", gap: 12, marginTop: 16, alignItems: "center" }}>
        <button
          type="button"
          onClick={() => load(Math.max(1, page - 1))}
          disabled={loading || page <= 1}
          style={{ padding: "8px 12px" }}
        >
          Prev
        </button>
        <span>Page {page}</span>
        <button
          type="button"
          onClick={() => load(page + 1)}
          disabled={loading || !data.hasMore}
          style={{ padding: "8px 12px" }}
        >
          Next
        </button>
      </div>
    </div>
  );
}

const th = { borderBottom: "1px solid #ccc", textAlign: "left", padding: "8px 6px" };
const td = { borderBottom: "1px solid #eee", padding: "6px 6px" };
