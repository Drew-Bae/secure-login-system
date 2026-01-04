import { useEffect, useState } from "react";
import { fetchAdminAuditEvents } from "../api/auth";

export default function AdminAuditLog() {
  const [action, setAction] = useState("");
  const [email, setEmail] = useState("");
  const [ip, setIp] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [page, setPage] = useState(1);

  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [data, setData] = useState({ events: [], total: 0, hasMore: false, limit: 50 });

  async function load(p = 1) {
    setLoading(true);
    setStatus(null);
    try {
      const res = await fetchAdminAuditEvents({
        action: action || undefined,
        email: email || undefined,
        ip: ip || undefined,
        from: from || undefined,
        to: to || undefined,
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
            : "Failed to load audit events.",
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
      <h1>Admin – Audit Log</h1>

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
        <input
          placeholder="Action (ex: ADMIN_LOCK_USER)"
          value={action}
          onChange={(e) => setAction(e.target.value)}
          style={{ padding: "8px 10px", minWidth: 260 }}
        />

        <input
          placeholder="Email contains (actor or target)"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          style={{ padding: "8px 10px", minWidth: 260 }}
        />

        <input
          placeholder="IP"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          style={{ padding: "8px 10px", minWidth: 160 }}
        />

        <input
          type="datetime-local"
          value={from}
          onChange={(e) => setFrom(e.target.value)}
          style={{ padding: "8px 10px" }}
        />

        <input
          type="datetime-local"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          style={{ padding: "8px 10px" }}
        />

        <button type="button" onClick={() => load(1)} disabled={loading} style={{ padding: "8px 12px" }}>
          {loading ? "Loading..." : "Apply"}
        </button>
      </div>

      {status && <p style={{ color: "crimson", marginBottom: 12 }}>{status.message}</p>}

      <p style={{ opacity: 0.8, marginBottom: 12 }}>
        Showing {data.events.length} of {data.total}
      </p>

      <div style={{ overflowX: "auto" }}>
        <table style={{ borderCollapse: "collapse", minWidth: 1100, fontSize: 14 }}>
          <thead>
            <tr>
              <th style={th}>Time</th>
              <th style={th}>Actor</th>
              <th style={th}>Action</th>
              <th style={th}>Target</th>
              <th style={th}>IP</th>
              <th style={th}>User Agent</th>
              <th style={th}>Meta</th>
            </tr>
          </thead>
          <tbody>
            {data.events.map((e) => (
              <tr key={e._id}>
                <td style={td}>{new Date(e.createdAt).toLocaleString()}</td>
                <td style={td}>
                  {e.actorUserId?.email || "—"}
                  <div style={{ opacity: 0.7 }}>{e.actorRole}</div>
                </td>
                <td style={td}>{e.action}</td>
                <td style={td}>{e.targetUserId?.email || e.targetDeviceId || "—"}</td>
                <td style={td}>{e.ip || "—"}</td>
                <td style={td}>{truncate(e.userAgent || "—", 80)}</td>
                <td style={td}>
                  <details>
                    <summary style={{ cursor: "pointer" }}>view</summary>
                    <pre style={{ marginTop: 8, whiteSpace: "pre-wrap" }}>
                      {JSON.stringify(e.meta || {}, null, 2)}
                    </pre>
                  </details>
                </td>
              </tr>
            ))}
            {data.events.length === 0 && !loading && (
              <tr>
                <td style={td} colSpan={7}>No audit events found.</td>
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

function truncate(s, n) {
  const str = String(s);
  return str.length > n ? str.slice(0, n - 1) + "…" : str;
}

const th = { borderBottom: "1px solid #ccc", textAlign: "left", padding: "8px 6px" };
const td = { borderBottom: "1px solid #eee", padding: "6px 6px", verticalAlign: "top" };
