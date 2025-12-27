import { useEffect, useState } from "react";
import { fetchMe, fetchLoginHistory } from "../api/auth";

export default function Security() {
  const [me, setMe] = useState(null);
  const [attempts, setAttempts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);

  async function load() {
    setLoading(true);
    setStatus(null);

    try {
      const [meRes, histRes] = await Promise.all([fetchMe(), fetchLoginHistory()]);
      setMe(meRes.data.user);
      setAttempts(histRes.data.attempts || []);
    } catch (err) {
      const code = err.response?.status;
      if (code === 401) {
        setStatus({ type: "error", message: "Please log in to view security info." });
      } else {
        setStatus({ type: "error", message: "Failed to load security info." });
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Security</h1>
      <p>View your recent login activity and security settings.</p>

      <button
        type="button"
        onClick={load}
        disabled={loading}
        style={{ margin: "12px 0", padding: "6px 12px" }}
      >
        {loading ? "Refreshing..." : "Refresh"}
      </button>

      {status && (
        <p style={{ color: "crimson", marginTop: 8 }}>{status.message}</p>
      )}

      {me && (
        <div style={{ marginTop: 12, marginBottom: 16 }}>
          <h3 style={{ marginBottom: 8 }}>Account</h3>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            <li><strong>Email:</strong> {me.email}</li>
            <li><strong>Role:</strong> {me.role}</li>
            <li><strong>MFA Enabled:</strong> {me.mfaEnabled ? "Yes" : "No"}</li>
          </ul>
        </div>
      )}

      <h3 style={{ marginTop: 18 }}>Recent Login Attempts</h3>

      {attempts.length === 0 && !loading ? (
        <p>No login attempts to display.</p>
      ) : (
        <div style={{ overflowX: "auto", marginTop: 8 }}>
          <table
            style={{
              borderCollapse: "collapse",
              minWidth: 800,
              fontSize: 14,
            }}
          >
            <thead>
              <tr>
                <th style={thStyle}>Time</th>
                <th style={thStyle}>Success</th>
                <th style={thStyle}>Suspicious</th>
                <th style={thStyle}>Risk</th>
                <th style={thStyle}>Reasons</th>
                <th style={thStyle}>IP</th>
                <th style={thStyle}>Device</th>
                <th style={thStyle}>User Agent</th>
              </tr>
            </thead>
            <tbody>
              {attempts.map((a) => (
                <tr key={a._id}>
                  <td style={tdStyle}>{new Date(a.createdAt).toLocaleString()}</td>
                  <td style={tdStyle}>{a.success ? "✅" : "❌"}</td>
                  <td style={tdStyle}>{a.suspicious ? "⚠️ Yes" : "No"}</td>
                  <td style={tdStyle}>
                    {typeof a.riskScore === "number" ? a.riskScore : "-"}
                  </td>
                  <td style={tdStyle}>
                    {Array.isArray(a.reasons) && a.reasons.length > 0
                      ? a.reasons.join(", ")
                      : "-"}
                  </td>
                  <td style={tdStyle}>{a.ip || "-"}</td>
                  <td style={tdStyle}>
                    {a.deviceId && a.deviceId !== "unknown" ? a.deviceId.slice(0, 8) : "-"}
                  </td>
                  <td style={tdStyle}>
                    <span
                      style={{
                        display: "inline-block",
                        maxWidth: 360,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                      }}
                      title={a.userAgent}
                    >
                      {a.userAgent || "-"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const thStyle = {
  borderBottom: "1px solid #ccc",
  textAlign: "left",
  padding: "8px 6px",
};

const tdStyle = {
  borderBottom: "1px solid #eee",
  padding: "6px 6px",
};
