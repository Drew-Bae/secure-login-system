import { useEffect, useState } from "react";
import { fetchLoginAttempts } from "../api/auth";

export default function AdminLoginAttempts() {
  const [attempts, setAttempts] = useState([]);
  const [onlySuspicious, setOnlySuspicious] = useState(true);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);

  async function loadAttempts(options = {}) {
    setLoading(true);
    setStatus(null);

    try {
      const res = await fetchLoginAttempts({
        onlySuspicious: options.onlySuspicious ?? onlySuspicious,
      });
      setAttempts(res.data.attempts || []);
    } catch (err) {
      const code = err.response?.status;
      if (code === 401 || code === 403) {
        setStatus({
          type: "error",
          message: "You must be logged in as an admin to view this data.",
        });
      } else {
        setStatus({
          type: "error",
          message: "Failed to load login attempts.",
        });
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadAttempts({ onlySuspicious });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [onlySuspicious]);

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Admin – Login Attempts</h1>
      <p style={{ marginBottom: 16 }}>
        This view shows recent login attempts with basic suspicious login
        detection.
      </p>

      <div style={{ marginBottom: 16 }}>
        <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          <input
            type="checkbox"
            checked={onlySuspicious}
            onChange={(e) => setOnlySuspicious(e.target.checked)}
          />
          Show only suspicious attempts
        </label>

        <button
          type="button"
          onClick={() => loadAttempts({ onlySuspicious })}
          disabled={loading}
          style={{ marginLeft: 16, padding: "6px 12px" }}
        >
          {loading ? "Refreshing..." : "Refresh"}
        </button>
      </div>

      {status && (
        <p
          style={{
            marginBottom: 16,
            color: status.type === "error" ? "crimson" : "green",
          }}
        >
          {status.message}
        </p>
      )}

      {attempts.length === 0 && !loading ? (
        <p>No login attempts to display.</p>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table
            style={{
              borderCollapse: "collapse",
              minWidth: 700,
              fontSize: 14,
            }}
          >
            <thead>
              <tr>
                <th style={thStyle}>Time</th>
                <th style={thStyle}>Email</th>
                <th style={thStyle}>IP</th>
                <th style={thStyle}>User Agent</th>
                <th style={thStyle}>Success</th>
                <th style={thStyle}>Suspicious</th>
                <th style={thStyle}>Reasons</th>
              </tr>
            </thead>
            <tbody>
              {attempts.map((a) => (
                <tr key={a._id}>
                  <td style={tdStyle}>
                    {new Date(a.createdAt).toLocaleString()}
                  </td>
                  <td style={tdStyle}>{a.email}</td>
                  <td style={tdStyle}>{a.ip || "-"}</td>
                  <td style={tdStyle}>
                    <span
                      style={{
                        display: "inline-block",
                        maxWidth: 250,
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                        textOverflow: "ellipsis",
                      }}
                      title={a.userAgent}
                    >
                      {a.userAgent || "-"}
                    </span>
                  </td>
                  <td style={tdStyle}>
                    {a.success ? "✅" : "❌"}
                  </td>
                  <td style={tdStyle}>
                    {a.suspicious ? "⚠️ Yes" : "No"}
                  </td>
                  <td style={tdStyle}>
                    {Array.isArray(a.reasons) && a.reasons.length > 0
                      ? a.reasons.join(", ")
                      : "-"}
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
