import { useEffect, useState } from "react";
import { fetchAdminLoginAttempts, adminBlockIp } from "../api/auth";

export default function AdminLoginAttempts() {
  const [attempts, setAttempts] = useState([]);

  // filters
  const [onlySuspicious, setOnlySuspicious] = useState(true);
  const [email, setEmail] = useState("");
  const [ip, setIp] = useState("");
  const [success, setSuccess] = useState(""); // "", "true", "false"
  const [minRisk, setMinRisk] = useState("");
  const [maxRisk, setMaxRisk] = useState("");

  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);

  async function doAction(fn) {
    setLoading(true);
    setStatus(null);
    try {
      await fn();
      await loadAttempts();
      setStatus({ type: "ok", message: "Action completed." });
    } catch (err) {
      const msg = err.response?.data?.message || "Action failed.";
      setStatus({ type: "error", message: msg });
    } finally {
      setLoading(false);
    }
  }

  async function loadAttempts() {
    setLoading(true);
    setStatus(null);

    try {
      const params = {
        onlySuspicious: onlySuspicious ? "true" : undefined,
        email: email || undefined,
        ip: ip || undefined,
        success: success || undefined,
        minRisk: minRisk !== "" ? Number(minRisk) : undefined,
        maxRisk: maxRisk !== "" ? Number(maxRisk) : undefined,

        // keep it simple for now
        page: 1,
        limit: 100,
      };

      const res = await fetchAdminLoginAttempts(params);
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
    loadAttempts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Admin – Login Attempts</h1>
      <p style={{ marginBottom: 16 }}>
        Filter login attempts by email, IP, success/fail, and risk score.
      </p>

      {/* Filters */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
        <label style={{ display: "inline-flex", alignItems: "center", gap: 8 }}>
          <input
            type="checkbox"
            checked={onlySuspicious}
            onChange={(e) => setOnlySuspicious(e.target.checked)}
          />
          Only suspicious
        </label>

        <input
          placeholder="Email contains"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          style={{ padding: "8px 10px", minWidth: 220 }}
        />

        <input
          placeholder="IP"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          style={{ padding: "8px 10px", minWidth: 160 }}
        />

        <select
          value={success}
          onChange={(e) => setSuccess(e.target.value)}
          style={{ padding: "8px 10px" }}
        >
          <option value="">Success: Any</option>
          <option value="true">Success only</option>
          <option value="false">Failures only</option>
        </select>

        <input
          placeholder="Min risk"
          value={minRisk}
          onChange={(e) => setMinRisk(e.target.value)}
          style={{ padding: "8px 10px", width: 110 }}
        />

        <input
          placeholder="Max risk"
          value={maxRisk}
          onChange={(e) => setMaxRisk(e.target.value)}
          style={{ padding: "8px 10px", width: 110 }}
        />

        <button
          type="button"
          onClick={loadAttempts}
          disabled={loading}
          style={{ padding: "8px 12px" }}
        >
          {loading ? "Loading..." : "Apply"}
        </button>

        <button
          type="button"
          onClick={() => {
            setOnlySuspicious(true);
            setEmail("");
            setIp("");
            setSuccess("");
            setMinRisk("");
            setMaxRisk("");
            // load with defaults immediately
            setTimeout(() => loadAttempts(), 0);
          }}
          disabled={loading}
          style={{ padding: "8px 12px" }}
        >
          Clear
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
          <table style={{ borderCollapse: "collapse", minWidth: 900, fontSize: 14 }}>
            <thead>
              <tr>
                <th style={thStyle}>Time</th>
                <th style={thStyle}>Email</th>
                <th style={thStyle}>IP</th>
                <th style={thStyle}>Country/City</th>
                <th style={thStyle}>Success</th>
                <th style={thStyle}>Suspicious</th>
                <th style={thStyle}>Risk</th>
                <th style={thStyle}>Reasons</th>
                <th style={thStyle}>Response</th>
              </tr>
            </thead>
            <tbody>
              {attempts.map((a) => (
                <tr key={a._id}>
                  <td style={tdStyle}>{new Date(a.createdAt).toLocaleString()}</td>
                  <td style={tdStyle}>{a.email}</td>
                  <td style={tdStyle}>{maskIp(a.ip)}</td>
                  <td style={tdStyle}>
                    {a.geo?.country ? `${a.geo.country}${a.geo.city ? " / " + a.geo.city : ""}` : "-"}
                  </td>
                  <td style={tdStyle}>{a.success ? "✅" : "❌"}</td>
                  <td style={tdStyle}>{a.suspicious ? "⚠️ Yes" : "No"}</td>
                  <td style={tdStyle}>{typeof a.riskScore === "number" ? a.riskScore : "-"}</td>
                  <td style={tdStyle}>
                    {Array.isArray(a.reasons) && a.reasons.length > 0 ? a.reasons.join(", ") : "-"}
                  </td>
                  <td style={tdStyle}>
                    <button
                      type="button"
                      onClick={async () => {
                        if (!a.ip || a.ip === "-") return;

                        const minutesRaw = window.prompt("Block how many minutes?", "60");
                        if (!minutesRaw) return;

                        const minutes = parseInt(minutesRaw, 10);
                        if (!Number.isFinite(minutes) || minutes < 1) {
                          window.alert("Please enter a valid number of minutes (>= 1).");
                          return;
                        }

                        const reason = window.prompt("Reason (optional):", "Suspicious activity") || "";
                        await doAction(() => adminBlockIp(a.ip, minutes, reason));
                      }}
                      disabled={!a.ip || loading}
                      style={{ padding: "6px 10px" }}
                    >
                      Block IP
                    </button>
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


function maskIp(ip) {
  const s = String(ip || "").trim();
  if (!s) return "—";

  // IPv4 masking: keep /24
  if (s.includes(".") && !s.includes(":")) {
    const parts = s.split(".");
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    return s;
  }

  // IPv6 masking (rough): keep /48-ish prefix
  if (s.includes(":")) {
    const parts = s.split(":").filter(Boolean);
    const prefix = parts.slice(0, 3).join(":");
    return prefix ? `${prefix}::/48` : "—";
  }

  return s;
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
