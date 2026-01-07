import { useEffect, useMemo, useState } from "react";
import {
  fetchMe,
  fetchLoginHistory,
  trustDevice,
  getCurrentDeviceId,
  logoutAllDevices,
  changePassword, // ✅ add
} from "../api/auth";

const LAST_LOGIN_META_KEY = "sls_last_login_meta";

function readLastLoginMeta() {
  try {
    const raw = sessionStorage.getItem(LAST_LOGIN_META_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export default function Security() {
  const [me, setMe] = useState(null);
  const [attempts, setAttempts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);

  const [actionStatus, setActionStatus] = useState(null);

  // ✅ Change password state
  const [pwCurrent, setPwCurrent] = useState("");
  const [pwNew, setPwNew] = useState("");
  const [pwConfirm, setPwConfirm] = useState("");
  const [pwStatus, setPwStatus] = useState(null);

  const lastLoginMeta = useMemo(() => readLastLoginMeta(), []);

  const currentDeviceId = useMemo(() => {
    try {
      return getCurrentDeviceId();
    } catch {
      return null;
    }
  }, []);

  const reasons = Array.isArray(lastLoginMeta?.reasons) ? lastLoginMeta.reasons : [];
  const highRisk = Boolean(lastLoginMeta?.highRisk);
  const riskScore =
    typeof lastLoginMeta?.riskScore === "number" ? lastLoginMeta.riskScore : null;

  const deviceRelated =
    reasons.includes("device_untrusted") || reasons.includes("new_device_for_account");

  const ipRelated = reasons.includes("new_ip_for_account");
  const travelRelated = reasons.includes("impossible_travel");

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

  async function handleTrustThisDevice() {
    setActionStatus(null);

    if (!currentDeviceId) {
      setActionStatus({ type: "error", message: "Could not determine this device ID." });
      return;
    }

    try {
      await trustDevice(currentDeviceId);
      setActionStatus({
        type: "success",
        message: "This device is now trusted. Future logins from it should look less risky.",
      });
      // Refresh activity list (optional but feels good)
      await load();
    } catch (err) {
      const msg = err.response?.data?.message || "Failed to trust this device.";
      setActionStatus({ type: "error", message: msg });
    }
  }

  async function handleLogoutAllDevices() {
    setActionStatus(null);

    try {
      await logoutAllDevices();
      // token cookie is cleared, plus server revokes all sessions
      window.location.href = "/login";
    } catch (err) {
      const msg = err.response?.data?.message || "Failed to log out of all devices.";
      setActionStatus({ type: "error", message: msg });
    }
  }

  // ✅ Change password handler
  async function handleChangePassword(e) {
    e.preventDefault();
    setPwStatus(null);

    if (!pwCurrent || !pwNew || !pwConfirm) {
      setPwStatus({ type: "error", message: "Fill out all password fields." });
      return;
    }

    if (pwNew !== pwConfirm) {
      setPwStatus({ type: "error", message: "New passwords do not match." });
      return;
    }

    try {
      const res = await changePassword({ currentPassword: pwCurrent, newPassword: pwNew });
      setPwStatus({
        type: "success",
        message: res.data?.message || "Password changed. Redirecting...",
      });

      setPwCurrent("");
      setPwNew("");
      setPwConfirm("");

      // backend clears cookie, so send them to login
      setTimeout(() => {
        window.location.href = "/login";
      }, 800);
    } catch (err) {
      const msg = err.response?.data?.message || "Failed to change password.";
      setPwStatus({ type: "error", message: msg });
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Security</h1>
      <p>View your recent login activity and security settings.</p>

      {/* Risk-based banner (based on the last login response) */}
      {lastLoginMeta && (highRisk || reasons.length > 0) && (
        <div
          style={{
            marginTop: 12,
            padding: 12,
            border: "1px solid #ddd",
            borderRadius: 10,
            background: highRisk ? "#fff7ed" : "#f8fafc",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
            <div>
              <div style={{ fontWeight: 700, marginBottom: 4 }}>
                {highRisk ? "⚠️ High-risk login detected" : "Login security signals detected"}
              </div>

              <div style={{ opacity: 0.9, fontSize: 14 }}>
                {riskScore !== null && (
                  <span>
                    Risk score: <strong>{riskScore}</strong>.{" "}
                  </span>
                )}
                {deviceRelated && <span>New or untrusted device. </span>}
                {ipRelated && <span>New IP address. </span>}
                {travelRelated && <span>Possible “impossible travel”. </span>}
                {!deviceRelated && !ipRelated && !travelRelated && reasons.length > 0 && (
                  <span>Signals: {reasons.join(", ")}.</span>
                )}
              </div>

              <div style={{ marginTop: 10, display: "flex", gap: 10, flexWrap: "wrap" }}>
                {deviceRelated && (
                  <button
                    type="button"
                    onClick={handleTrustThisDevice}
                    style={{ padding: "6px 12px" }}
                  >
                    Trust this device
                  </button>
                )}

                {me && !me.mfaEnabled && (
                  <a href="/mfa/setup" style={{ display: "inline-block", padding: "6px 12px" }}>
                    Enable MFA
                  </a>
                )}

                <a href="/devices" style={{ display: "inline-block", padding: "6px 12px" }}>
                  Review devices
                </a>
              </div>

              {actionStatus && (
                <div
                  style={{
                    marginTop: 10,
                    color: actionStatus.type === "error" ? "crimson" : "green",
                  }}
                >
                  {actionStatus.message}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <button
        type="button"
        onClick={load}
        disabled={loading}
        style={{ margin: "12px 0", padding: "6px 12px" }}
      >
        {loading ? "Refreshing..." : "Refresh"}
      </button>

      {status && <p style={{ color: "crimson", marginTop: 8 }}>{status.message}</p>}

      {me && (
        <div style={{ marginTop: 12, marginBottom: 16 }}>
          <h3 style={{ marginBottom: 8 }}>Account</h3>
          <ul style={{ margin: 0, paddingLeft: 18 }}>
            <li>
              <strong>Email:</strong> {me.email}
            </li>
            <li>
              <strong>Role:</strong> {me.role}
            </li>
            <li>
              <strong>MFA Enabled:</strong> {me.mfaEnabled ? "Yes" : "No"}
            </li>
          </ul>

          <div style={{ marginTop: 12, display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button
              type="button"
              onClick={handleLogoutAllDevices}
              style={{ padding: "6px 12px" }}
            >
              Log out of all devices
            </button>
          </div>

          {/* ✅ Change password */}
          <div style={{ marginTop: 18, paddingTop: 12, borderTop: "1px solid #eee" }}>
            <h3 style={{ marginBottom: 8 }}>Change password</h3>

            <form onSubmit={handleChangePassword} style={{ maxWidth: 360 }}>
              <label style={{ display: "block", marginTop: 8 }}>
                Current password
                <input
                  type="password"
                  value={pwCurrent}
                  onChange={(e) => setPwCurrent(e.target.value)}
                  style={{ width: "100%", padding: "8px 10px", marginTop: 4 }}
                />
              </label>

              <label style={{ display: "block", marginTop: 10 }}>
                New password
                <input
                  type="password"
                  value={pwNew}
                  onChange={(e) => setPwNew(e.target.value)}
                  minLength={12}
                  style={{ width: "100%", padding: "8px 10px", marginTop: 4 }}
                />
                <div style={{ fontSize: 12, opacity: 0.75, marginTop: 6 }}>
                  At least 12 characters, with uppercase, lowercase, number, and a special character.
                </div>
              </label>

              <label style={{ display: "block", marginTop: 10 }}>
                Confirm new password
                <input
                  type="password"
                  value={pwConfirm}
                  onChange={(e) => setPwConfirm(e.target.value)}
                  minLength={12}
                  style={{ width: "100%", padding: "8px 10px", marginTop: 4 }}
                />
              </label>

              <button type="submit" style={{ marginTop: 12, padding: "8px 12px" }}>
                Change password
              </button>

              {pwStatus && (
                <p style={{ marginTop: 10, color: pwStatus.type === "error" ? "crimson" : "green" }}>
                  {pwStatus.message}
                </p>
              )}
            </form>
          </div>
        </div>
      )}

      <h3 style={{ marginTop: 18 }}>Recent Login Attempts</h3>

      {attempts.length === 0 && !loading ? (
        <p>No login attempts to display.</p>
      ) : (
        <div style={{ overflowX: "auto", marginTop: 8 }}>
          <table style={{ borderCollapse: "collapse", minWidth: 800, fontSize: 14 }}>
            <thead>
              <tr>
                <th style={thStyle}>Time</th>
                <th style={thStyle}>Success</th>
                <th style={thStyle}>Suspicious</th>
                <th style={thStyle}>Risk</th>
                <th style={thStyle}>Reasons</th>
                <th style={thStyle}>IP</th>
                <th style={thStyle}>Country/City</th>
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
                  <td style={tdStyle}>{typeof a.riskScore === "number" ? a.riskScore : "-"}</td>
                  <td style={tdStyle}>
                    {Array.isArray(a.reasons) && a.reasons.length > 0 ? a.reasons.join(", ") : "-"}
                  </td>
                  <td style={tdStyle}>{a.ip || "-"}</td>
                  <td style={tdStyle}>
                    {a.geo?.country
                      ? `${a.geo.country}${a.geo.city ? " / " + a.geo.city : ""}`
                      : "-"}
                  </td>
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
