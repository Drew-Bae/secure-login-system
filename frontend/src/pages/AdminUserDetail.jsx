import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import {
  fetchAdminUserDetail,
  adminUnlockUser,
  adminLockUser,
  adminRevokeSessions,
} from "../api/auth";

export default function AdminUserDetail() {
  const { userId } = useParams();

  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [payload, setPayload] = useState(null);

  async function load() {
    setLoading(true);
    setStatus(null);
    try {
      const res = await fetchAdminUserDetail(userId);
      setPayload(res.data);
    } catch (err) {
      setStatus({ type: "error", message: "Failed to load user details." });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userId]);

  async function doAction(fn) {
    setStatus(null);
    setLoading(true);
    try {
      await fn();
      await load();
      setStatus({ type: "ok", message: "Action completed." });
    } catch (err) {
      setStatus({ type: "error", message: "Action failed." });
    } finally {
      setLoading(false);
    }
  }

  if (!payload && loading) {
    return <div style={{ padding: 24, fontFamily: "system-ui" }}>Loading...</div>;
  }

  const user = payload?.user;
  const devices = payload?.devices || [];
  const attempts = payload?.attempts || [];

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Admin – User Detail</h1>

      {status && (
        <p style={{ color: status.type === "error" ? "crimson" : "green" }}>
          {status.message}
        </p>
      )}

      {!user ? (
        <p>User not found.</p>
      ) : (
        <>
          <div style={{ marginBottom: 16 }}>
            <div><strong>Email:</strong> {user.email}</div>
            <div><strong>Role:</strong> {user.role}</div>
            <div><strong>MFA:</strong> {user.mfaEnabled ? "enabled" : "disabled"}</div>
            <div><strong>Failed logins:</strong> {user.failedLoginCount ?? 0}</div>
            <div>
              <strong>Locked until:</strong>{" "}
              {user.lockoutUntil ? new Date(user.lockoutUntil).toLocaleString() : "—"}
            </div>
          </div>

          <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
            <button
              type="button"
              onClick={() => doAction(() => adminUnlockUser(user._id))}
              disabled={loading}
              style={{ padding: "8px 12px" }}
            >
              Unlock
            </button>

            <button
              type="button"
              onClick={() => doAction(() => adminLockUser(user._id, 60))}
              disabled={loading}
              style={{ padding: "8px 12px" }}
            >
              Lock 60 min
            </button>

            <button
              type="button"
              onClick={() => doAction(() => adminRevokeSessions(user._id))}
              disabled={loading}
              style={{ padding: "8px 12px" }}
            >
              Revoke Sessions
            </button>

            <button
              type="button"
              onClick={load}
              disabled={loading}
              style={{ padding: "8px 12px" }}
            >
              Refresh
            </button>
          </div>

          <h2>Devices</h2>
          {devices.length === 0 ? (
            <p>No devices recorded.</p>
          ) : (
            <div style={{ overflowX: "auto", marginBottom: 24 }}>
              <table style={{ borderCollapse: "collapse", minWidth: 900, fontSize: 14 }}>
                <thead>
                  <tr>
                    <th style={th}>Device ID</th>
                    <th style={th}>Trusted</th>
                    <th style={th}>Compromised</th>
                    <th style={th}>Last Seen</th>
                    <th style={th}>Last IP</th>
                    <th style={th}>Last Geo</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map((d) => (
                    <tr key={d._id}>
                      <td style={td}>{d.deviceId?.slice(0, 12) || "-"}</td>
                      <td style={td}>{d.trusted ? "✅" : "—"}</td>
                      <td style={td}>{d.compromisedAt ? "⚠️" : "—"}</td>
                      <td style={td}>{d.lastSeenAt ? new Date(d.lastSeenAt).toLocaleString() : "—"}</td>
                      <td style={td}>{d.lastIp || "—"}</td>
                      <td style={td}>{d.lastGeo?.country ? `${d.lastGeo.country}${d.lastGeo.city ? " / " + d.lastGeo.city : ""}` : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <h2>Recent Login Attempts</h2>
          {attempts.length === 0 ? (
            <p>No login attempts.</p>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ borderCollapse: "collapse", minWidth: 900, fontSize: 14 }}>
                <thead>
                  <tr>
                    <th style={th}>Time</th>
                    <th style={th}>IP</th>
                    <th style={th}>Country/City</th>
                    <th style={th}>Success</th>
                    <th style={th}>Suspicious</th>
                    <th style={th}>Risk</th>
                    <th style={th}>Reasons</th>
                  </tr>
                </thead>
                <tbody>
                  {attempts.map((a) => (
                    <tr key={a._id}>
                      <td style={td}>{new Date(a.createdAt).toLocaleString()}</td>
                      <td style={td}>{a.ip || "—"}</td>
                      <td style={td}>{a.geo?.country ? `${a.geo.country}${a.geo.city ? " / " + a.geo.city : ""}` : "—"}</td>
                      <td style={td}>{a.success ? "✅" : "❌"}</td>
                      <td style={td}>{a.suspicious ? "⚠️" : "—"}</td>
                      <td style={td}>{typeof a.riskScore === "number" ? a.riskScore : "—"}</td>
                      <td style={td}>{Array.isArray(a.reasons) && a.reasons.length ? a.reasons.join(", ") : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}

const th = { borderBottom: "1px solid #ccc", textAlign: "left", padding: "8px 6px" };
const td = { borderBottom: "1px solid #eee", padding: "6px 6px" };
