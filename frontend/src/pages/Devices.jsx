import { useEffect, useState } from "react";
import {
  fetchDevices,
  trustDevice,
  revokeDevice,
  markDeviceCompromised,
  getCurrentDeviceId,
  logoutUser,
} from "../api/auth";

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const currentDeviceId = getCurrentDeviceId();

  async function load() {
    setLoading(true);
    setStatus(null);
    try {
      const res = await fetchDevices();
      setDevices(res.data.devices || []);
    } catch (err) {
      setStatus({ type: "error", message: "Failed to load devices. Are you logged in?" });
    } finally {
      setLoading(false);
    }
  }

  async function handleTrust(deviceId) {
    setStatus(null);
    try {
      await trustDevice(deviceId);
      setStatus({ type: "success", message: "Device trusted." });
      await load();
    } catch (err) {
      setStatus({ type: "error", message: "Failed to trust device." });
    }
  }

  async function handleRevoke(deviceId) {
    setStatus(null);
    const ok = window.confirm("Revoke this device session? (It will be logged out.)");
    if (!ok) return;

    try {
      await revokeDevice(deviceId);

      // ✅ If you revoked THIS device, clear cookie and force re-login
      if (deviceId === currentDeviceId) {
        await logoutUser(); // clears auth cookie
        window.location.href = "/login";
        return;
      }

      setStatus({ type: "success", message: "Device session revoked." });
      await load();
    } catch (err) {
      setStatus({ type: "error", message: "Failed to revoke device." });
    }
  }

  async function handleCompromised(deviceId) {
    setStatus(null);
    const reason = window.prompt("Reason (optional):", "lost_device");
    const ok = window.confirm("Mark this device compromised and revoke it?");
    if (!ok) return;

    try {
      await markDeviceCompromised(deviceId, reason || "user_marked_compromised");

      // ✅ If you compromised THIS device, clear cookie and force re-login
      if (deviceId === currentDeviceId) {
        await logoutUser(); // clears auth cookie
        window.location.href = "/login";
        return;
      }

      setStatus({ type: "success", message: "Device marked compromised and revoked." });
      await load();
    } catch (err) {
      setStatus({ type: "error", message: "Failed to mark device compromised." });
    }
  }

  useEffect(() => {
    load();
  }, []);

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Devices</h1>
      <p>Manage devices that have accessed your account.</p>

      <button onClick={load} disabled={loading} style={{ padding: "6px 12px" }}>
        {loading ? "Refreshing..." : "Refresh"}
      </button>

      {status && (
        <p style={{ marginTop: 12, color: status.type === "error" ? "crimson" : "green" }}>
          {status.message}
        </p>
      )}

      <div style={{ marginTop: 16, overflowX: "auto" }}>
        <table style={{ borderCollapse: "collapse", minWidth: 900, fontSize: 14 }}>
          <thead>
            <tr>
              <th style={th}>Device</th>
              <th style={th}>Compromised</th>
              <th style={th}>Trusted</th>
              <th style={th}>Last Seen</th>
              <th style={th}>Location</th>
              <th style={th}>IP</th>
              <th style={th}>User Agent</th>
              <th style={th}>Action</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d._id}>
                <td style={td}>
                  {d.deviceId ? (
                    <>
                      {d.deviceId.slice(0, 8)}
                      {currentDeviceId === d.deviceId ? (
                        <span style={{ marginLeft: 8, opacity: 0.7 }}>(this device)</span>
                      ) : null}
                    </>
                  ) : (
                    "-"
                  )}
                </td>
                <td style={td}>{d.compromisedAt ? "⚠️" : "—"}</td>
                <td style={td}>{d.trusted ? "✅" : "❌"}</td>
                <td style={td}>{d.lastSeenAt ? new Date(d.lastSeenAt).toLocaleString() : "-"}</td>
                <td style={td}>
                  {d.lastGeo?.country
                    ? `${d.lastGeo.country}${d.lastGeo.city ? " / " + d.lastGeo.city : ""}`
                    : "-"}
                </td>
                <td style={td}>{d.lastIp || "-"}</td>
                <td style={td}>
                  <span
                    style={{
                      display: "inline-block",
                      maxWidth: 320,
                      whiteSpace: "nowrap",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                    }}
                    title={d.lastUserAgent}
                  >
                    {d.lastUserAgent || "-"}
                  </span>
                </td>
                <td style={td}>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    {d.trusted ? (
                      <span style={{ opacity: 0.7 }}>Trusted</span>
                    ) : (
                      <button onClick={() => handleTrust(d.deviceId)} style={{ padding: "4px 10px" }}>
                        Trust
                      </button>
                    )}

                    <button onClick={() => handleRevoke(d.deviceId)} style={{ padding: "4px 10px" }}>
                      Revoke
                    </button>

                    <button onClick={() => handleCompromised(d.deviceId)} style={{ padding: "4px 10px" }}>
                      Compromised
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {devices.length === 0 && (
              <tr>
                <td style={td} colSpan={7}>
                  No devices yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const th = { borderBottom: "1px solid #ccc", textAlign: "left", padding: "8px 6px" };
const td = { borderBottom: "1px solid #eee", padding: "6px 6px" };
