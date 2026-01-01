import { useEffect, useState } from "react";
import { fetchDevices, trustDevice } from "../api/auth";

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);

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
                <td style={td}>{d.deviceId ? d.deviceId.slice(0, 8) : "-"}</td>
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
                  {d.trusted ? (
                    "—"
                  ) : (
                    <button
                      onClick={() => handleTrust(d.deviceId)}
                      style={{ padding: "4px 10px" }}
                    >
                      Trust
                    </button>
                  )}
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
