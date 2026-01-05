import { useCallback, useEffect, useState } from "react";
import { fetchBlockedIps, adminUnblockIp } from "../api/auth";

export default function AdminBlockedIps() {
  const [ip, setIp] = useState("");
  const [active, setActive] = useState("true");
  const [page, setPage] = useState(1);

  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState(null);
  const [data, setData] = useState({ blocks: [], total: 0, hasMore: false });

  const load = useCallback(async (p = 1) => {
    setLoading(true);
    setStatus(null);
    try {
        const res = await fetchBlockedIps({ ip: ip || undefined, active, page: p, limit: 50 });
        setData(res.data);
        setPage(p);
    } catch (err) {
        setStatus({ type: "error", message: "Failed to load blocked IPs." });
    } finally {
        setLoading(false);
    }
    }, [ip, active]);


  async function doUnblock(id) {
    setLoading(true);
    setStatus(null);
    try {
      await adminUnblockIp(id);
      await load(page);
      setStatus({ type: "ok", message: "Unblocked." });
    } catch {
      setStatus({ type: "error", message: "Unblock failed." });
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load(1);
    }, [load]);

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Admin – Blocked IPs</h1>

      {status && (
        <p style={{ color: status.type === "error" ? "crimson" : "green" }}>
          {status.message}
        </p>
      )}

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
        <input
          placeholder="Search IP..."
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          style={{ padding: "8px 10px", minWidth: 240 }}
        />

        <select value={active} onChange={(e) => setActive(e.target.value)} style={{ padding: "8px 10px" }}>
          <option value="true">Active</option>
          <option value="false">Expired</option>
        </select>

        <button type="button" onClick={() => load(1)} disabled={loading} style={{ padding: "8px 12px" }}>
          {loading ? "Loading..." : "Apply"}
        </button>
      </div>

      <p style={{ opacity: 0.8, marginBottom: 12 }}>
        Showing {data.blocks.length} of {data.total}
      </p>

      <div style={{ overflowX: "auto" }}>
        <table style={{ borderCollapse: "collapse", minWidth: 900, fontSize: 14 }}>
          <thead>
            <tr>
              <th style={th}>IP</th>
              <th style={th}>Reason</th>
              <th style={th}>Expires</th>
              <th style={th}>Action</th>
            </tr>
          </thead>
          <tbody>
            {data.blocks.map((b) => (
              <tr key={b._id}>
                <td style={td}>{b.ip}</td>
                <td style={td}>{b.reason || "—"}</td>
                <td style={td}>{b.expiresAt ? new Date(b.expiresAt).toLocaleString() : "—"}</td>
                <td style={td}>
                  <button
                    type="button"
                    disabled={loading}
                    onClick={() => doUnblock(b._id)}
                    style={{ padding: "6px 10px" }}
                  >
                    Unblock
                  </button>
                </td>
              </tr>
            ))}
            {data.blocks.length === 0 && !loading && (
              <tr><td style={td} colSpan={4}>No blocks found.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div style={{ display: "flex", gap: 12, marginTop: 16, alignItems: "center" }}>
        <button type="button" onClick={() => load(Math.max(1, page - 1))} disabled={loading || page <= 1} style={{ padding: "8px 12px" }}>
          Prev
        </button>
        <span>Page {page}</span>
        <button type="button" onClick={() => load(page + 1)} disabled={loading || !data.hasMore} style={{ padding: "8px 12px" }}>
          Next
        </button>
      </div>
    </div>
  );
}

const th = { borderBottom: "1px solid #ccc", textAlign: "left", padding: "8px 6px" };
const td = { borderBottom: "1px solid #eee", padding: "6px 6px" };
