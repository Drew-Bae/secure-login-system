import { useState } from "react";
import { mfaSetup, mfaVerify } from "../api/auth";

export default function MfaSetup() {
  const [qrDataUrl, setQrDataUrl] = useState(null);
  const [code, setCode] = useState("");
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [backupCodes, setBackupCodes] = useState([]);

  async function handleStart() {
    setLoading(true);
    setStatus(null);
    try {
      const res = await mfaSetup();
      setQrDataUrl(res.data.qrDataUrl);
      setStatus({
        type: "success",
        message: "Scan the QR code and enter the 6-digit code to enable MFA.",
      });
    } catch (err) {
      const message =
        err.response?.data?.message || "Failed to start MFA setup.";
      setStatus({ type: "error", message });
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify(e) {
    e.preventDefault();
    setLoading(true);
    setStatus(null);

    try {
      const res = await mfaVerify(code);

      const codes = res.data?.backupCodes || [];
      setBackupCodes(codes);

      setStatus({
        type: "success",
        message:
          res.data?.message ||
          "MFA enabled. Save your backup codes now — you won’t be able to view them again.",
      });

      setCode("");
    } catch (err) {
      const message =
        err.response?.data?.message || "Invalid code. Try again.";
      setStatus({ type: "error", message });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui", maxWidth: 600 }}>
      <h1>MFA Setup</h1>

      <p>
        Enable multi-factor authentication (TOTP) using an authenticator app
        (Google Authenticator, Authy, 1Password, etc.).
      </p>

      <button
        type="button"
        onClick={handleStart}
        disabled={loading}
        style={{ marginTop: 12, padding: "8px 16px" }}
      >
        {loading ? "Starting..." : "Start MFA setup"}
      </button>

      {qrDataUrl && (
        <div style={{ marginTop: 20 }}>
          <p style={{ marginBottom: 8 }}>
            Scan this QR code with your authenticator app:
          </p>
          <img
            src={qrDataUrl}
            alt="MFA QR Code"
            style={{ width: 220, height: 220, border: "1px solid #ddd" }}
          />
        </div>
      )}

      {qrDataUrl && (
        <form onSubmit={handleVerify} style={{ marginTop: 20, maxWidth: 320 }}>
          <label style={{ display: "block" }}>
            Verification Code
            <input
              type="text"
              inputMode="numeric"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              required
              placeholder="123456"
              style={{ display: "block", width: "100%", marginTop: 4 }}
            />
          </label>

          <button
            type="submit"
            disabled={loading}
            style={{ marginTop: 12, padding: "8px 16px" }}
          >
            {loading ? "Verifying..." : "Verify & Enable MFA"}
          </button>
        </form>
      )}

      {status && (
        <p
          style={{
            marginTop: 16,
            color: status.type === "error" ? "crimson" : "green",
          }}
        >
          {status.message}
        </p>
      )}

      <p style={{ marginTop: 16, color: "#666" }}>
        Note: You must be logged in to start MFA setup.
      </p>

      {backupCodes.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <h3 style={{ marginBottom: 8 }}>Your Backup Codes</h3>
          <p style={{ color: "#b45309", marginTop: 0 }}>
            Save these الآن. For security, they will not be shown again.
          </p>

          <div
            style={{
              border: "1px solid #ddd",
              borderRadius: 8,
              padding: 12,
              maxWidth: 360,
              background: "#fafafa",
            }}
          >
            {backupCodes.map((c) => (
              <div
                key={c}
                style={{
                  fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
                  padding: "4px 0",
                }}
              >
                {c}
              </div>
            ))}
          </div>

          <button
            type="button"
            onClick={() => navigator.clipboard.writeText(backupCodes.join("\n"))}
            style={{ marginTop: 12, padding: "6px 12px" }}
          >
            Copy all
          </button>
        </div>
      )}
    </div>
  );
}
