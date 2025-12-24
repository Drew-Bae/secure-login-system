import { useState } from "react";
import { generateBackupCodes } from "../api/auth";

export default function BackupCodes() {
  const [codes, setCodes] = useState([]);
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleGenerate() {
    setLoading(true);
    setStatus(null);
    setCodes([]);

    try {
      const res = await generateBackupCodes();
      setCodes(res.data.backupCodes || []);
      setStatus({
        type: "success",
        message:
          res.data?.message ||
          "Backup codes generated. Save them now — you won’t be able to view them again.",
      });
    } catch (err) {
      const message =
        err.response?.data?.message ||
        "Failed to generate backup codes. Make sure MFA is enabled and you are logged in.";
      setStatus({ type: "error", message });
    } finally {
      setLoading(false);
    }
  }

  function handleCopyAll() {
    const text = codes.join("\n");
    navigator.clipboard.writeText(text);
    setStatus({ type: "success", message: "Copied backup codes to clipboard." });
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui", maxWidth: 700 }}>
      <h1>Backup Codes</h1>
      <p>
        Backup codes are one-time use codes that let you sign in if you lose
        access to your authenticator app.
      </p>

      <button
        type="button"
        onClick={handleGenerate}
        disabled={loading}
        style={{ marginTop: 12, padding: "8px 16px" }}
      >
        {loading ? "Generating..." : "Generate new backup codes"}
      </button>

      {codes.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <p style={{ marginBottom: 8 }}>
            Save these now. You won’t be able to view them again:
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
            {codes.map((c) => (
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
            onClick={handleCopyAll}
            style={{ marginTop: 12, padding: "6px 12px" }}
          >
            Copy all
          </button>
        </div>
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
        Tip: Store backup codes in a password manager.
      </p>
    </div>
  );
}
