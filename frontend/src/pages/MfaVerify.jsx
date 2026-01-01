import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { mfaLogin } from "../api/auth";
import { useAuth } from "../context/AuthContext";

export default function MfaVerify() {
  const navigate = useNavigate();
  const [code, setCode] = useState("");
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const { refreshMe } = useAuth();

  const preAuthToken = sessionStorage.getItem("preAuthToken");

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setStatus(null);

    try {
      const res = await mfaLogin({ preAuthToken, code });
      setStatus({ type: "success", message: res.data?.message || "MFA verified." });

      // Clear token after successful verification
      sessionStorage.removeItem("preAuthToken");

      // Hydrate auth state, then send them to the Security page (visual cue)
      await refreshMe();
      navigate("/security", { replace: true });
      return;

    } catch (err) {
      const message =
        err.response?.data?.message || "Invalid code or session expired.";
      setStatus({ type: "error", message });
    } finally {
      setLoading(false);
    }
  }

  if (!preAuthToken) {
    return (
      <div style={{ padding: 24, fontFamily: "system-ui" }}>
        <h1>MFA Verification</h1>
        <p style={{ color: "crimson" }}>
          Missing pre-auth session. Please log in again.
        </p>
        <p>
          <Link to="/login">Back to login</Link>
        </p>
      </div>
    );
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>MFA Verification</h1>
      <p>Enter the 6-digit code from your authenticator app.</p>

      <form onSubmit={handleSubmit} style={{ maxWidth: 320 }}>
        <label style={{ display: "block", marginTop: 12 }}>
          Code (Authenticator or Backup Code)
          <input
            type="text"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            required
            placeholder="123456 or ABCD-EFGH"
            style={{ display: "block", width: "100%", marginTop: 4 }}
          />
        </label>

        <button
          type="submit"
          disabled={loading}
          style={{ marginTop: 16, padding: "8px 16px" }}
        >
          {loading ? "Verifying..." : "Verify"}
        </button>
      </form>

      <p style={{ marginTop: 12 }}>
        Lost your authenticator? Use one of the backup codes you saved during MFA setup.
      </p>

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

      <p style={{ marginTop: 16 }}>
        <Link to="/login">Back to login</Link>
      </p>
    </div>
  );
}
