import { useMemo, useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { resetPassword } from "../api/auth";

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = useMemo(() => searchParams.get("token"), [searchParams]);

  const [password, setPassword] = useState("");
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setStatus(null);

    try {
      const res = await resetPassword({ token, password });
      setStatus({
        type: "success",
        message: res.data?.message || "Password reset successful.",
      });
      setDone(true);
      setPassword("");
    } catch (err) {
      const message =
        err.response?.data?.message || "Reset failed. Token may be invalid or expired.";
      setStatus({ type: "error", message });
    } finally {
      setLoading(false);
    }
  }

  if (!token) {
    return (
      <div style={{ padding: 24, fontFamily: "system-ui" }}>
        <h1>Reset Password</h1>
        <p style={{ color: "crimson" }}>
          Missing reset token. Please use the link from your email.
        </p>
        <p>
          <Link to="/forgot-password">Request a new reset link</Link>
        </p>
      </div>
    );
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Reset Password</h1>
      <p>Choose a new password for your account.</p>

      <form onSubmit={handleSubmit} style={{ maxWidth: 320 }}>
        <label style={{ display: "block", marginTop: 12 }}>
          New Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={12}
            style={{ display: "block", width: "100%", marginTop: 4 }}
            disabled={done}
          />
          <div style={{ fontSize: 12, opacity: 0.75, marginTop: 6 }}>
            At least 12 characters, with uppercase, lowercase, number, and a special character.
          </div>
        </label>

        <button
          type="submit"
          disabled={loading || done}
          style={{ marginTop: 16, padding: "8px 16px" }}
        >
          {loading ? "Resetting..." : "Reset password"}
        </button>
      </form>

      {done && (
        <p style={{ marginTop: 16 }}>
          <Link to="/login">Go to login</Link>
        </p>
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
    </div>
  );
}
