import { useEffect, useMemo, useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { fetchResetPasswordInfo, resetPassword } from "../api/auth";
import { useAuth } from "../context/AuthContext";

export default function ResetPassword() {
  const { user, logout } = useAuth();
  const [searchParams] = useSearchParams();
  const token = useMemo(() => searchParams.get("token"), [searchParams]);

  const [password, setPassword] = useState("");
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);
  const [target, setTarget] = useState(null);
  const [notice, setNotice] = useState(null);
  const [tokenError, setTokenError] = useState(null);

  useEffect(() => {
    if (!token) return;
    let cancelled = false;

    (async () => {
      try {
        const res = await fetchResetPasswordInfo(token);
        if (cancelled) return;
        setTarget(res.data || null);
        setTokenError(null);
      } catch (err) {
        if (cancelled) return;
        setTarget(null);
        setTokenError(
          err.response?.data?.message || "Reset token is invalid or has expired."
        );
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [token]);

  useEffect(() => {
    if (!target) return;
    if (!user) return;
    if (String(user.id) === String(target.userId)) return;

    (async () => {
      try {
        await logout();
      } finally {
        setNotice(
          `You were signed in as ${user.email}. This reset link is for ${target.emailMasked}, so we signed you out to proceed safely.`
        );
      }
    })();
  }, [target, user, logout]);

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
      // Ensure the UI doesn't continue to show a different signed-in user after password reset.
      // Backend clears the cookie as well; this just updates client state.
      try {
        await logout();
      } catch {
        // ignore
      }
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

  if (tokenError) {
    return (
      <div style={{ padding: 24, fontFamily: "system-ui" }}>
        <h1>Reset Password</h1>
        <p style={{ color: "crimson" }}>{tokenError}</p>
        <p>
          <Link to="/forgot-password">Request a new reset link</Link>
        </p>
      </div>
    );
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Reset Password</h1>
      <p>
        Choose a new password for your account.
        {target?.emailMasked ? (
          <>
            {" "}
            <span style={{ opacity: 0.85 }}>
              (Resetting password for <strong>{target.emailMasked}</strong>)
            </span>
          </>
        ) : null}
      </p>

      {notice && (
        <p style={{ marginTop: 12, padding: 12, border: "1px solid #ccc" }}>{notice}</p>
      )}

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
