import { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { sendStepUpEmail, resendEmailVerification, forgotPassword } from "../api/auth";

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { login } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showEnableMfaLink, setShowEnableMfaLink] = useState(false);

  // Email verification UI
  const [verifyRequired, setVerifyRequired] = useState(false);
  const [verifyMsg, setVerifyMsg] = useState("");
  const [resendLoading, setResendLoading] = useState(false);
  const [resendMsg, setResendMsg] = useState("");

  // Reset password
  const [resetRequired, setResetRequired] = useState(false);
  const [resetMsg, setResetMsg] = useState("");
  const [resetLoading, setResetLoading] = useState(false);
  const [resetSentMsg, setResetSentMsg] = useState("");


  // If the user edits the email, clear verification/resend messages
  useEffect(() => {
    setVerifyRequired(false);
    setVerifyMsg("");
    setResendMsg("");
    setResetRequired(false);
    setResetMsg("");
    setResetSentMsg("");
  }, [email]);

  async function handleSendResetEmail() {
  if (!email) return;

  setResetLoading(true);
  setResetSentMsg("");

  try {
    const res = await forgotPassword(email);
    setResetSentMsg(res.data?.message || "If that email exists, a reset link has been sent.");
  } catch (err) {
    setResetSentMsg(err.response?.data?.message || "Could not send reset email.");
  } finally {
    setResetLoading(false);
  }
}

  async function handleResendVerification() {
    if (!email) return;

    setResendLoading(true);
    setResendMsg("");

    try {
      const res = await resendEmailVerification(email);
      setResendMsg(res.data?.message || "Verification email sent.");
    } catch (err) {
      setResendMsg(err.response?.data?.message || "Could not resend verification email.");
    } finally {
      setResendLoading(false);
    }
  }

  async function handleLogin(e) {
    e.preventDefault();

    setLoading(true);
    setStatus(null);
    setShowEnableMfaLink(false);

    // Clear any previous verify-required UI for a fresh attempt
    setVerifyRequired(false);
    setVerifyMsg("");
    setResendMsg("");

    try {
      const res = await login({ email, password });

      // MFA step-up required
      if (res.data?.mfaRequired) {
        sessionStorage.setItem("preAuthToken", res.data.preAuthToken);
        setStatus({ type: "success", message: "MFA required. Continue to verification." });
        setPassword("");
        navigate("/mfa-verify");
        return;
      }

      // Email step-up required (high-risk without MFA)
      if (res.data?.stepUpRequired && res.data?.stepUpMethod === "email") {
        sessionStorage.setItem("preAuthToken", res.data.preAuthToken);

        // Trigger email
        try {
          await sendStepUpEmail(res.data.preAuthToken, res.data.risk);
        } catch (e) {
          console.error("sendStepUpEmail failed:", e);
        }

        setStatus({
          type: "success",
          message: "Check your email to verify this login. The link expires in 10 minutes.",
        });
        setPassword("");
        return;
      }

      // Normal success (with optional high-risk warning)
      if (res.data?.highRisk) {
        setStatus({
          type: "success",
          message: `Logged in (High risk flagged: ${res.data.riskScore}). Enable MFA for stronger protection.`,
        });
        setShowEnableMfaLink(true);
      } else {
        setStatus({ type: "success", message: res.data?.message || "Logged in" });
      }

      setPassword("");

      // Navigate back to the page the user originally requested, if any
      const from = location.state?.from || "/security";
      navigate(from);
    } catch (err) {
      const code = err.response?.status;
      const data = err.response?.data;

      // ✅ Email verification required
      if (code === 403 && data?.actionRequired === "VERIFY_EMAIL") {
        setVerifyRequired(true);
        setVerifyMsg(data?.message || "Please verify your email to continue.");
        // Message is rendered in the Verify Email panel below; avoid duplicating it via `status`.
        setStatus(null);
        return;
      }

      // ✅ Forced password reset required
      if (code === 403 && data?.actionRequired === "FORCE_PASSWORD_RESET") {
        setResetRequired(true);
        setResetMsg(data?.message || "Password reset required.");
        // Message is rendered in the Reset panel below; avoid duplicating it via `status`.
        setStatus(null);
        return;
      }

      // Risk-based block when MFA is not enabled
      if (code === 403 && data?.actionRequired === "ENABLE_MFA") {
        setStatus({ type: "error", message: `${data.message} (Risk: ${data.riskScore})` });
        setShowEnableMfaLink(true);
        return;
      }

      const message = data?.message || "Login failed. Check your credentials.";
      setStatus({ type: "error", message });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Login</h1>

      <form onSubmit={handleLogin} style={{ maxWidth: 320 }}>
        <label style={{ display: "block", marginTop: 12 }}>
          Email
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            style={{ display: "block", width: "100%", marginTop: 4 }}
          />
        </label>

        <label style={{ display: "block", marginTop: 12 }}>
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={{ display: "block", width: "100%", marginTop: 4 }}
          />
        </label>

        <button type="submit" disabled={loading} style={{ marginTop: 16, padding: "8px 16px" }}>
          {loading ? "Logging in..." : "Login"}
        </button>

        <p style={{ marginTop: 12 }}>
          <a href="/forgot-password">Forgot password?</a>
        </p>
      </form>

      {status && (
        <>
          <p style={{ marginTop: 16, color: status.type === "error" ? "crimson" : "green" }}>
            {status.message}
          </p>

          {showEnableMfaLink && (
            <p style={{ marginTop: 12 }}>
              <a href="/mfa/setup">Enable MFA</a>
            </p>
          )}
        </>
      )}

      {/* ✅ VERIFY EMAIL PANEL */}
      {verifyRequired && (
        <div style={{ marginTop: 16, maxWidth: 420 }}>
          <p style={{ color: "crimson" }}>{verifyMsg}</p>

          <button
            type="button"
            onClick={handleResendVerification}
            disabled={resendLoading || !email}
            style={{ marginTop: 8, padding: "8px 12px" }}
          >
            {resendLoading ? "Sending..." : "Resend verification email"}
          </button>

          {resendMsg && <p style={{ marginTop: 8 }}>{resendMsg}</p>}
        </div>
      )}

      {/* ✅ FORCE RESET PANEL */}
      {resetRequired && (
        <div style={{ marginTop: 16, maxWidth: 420 }}>
          <p style={{ color: "crimson" }}>{resetMsg}</p>

          <button
            type="button"
            onClick={handleSendResetEmail}
            disabled={resetLoading || !email}
            style={{ marginTop: 8, padding: "8px 12px" }}
          >
            {resetLoading ? "Sending..." : "Send password reset email"}
          </button>

          {resetSentMsg && <p style={{ marginTop: 8 }}>{resetSentMsg}</p>}
        </div>
      )}
    </div>
  );
}
