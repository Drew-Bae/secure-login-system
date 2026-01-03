import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { sendStepUpEmail } from "../api/auth";

export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, login } = useAuth();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");

  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showEnableMfaLink, setShowEnableMfaLink] = useState(false);

  // If already logged in, send user to a meaningful page
  useEffect(() => {
    if (user) navigate("/security");
  }, [user, navigate]);

  async function handleLogin(e) {
    e.preventDefault();
    setLoading(true);
    setStatus(null);
    setShowEnableMfaLink(false);

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
        const { sendStepUpEmail } = await import("../api/auth");
        await sendStepUpEmail(res.data.preAuthToken, res.data.risk);

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

      // Risk-based block when MFA is not enabled
      if (code === 403 && data?.actionRequired === "ENABLE_MFA") {
        setStatus({ type: "error", message: `${data.message} (Risk: ${data.riskScore})` });
        setShowEnableMfaLink(true);
        return;
      }

      const message = err.response?.data?.message || "Login failed. Check your credentials.";
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
    </div>
  );
}
