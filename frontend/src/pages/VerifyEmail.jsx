import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { verifyEmail, resendEmailVerification } from "../api/auth";

export default function VerifyEmail() {
  const [params] = useSearchParams();
  const token = params.get("token") || "";

  const [status, setStatus] = useState({
    type: "info",
    message: "Verifying your email...",
  });

  const [resendEmail, setResendEmail] = useState("");
  const [resendStatus, setResendStatus] = useState(null);
  const [resendLoading, setResendLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;

    (async () => {
      if (!token) {
        setStatus({ type: "error", message: "Missing verification token." });
        return;
      }

      try {
        const res = await verifyEmail(token);
        if (cancelled) return;
        setStatus({ type: "success", message: res.data?.message || "Email verified." });
      } catch (err) {
        if (cancelled) return;
        const msg =
          err.response?.data?.message ||
          "Verification failed. The link may be invalid or expired.";
        setStatus({ type: "error", message: msg });
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [token]);

  async function handleResend(e) {
    e.preventDefault();
    setResendLoading(true);
    setResendStatus(null);

    try {
      const res = await resendEmailVerification(resendEmail);
      setResendStatus({ type: "success", message: res.data?.message || "Sent." });
      setResendEmail("");
    } catch (err) {
      const msg = err.response?.data?.message || "Could not resend verification link.";
      setResendStatus({ type: "error", message: msg });
    } finally {
      setResendLoading(false);
    }
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Verify Email</h1>

      <p
        style={{
          color:
            status.type === "error" ? "crimson" : status.type === "success" ? "green" : "#333",
        }}
      >
        {status.message}
      </p>

      {status.type === "success" && (
        <p style={{ marginTop: 16 }}>
          <Link to="/login">Go to Login</Link>
        </p>
      )}

      {status.type === "error" && (
        <div style={{ marginTop: 24, maxWidth: 420 }}>
          <h3>Resend a new link</h3>
          <form onSubmit={handleResend}>
            <label style={{ display: "block", marginTop: 12 }}>
              Email
              <input
                type="email"
                value={resendEmail}
                onChange={(e) => setResendEmail(e.target.value)}
                required
                style={{ display: "block", width: "100%", marginTop: 4 }}
              />
            </label>

            <button
              type="submit"
              disabled={resendLoading}
              style={{ marginTop: 12, padding: "8px 16px" }}
            >
              {resendLoading ? "Sending..." : "Resend verification email"}
            </button>
          </form>

          {resendStatus && (
            <p style={{ marginTop: 12, color: resendStatus.type === "error" ? "crimson" : "green" }}>
              {resendStatus.message}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
