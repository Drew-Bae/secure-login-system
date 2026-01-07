import { useState } from "react";
import { registerUser, resendEmailVerification } from "../api/auth";

export default function Register() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showVerifyPrompt, setShowVerifyPrompt] = useState(false);
  const [verifyMsg, setVerifyMsg] = useState("");
  const [resendLoading, setResendLoading] = useState(false);
  const [resendMsg, setResendMsg] = useState("");


  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setStatus(null);

    try {
      const res = await registerUser({ email, password });
      setStatus({ type: "success", message: res.data.message || "Registered" });
      setPassword("");
      setShowVerifyPrompt(true);
      setVerifyMsg("Account created. Please verify your email before logging in.");
      setResendMsg(""); 
    } catch (err) {
      setShowVerifyPrompt(false);
      setVerifyMsg("");
      setResendMsg("");

      const message = err.response?.data?.message || "Registration failed. Try again.";
      setStatus({ type: "error", message });
    } finally {
      setLoading(false);
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

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Create an account</h1>
      <form onSubmit={handleSubmit} style={{ maxWidth: 320 }}>
        <label style={{ display: "block", marginTop: 12 }}>
          Email
          <input
            type="email"
            value={email}
            onChange={(e) => {
              setEmail(e.target.value);
              setShowVerifyPrompt(false);
              setVerifyMsg("");
              setResendMsg("");
            }}
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
            minLength={12}
            style={{ display: "block", width: "100%", marginTop: 4 }}
          />
          <div style={{ fontSize: 12, opacity: 0.75, marginTop: 6 }}>
            At least 12 characters, with upper, lower, number, and a special character.
          </div>
        </label>

        <button
          type="submit"
          disabled={loading}
          style={{ marginTop: 16, padding: "8px 16px" }}
        >
          {loading ? "Creating..." : "Register"}
        </button>
      </form>

      {showVerifyPrompt && (
        <div style={{ marginTop: 16 }}>
          <p>{verifyMsg}</p>

          <button
            type="button"
            onClick={handleResendVerification}
            disabled={resendLoading || !email}
            style={{ padding: "8px 12px" }}
          >
            {resendLoading ? "Sending..." : "Resend verification email"}
          </button>

          {resendMsg && <p style={{ marginTop: 8 }}>{resendMsg}</p>}
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
    </div>
  );
}
