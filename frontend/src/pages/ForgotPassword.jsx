import { useState } from "react";
import { forgotPassword } from "../api/auth";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setStatus(null);

    try {
      const res = await forgotPassword(email);
      setStatus({
        type: "success",
        message: res.data?.message || "If that email exists, a reset link was sent.",
      });
      setEmail("");
    } catch (err) {
      // Still show a generic message to avoid leaking info
      setStatus({
        type: "success",
        message: "If that email exists, a reset link was sent.",
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Forgot Password</h1>
      <p>Enter your email to receive a password reset link.</p>

      <form onSubmit={handleSubmit} style={{ maxWidth: 320 }}>
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

        <button
          type="submit"
          disabled={loading}
          style={{ marginTop: 16, padding: "8px 16px" }}
        >
          {loading ? "Sending..." : "Send reset link"}
        </button>
      </form>

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
