import { useState } from "react";
import { registerUser } from "../api/auth";

export default function Register() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setLoading(true);
    setStatus(null);

    try {
      const res = await registerUser({ email, password });
      setStatus({ type: "success", message: res.data.message || "Registered" });
      setEmail("");
      setPassword("");
    } catch (err) {
      const message =
        err.response?.data?.message || "Registration failed. Try again.";
      setStatus({ type: "error", message });
    } finally {
      setLoading(false);
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
            minLength={6}
            style={{ display: "block", width: "100%", marginTop: 4 }}
          />
        </label>

        <button
          type="submit"
          disabled={loading}
          style={{ marginTop: 16, padding: "8px 16px" }}
        >
          {loading ? "Creating..." : "Register"}
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
