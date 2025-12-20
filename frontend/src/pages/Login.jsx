import { useState } from "react";
import { loginUser, logoutUser } from "../api/auth";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(false);
  const [loggedIn, setLoggedIn] = useState(false);

  async function handleLogin(e) {
    e.preventDefault();
    setLoading(true);
    setStatus(null);

    try {
      const res = await loginUser({ email, password });

      // If MFA required, store token and redirect
      if (res.data?.mfaRequired) {
        sessionStorage.setItem("preAuthToken", res.data.preAuthToken);
        setStatus({ type: "success", message: "MFA required. Continue to verification." });
        setLoggedIn(false);
        setPassword("");

        // redirect (hard redirect works, but we’ll do SPA navigation)
        window.location.href = "/mfa-verify";
        return;
      }

      setStatus({ type: "success", message: res.data.message || "Logged in" });
      setLoggedIn(true);
      setPassword("");
    } catch (err) {
      const message =
        err.response?.data?.message || "Login failed. Check your credentials.";
      setStatus({ type: "error", message });
      setLoggedIn(false);
    } finally {
      setLoading(false);
    }
  }

  async function handleLogout() {
    try {
      await logoutUser();
      setLoggedIn(false);
      setStatus({ type: "success", message: "Logged out" });
    } catch (err) {
      const message =
        err.response?.data?.message || "Logout failed. Try again.";
      setStatus({ type: "error", message });
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

        <button
          type="submit"
          disabled={loading}
          style={{ marginTop: 16, padding: "8px 16px" }}
        >
          {loading ? "Logging in..." : "Login"}
        </button>
        <p style={{ marginTop: 12 }}>
          <a href="/forgot-password">Forgot password?</a>
        </p>
      </form>

      {loggedIn && (
        <button
          onClick={handleLogout}
          style={{ marginTop: 16, padding: "6px 12px" }}
        >
          Logout
        </button>
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
