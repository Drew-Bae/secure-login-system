import React from "react";
import { Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function Home() {
  return (
    <div style={{ padding: 24, fontFamily: "system-ui" }}>
      <h1>Secure Login System</h1>
      <p>Frontend running.</p>
      <AccountBadge />
    </div>
  );
}

function AccountBadge() {
  const { user, initializing } = useAuth();

  if (initializing) return <p style={{ opacity: 0.75 }}>Checking session...</p>;

  if (!user) {
    return (
      <p>
        You are not logged in. <Link to="/login">Log in</Link>
      </p>
    );
  }

  return (
    <p>
      Signed in as <strong>{user.email}</strong> — view your{" "}
      <Link to="/security">security</Link>.
    </p>
  );
}
