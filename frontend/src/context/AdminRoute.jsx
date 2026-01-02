import React from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function AdminRoute({ children }) {
  const { user, initializing } = useAuth();

  if (initializing) return null;
  if (!user) return <Navigate to="/login" replace />;
  if (user.role !== "admin") {
    return (
      <div style={{ padding: 24, fontFamily: "system-ui" }}>
        <h2>403 — Admin access required</h2>
        <p>You are logged in, but your account does not have admin privileges.</p>
      </div>
    );
  }

  return children;
}
