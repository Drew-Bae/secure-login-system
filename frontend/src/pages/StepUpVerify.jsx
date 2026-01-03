import React, { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { verifyStepUp } from "../api/auth";
import { useAuth } from "../context/AuthContext";

function useQuery() {
  return new URLSearchParams(useLocation().search);
}

export default function StepUpVerify() {
  const q = useQuery();
  const navigate = useNavigate();

  const token = q.get("token");
  const preAuthToken = q.get("preAuthToken");
  const { refreshMe } = useAuth();

  const [status, setStatus] = useState({ type: "info", message: "Verifying..." });

  useEffect(() => {
    async function run() {
      if (!token || !preAuthToken) {
        setStatus({ type: "error", message: "Missing verification info." });
        return;
      }

      try {
        await verifyStepUp(token, preAuthToken);
        await refreshMe();
        setStatus({ type: "success", message: "Verified! Redirecting..." });
        setTimeout(() => navigate("/security"), 800);
      } catch (err) {
        setStatus({ type: "error", message: "Verification failed or expired." });
      }
    }
    run();
  }, [token, preAuthToken, navigate]);

  return (
    <div style={{ maxWidth: 560, margin: "40px auto", padding: 16 }}>
      <h2>Verify Login</h2>
      <p>{status.message}</p>

      {status.type === "error" && (
        <button onClick={() => navigate("/login")} style={{ marginTop: 12 }}>
          Back to Login
        </button>
      )}
    </div>
  );
}
