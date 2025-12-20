import axios from "axios";

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || "/api",
  withCredentials: true,
});

// POST /api/auth/register
export function registerUser({ email, password }) {
  return api.post("/auth/register", { email, password });
}

// POST /api/auth/login
export function loginUser({ email, password }) {
  return api.post("/auth/login", { email, password });
}

// POST /api/auth/logout
export function logoutUser() {
  return api.post("/auth/logout");
}

// GET /api/admin/login-attempts
export function fetchLoginAttempts({ onlySuspicious = false } = {}) {
  return api.get("/admin/login-attempts", {
    params: { onlySuspicious },
  });
}

// POST? /api/auth/forgot-password
export function forgotPassword(email) {
  return api.post("/auth/forgot-password", { email });
}

// POST? /api/auth/reset-password
export function resetPassword({ token, password }) {
  return api.post("/auth/reset-password", { token, password });
}

// POST? /api/auth/mfa-login
export function mfaLogin({ preAuthToken, code }) {
  return api.post("/auth/mfa-login", { preAuthToken, code });
}

// POST? /mfa/setup
export function mfaSetup() {
  return api.post("/mfa/setup");
}

// POST? /mfa/verify
export function mfaVerify(code) {
  return api.post("/mfa/verify", { code });
}
