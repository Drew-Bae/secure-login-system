import axios from "axios";

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || "/api",
  withCredentials: true,
});

function getDeviceId() {
  const key = "sls_device_id";
  let id = localStorage.getItem(key);

  if (!id) {
    id = crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`;
    localStorage.setItem(key, id);
  }

  return id;
}

api.interceptors.request.use((config) => {
  config.headers["x-device-id"] = getDeviceId();
  return config;
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

// POST /api/auth/forgot-password
export function forgotPassword(email) {
  return api.post("/auth/forgot-password", { email });
}

// POST /api/auth/reset-password
export function resetPassword({ token, password }) {
  return api.post("/auth/reset-password", { token, password });
}

// POST /api/auth/mfa-login
export function mfaLogin({ preAuthToken, code }) {
  return api.post("/auth/mfa-login", { preAuthToken, code });
}

// POST /mfa/setup
export function mfaSetup() {
  return api.post("/mfa/setup");
}

// POST /mfa/verify
export function mfaVerify(code) {
  return api.post("/mfa/verify", { code });
}

// POST /mfa/backup-codes/generate
export function generateBackupCodes() {
  return api.post("/mfa/backup-codes/generate");
}

// GET /auth/me
export function fetchMe() {
  return api.get("/auth/me");
}

// GET /auth/login-history
export function fetchLoginHistory() {
  return api.get("/auth/login-history");
}

// GET /devices
export function fetchDevices() {
  return api.get("/devices");
}

// POST /devices/deviceId/trust
export function trustDevice(deviceId) {
  return api.post(`/devices/${deviceId}/trust`);
}
