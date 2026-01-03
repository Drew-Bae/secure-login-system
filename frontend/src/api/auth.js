import client from "./client";

const api = client;

/**
 * ---- Device ID header (keep as-is) ----
 */
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

/**
 * ---- CSRF (double-submit) ----
 * Backend sets a csrfToken cookie (on API origin)
 * Frontend cannot reliably read that cookie cross-origin,
 * so we store the token returned from GET /auth/csrf in sessionStorage
 * and send it in X-CSRF-Token for state-changing requests.
 */
const CSRF_STORAGE_KEY = "sls_csrf_token";

function getStoredCsrf() {
  return sessionStorage.getItem(CSRF_STORAGE_KEY);
}

function setStoredCsrf(token) {
  if (token) sessionStorage.setItem(CSRF_STORAGE_KEY, token);
}

async function mintCsrf() {
  const res = await api.get("/auth/csrf");
  const token = res.data?.csrfToken;
  setStoredCsrf(token);
  return token;
}

async function ensureCsrf() {
  let token = getStoredCsrf();
  if (!token) token = await mintCsrf();
  return token;
}

// Attach CSRF header for state-changing requests
api.interceptors.request.use(async (config) => {
  const method = (config.method || "get").toLowerCase();

  if (["post", "put", "patch", "delete"].includes(method)) {
    const token = await ensureCsrf();
    if (token) config.headers["X-CSRF-Token"] = token;
  }

  return config;
});

/**
 * ---- API wrappers ----
 */

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

// Expose for UI features (Trust this device, highlighting current device)
export function getCurrentDeviceId() {
  return getDeviceId();
}

// POST /auth/logout-all
export function logoutAllDevices() {
  return api.post("/auth/logout-all");
}

// POST /devices/:deviceId/revoke
export function revokeDevice(deviceId) {
  return api.post(`/devices/${deviceId}/revoke`);
}

// POST /devices/:deviceId/compromised
export function markDeviceCompromised(deviceId, reason) {
  return api.post(`/devices/${deviceId}/compromised`, { reason });
}

// POST /auth/stepup-email
export function sendStepUpEmail(preAuthToken, risk) {
  return api.post("/auth/stepup-email", { preAuthToken, risk });
}

// POST /auth/verify-stepup
export function verifyStepUp(token, preAuthToken) {
  return api.post("/auth/verify-stepup", { token, preAuthToken });
}