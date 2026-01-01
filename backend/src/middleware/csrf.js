// backend/src/middleware/csrf.js
const crypto = require("crypto");

const isProduction = process.env.NODE_ENV === "production";

function getCookieOptions() {
  return {
    httpOnly: false,                 // must be readable by JS for double-submit
    secure: isProduction,            // required if SameSite=None
    sameSite: isProduction ? "none" : "lax",
    path: "/",
  };
}

/**
 * Double-submit CSRF:
 * - Server sets csrfToken cookie (NOT HttpOnly)
 * - Client sends matching X-CSRF-Token header on state-changing requests
 */
function csrfIssue(req, res) {
  const token = crypto.randomBytes(32).toString("hex");
  res.cookie("csrfToken", token, getCookieOptions());
  return res.status(200).json({ csrfToken: token });
}

function csrfProtect(req, res, next) {
  const method = req.method.toUpperCase();

  // Only protect state-changing requests
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return next();

  // Allow CSRF mint endpoint itself
  if (req.path === "/api/auth/csrf") return next();

  const cookieToken = req.cookies?.csrfToken;
  const headerToken = req.headers["x-csrf-token"];

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ message: "CSRF token missing or invalid" });
  }

  return next();
}

module.exports = { csrfIssue, csrfProtect };
