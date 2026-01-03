// backend/src/middleware/csrf.js
const crypto = require("crypto");
const { csrfCookieOptions } = require("../config/cookies");

/**
 * Double-submit CSRF:
 * - Server sets csrfToken cookie (NOT HttpOnly)
 * - Client sends matching X-CSRF-Token header on state-changing requests
 */
function csrfIssue(req, res) {
  const token = crypto.randomBytes(32).toString("hex");
  res.cookie("csrf_token", token, csrfCookieOptions());
  return res.status(200).json({ csrfToken: token });
}

function csrfProtect(req, res, next) {
  const method = req.method.toUpperCase();

  // Only protect state-changing requests
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return next();

  // Allow CSRF mint endpoint itself (use originalUrl because req.path may be mounted)
  const url = req.originalUrl || "";
  if (url.startsWith("/api/auth/csrf")) return next();

  const cookieToken = req.cookies?.csrf_token || req.cookies?.csrfToken;
  const headerToken = req.headers["x-csrf-token"];

  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ message: "CSRF token missing or invalid" });
  }

  return next();
}

module.exports = { csrfIssue, csrfProtect };
