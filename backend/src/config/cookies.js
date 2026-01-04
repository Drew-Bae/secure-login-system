const isProduction = process.env.NODE_ENV === "production";

function boolEnv(name, fallback) {
  if (process.env[name] == null) return fallback;
  return String(process.env[name]).toLowerCase() === "true";
}

// Auth cookie (HttpOnly JWT)
function authCookieOptions() {
  const secure = boolEnv("COOKIE_SECURE", isProduction);
  const sameSite = process.env.COOKIE_SAMESITE || (secure ? "none" : "lax");

  // Optional: set COOKIE_DOMAIN for subdomain setups
  const domain = process.env.COOKIE_DOMAIN || undefined;

  return {
    httpOnly: true,
    secure,
    sameSite,
    path: "/",
    domain,
    maxAge: 7 * 24 * 60 * 60 * 1000,
  };
}

// CSRF cookie (readable by JS, paired with header)
function csrfCookieOptions() {
  const secure = boolEnv("COOKIE_SECURE", isProduction);
  const sameSite = process.env.COOKIE_SAMESITE || (secure ? "none" : "lax");
  const domain = process.env.COOKIE_DOMAIN || undefined;

  return {
    httpOnly: false,
    secure,
    sameSite,
    path: "/",
    domain,
  };
}

function authCookieClearOptions() {
  const opts = authCookieOptions();
  delete opts.maxAge;     // IMPORTANT: don’t pass maxAge to clearCookie
  delete opts.expires;    // just in case
  return opts;
}

module.exports = { authCookieOptions, authCookieClearOptions, csrfCookieOptions };
