const isTest = process.env.NODE_ENV === "test";

function getIp(req) {
  const raw = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip || "";
  return raw.startsWith("::ffff:") ? raw.slice(7) : raw;
}

function normEmail(email) {
  return String(email || "").trim().toLowerCase();
}

/**
 * Simple sliding-window limiter for login attempts per (email + ip).
 * - window: 10 minutes
 * - max: N attempts per window per (email, ip)
 */
const WINDOW_MS = 10 * 60 * 1000;

function maxAttempts() {
  return Number(process.env.LOGIN_EMAIL_IP_MAX || 10);
}

const store = new Map();
// key -> { count, firstTs }

function prune(now) {
  for (const [k, v] of store.entries()) {
    if (now - v.firstTs > WINDOW_MS) store.delete(k);
  }
}

// Default: bypass in tests to avoid flakiness.
// Set FORCE_LOGIN_TRACKER=true in a specific test to enable it.
function shouldBypass() {
  if (isTest && process.env.FORCE_LOGIN_TRACKER !== "true") return true;
  return false;
}

function loginAttemptTracker(req, res, next) {
  if (shouldBypass()) return next();

  const email = normEmail(req.body?.email);
  const ip = getIp(req);

  // If no email provided, fall back to IP-only
  const key = email ? `${email}::${ip}` : `__noemail__::${ip}`;
  const now = Date.now();

  prune(now);

  const existing = store.get(key);
  if (!existing) {
    store.set(key, { count: 1, firstTs: now });
    return next();
  }

  if (now - existing.firstTs > WINDOW_MS) {
    store.set(key, { count: 1, firstTs: now });
    return next();
  }

  existing.count += 1;
  store.set(key, existing);

  if (existing.count > maxAttempts()) {
    return res.status(429).json({ message: "Too many attempts. Please try again later." });
  }

  return next();
}

// For Jest: prevent state bleed between tests
function __resetForTests() {
  store.clear();
}

module.exports = { loginAttemptTracker, __resetForTests };
