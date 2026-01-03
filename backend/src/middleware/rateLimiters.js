const rateLimit = require("express-rate-limit");

function getClientIp(req) {
  const raw = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip || "";
  return raw.startsWith("::ffff:") ? raw.slice(7) : raw;
}

const isTest = process.env.NODE_ENV === "test";

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isTest ? 1000 : Number(process.env.LOGIN_RATE_LIMIT_MAX || 20),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  message: { message: "Too many attempts. Please try again later." },
});

const mfaLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: isTest ? 1000 : Number(process.env.MFA_RATE_LIMIT_MAX || 30),
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => getClientIp(req),
  message: { message: "Too many attempts. Please try again later." },
});

module.exports = { loginLimiter, mfaLimiter };
