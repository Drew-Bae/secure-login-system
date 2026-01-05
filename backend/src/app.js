require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");

const authRoutes = require("./routes/authRoutes");
const adminRoutes = require("./routes/adminRoutes");
const mfaRoutes = require("./routes/mfaRoutes");
const deviceRoutes = require("./routes/deviceRoutes");

const { authLimiter } = require("./middleware/rateLimit");
const { csrfProtect } = require("./middleware/csrf");
const { blockIpMiddleware } = require("./middleware/blockIpMiddleware");

const app = express();

// Security headers
app.use(helmet());

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS
const allowedOrigins = (process.env.CLIENT_URLS || process.env.CLIENT_URL || "http://localhost:3000")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

const allowVercelPreviews = process.env.ALLOW_VERCEL_PREVIEWS === "true";

function isVercelPreviewOrigin(origin) {
  // Examples:
  // https://secure-login-system-gwg2om447-drewbaes-projects.vercel.app
  // https://secure-login-system-somehash.vercel.app
  if (!origin) return false;

  return (
    /^https:\/\/secure-login-system-[a-z0-9-]+\.vercel\.app$/.test(origin) ||
    /^https:\/\/secure-login-system-[a-z0-9-]+-drewbaes-projects\.vercel\.app$/.test(origin)
  );
}

app.use(
  cors({
    origin: function (origin, cb) {
      // allow non-browser tools (curl, Postman) with no origin
      if (!origin) return cb(null, true);

      // exact allowlist
      if (allowedOrigins.includes(origin)) return cb(null, true);

      // optional: allow Vercel preview deployments for this project
      if (allowVercelPreviews && isVercelPreviewOrigin(origin)) return cb(null, true);

      return cb(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
  })
);

// Trust proxy (important for x-forwarded-for parsing)
app.set("trust proxy", 1);

// CSRF protection (double-submit)
app.use(csrfProtect);

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", message: "Secure Login System API running" });
});

// Rate limiting for auth routes
app.use("/api/auth", authLimiter);

// Block IP
app.use(blockIpMiddleware);

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/mfa", mfaRoutes);
app.use("/api/devices", deviceRoutes);

module.exports = app;
