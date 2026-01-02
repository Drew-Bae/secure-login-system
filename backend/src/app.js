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

const app = express();

// Security headers
app.use(helmet());

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS
const allowedOrigin = process.env.CLIENT_URL || "http://localhost:3000";
app.use(
  cors({
    origin: allowedOrigin,
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

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/mfa", mfaRoutes);
app.use("/api/devices", deviceRoutes);

module.exports = app;
