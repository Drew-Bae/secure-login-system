require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const adminRoutes = require("./routes/adminRoutes");
const { authLimiter } = require("./middleware/rateLimit");
const mfaRoutes = require("./routes/mfaRoutes");
const deviceRoutes = require("./routes/deviceRoutes");
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

app.use(csrfProtect);

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", message: "Secure Login System API running" });
});

const PORT = process.env.PORT || 5000;

// Trust proxy (for correct IP behind Render later)
app.set("trust proxy", 1);

// Rate limiting for auth routes
app.use("/api/auth", authLimiter);

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/mfa", mfaRoutes);
app.use("/api/devices", deviceRoutes);

connectDB();
app.listen(PORT, "0.0.0.0", () =>
  console.log(`API listening on port ${PORT}`)
);
