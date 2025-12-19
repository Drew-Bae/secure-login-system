require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const adminRoutes = require("./routes/adminRoutes");
const { authLimiter } = require("./middleware/rateLimit");

const app = express();

app.set("trust proxy", 1); 

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

connectDB();
app.listen(PORT, "0.0.0.0", () =>
  console.log(`API listening on port ${PORT}`)
);
