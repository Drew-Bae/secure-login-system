const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");
require("dotenv").config();

const app = express();

// Security headers
app.use(helmet());

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// CORS (tighten later when deployed)
app.use(
  cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
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

// Routes
app.use("/api/auth", authRoutes);

connectDB();
app.listen(PORT, "0.0.0.0", () =>
  console.log(`API listening on port ${PORT}`)
);
