const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const User = require("../models/User");
const LoginAttempt = require("../models/LoginAttempt");

const router = express.Router();

const isProduction = process.env.NODE_ENV === "production";

// helper to create JWT
function createToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "7d" });
}

// REGISTER
router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({
      email,
      password: hashed,
    });

    return res
      .status(201)
      .json({ message: "User registered", userId: user._id });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const ip = req.ip;
  const userAgent = req.headers["user-agent"] || "unknown";

  try {
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });

    let success = false;

    if (user) {
      const match = await bcrypt.compare(password, user.password);
      success = match;
    }

    // Log the attempt
    await LoginAttempt.create({
      email,
      ip,
      userAgent,
      success,
    });

    if (!user || !success) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = createToken(user._id);

    res.cookie("token", token, {
      httpOnly: true,
      secure: isProduction, // HTTPS only in production
      sameSite: isProduction ? "none" : "lax",
    });

    return res.json({ message: "Logged in" });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// LOGOUT
router.post("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ message: "Logged out" });
});

module.exports = router;
