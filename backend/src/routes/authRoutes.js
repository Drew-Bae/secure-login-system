const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const User = require("../models/User");
const LoginAttempt = require("../models/LoginAttempt");

const router = express.Router();

const isProduction = process.env.NODE_ENV === "production";

const crypto = require("crypto");
const { sendPasswordResetEmail } = require("../services/emailService");

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

// FORGOT PASSWORD
router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    // Always respond the same to prevent account enumeration
    const genericResponse = {
      message: "If that email exists, a password reset link has been sent.",
    };

    if (!email) {
      return res.status(200).json(genericResponse);
    }

    const user = await User.findOne({ email });

    // If user doesn't exist, still respond generically
    if (!user) {
      return res.status(200).json(genericResponse);
    }

    // Create random token (raw) and hash it for storage
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");

    // Expire in 20 minutes
    const expires = new Date(Date.now() + 20 * 60 * 1000);

    user.resetPasswordTokenHash = tokenHash;
    user.resetPasswordExpiresAt = expires;
    await user.save();

    // Build reset URL for frontend (we’ll set this in env later)
    const base = process.env.CLIENT_URL || "http://localhost:3000";
    const resetUrl = `${base}/reset-password?token=${rawToken}`;

    await sendPasswordResetEmail({ to: user.email, resetUrl });

    return res.status(200).json(genericResponse);
  } catch (err) {
    console.error("Forgot password error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const ip = req.ip;
  const userAgent = req.headers["user-agent"] || "unknown";

  try {
    // Basic validation
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });

    let success = false;

    if (user) {
      const match = await bcrypt.compare(password, user.password);
      success = match;
    }

    // --- Suspicious login logic v1 ---
    const suspiciousReasons = [];

    // Recent attempts for this email (last 10)
    const recentAttempts = await LoginAttempt.find({ email })
      .sort({ createdAt: -1 })
      .limit(10);

    // 1) Multiple recent failures in last 10 minutes
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
    const recentFailures = recentAttempts.filter(
      (a) => a.createdAt > tenMinutesAgo && a.success === false
    );

    if (!success && recentFailures.length >= 3) {
      suspiciousReasons.push("multiple_failed_attempts_recently");
    }

    // 2) Successful login from a new IP
    if (success) {
      const hasSeenIpBefore = recentAttempts.some(
        (a) => a.success === true && a.ip === ip
      );
      if (!hasSeenIpBefore) {
        suspiciousReasons.push("new_ip_for_account");
      }
    }

    const suspicious = suspiciousReasons.length > 0;

    // Log the attempt with suspicion metadata
    await LoginAttempt.create({
      email,
      ip,
      userAgent,
      success,
      suspicious,
      reasons: suspiciousReasons,
    });

    // If invalid, bail out AFTER logging
    if (!user || !success) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Create JWT + cookie
    const token = createToken(user._id);

    res.cookie("token", token, {
      httpOnly: true,
      secure: isProduction,                 // HTTPS only in prod
      sameSite: isProduction ? "none" : "lax",
    });

    return res.json({ message: "Logged in" });
  } catch (err) {
    console.error("Login error:", err);

    // Optional: log a failed attempt if something blows up before success
    try {
      await LoginAttempt.create({
        email,
        ip,
        userAgent,
        success: false,
        suspicious: true,
        reasons: ["server_error_during_login"],
      });
    } catch (logErr) {
      console.error("Failed to log login attempt:", logErr);
    }

    return res.status(500).json({ message: "Server error" });
  }
});

// LOGOUT
router.post("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ message: "Logged out" });
});

module.exports = router;
