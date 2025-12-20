const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const User = require("../models/User");
const LoginAttempt = require("../models/LoginAttempt");

const router = express.Router();

const isProduction = process.env.NODE_ENV === "production";

const crypto = require("crypto");
const { sendPasswordResetEmail } = require("../services/emailService");

const speakeasy = require("speakeasy");

// helper to create JWT
function createToken(userId) {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: "7d" });
}

// helper to create PREAUTH_JWT
function createPreAuthToken(userId) {
  return jwt.sign({ userId, type: "preauth" }, process.env.PREAUTH_JWT_SECRET, {
    expiresIn: "5m",
  });
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
  const genericResponse = {
    message: "If that email exists, a password reset link has been sent.",
  };

  try {
    const { email } = req.body;

    if (!email) return res.status(200).json(genericResponse);

    const user = await User.findOne({ email });
    if (!user) return res.status(200).json(genericResponse);

    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const expires = new Date(Date.now() + 20 * 60 * 1000);

    user.resetPasswordTokenHash = tokenHash;
    user.resetPasswordExpiresAt = expires;
    await user.save();

    const base = process.env.CLIENT_URL || "http://localhost:3000";
    const resetUrl = `${base}/reset-password?token=${rawToken}`;

    // If email fails, don't throw the whole route
    try {
      await sendPasswordResetEmail({ to: user.email, resetUrl });
    } catch (e) {
      console.error("sendPasswordResetEmail failed:", e);
    }

    return res.status(200).json(genericResponse);
  } catch (err) {
    console.error("Forgot password error:", err);
    return res.status(200).json(genericResponse); // <- important
  }
});


// RESET PASSWORD
router.post("/reset-password", async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ message: "Invalid request" });
    }

    // Hash the provided token to match stored hash
    const tokenHash = crypto
      .createHash("sha256")
      .update(token)
      .digest("hex");

    // Find user with matching token AND valid expiry
    const user = await User.findOne({
      resetPasswordTokenHash: tokenHash,
      resetPasswordExpiresAt: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({
        message: "Reset token is invalid or has expired",
      });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update password and invalidate token
    user.password = hashedPassword;
    user.resetPasswordTokenHash = undefined;
    user.resetPasswordExpiresAt = undefined;

    await user.save();

    return res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("Reset password error:", err);
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

    // Always keep responses generic
    if (!user) {
      // still log attempt (unknown user)
      await LoginAttempt.create({
        email,
        ip,
        userAgent,
        success: false,
        suspicious: false,
        reasons: [],
      });

      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Check lockout
    const now = new Date();
    if (user.lockoutUntil && user.lockoutUntil > now) {
      const suspiciousReasons = ["account_locked"];

      await LoginAttempt.create({
        email,
        ip,
        userAgent,
        success: false,
        suspicious: true,
        reasons: suspiciousReasons,
      });

      return res.status(429).json({
        message: "Account temporarily locked. Please try again later.",
      });
    }

    // Verify password
    const match = await bcrypt.compare(password, user.password);
    const success = match;

    // Suspicious logic v1 (keeps your existing approach)
    const suspiciousReasons = [];

    const recentAttempts = await LoginAttempt.find({ email })
      .sort({ createdAt: -1 })
      .limit(10);

    // Multiple recent failures in last 10 minutes
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
    const recentFailures = recentAttempts.filter(
      (a) => a.createdAt > tenMinutesAgo && a.success === false
    );

    if (!success && recentFailures.length >= 3) {
      suspiciousReasons.push("multiple_failed_attempts_recently");
    }

    // Successful login from a new IP
    if (success) {
      const hasSeenIpBefore = recentAttempts.some(
        (a) => a.success === true && a.ip === ip
      );
      if (!hasSeenIpBefore) {
        suspiciousReasons.push("new_ip_for_account");
      }
    }

    // Lockout mechanics
    if (!success) {
      user.failedLoginCount = (user.failedLoginCount || 0) + 1;

      // Lock after 5 failures
      if (user.failedLoginCount >= 5) {
        user.lockoutUntil = new Date(Date.now() + 15 * 60 * 1000);
        suspiciousReasons.push("lockout_triggered");
      }

      await user.save();
    } else {
      // Reset failure counters on success
      user.failedLoginCount = 0;
      user.lockoutUntil = undefined;
      await user.save();
    }

    const suspicious = suspiciousReasons.length > 0;

    // Log attempt
    await LoginAttempt.create({
      email,
      ip,
      userAgent,
      success,
      suspicious,
      reasons: suspiciousReasons,
    });

    if (!success) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    // If MFA enabled, require step-up verification
    if (user.mfaEnabled) {
      const preAuthToken = createPreAuthToken(user._id);

      // Log the attempt as success=true (password correct), but MFA pending
      // (You can optionally add another reason like "mfa_required".)
      return res.json({
        message: "MFA required",
        mfaRequired: true,
        preAuthToken,
      });
    }

    const token = createToken(user._id);

    res.cookie("token", token, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
    });

    return res.json({ message: "Logged in" });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// MFA LOGIN
router.post("/mfa-login", async (req, res) => {
  try {
    const { preAuthToken, code } = req.body;

    if (!preAuthToken || !code) {
      return res.status(400).json({ message: "Invalid request" });
    }

    let payload;
    try {
      payload = jwt.verify(preAuthToken, process.env.PREAUTH_JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: "Pre-auth token expired or invalid" });
    }

    if (payload.type !== "preauth") {
      return res.status(401).json({ message: "Invalid pre-auth token" });
    }

    const user = await User.findById(payload.userId);
    if (!user || !user.mfaEnabled || !user.mfaSecret) {
      return res.status(401).json({ message: "MFA not enabled for this account" });
    }

    const ok = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token: String(code).replace(/\s/g, ""),
      window: 1,
    });

    if (!ok) {
      return res.status(400).json({ message: "Invalid MFA code" });
    }

    // Issue the real auth token
    const token = createToken(user._id);

    res.cookie("token", token, {
      httpOnly: true,
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
    });

    return res.json({ message: "Logged in with MFA" });
  } catch (err) {
    console.error("MFA login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// LOGOUT
router.post("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ message: "Logged out" });
});

module.exports = router;
