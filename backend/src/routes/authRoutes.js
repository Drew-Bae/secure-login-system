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
const { requireAuth } = require("../middleware/authMiddleware");
const geoip = require("geoip-lite");
const TrustedDevice = require("../models/TrustedDevice");
const { csrfIssue } = require("../middleware/csrf");
const { decrypt } = require("../utils/crypto");
const { authCookieOptions } = require("../config/cookies");


// helper to create JWT (session token)
function createToken({ user, deviceId, deviceTokenVersion }) {
  return jwt.sign(
    {
      userId: user._id?.toString?.() || user.userId || user.id,
      role: user.role,
      tokenVersion: user.tokenVersion || 0,

      // device-bound session
      deviceId: deviceId || "unknown",
      deviceTokenVersion: deviceTokenVersion || 0,
    },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// helper to create PREAUTH_JWT
function createPreAuthToken(userId) {
  return jwt.sign({ userId, type: "preauth" }, process.env.PREAUTH_JWT_SECRET, {
    expiresIn: "5m",
  });
}

const RISK_WARN_THRESHOLD = 60;
const RISK_BLOCK_THRESHOLD = 85;
const NEW_ACCOUNT_GRACE_HOURS = 24;
const NEW_ACCOUNT_SUCCESS_LOGINS_GRACE = 2;
const NEW_ACCOUNT_RISK_CAP = 40;

// helper to compute RiskScore
function computeRiskScore({ success, reasons = [] }) {
  // Base score
  let score = 0;

  // Reason weights (tune anytime)
  const weights = {
    new_device_for_account: 35,
    new_ip_for_account: 20,
    multiple_failed_attempts_recently: 25,
    lockout_triggered: 40,
    account_locked: 50,
    impossible_travel: 60,
    high_risk_login: 0, // if you added this earlier
    device_untrusted: 25,
  };

  for (const r of reasons) {
    score += weights[r] || 5; // unknown reasons get small weight
  }

  // Add context-based adjustments
  if (!success) score += 10; // failed attempt is inherently higher risk

  // Clamp 0–100
  score = Math.max(0, Math.min(100, score));
  return score;
}

// helper for geo-location
function toRad(d) {
  return (d * Math.PI) / 180;
}

function haversineMiles(lat1, lon1, lat2, lon2) {
  const R = 3958.8; // Earth radius in miles
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// GET /api/auth/csrf
router.get("/csrf", csrfIssue);

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

  const rawIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
  const ip = rawIp?.startsWith("::ffff:") ? rawIp.replace("::ffff:", "") : rawIp;
  const userAgent = req.headers["user-agent"] || "unknown";
  const deviceId = req.headers["x-device-id"] || "unknown";

  const geo = geoip.lookup(ip);
  const geoObj = geo
    ? {
        country: geo.country,
        region: geo.region,
        city: geo.city,
        ll: geo.ll, // [lat, lon]
      }
    : undefined;

  try {
    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const user = await User.findOne({ email });

    // Always keep responses generic
    if (!user) {
      const reasons = [];
      const riskScore = computeRiskScore({ success: false, reasons });

      // still log attempt (unknown user)
      await LoginAttempt.create({
        email,
        ip,
        userAgent,
        deviceId,
        success: false,
        suspicious: false,
        reasons,
        riskScore,
        rawRiskScore,
        geo: geoObj,
      });

      return res.status(400).json({ message: "Invalid credentials" });
    }

    // Check lockout
    const now = new Date();
    if (user.lockoutUntil && user.lockoutUntil > now) {
      const suspiciousReasons = ["account_locked"];
      const riskScore = computeRiskScore({ success: false, reasons: suspiciousReasons });

      await LoginAttempt.create({
        email,
        ip,
        userAgent,
        deviceId,
        success: false,
        suspicious: true,
        reasons: suspiciousReasons,
        riskScore,
        rawRiskScore,
        geo: geoObj,
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

    const accountAgeHours =
      (Date.now() - new Date(user.createdAt).getTime()) / (1000 * 60 * 60);

    const priorSuccessfulLogins = recentAttempts.filter((a) => a.success === true).length;

    const isNewAccount =
      accountAgeHours < NEW_ACCOUNT_GRACE_HOURS &&
      priorSuccessfulLogins < NEW_ACCOUNT_SUCCESS_LOGINS_GRACE;

    // Multiple recent failures in last 10 minutes
    const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000);
    const recentFailures = recentAttempts.filter(
      (a) => a.createdAt > tenMinutesAgo && a.success === false
    );

    if (!success && recentFailures.length >= 3) {
      suspiciousReasons.push("multiple_failed_attempts_recently");
    }

    // Successful login from a new IP
    if (success && !isNewAccount) {
      const hasSeenIpBefore = recentAttempts.some(
        (a) => a.success === true && a.ip === ip
      );
      if (!hasSeenIpBefore) {
        suspiciousReasons.push("new_ip_for_account");
      }
    }

    // device check
    // ---- DEVICE TRACKING & TRUST LOGIC ----
    let isNewDevice = false;
    let deviceDoc = null;

    if (success && deviceId && deviceId !== "unknown") {
      const existedBefore = await TrustedDevice.exists({ userId: user._id, deviceId });
      isNewDevice = !existedBefore;

      deviceDoc = await TrustedDevice.findOneAndUpdate(
        { userId: user._id, deviceId },
        {
          $setOnInsert: {
            userId: user._id,
            deviceId,
            firstSeenAt: new Date(),
            trusted: false,
            tokenVersion: 0,
          },
          $set: {
            lastSeenAt: new Date(),
            lastIp: ip,
            lastUserAgent: userAgent,
            lastGeo: geoObj,
          },
        },
        { upsert: true, new: true }
      );

      // If user marked device compromised, do not allow issuing a token for it
      if (deviceDoc?.compromisedAt) {
        return res.status(401).json({
          message: "This device is marked compromised. Use another device or revoke it in Devices.",
        });
      }

      if (!isNewAccount) {
        if (isNewDevice) {
          suspiciousReasons.push("new_device_for_account");
          suspiciousReasons.push("device_untrusted");
        } else {
          const known = deviceDoc; // reuse doc we already have
          if (known && !known.trusted) suspiciousReasons.push("device_untrusted");
        }
      }
    }
    // ---- END DEVICE LOGIC ----


    // Impossible travel heuristic: compare to last successful login with geo
    if (success && geoObj?.ll?.length === 2) {
      const lastSuccessWithGeo = recentAttempts.find(
        (a) => a.success === true && a.geo?.ll?.length === 2
      );

      if (lastSuccessWithGeo) {
        const [lat1, lon1] = lastSuccessWithGeo.geo.ll;
        const [lat2, lon2] = geoObj.ll;

        const miles = haversineMiles(lat1, lon1, lat2, lon2);

        const prevTime = new Date(lastSuccessWithGeo.createdAt).getTime();
        const nowTime = Date.now();
        const hours = Math.max(0.001, (nowTime - prevTime) / (1000 * 60 * 60));

        const mph = miles / hours;

        // Threshold: faster than commercial air travel + airport time buffer
        if (miles >= 300 && mph > 600) {
          suspiciousReasons.push("impossible_travel");
        }
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

    // Compute raw risk from signal reasons only (exclude label reasons)
    const rawRiskScore = computeRiskScore({
      success,
      reasons: suspiciousReasons.filter((r) => r !== "high_risk_login"),
    });

    // Policy risk score (can be capped for new accounts)
    let riskScore = rawRiskScore;

    // New account cap (prevents early false positives from causing warn/block)
    if (isNewAccount) {
      riskScore = Math.min(riskScore, NEW_ACCOUNT_RISK_CAP);
    }

    const highRisk = riskScore >= RISK_WARN_THRESHOLD;
    const blockRisk = riskScore >= RISK_BLOCK_THRESHOLD;

    // Add label for UI/audit only (do NOT recompute)
    if (success && highRisk && !suspiciousReasons.includes("high_risk_login")) {
      suspiciousReasons.push("high_risk_login");
    }

    // Suspicious is an admin/audit label: use raw signals (or strong reasons)
    // This makes "impossible_travel" show up even if the policy score is capped.
    const suspicious =
      rawRiskScore >= RISK_WARN_THRESHOLD ||
      suspiciousReasons.includes("impossible_travel") ||
      suspiciousReasons.includes("lockout_triggered") ||
      suspiciousReasons.includes("account_locked");

    // Log attempt
    await LoginAttempt.create({
      email,
      ip,
      userAgent,
      deviceId,
      success,
      suspicious,
      reasons: suspiciousReasons,
      riskScore,      // capped policy score
      rawRiskScore,   // uncapped signal score
      geo: geoObj,
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
        riskScore,
        highRisk,
        reasons: suspiciousReasons,
      });
    }

    // Risk-based policy when MFA is NOT enabled
    if (!user.mfaEnabled && success && blockRisk) {
      // Log attempt already recorded; do NOT issue JWT
      return res.status(403).json({
        message: "High-risk login blocked. Please enable MFA to continue.",
        actionRequired: "ENABLE_MFA",
        riskScore,
        reasons: suspiciousReasons,
      });
    }

    const token = createToken({
      user,
      deviceId,
      deviceTokenVersion: deviceDoc?.tokenVersion || 0,
    });


    res.cookie("token", token, authCookieOptions());

    return res.json({ 
      message: "Logged in",
      riskScore,
      highRisk,
      reasons: suspiciousReasons, 
    });
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
    if (!user || !user.mfaEnabled || !user.mfaSecretEncrypted) {
      return res.status(401).json({ message: "MFA not enabled for this account" });
    }
    
    // --- device + metadata for device-bound token ---
    const rawIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
    const ip = rawIp?.startsWith("::ffff:") ? rawIp.replace("::ffff:", "") : rawIp;
    const userAgent = req.headers["user-agent"] || "unknown";
    const deviceId = req.headers["x-device-id"] || "unknown";

    const geo = geoip.lookup(ip);
    const geoObj = geo
      ? { country: geo.country, region: geo.region, city: geo.city, ll: geo.ll }
      : undefined;

    let deviceDoc = null;

    if (deviceId !== "unknown") {
      deviceDoc = await TrustedDevice.findOneAndUpdate(
        { userId: user._id, deviceId },
        {
          $setOnInsert: {
            userId: user._id,
            deviceId,
            firstSeenAt: new Date(),
            trusted: false,
            tokenVersion: 0,
          },
          $set: {
            lastSeenAt: new Date(),
            lastIp: ip,
            lastUserAgent: userAgent,
            lastGeo: geoObj,
          },
        },
        { upsert: true, new: true }
      );

      if (deviceDoc?.compromisedAt) {
        return res.status(401).json({
          message: "This device is marked compromised. Use another device or revoke it in Devices.",
        });
      }
    }


    const cleaned = String(code).replace(/\s/g, "");
    const normalized = cleaned.toUpperCase();

    // Allow users to type backup code with or without dash
    const normalizedBackupCandidate =
      normalized.length === 8 ? `${normalized.slice(0, 4)}-${normalized.slice(4)}` : normalized;

    // 1) Try TOTP first
    const totpOk = speakeasy.totp.verify({
      secret: decrypt(user.mfaSecretEncrypted),
      encoding: "base32",
      token: cleaned,
      window: 1,
    });

    let backupUsed = false;

    if (!totpOk) {
      // 2) Try backup codes (one-time)
      const hashes = Array.isArray(user.backupCodeHashes) ? user.backupCodeHashes : [];

      let matchedIndex = -1;

      for (let i = 0; i < hashes.length; i++) {
        const match = await bcrypt.compare(normalizedBackupCandidate, hashes[i]);
        if (match) {
          matchedIndex = i;
          break;
        }
      }

      if (matchedIndex === -1) {
        return res.status(400).json({ message: "Invalid MFA code" });
      }

      // Consume the backup code
      user.backupCodeHashes.splice(matchedIndex, 1);
      await user.save();

      backupUsed = true;
    }

    // Issue the real auth token
    const token = createToken({
      user,
      deviceId,
      deviceTokenVersion: deviceDoc?.tokenVersion || 0,
    });


    res.cookie("token", token, authCookieOptions());

    return res.json({
      message: backupUsed ? "Logged in with backup code" : "Logged in with MFA",
    });
  } catch (err) {
    console.error("MFA login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// LOGOUT
router.post("/logout", (req, res) => {
  // NOTE: For cross-site cookies (SameSite=None; Secure), you must clear with matching options
  res.clearCookie("token", authCookieOptions());

  return res.json({ message: "Logged out" });
});

// GLOBAL LOGOUT
router.post("/logout-all", requireAuth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: "User not found" });

  user.tokenVersion = (user.tokenVersion || 0) + 1;
  await user.save();

  // Also clear this browser's cookie immediately
  res.clearCookie("token", authCookieOptions());

  return res.json({ message: "Logged out of all devices" });
});

// ME
router.get("/me", requireAuth, async (req, res) => {
  const user = req.user;
  return res.json({
    user: {
      id: user._id,
      email: user.email,
      role: user.role,
      mfaEnabled: user.mfaEnabled,
    },
  });
});

// Login History
router.get("/login-history", requireAuth, async (req, res) => {
  try {
    const email = req.user.email;

    const attempts = await LoginAttempt.find({ email })
      .sort({ createdAt: -1 })
      .limit(50);

    return res.json({ attempts });
  } catch (err) {
    console.error("Login history error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});


module.exports = router;
