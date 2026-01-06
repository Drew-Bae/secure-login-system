const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const LoginAttempt = require("../models/LoginAttempt");
const router = express.Router();
const isProduction = process.env.NODE_ENV === "production";
const crypto = require("crypto");
const { sendPasswordResetEmail, sendStepUpEmail, sendEmailVerificationEmail } =
  require("../services/emailService");
const speakeasy = require("speakeasy");
const { requireAuth } = require("../middleware/authMiddleware");
const geoip = require("geoip-lite");
const TrustedDevice = require("../models/TrustedDevice");
const { csrfIssue } = require("../middleware/csrf");
const { decrypt } = require("../utils/crypto");
const {
  authCookieOptions,
  authCookieClearOptions,
  csrfCookieOptions,
} = require("../config/cookies");
const { loginLimiter, mfaLimiter } = require("../middleware/rateLimiters");
const { sleep } = require("../utils/sleep");
const { loginAttemptTracker } = require("../middleware/loginAttemptTracker");
const StepUpChallenge = require("../models/StepUpChallenge");
const { generateToken, hashToken } = require("../utils/stepUpTokens");
const { writeAudit } = require("../utils/audit");

function getClientUrlBase() {
  const single = (process.env.CLIENT_URL || "").trim();
  if (single) return single.replace(/\/$/, "");

  const list = (process.env.CLIENT_URLS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => s.replace(/\/$/, ""));

  // Prefer a non-localhost URL if present
  const nonLocal = list.find((u) => !u.includes("localhost") && !u.includes("127.0.0.1"));
  return nonLocal || list[0] || "http://localhost:3000";
}

const EMAIL_VERIFY_TTL_HOURS = 24;

async function issueEmailVerification(user) {
  // In tests, auto-verify to keep integration tests focused on auth/session behavior.
  if (process.env.NODE_ENV === "test") {
    user.emailVerifiedAt = user.emailVerifiedAt || new Date();
    user.emailVerifyTokenHash = undefined;
    user.emailVerifyExpiresAt = undefined;
    await user.save();
    return { verifyUrl: null };
  }

  const token = generateToken();
  user.emailVerifyTokenHash = hashToken(token);
  user.emailVerifyExpiresAt = new Date(Date.now() + EMAIL_VERIFY_TTL_HOURS * 60 * 60 * 1000);
  await user.save();

  const base = getClientUrlBase();
  const verifyUrl = `${base}/verify-email?token=${token}`;

  try {
    await sendEmailVerificationEmail({ to: user.email, verifyUrl });
  } catch (e) {
    console.error("sendEmailVerificationEmail failed:", e);
  }

  return { verifyUrl };
}

const RESET_TTL_MINUTES = 20;

async function issuePasswordReset(user, ttlMinutes = RESET_TTL_MINUTES) {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
  const expires = new Date(Date.now() + ttlMinutes * 60 * 1000);

  user.resetPasswordTokenHash = tokenHash;
  user.resetPasswordExpiresAt = expires;
  await user.save();

  const base = getClientUrlBase();
  const resetUrl = `${base}/reset-password?token=${rawToken}`;

  try {
    await sendPasswordResetEmail({ to: user.email, resetUrl });
  } catch (e) {
    console.error("sendPasswordResetEmail failed:", e);
  }

  return { expires };
}

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

const isTest = process.env.NODE_ENV === "test";

function calcDelayMs(fails) {
  // 250, 500, 1000, 2000, 4000 (capped) + jitter
  const base = 250;
  const pow = Math.min(4, Math.max(0, fails || 0));
  const jitter = Math.floor(Math.random() * 120);
  return Math.min(4000, base * (2 ** pow) + jitter);
}

function shouldStepUp({ riskLabel, user }) {
  // riskLabel expected: "low" | "medium" | "high"
  if (riskLabel !== "high") return false;
  // If MFA is enabled, we can step-up via MFA.
  // If not, we still step-up via email verification later.
  return true;
}

// GET /api/auth/csrf
router.get("/csrf", csrfIssue);

// REGISTER
router.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const normalizedEmail = String(email).toLowerCase().trim();

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password are required" });
    }

    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      return res.status(400).json({ message: "Email already registered" });
    }

    const hashed = await bcrypt.hash(password, 10);

    const user = await User.create({ email: normalizedEmail, password: hashed });
    await issueEmailVerification(user);

    return res
      .status(201)
      .json({ message: "User registered. Please check your email to verify your account.", userId: user._id });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// RESEND EMAIL VERIFICATION
router.post("/resend-verification", async (req, res) => {
  const genericResponse = {
    message: "If that email exists, a verification link has been sent.",
  };

  try {
    const { email } = req.body || {};
    if (!email) return res.status(200).json(genericResponse);

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user) return res.status(200).json(genericResponse);

    if (user.emailVerifiedAt) return res.status(200).json(genericResponse);

    await issueEmailVerification(user);
    return res.status(200).json(genericResponse);
  } catch (err) {
    console.error("Resend verification error:", err);
    return res.status(200).json(genericResponse);
  }
});

// VERIFY EMAIL (token link)
router.get("/verify-email", async (req, res) => {
  try {
    const token = String(req.query?.token || "").trim();
    if (!token) return res.status(400).json({ message: "Verification token is required" });

    const tokenHash = hashToken(token);
    const user = await User.findOne({
      emailVerifyTokenHash: tokenHash,
      emailVerifyExpiresAt: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({ message: "Verification token is invalid or has expired" });
    }

    if (!user.emailVerifiedAt) user.emailVerifiedAt = new Date();
    user.emailVerifyTokenHash = undefined;
    user.emailVerifyExpiresAt = undefined;
    await user.save();

    return res.json({ message: "Email verified successfully" });
  } catch (err) {
    console.error("Verify email error:", err);
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

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });
    if (!user) return res.status(200).json(genericResponse);

    await issuePasswordReset(user); // ✅ here

    return res.status(200).json(genericResponse);
  } catch (err) {
    console.error("Forgot password error:", err);
    return res.status(200).json(genericResponse);
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

    // Clear forced-reset flag if it was set
    user.mustResetPassword = false;
    user.mustResetPasswordAt = null;
    user.mustResetPasswordReason = undefined;

    // Revoke sessions after password change (good security practice)
    user.tokenVersion = (user.tokenVersion || 0) + 1;

    await user.save();

    return res.json({ message: "Password reset successful" });
  } catch (err) {
    console.error("Reset password error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// POST /api/auth/change-password
// - requires current password
// - updates password
// - revokes all sessions (tokenVersion++)
// - clears auth cookie so user re-auths immediately
router.post("/change-password", requireAuth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ message: "Current password and new password are required." });
    }

    // Keep it simple (you can upgrade to zxcvbn later)
    if (String(newPassword).length < 8) {
      return res.status(400).json({ message: "New password must be at least 8 characters." });
    }

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    const ok = await bcrypt.compare(currentPassword, user.password);
    if (!ok) {
      return res.status(400).json({ message: "Current password is incorrect." });
    }

    // prevent no-op change
    const same = await bcrypt.compare(newPassword, user.password);
    if (same) {
      return res.status(400).json({ message: "New password must be different from your current password." });
    }

    user.password = await bcrypt.hash(newPassword, 10);

    // Revoke sessions after password change
    user.tokenVersion = (user.tokenVersion || 0) + 1;

    await user.save();

    // Best-effort audit log (don’t block user if audit fails)
    writeAudit(req, {
      action: "password_change",
      targetUserId: user._id,
      meta: { revokedAllSessions: true },
    }).catch(() => {});

    // Clear this browser session immediately
    res.clearCookie("token", authCookieClearOptions());

    return res.json({ message: "Password changed. Please log in again." });
  } catch (err) {
    console.error("Change password error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// LOGIN
router.post("/login", loginAttemptTracker, loginLimiter, async (req, res) => {
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

    const user = await User.findOne({ email: String(email).toLowerCase().trim() });

    // Always keep responses generic
    if (!user) {
      if (!isTest) await sleep(300 + Math.floor(Math.random() * 120));

      const reasons = [];
      const rawRiskScore = computeRiskScore({ success: false, reasons });
      const riskScore = rawRiskScore;

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
      const rawRiskScore = computeRiskScore({ success: false, reasons: suspiciousReasons });
      const riskScore = rawRiskScore;

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
        message: "Too many attempts. Please try again later.",
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
      if (!isTest) {
        await sleep(calcDelayMs(user.failedLoginCount || 0));
      }
      return res.status(400).json({ message: "Invalid credentials" });
    }

    if (!user.emailVerifiedAt) {
      const now = new Date();
      const hasValidToken =
        !!user.emailVerifyTokenHash &&
        !!user.emailVerifyExpiresAt &&
        user.emailVerifyExpiresAt > now;

      // Avoid spamming: only send a new link if there isn't a valid one on file.
      if (!hasValidToken) {
        await issueEmailVerification(user);
      }

      // ✅ IMPORTANT: in test env, issueEmailVerification() auto-verifies.
      // So only block if the user is STILL not verified.
      if (!user.emailVerifiedAt) {
        return res.status(403).json({
          message: "Please verify your email to continue.",
          actionRequired: "VERIFY_EMAIL",
        });
      }
    }

    // ✅ Forced password reset (admin action)
    if (user.mustResetPassword) {
      const now = new Date();
      const hasValidReset =
        !!user.resetPasswordTokenHash &&
        !!user.resetPasswordExpiresAt &&
        user.resetPasswordExpiresAt > now;

      // Avoid spamming: only send a new reset link if none is valid
      if (!hasValidReset) {
        await issuePasswordReset(user, 60); // longer TTL for forced resets
      }

      return res.status(403).json({
        message: "Password reset required. Please reset your password to continue.",
        actionRequired: "FORCE_PASSWORD_RESET",
      });
    }

    const riskLabel = blockRisk ? "high" : highRisk ? "medium" : "low";

    const stepUpRequired = shouldStepUp({ riskLabel, user });

    if (stepUpRequired) {
      const preAuthToken = createPreAuthToken(user._id);

      // Prefer MFA when enabled
      if (user.mfaEnabled) {
        return res.status(200).json({
          message: "MFA required",
          mfaRequired: true,
          preAuthToken,
          risk: { label: riskLabel, reasons: suspiciousReasons, riskScore },
        });
      }

      // Otherwise email step-up
      return res.status(200).json({
        stepUpRequired: true,
        stepUpMethod: "email",
        preAuthToken,
        risk: { label: riskLabel, reasons: suspiciousReasons, riskScore },
      });
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

    // ✅ Email step-up when risky and MFA is NOT enabled
    // (Don't issue the auth cookie yet)
    if (!user.mfaEnabled && success && highRisk && !blockRisk) {
      const preAuthToken = createPreAuthToken(user._id);

      return res.status(200).json({
        stepUpRequired: true,
        stepUpMethod: "email",
        preAuthToken,

        // keep existing fields for consistency / UI
        riskScore,
        highRisk,
        reasons: suspiciousReasons,

        // optional structured object your UI already passes to sendStepUpEmail
        risk: {
          label: "medium",
          riskScore,
          reasons: suspiciousReasons,
        },
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

// STEPUP-EMAIL
router.post("/stepup-email", async (req, res) => {
  try {
    const { preAuthToken, risk } = req.body || {};
    if (!preAuthToken) return res.status(400).json({ message: "Missing preAuthToken" });

    const payload = jwt.verify(preAuthToken, process.env.PREAUTH_JWT_SECRET);
    if (payload.type !== "preauth") return res.status(400).json({ message: "Invalid preAuthToken" });

    const user = await User.findById(payload.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const rawIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
    const ip = rawIp?.startsWith("::ffff:") ? rawIp.replace("::ffff:", "") : rawIp;
    const userAgent = req.headers["user-agent"] || "unknown";
    const deviceId = req.headers["x-device-id"] || "unknown";

    const token = generateToken();
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await StepUpChallenge.create({
      userId: user._id,
      tokenHash,
      expiresAt,
      ip,
      userAgent,
      deviceId,
      riskLabel: risk?.label,
      reasons: risk?.reasons || [],
    });

    const clientBase = getClientUrlBase();
    const verifyUrl = `${clientBase}/step-up/verify?token=${token}&preAuthToken=${encodeURIComponent(preAuthToken)}`;

    try {
      await sendStepUpEmail({ to: user.email, verifyUrl });
    } catch (e) {
      console.error("sendStepUpEmail failed:", e);
    }

    return res.json({ message: "Verification email sent" });
  } catch (err) {
    console.error("stepup-email error:", err);
    return res.status(400).json({ message: "Invalid request" });
  }
});

// VERIFY STEPUP
router.post("/verify-stepup", async (req, res) => {
  try {
    const { token, preAuthToken } = req.body || {};
    if (!token || !preAuthToken) return res.status(400).json({ message: "Missing token" });

    const payload = jwt.verify(preAuthToken, process.env.PREAUTH_JWT_SECRET);
    if (payload.type !== "preauth") return res.status(400).json({ message: "Invalid preAuthToken" });

    const user = await User.findById(payload.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const rawIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
    const ip = rawIp?.startsWith("::ffff:") ? rawIp.replace("::ffff:", "") : rawIp;
    const userAgent = req.headers["user-agent"] || "unknown";
    const deviceId = req.headers["x-device-id"] || "unknown";

    const tokenHash = hashToken(token);

    const challenge = await StepUpChallenge.findOne({
      userId: user._id,
      tokenHash,
      usedAt: { $exists: false },
      expiresAt: { $gt: new Date() },
    });

    if (!challenge) return res.status(400).json({ message: "Invalid or expired token" });

    // Bind check: enforce device match when possible (IP can change on mobile/VPN)
    if (challenge.deviceId && challenge.deviceId !== "unknown" && challenge.deviceId !== deviceId) {
      return res.status(400).json({ message: "Challenge device mismatch" });
    }

    challenge.usedAt = new Date();
    await challenge.save();

    // Ensure device isn't compromised + get tokenVersion for device-bound JWT
    let deviceDoc = null;
    if (deviceId !== "unknown") {
      deviceDoc = await TrustedDevice.findOne({ userId: user._id, deviceId }).select(
        "tokenVersion compromisedAt"
      );
      if (deviceDoc?.compromisedAt) {
        return res.status(401).json({ message: "Device is compromised" });
      }
    }

    // IMPORTANT: use your *current* createToken signature.
    // If your createToken expects an object { user, deviceId, deviceTokenVersion }, use that.
    const jwtToken = createToken({
      user,
      deviceId,
      deviceTokenVersion: deviceDoc?.tokenVersion || 0,
    });

    res.cookie("token", jwtToken, authCookieOptions());
    return res.json({ ok: true });
  } catch (err) {
    console.error("verify-stepup error:", err);
    return res.status(400).json({ message: "Invalid request" });
  }
});

// MFA LOGIN
router.post("/mfa-login", mfaLimiter, async (req, res) => {
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
  res.clearCookie("token", authCookieClearOptions());
  return res.json({ message: "Logged out" });
});


// GLOBAL LOGOUT
router.post("/logout-all", requireAuth, async (req, res) => {
  const user = await User.findById(req.user.id);
  if (!user) return res.status(404).json({ message: "User not found" });

  user.tokenVersion = (user.tokenVersion || 0) + 1;
  await user.save();

  // Also clear this browser's cookie immediately
  res.clearCookie("token", authCookieClearOptions());

  return res.json({ message: "Logged out of all devices" });
});

// ME
router.get("/me", requireAuth, async (req, res) => {
  const user = req.user;
  return res.json({
    user: {
      id: user._id,
      email: user.email,
      emailVerified: !!user.emailVerifiedAt,
      emailVerifiedAt: user.emailVerifiedAt,
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
