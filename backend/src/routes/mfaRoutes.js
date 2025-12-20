const express = require("express");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const { requireAuth } = require("../middleware/authMiddleware");

const router = express.Router();

/**
 * POST /api/mfa/setup
 * Requires user to be logged in (JWT cookie).
 * Generates a TOTP secret and returns:
 * - otpauth URL (for authenticator apps)
 * - QR code image as a data URL (easy for frontend)
 */
router.post("/setup", requireAuth, async (req, res) => {
  try {
    const user = req.user;

    // If already enabled, don't regenerate
    if (user.mfaEnabled) {
      return res.status(400).json({ message: "MFA is already enabled." });
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `Secure Login System (${user.email})`,
      length: 20,
    });

    // Store base32 secret temporarily (until verified)
    user.mfaSecret = secret.base32;
    await user.save();

    // Generate QR code (data URL)
    const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url);

    return res.json({
      message: "MFA setup started. Scan QR code and verify.",
      otpauthUrl: secret.otpauth_url,
      qrDataUrl,
    });
  } catch (err) {
    console.error("MFA setup error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * POST /api/mfa/verify
 * Body: { code: "123456" }
 * Requires user to be logged in.
 * Verifies TOTP code and enables MFA.
 */
router.post("/verify", requireAuth, async (req, res) => {
  try {
    const user = req.user;
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ message: "MFA code is required." });
    }

    if (!user.mfaSecret) {
      return res.status(400).json({
        message: "MFA setup not found. Please run setup again.",
      });
    }

    if (user.mfaEnabled) {
      return res.status(400).json({ message: "MFA is already enabled." });
    }

    const ok = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: "base32",
      token: String(code).replace(/\s/g, ""),
      window: 1, // allow slight clock drift
    });

    if (!ok) {
      return res.status(400).json({ message: "Invalid MFA code." });
    }

    user.mfaEnabled = true;
    await user.save();

    return res.json({ message: "MFA enabled successfully." });
  } catch (err) {
    console.error("MFA verify error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
