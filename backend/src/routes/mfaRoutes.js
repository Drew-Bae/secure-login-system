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

module.exports = router;
