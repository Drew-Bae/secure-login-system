const express = require("express");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");
const { requireAuth } = require("../middleware/authMiddleware");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const { encrypt, decrypt } = require("../utils/crypto");

const router = express.Router();

function generateBackupCodesRaw(count = 10) {
  // Generate codes like: ABCD-EFGH (8 chars split for readability)
  return Array.from({ length: count }).map(() => {
    const raw = crypto.randomBytes(4).toString("hex").toUpperCase(); // 8 chars
    return `${raw.slice(0, 4)}-${raw.slice(4)}`;
  });
}

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

    user.mfaSecretEncrypted = encrypt(secret.base32);
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

    if (!user.mfaSecretEncrypted) {
      return res.status(400).json({
        message: "MFA setup not found. Please run setup again.",
      });
    }

    if (user.mfaEnabled) {
      return res.status(400).json({ message: "MFA is already enabled." });
    }

    const decryptedSecret = decrypt(user.mfaSecretEncrypted);

    const ok = speakeasy.totp.verify({
      secret: decryptedSecret,
      encoding: "base32",
      token: String(code).replace(/\s/g, ""),
      window: 1,
    });

    if (!ok) {
      return res.status(400).json({ message: "Invalid MFA code." });
    }

    user.mfaEnabled = true;

    // Issue backup codes ONCE at MFA enable-time
    // (Only if they don't already exist)
    let backupCodes = null;

    if (!Array.isArray(user.backupCodeHashes) || user.backupCodeHashes.length === 0) {
      const rawCodes = generateBackupCodesRaw(10);
      const hashes = await Promise.all(rawCodes.map((c) => bcrypt.hash(c, 10)));

      user.backupCodeHashes = hashes;
      backupCodes = rawCodes;
    }

    await user.save();

    return res.json({
      message: "MFA enabled successfully. Save your backup codes now — you won’t be able to view them again.",
      backupCodes, // null if already existed
    });

  } catch (err) {
    console.error("MFA verify error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
