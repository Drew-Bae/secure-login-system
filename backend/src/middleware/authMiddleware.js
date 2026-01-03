const jwt = require("jsonwebtoken");
const User = require("../models/User");
const TrustedDevice = require("../models/TrustedDevice");

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.token;
    if (!token) return res.status(401).json({ message: "Not authenticated" });

    const payload = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(payload.userId).select(
      "email role tokenVersion mfaEnabled mfaSecretEncrypted backupCodeHashes failedLoginCount lockoutUntil"
    );

    if (!user) return res.status(401).json({ message: "User not found" });

    // Global revoke check
    const currentVersion = user.tokenVersion || 0;
    const tokenVersion = payload.tokenVersion || 0;
    if (tokenVersion !== currentVersion) {
      return res.status(401).json({ message: "Session revoked. Please log in again." });
    }

    // Per-device revoke check (we’ll fully wire this up next step)
    if (payload.deviceId && payload.deviceId !== "unknown") {
      const device = await TrustedDevice.findOne({ userId: user._id, deviceId: payload.deviceId })
        .select("tokenVersion compromisedAt");

      if (!device) return res.status(401).json({ message: "Device session revoked. Please log in again." });

      const dv = device.tokenVersion || 0;
      const tokenDv = payload.deviceTokenVersion || 0;
      if (tokenDv !== dv) {
        return res.status(401).json({ message: "Device session revoked. Please log in again." });
      }
      if (device.compromisedAt) {
        return res.status(401).json({ message: "Device marked compromised. Please log in again." });
      }
    }

    req.user = user;
    next();
  } catch (err) {
    console.error("Auth middleware error:", err);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
}

module.exports = { requireAuth, requireAdmin };
