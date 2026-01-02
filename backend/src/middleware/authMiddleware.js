const jwt = require("jsonwebtoken");
const User = require("../models/User");

async function requireAuth(req, res, next) {
  try {
    const token = req.cookies?.token;

    if (!token) {
      return res.status(401).json({ message: "Not authenticated" });
    }

    const payload = jwt.verify(token, process.env.JWT_SECRET);

    // Load the latest user state (needed for tokenVersion checks)
    // Select only what you need to keep it light and avoid exposing sensitive fields
    const user = await User.findById(payload.userId).select(
      "email role tokenVersion mfaEnabled"
    );

    if (!user) {
      return res.status(401).json({ message: "User not found" });
    }

    // ---- Global session revocation check ----
    // If tokenVersion in JWT doesn't match the current user tokenVersion,
    // that means the user triggered "logout all devices" (or similar).
    const currentVersion = user.tokenVersion || 0;
    const tokenVersion = payload.tokenVersion || 0;

    if (tokenVersion !== currentVersion) {
      return res.status(401).json({ message: "Session revoked. Please log in again." });
    }
    // ----------------------------------------

    // Keep req.user lightweight (avoid attaching full mongoose doc if you don't need it)
    req.user = {
      id: user._id.toString(),
      email: user.email,
      role: user.role,
      mfaEnabled: user.mfaEnabled,
      tokenVersion: currentVersion,
    };

    next();
  } catch (err) {
    console.error("Auth middleware error:", err);
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// Simple admin check (based on role field)
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ message: "Admin access required" });
  }
  next();
}

module.exports = { requireAuth, requireAdmin };
