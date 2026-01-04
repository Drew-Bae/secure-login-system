const express = require("express");
const mongoose = require("mongoose");
const LoginAttempt = require("../models/LoginAttempt");
const User = require("../models/User");
const TrustedDevice = require("../models/TrustedDevice");
const { requireAuth, requireAdmin } = require("../middleware/authMiddleware");
const { writeAudit } = require("../utils/audit");

const router = express.Router();

function toInt(v, fallback) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

function escapeRegex(input) {
  return String(input).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function parseDateMaybe(v) {
  if (!v) return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * GET /api/admin/login-attempts
 * Query:
 *  - onlySuspicious=true|false
 *  - email (contains, case-insensitive)
 *  - ip, deviceId
 *  - success=true|false
 *  - country
 *  - minRisk, maxRisk
 *  - from, to (ISO date)
 *  - page, limit
 */
router.get("/login-attempts", requireAuth, requireAdmin, async (req, res) => {
  try {
    const {
      onlySuspicious,
      email,
      ip,
      deviceId,
      success,
      country,
      minRisk,
      maxRisk,
      from,
      to,
      page = "1",
      limit = "50",
    } = req.query;

    const q = {};

    if (onlySuspicious === "true") q.suspicious = true;

    if (email) {
      const safe = escapeRegex(String(email).slice(0, 200));
      q.email = { $regex: safe, $options: "i" };
    }
    if (ip) q.ip = String(ip).slice(0, 100);
    if (deviceId) q.deviceId = String(deviceId).slice(0, 200);

    if (success === "true") q.success = true;
    if (success === "false") q.success = false;

    if (country) q["geo.country"] = String(country).slice(0, 50);

    const min = minRisk !== undefined ? Number(minRisk) : null;
    const max = maxRisk !== undefined ? Number(maxRisk) : null;
    if (Number.isFinite(min) || Number.isFinite(max)) {
      q.riskScore = {};
      if (Number.isFinite(min)) q.riskScore.$gte = min;
      if (Number.isFinite(max)) q.riskScore.$lte = max;
    }

    const fromD = parseDateMaybe(from);
    const toD = parseDateMaybe(to);
    if (fromD || toD) {
      q.createdAt = {};
      if (fromD) q.createdAt.$gte = fromD;
      if (toD) q.createdAt.$lte = toD;
    }

    const pageNum = Math.max(1, toInt(page, 1));
    const limitNum = Math.min(200, Math.max(1, toInt(limit, 50)));
    const skip = (pageNum - 1) * limitNum;

    const [total, attempts] = await Promise.all([
      LoginAttempt.countDocuments(q),
      LoginAttempt.find(q).sort({ createdAt: -1 }).skip(skip).limit(limitNum),
    ]);

    res.json({
      attempts,
      page: pageNum,
      limit: limitNum,
      total,
      hasMore: skip + attempts.length < total,
    });
  } catch (err) {
    console.error("Admin login-attempts error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * GET /api/admin/users
 * Query:
 *  - q (email contains)
 *  - role=user|admin
 *  - locked=true|false
 *  - mfaEnabled=true|false
 *  - page, limit
 */
router.get("/users", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { q, role, locked, mfaEnabled, page = "1", limit = "50" } = req.query;

    const query = {};

    if (q) {
      const safe = escapeRegex(String(q).slice(0, 200));
      query.email = { $regex: safe, $options: "i" };
    }

    if (role === "admin" || role === "user") query.role = role;

    if (mfaEnabled === "true") query.mfaEnabled = true;
    if (mfaEnabled === "false") query.mfaEnabled = false;

    if (locked === "true") query.lockoutUntil = { $gt: new Date() };
    if (locked === "false") query.$or = [{ lockoutUntil: null }, { lockoutUntil: { $lte: new Date() } }];

    const pageNum = Math.max(1, toInt(page, 1));
    const limitNum = Math.min(200, Math.max(1, toInt(limit, 50)));
    const skip = (pageNum - 1) * limitNum;

    const [total, users] = await Promise.all([
      User.countDocuments(query),
      User.find(query)
        .select("email role mfaEnabled failedLoginCount lockoutUntil tokenVersion createdAt updatedAt")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum),
    ]);

    res.json({
      users,
      page: pageNum,
      limit: limitNum,
      total,
      hasMore: skip + users.length < total,
    });
  } catch (err) {
    console.error("Admin users error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * GET /api/admin/users/:id
 * Returns: user + devices + last login attempts
 */
router.get("/users/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ message: "Invalid user id" });

    const user = await User.findById(id).select(
      "email role mfaEnabled failedLoginCount lockoutUntil tokenVersion createdAt updatedAt"
    );
    if (!user) return res.status(404).json({ message: "User not found" });

    const [devices, attempts] = await Promise.all([
      TrustedDevice.find({ userId: user._id }).sort({ lastSeenAt: -1 }).limit(50),
      LoginAttempt.find({ email: user.email }).sort({ createdAt: -1 }).limit(50),
    ]);

    res.json({ user, devices, attempts });
  } catch (err) {
    console.error("Admin user detail error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * POST /api/admin/users/:id/unlock
 */
router.post("/users/:id/unlock", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ message: "Invalid user id" });

    const user = await User.findById(id);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.failedLoginCount = 0;
    user.lockoutUntil = null;
    await user.save();

    await writeAudit(req, { action: "ADMIN_UNLOCK_USER", targetUserId: user._id, meta: { email: user.email } });

    res.json({ ok: true });
  } catch (err) {
    console.error("Admin unlock error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * POST /api/admin/users/:id/lock
 * body: { minutes: number }
 */
router.post("/users/:id/lock", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ message: "Invalid user id" });

    const minutes = Math.min(7 * 24 * 60, Math.max(1, toInt(req.body?.minutes, 60))); // cap 7 days
    const until = new Date(Date.now() + minutes * 60 * 1000);

    const user = await User.findById(id);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.lockoutUntil = until;
    user.failedLoginCount = Math.max(user.failedLoginCount || 0, 5);
    await user.save();

    await writeAudit(req, {
      action: "ADMIN_LOCK_USER",
      targetUserId: user._id,
      meta: { email: user.email, minutes, lockoutUntil: until.toISOString() },
    });

    res.json({ ok: true, lockoutUntil: until });
  } catch (err) {
    console.error("Admin lock error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * POST /api/admin/users/:id/revoke-sessions
 * increments tokenVersion to force re-login everywhere
 */
router.post("/users/:id/revoke-sessions", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ message: "Invalid user id" });

    const user = await User.findById(id);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.tokenVersion = (user.tokenVersion || 0) + 1;
    await user.save();

    await writeAudit(req, {
      action: "ADMIN_REVOKE_SESSIONS",
      targetUserId: user._id,
      meta: { email: user.email, tokenVersion: user.tokenVersion },
    });

    res.json({ ok: true, tokenVersion: user.tokenVersion });
  } catch (err) {
    console.error("Admin revoke sessions error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
