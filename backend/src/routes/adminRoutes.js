const express = require("express");
const mongoose = require("mongoose");
const LoginAttempt = require("../models/LoginAttempt");
const User = require("../models/User");
const TrustedDevice = require("../models/TrustedDevice");
const { requireAuth, requireAdmin } = require("../middleware/authMiddleware");
const { writeAudit } = require("../utils/audit");
const AuditEvent = require("../models/AuditEvent");
const BlockedIp = require("../models/BlockedIp");
const { getClientIp } = require("../middleware/blockIpMiddleware");
const crypto = require("crypto");
const { sendPasswordResetEmail } = require("../services/emailService");

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

function maskIp(ip) {
  const s = String(ip || "").trim();
  if (!s) return "";

  // IPv4 -> /24 masking
  if (s.includes(".") && !s.includes(":")) {
    const parts = s.split(".");
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    return s;
  }

  // IPv6 -> /48-ish masking
  if (s.includes(":")) {
    const parts = s.split(":").filter(Boolean);
    const prefix = parts.slice(0, 3).join(":");
    return prefix ? `${prefix}::/48` : "";
  }

  return s;
}

function getClientUrlBase() {
  const single = (process.env.CLIENT_URL || "").trim();
  if (single) return single.replace(/\/$/, "");

  const list = (process.env.CLIENT_URLS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => s.replace(/\/$/, ""));

  const nonLocal = list.find((u) => !u.includes("localhost") && !u.includes("127.0.0.1"));
  return nonLocal || list[0] || "http://localhost:3000";
}

async function buildAuditQuery(req) {
  const {
    action,
    email,
    actorUserId,
    targetUserId,
    ip,
    from,
    to,
  } = req.query;

  const conditions = [];

  if (action) {
    const list = String(action)
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
      .slice(0, 50);

    if (list.length === 1) conditions.push({ action: list[0] });
    if (list.length > 1) conditions.push({ action: { $in: list } });
  }

  if (email) {
    const safe = escapeRegex(String(email).slice(0, 200));
    const users = await User.find({ email: { $regex: safe, $options: "i" } })
      .select("_id")
      .limit(200);

    const ids = users.map((u) => u._id);
    if (ids.length === 0) return { none: true };

    conditions.push({
      $or: [{ actorUserId: { $in: ids } }, { targetUserId: { $in: ids } }],
    });
  }

  if (actorUserId) {
    if (!mongoose.isValidObjectId(actorUserId)) {
      const err = new Error("Invalid actorUserId");
      err.status = 400;
      throw err;
    }
    conditions.push({ actorUserId });
  }

  if (targetUserId) {
    if (!mongoose.isValidObjectId(targetUserId)) {
      const err = new Error("Invalid targetUserId");
      err.status = 400;
      throw err;
    }
    conditions.push({ targetUserId });
  }

  if (ip) conditions.push({ ip: String(ip).slice(0, 100) });

  const fromD = parseDateMaybe(from);
  const toD = parseDateMaybe(to);
  if (fromD || toD) {
    const range = {};
    if (fromD) range.$gte = fromD;
    if (toD) range.$lte = toD;
    conditions.push({ createdAt: range });
  }

  return { query: conditions.length ? { $and: conditions } : {} };
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
        .select("email role mfaEnabled failedLoginCount lockoutUntil tokenVersion mustResetPassword mustResetPasswordAt createdAt updatedAt")
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
      "email role mfaEnabled failedLoginCount lockoutUntil tokenVersion mustResetPassword mustResetPasswordAt mustResetPasswordReason createdAt updatedAt"
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
 * GET /api/admin/audit
 * Query:
 *  - action (exact or comma-separated list)
 *  - email (matches actor or target email, case-insensitive)
 *  - actorUserId, targetUserId (ObjectId)
 *  - ip
 *  - from, to (ISO date)
 *  - page, limit
 */
router.get("/audit", requireAuth, requireAdmin, async (req, res) => {
  try {
    const {
      action,
      email,
      actorUserId,
      targetUserId,
      ip,
      from,
      to,
      page = "1",
      limit = "50",
    } = req.query;

    const conditions = [];

    // action filter: allow comma-separated
    if (action) {
      const list = String(action)
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .slice(0, 50);

      if (list.length === 1) conditions.push({ action: list[0] });
      if (list.length > 1) conditions.push({ action: { $in: list } });
    }

    // filter by email (actor OR target)
    if (email) {
      const safe = escapeRegex(String(email).slice(0, 200));
      const users = await User.find({ email: { $regex: safe, $options: "i" } })
        .select("_id")
        .limit(200);

      const ids = users.map((u) => u._id);
      if (ids.length === 0) {
        // No matching users -> no results
        return res.json({ events: [], page: 1, limit: 50, total: 0, hasMore: false });
      }

      conditions.push({
        $or: [{ actorUserId: { $in: ids } }, { targetUserId: { $in: ids } }],
      });
    }

    if (actorUserId) {
      if (!mongoose.isValidObjectId(actorUserId)) return res.status(400).json({ message: "Invalid actorUserId" });
      conditions.push({ actorUserId });
    }

    if (targetUserId) {
      if (!mongoose.isValidObjectId(targetUserId)) return res.status(400).json({ message: "Invalid targetUserId" });
      conditions.push({ targetUserId });
    }

    if (ip) conditions.push({ ip: String(ip).slice(0, 100) });

    const fromD = parseDateMaybe(from);
    const toD = parseDateMaybe(to);
    if (fromD || toD) {
      const range = {};
      if (fromD) range.$gte = fromD;
      if (toD) range.$lte = toD;
      conditions.push({ createdAt: range });
    }

    const query = conditions.length ? { $and: conditions } : {};

    const pageNum = Math.max(1, toInt(page, 1));
    const limitNum = Math.min(200, Math.max(1, toInt(limit, 50)));
    const skip = (pageNum - 1) * limitNum;

    const [total, events] = await Promise.all([
      AuditEvent.countDocuments(query),
      AuditEvent.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum)
        .populate({ path: "actorUserId", select: "email role" })
        .populate({ path: "targetUserId", select: "email role" }),
    ]);

    res.json({
      events,
      page: pageNum,
      limit: limitNum,
      total,
      hasMore: skip + events.length < total,
    });
  } catch (err) {
    console.error("Admin audit error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * GET /api/admin/audit/export.json
 * Downloads filtered audit events as JSON
 */
router.get("/audit/export.json", requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await buildAuditQuery(req);
    if (result.none) {
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Content-Disposition", 'attachment; filename="audit-export.json"');
      return res.send(JSON.stringify([], null, 2));
    }

    const events = await AuditEvent.find(result.query)
      .sort({ createdAt: -1 })
      .limit(5000)
      .populate({ path: "actorUserId", select: "email role" })
      .populate({ path: "targetUserId", select: "email role" });

    res.setHeader("Content-Type", "application/json");
    res.setHeader("Content-Disposition", 'attachment; filename="audit-export.json"');
    const safeEvents = events.map((e) => ({ ...(typeof e.toObject === "function" ? e.toObject() : e), ip: maskIp(e.ip) }));
    return res.send(JSON.stringify(safeEvents, null, 2));
  } catch (err) {
    console.error("Admin audit export.json error:", err);
    return res.status(err.status || 500).json({ message: err.message || "Server error" });
  }
});

/**
 * GET /api/admin/audit/export.csv
 * Downloads filtered audit events as CSV
 */
router.get("/audit/export.csv", requireAuth, requireAdmin, async (req, res) => {
  try {
    const result = await buildAuditQuery(req);
    if (result.none) {
      res.setHeader("Content-Type", "text/csv");
      res.setHeader("Content-Disposition", 'attachment; filename="audit-export.csv"');
      return res.send("time,action,actor_email,actor_role,target_email,target_role,target_device_id,ip,user_agent,meta\n");
    }

    const events = await AuditEvent.find(result.query)
      .sort({ createdAt: -1 })
      .limit(5000)
      .populate({ path: "actorUserId", select: "email role" })
      .populate({ path: "targetUserId", select: "email role" });

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", 'attachment; filename="audit-export.csv"');

    // CSV header
    const header = [
      "time",
      "action",
      "actor_email",
      "actor_role",
      "target_email",
      "target_role",
      "target_device_id",
      "ip",
      "user_agent",
      "meta",
    ].join(",") + "\n";

    function csvEscape(v) {
      const s = v === null || v === undefined ? "" : String(v);
      const needs = /[",\n]/.test(s);
      const escaped = s.replace(/"/g, '""');
      return needs ? `"${escaped}"` : escaped;
    }

    const lines = events.map((e) => {
      const actorEmail = e.actorUserId?.email || "";
      const actorRole = e.actorUserId?.role || e.actorRole || "";
      const targetEmail = e.targetUserId?.email || "";
      const targetRole = e.targetUserId?.role || "";
      const meta = e.meta ? JSON.stringify(e.meta) : "";

      return [
        csvEscape(e.createdAt ? new Date(e.createdAt).toISOString() : ""),
        csvEscape(e.action || ""),
        csvEscape(actorEmail),
        csvEscape(actorRole),
        csvEscape(targetEmail),
        csvEscape(targetRole),
        csvEscape(e.targetDeviceId || ""),
        csvEscape(maskIp(e.ip) || ""),
        csvEscape(e.userAgent || ""),
        csvEscape(meta),
      ].join(",");
    });

    return res.send(header + lines.join("\n") + (lines.length ? "\n" : ""));
  } catch (err) {
    console.error("Admin audit export.csv error:", err);
    return res.status(err.status || 500).json({ message: err.message || "Server error" });
  }
});

/**
 * GET /api/admin/blocked-ips
 * Query:
 *  - active=true|false (default true)
 *  - ip (contains)
 *  - page, limit
 */
router.get("/blocked-ips", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { active = "true", ip, page = "1", limit = "50" } = req.query;

    const q = {};
    if (ip) {
      const safe = escapeRegex(String(ip).slice(0, 200));
      q.ip = { $regex: safe, $options: "i" };
    }

    if (active === "true") q.expiresAt = { $gt: new Date() };
    if (active === "false") q.expiresAt = { $lte: new Date() };

    const pageNum = Math.max(1, toInt(page, 1));
    const limitNum = Math.min(200, Math.max(1, toInt(limit, 50)));
    const skip = (pageNum - 1) * limitNum;

    const [total, blocks] = await Promise.all([
      BlockedIp.countDocuments(q),
      BlockedIp.find(q).sort({ expiresAt: -1 }).skip(skip).limit(limitNum),
    ]);

    res.json({ blocks, page: pageNum, limit: limitNum, total, hasMore: skip + blocks.length < total });
  } catch (err) {
    console.error("Admin blocked-ips list error:", err);
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

/**
 * POST /api/admin/users/:id/force-password-reset
 * body: { reason?: string, sendEmail?: boolean }
 */
router.post("/users/:id/force-password-reset", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ message: "Invalid user id" });

    const reason = String(req.body?.reason || "").trim().slice(0, 500);
    const sendEmail = req.body?.sendEmail !== false; // default true

    const user = await User.findById(id);
    if (!user) return res.status(404).json({ message: "User not found" });

    // Set forced reset flags
    user.mustResetPassword = true;
    user.mustResetPasswordAt = new Date();
    user.mustResetPasswordReason = reason || undefined;

    // Revoke sessions so the user is forced to re-auth
    user.tokenVersion = (user.tokenVersion || 0) + 1;

    // Generate reset token + expiry
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 60 minutes

    user.resetPasswordTokenHash = tokenHash;
    user.resetPasswordExpiresAt = expires;

    await user.save();

    if (sendEmail) {
      const base = getClientUrlBase();
      const resetUrl = `${base}/reset-password?token=${rawToken}`;

      try {
        await sendPasswordResetEmail({ to: user.email, resetUrl });
      } catch (e) {
        console.error("Admin forced reset email failed:", e);
      }
    }

    await writeAudit(req, {
      action: "ADMIN_FORCE_PASSWORD_RESET",
      targetUserId: user._id,
      meta: { email: user.email, reason, sendEmail, expiresAt: expires.toISOString(), tokenVersion: user.tokenVersion },
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error("Admin force-password-reset error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

/**
 * POST /api/admin/users/:id/note
 * body: { note: string }
 */
router.post("/users/:id/note", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ message: "Invalid user id" });

    const note = String(req.body?.note || "").trim();
    if (!note || note.length < 2) return res.status(400).json({ message: "Note is required" });
    if (note.length > 2000) return res.status(400).json({ message: "Note too long" });

    const user = await User.findById(id).select("email role");
    if (!user) return res.status(404).json({ message: "User not found" });

    await writeAudit(req, {
      action: "ADMIN_ADD_NOTE",
      targetUserId: user._id,
      meta: { email: user.email, note },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Admin note error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * POST /api/admin/devices/:deviceRecordId/compromised
 * body: { compromised: boolean }
 */
router.post("/devices/:deviceRecordId/compromised", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { deviceRecordId } = req.params;
    if (!mongoose.isValidObjectId(deviceRecordId)) {
      return res.status(400).json({ message: "Invalid device id" });
    }

    const compromised = Boolean(req.body?.compromised);

    const device = await TrustedDevice.findById(deviceRecordId);
    if (!device) return res.status(404).json({ message: "Device not found" });

    device.compromisedAt = compromised ? new Date() : null;
    await device.save();

    await writeAudit(req, {
      action: compromised ? "ADMIN_MARK_DEVICE_COMPROMISED" : "ADMIN_UNMARK_DEVICE_COMPROMISED",
      targetUserId: device.userId,
      targetDeviceId: device.deviceId,
      meta: {
        deviceRecordId: device._id.toString(),
        deviceId: device.deviceId,
        compromised,
      },
    });

    res.json({ ok: true, compromisedAt: device.compromisedAt });
  } catch (err) {
    console.error("Admin device compromised error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * POST /api/admin/blocked-ips
 * body: { ip: string, minutes: number, reason?: string }
 */
router.post("/blocked-ips", requireAuth, requireAdmin, async (req, res) => {
  try {
    const ip = String(req.body?.ip || "").trim();
    if (!ip) return res.status(400).json({ message: "ip is required" });

    const minutes = Math.min(7 * 24 * 60, Math.max(1, toInt(req.body?.minutes, 60)));
    const expiresAt = new Date(Date.now() + minutes * 60 * 1000);
    const reason = String(req.body?.reason || "").trim().slice(0, 500);

    // Optional guard: prevent you from bricking yourself in local dev
    const requesterIp = getClientIp(req);
    if (ip === requesterIp) {
      return res.status(400).json({ message: "Refusing to block your current IP." });
    }

    const doc = await BlockedIp.findOneAndUpdate(
      { ip },
      {
        $set: {
          ip,
          expiresAt,
          reason,
          createdByUserId: req.user?._id,
        },
      },
      { upsert: true, new: true }
    );

    await writeAudit(req, {
      action: "ADMIN_BLOCK_IP",
      meta: { ip, minutes, expiresAt: expiresAt.toISOString(), reason },
    });

    res.json({ ok: true, blocked: doc });
  } catch (err) {
    if (err?.code === 11000) {
      return res.status(409).json({ message: "IP is already blocked" });
    }
    console.error("Admin block ip error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

/**
 * DELETE /api/admin/blocked-ips/:id
 */
router.delete("/blocked-ips/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    if (!mongoose.isValidObjectId(id)) return res.status(400).json({ message: "Invalid block id" });

    const doc = await BlockedIp.findById(id);
    if (!doc) return res.status(404).json({ message: "Not found" });

    await BlockedIp.deleteOne({ _id: id });

    await writeAudit(req, {
      action: "ADMIN_UNBLOCK_IP",
      meta: { ip: doc.ip, reason: doc.reason || "" },
    });

    res.json({ ok: true });
  } catch (err) {
    console.error("Admin unblock error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
