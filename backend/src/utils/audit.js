const AuditEvent = require("../models/AuditEvent");

async function writeAudit(req, { action, targetUserId, targetDeviceId, meta }) {
  const rawIp = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.ip;
  const ip = rawIp?.startsWith("::ffff:") ? rawIp.replace("::ffff:", "") : rawIp;

  return AuditEvent.create({
    actorUserId: req.user._id,
    actorRole: req.user.role === "admin" ? "admin" : "user",
    action,
    targetUserId,
    targetDeviceId,
    ip,
    userAgent: req.headers["user-agent"] || "unknown",
    meta: meta || {},
  });
}

module.exports = { writeAudit };
