const BlockedIp = require("../models/BlockedIp");

function getClientIp(req) {
  // If you later set `app.set("trust proxy", 1)`, req.ip will be the correct client IP.
  return (req.ip || "").replace(/^::ffff:/, ""); // normalize IPv4-mapped IPv6
}

async function blockIpMiddleware(req, res, next) {
  try {
    const ip = getClientIp(req);
    if (!ip) return next();

    const block = await BlockedIp.findOne({ ip }).lean();
    if (!block) return next();

    // extra safety: if TTL cleanup hasn't run yet
    if (block.expiresAt && new Date(block.expiresAt) <= new Date()) return next();

    return res.status(429).json({
      message: "Your IP is temporarily blocked.",
      blockedUntil: block.expiresAt,
      reason: block.reason || undefined,
    });
  } catch (err) {
    // Fail-open so a DB hiccup doesn't take your whole API down
    return next();
  }
}

module.exports = { blockIpMiddleware, getClientIp };
