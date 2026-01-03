const express = require("express");
const { requireAuth } = require("../middleware/authMiddleware");
const TrustedDevice = require("../models/TrustedDevice");
const { writeAudit } = require("../utils/audit");


const router = express.Router();

// GET /api/devices - list devices for current user
router.get("/", requireAuth, async (req, res) => {
  try {
    const devices = await TrustedDevice.find({ userId: req.user._id }).sort({
      lastSeenAt: -1,
    });

    return res.json({ devices });
  } catch (err) {
    console.error("List devices error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// POST /api/devices/:deviceId/trust - mark device as trusted
router.post("/:deviceId/trust", requireAuth, async (req, res) => {
  try {
    const { deviceId } = req.params;

    const device = await TrustedDevice.findOneAndUpdate(
      { userId: req.user._id, deviceId },
      { trusted: true },
      { new: true }
    );

    if (!device) {
      return res.status(404).json({ message: "Device not found" });
    }

    await writeAudit(req, {
      action: "DEVICE_TRUST",
      targetUserId: req.user._id,
      targetDeviceId: deviceId,
      meta: { trusted: true },
    });

    return res.json({ message: "Device marked as trusted", device });
  } catch (err) {
    console.error("Trust device error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// POST /api/devices/:deviceId/revoke - revoke ONE device session
router.post("/:deviceId/revoke", requireAuth, async (req, res) => {
  try {
    const { deviceId } = req.params;

    const device = await TrustedDevice.findOneAndUpdate(
      { userId: req.user._id, deviceId },
      { $inc: { tokenVersion: 1 } },
      { new: true }
    );

    if (!device) return res.status(404).json({ message: "Device not found" });

    await writeAudit(req, {
      action: "DEVICE_REVOKE",
      targetUserId: req.user._id,
      targetDeviceId: deviceId,
      meta: { tokenVersion: device.tokenVersion },
    });

    return res.json({ message: "Device session revoked", device });
  } catch (err) {
    console.error("Revoke device error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

// POST /api/devices/:deviceId/compromised - mark compromised + revoke
router.post("/:deviceId/compromised", requireAuth, async (req, res) => {
  try {
    const { deviceId } = req.params;
    const { reason } = req.body || {};

    const device = await TrustedDevice.findOneAndUpdate(
      { userId: req.user._id, deviceId },
      {
        $set: {
          compromisedAt: new Date(),
          compromisedReason: reason || "user_marked_compromised",
          trusted: false,
        },
        $inc: { tokenVersion: 1 },
      },
      { new: true }
    );

    if (!device) return res.status(404).json({ message: "Device not found" });

    await writeAudit(req, {
      action: "DEVICE_COMPROMISED",
      targetUserId: req.user._id,
      targetDeviceId: deviceId,
      meta: { reason: device.compromisedReason },
    });

    return res.json({ message: "Device marked compromised and revoked", device });
  } catch (err) {
    console.error("Compromised device error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});


module.exports = router;
