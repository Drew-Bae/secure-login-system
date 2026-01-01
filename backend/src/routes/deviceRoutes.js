const express = require("express");
const { requireAuth } = require("../middleware/authMiddleware");
const TrustedDevice = require("../models/TrustedDevice");

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

    return res.json({ message: "Device marked as trusted", device });
  } catch (err) {
    console.error("Trust device error:", err);
    return res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
