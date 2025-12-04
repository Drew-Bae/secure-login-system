const express = require("express");
const LoginAttempt = require("../models/LoginAttempt");
const { requireAuth, requireAdmin } = require("../middleware/authMiddleware");

const router = express.Router();

// GET /api/admin/login-attempts?onlySuspicious=true
router.get("/login-attempts", requireAuth, requireAdmin, async (req, res) => {
  try {
    const { onlySuspicious } = req.query;

    const query = {};
    if (onlySuspicious === "true") {
      query.suspicious = true;
    }

    const attempts = await LoginAttempt.find(query)
      .sort({ createdAt: -1 })
      .limit(100);

    res.json({ attempts });
  } catch (err) {
    console.error("Admin login-attempts error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
