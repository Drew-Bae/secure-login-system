const mongoose = require("mongoose");

const loginAttemptSchema = new mongoose.Schema(
  {
    email: { type: String, required: true },
    ip: { type: String },
    userAgent: { type: String },
    deviceId: { type: String },
    success: { type: Boolean, required: true },

    suspicious: { type: Boolean, default: false },
    reasons: [{ type: String }],
    
    riskScore: { type: Number, default: 0 },
  },
  { timestamps: true }
);

module.exports = mongoose.model("LoginAttempt", loginAttemptSchema);
