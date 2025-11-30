const mongoose = require("mongoose");

const loginAttemptSchema = new mongoose.Schema(
  {
    email: { type: String, required: true },
    ip: { type: String },
    userAgent: { type: String },
    success: { type: Boolean, required: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("LoginAttempt", loginAttemptSchema);
