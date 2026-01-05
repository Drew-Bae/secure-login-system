const mongoose = require("mongoose");

const BlockedIpSchema = new mongoose.Schema(
  {
    ip: { type: String, required: true, index: true },
    reason: { type: String, default: "" },
    expiresAt: { type: Date, required: true, index: true },
    createdByUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  },
  { timestamps: true }
);

// TTL index: Mongo will remove doc shortly after expiresAt
BlockedIpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

// Prevent duplicates (one active record per IP at a time)
BlockedIpSchema.index({ ip: 1 }, { unique: true });

module.exports = mongoose.model("BlockedIp", BlockedIpSchema);
