const mongoose = require("mongoose");

const auditEventSchema = new mongoose.Schema(
  {
    actorUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    actorRole: { type: String, enum: ["user", "admin"], required: true },

    action: { type: String, required: true }, // e.g. DEVICE_TRUST, DEVICE_REVOKE, DEVICE_COMPROMISED
    targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    targetDeviceId: { type: String },

    ip: { type: String },
    userAgent: { type: String },

    meta: { type: mongoose.Schema.Types.Mixed },
  },
  { timestamps: true }
);

auditEventSchema.index({ createdAt: -1 });

module.exports = mongoose.model("AuditEvent", auditEventSchema);
