const mongoose = require("mongoose");

const trustedDeviceSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    deviceId: { type: String, required: true },

    trusted: { type: Boolean, default: false },

    // Per-device revocation (increment to revoke one device/session)
    tokenVersion: { type: Number, default: 0 },

    // Mark device compromised
    compromisedAt: { type: Date },
    compromisedReason: { type: String },

    // Display fields for "Active devices"
    firstSeenAt: { type: Date, default: Date.now },
    lastSeenAt: { type: Date, default: Date.now },
    lastIp: { type: String },
    lastUserAgent: { type: String },

    lastGeo: {
      country: { type: String },
      region: { type: String },
      city: { type: String },
      ll: [{ type: Number }], // [lat, lon]
    },
  },
  { timestamps: true }
);

trustedDeviceSchema.index({ userId: 1, deviceId: 1 }, { unique: true });

module.exports = mongoose.model("TrustedDevice", trustedDeviceSchema);
