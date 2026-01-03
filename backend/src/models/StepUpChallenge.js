const mongoose = require("mongoose");

const stepUpChallengeSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

    tokenHash: { type: String, required: true }, // sha256(token)
    expiresAt: { type: Date, required: true },
    usedAt: { type: Date },

    // bind to reduce replay
    deviceId: { type: String },
    ip: { type: String },
    userAgent: { type: String },

    // optional context for reporting/debug
    riskLabel: { type: String },
    reasons: [{ type: String }],
  },
  { timestamps: true }
);

// auto-delete when expired
stepUpChallengeSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
// lookups
stepUpChallengeSchema.index({ userId: 1, tokenHash: 1 });

module.exports = mongoose.model("StepUpChallenge", stepUpChallengeSchema);
