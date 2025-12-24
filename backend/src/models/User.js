const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
    },
    
    failedLoginCount: { type: Number, default: 0 },
    lockoutUntil: { type: Date },
    mfaEnabled: { type: Boolean, default: false },
    mfaSecret: { type: String }, // base32 secret (Phase 2.3: encrypt at rest)
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    resetPasswordTokenHash: { type: String },
    resetPasswordExpiresAt: { type: Date },
    backupCodeHashes: [{ type: String }],
  },
  { timestamps: true }
);


module.exports = mongoose.model("User", userSchema);
