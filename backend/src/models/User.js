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
    tokenVersion: { type: Number, default: 0 },
    failedLoginCount: { type: Number, default: 0 },
    lockoutUntil: { type: Date },
    mfaEnabled: { type: Boolean, default: false },
    mfaSecretEncrypted: {
      ciphertext: String,
      iv: String,
      tag: String,
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    resetPasswordTokenHash: { type: String },
    resetPasswordExpiresAt: { type: Date },
    backupCodeHashes: [{ type: String }],
    // Email verification
    emailVerifiedAt: { type: Date },
    emailVerifyTokenHash: { type: String },
    emailVerifyExpiresAt: { type: Date },
  },
  { timestamps: true }
);


module.exports = mongoose.model("User", userSchema);
