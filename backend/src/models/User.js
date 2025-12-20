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
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    resetPasswordTokenHash: { type: String },
    resetPasswordExpiresAt: { type: Date },
  },
  { timestamps: true }
);


module.exports = mongoose.model("User", userSchema);
