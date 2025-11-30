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
    // Future fields:
    // mfaEnabled: Boolean,
    // lastLoginAt: Date,
    // riskScore: Number,
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
