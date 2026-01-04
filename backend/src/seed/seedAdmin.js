const bcrypt = require("bcrypt");
const User = require("../models/User");

async function seedAdmin() {
  const enabled = String(process.env.SEED_ADMIN || "").toLowerCase() === "true";
  if (!enabled) return;

  const forcePw = String(process.env.SEED_ADMIN_FORCE_PASSWORD || "").toLowerCase() === "true";

  const emailRaw = process.env.SEED_ADMIN_EMAIL;
  const password = process.env.SEED_ADMIN_PASSWORD;

  if (!emailRaw || !password) {
    console.warn("[seedAdmin] Missing SEED_ADMIN_EMAIL or SEED_ADMIN_PASSWORD");
    return;
  }

  const email = emailRaw.toLowerCase().trim();

  const existing = await User.findOne({ email });

  // If exists: ensure admin role; optionally force password reset
  if (existing) {
    let changed = false;

    if (existing.role !== "admin") {
      existing.role = "admin";
      changed = true;
    }

    if (forcePw) {
      existing.password = await bcrypt.hash(password, 10);

      // optional but helpful for "locked out" accounts
      existing.failedLoginCount = 0;
      existing.lockoutUntil = null;

      // optional: invalidate existing sessions if you want
      existing.tokenVersion = (existing.tokenVersion || 0) + 1;

      changed = true;
      console.log(`[seedAdmin] Forced password reset for: ${email}`);
    } else {
      console.log(`[seedAdmin] Admin exists (password unchanged): ${email}`);
    }

    if (changed) await existing.save();
    return;
  }

  // If not exists: create new admin with hashed password
  const hashed = await bcrypt.hash(password, 10);

  await User.create({
    email,
    password: hashed,
    role: "admin",
  });

  console.log(`[seedAdmin] Created admin user: ${email}`);
}

module.exports = { seedAdmin };
