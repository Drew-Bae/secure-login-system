const bcrypt = require("bcrypt");

const User = require("../models/User");
const TrustedDevice = require("../models/TrustedDevice");
const LoginAttempt = require("../models/LoginAttempt");
const AuditEvent = require("../models/AuditEvent");

function boolEnv(name, def = false) {
  const v = String(process.env[name] ?? "").toLowerCase().trim();
  if (!v) return def;
  return v === "true" || v === "1" || v === "yes";
}

function requireEnv(name) {
  const v = (process.env[name] || "").trim();
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

async function upsertUser({ email, password, role, forcePassword = false }) {
  const normalized = String(email).toLowerCase().trim();
  const existing = await User.findOne({ email: normalized });

  if (existing) {
    let changed = false;

    if (existing.role !== role) {
      existing.role = role;
      changed = true;
    }

    // Make demo logins frictionless
    if (!existing.emailVerifiedAt) {
      existing.emailVerifiedAt = new Date();
      changed = true;
    }

    if (forcePassword) {
      existing.password = await bcrypt.hash(password, 10);
      existing.failedLoginCount = 0;
      existing.lockoutUntil = null;
      existing.tokenVersion = (existing.tokenVersion || 0) + 1;
      changed = true;
    }

    if (changed) await existing.save();
    return existing;
  }

  const hashed = await bcrypt.hash(password, 10);

  return User.create({
    email: normalized,
    password: hashed,
    role,
    emailVerifiedAt: new Date(),
  });
}

async function upsertDevice({ userId, deviceId, patch }) {
  return TrustedDevice.findOneAndUpdate(
    { userId, deviceId },
    { $set: patch },
    { upsert: true, new: true }
  );
}

async function seedDemo() {
  const reset = boolEnv("SEED_DEMO_RESET", true);
  const forcePw = boolEnv("SEED_DEMO_FORCE_PASSWORD", true);

    const adminEmail = requireEnv("DEMO_ADMIN_EMAIL");
    const adminPassword = requireEnv("DEMO_ADMIN_PASSWORD");

    const userEmail = requireEnv("DEMO_USER_EMAIL");
    const userPassword = requireEnv("DEMO_USER_PASSWORD");

  const admin = await upsertUser({
    email: adminEmail,
    password: adminPassword,
    role: "admin",
    forcePassword: forcePw,
  });

  const user = await upsertUser({
    email: userEmail,
    password: userPassword,
    role: "user",
    forcePassword: forcePw,
  });

  if (reset) {
    await TrustedDevice.deleteMany({ userId: { $in: [admin._id, user._id] } });
    await LoginAttempt.deleteMany({ email: { $in: [admin.email, user.email] } });
    await AuditEvent.deleteMany({ "meta.seedTag": "demo" });
  }

  // Devices (user)
  await upsertDevice({
    userId: user._id,
    deviceId: "demo_device_trusted_1",
    patch: {
      trusted: true,
      tokenVersion: 0,
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
      lastIp: "73.10.20.30",
      lastUserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
      lastGeo: { country: "US", region: "AR", city: "Fayetteville", ll: [36.0626, -94.1574] },
    },
  });

  await upsertDevice({
    userId: user._id,
    deviceId: "demo_device_untrusted_1",
    patch: {
      trusted: false,
      tokenVersion: 1, // looks “revoked once”
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
      lastIp: "104.26.10.12",
      lastUserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
      lastGeo: { country: "US", region: "IL", city: "Chicago", ll: [41.8781, -87.6298] },
    },
  });

  await upsertDevice({
    userId: user._id,
    deviceId: "demo_device_compromised_1",
    patch: {
      trusted: false,
      tokenVersion: 2,
      compromisedAt: new Date(),
      compromisedReason: "lost_device",
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
      lastIp: "185.199.110.153",
      lastUserAgent: "Mozilla/5.0 (X11; Linux x86_64)",
      lastGeo: { country: "DE", region: "BE", city: "Berlin", ll: [52.52, 13.405] },
    },
  });

  // Some login attempts (user)
  await LoginAttempt.insertMany(
    [
      {
        email: user.email,
        ip: "73.10.20.30",
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        deviceId: "demo_device_trusted_1",
        success: true,
        suspicious: false,
        reasons: [],
        riskScore: 8,
        rawRiskScore: 8,
        geo: { country: "US", region: "AR", city: "Fayetteville", ll: [36.0626, -94.1574] },
      },
      {
        email: user.email,
        ip: "104.26.10.12",
        userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        deviceId: "demo_device_untrusted_1",
        success: true,
        suspicious: true,
        reasons: ["device_untrusted", "new_ip_for_account"],
        riskScore: 62,
        rawRiskScore: 62,
        geo: { country: "US", region: "IL", city: "Chicago", ll: [41.8781, -87.6298] },
      },
      {
        email: user.email,
        ip: "185.199.110.153",
        userAgent: "Mozilla/5.0 (X11; Linux x86_64)",
        deviceId: "demo_device_compromised_1",
        success: false,
        suspicious: true,
        reasons: ["device_compromised", "impossible_travel"],
        riskScore: 92,
        rawRiskScore: 92,
        geo: { country: "DE", region: "BE", city: "Berlin", ll: [52.52, 13.405] },
      },
      {
        email: user.email,
        ip: "73.10.20.30",
        userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        deviceId: "demo_device_trusted_1",
        success: false,
        suspicious: false,
        reasons: [],
        riskScore: 10,
        rawRiskScore: 10,
        geo: { country: "US", region: "AR", city: "Fayetteville", ll: [36.0626, -94.1574] },
      },
    ],
    { ordered: false }
  ).catch(() => {});

  // A few audit events (so Admin → Audit looks populated)
  await AuditEvent.insertMany(
    [
      {
        actorUserId: admin._id,
        actorRole: "admin",
        action: "ADMIN_FORCE_PASSWORD_RESET",
        targetUserId: user._id,
        ip: "127.0.0.1",
        userAgent: "seed-script",
        meta: { seedTag: "demo", reason: "credentials_suspected" },
      },
      {
        actorUserId: admin._id,
        actorRole: "admin",
        action: "ADMIN_LOCK_USER",
        targetUserId: user._id,
        ip: "127.0.0.1",
        userAgent: "seed-script",
        meta: { seedTag: "demo", minutes: 30 },
      },
      {
        actorUserId: user._id,
        actorRole: "user",
        action: "DEVICE_COMPROMISED",
        targetUserId: user._id,
        targetDeviceId: "demo_device_compromised_1",
        ip: "127.0.0.1",
        userAgent: "seed-script",
        meta: { seedTag: "demo", reason: "lost_device" },
      },
    ],
    { ordered: false }
  ).catch(() => {});

  console.log("✅ Demo data seeded.");
}

module.exports = { seedDemo };
