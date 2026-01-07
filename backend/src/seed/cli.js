require("dotenv").config();

const mongoose = require("mongoose");
const connectDB = require("../config/db");
const { seedAdmin } = require("./seedAdmin");
const { seedDemo } = require("./seedDemo");

function requireEnv(name) {
  const v = (process.env[name] || "").trim();
  if (!v) {
    const err = new Error(`Missing required env var: ${name}`);
    err.status = 400;
    throw err;
  }
  return v;
}

async function main() {
  const mode = (process.argv[2] || "demo").toLowerCase();

  await connectDB();

  try {
    if (mode === "admin") {
      // NOTE: We intentionally do NOT provide default credentials in code.
      // This prevents shipping a public repo with a known admin email/password.
      process.env.SEED_ADMIN = "true";

      requireEnv("SEED_ADMIN_EMAIL");
      requireEnv("SEED_ADMIN_PASSWORD");

      // Only set this to true temporarily if the admin already exists locally
      // and you want to reset its password.
      process.env.SEED_ADMIN_FORCE_PASSWORD =
        (process.env.SEED_ADMIN_FORCE_PASSWORD || "false").toLowerCase();

      await seedAdmin();
      console.log("✅ seed:admin complete");
    } else {
      // Demo data seeding (requires explicit creds via env for any demo users)
      await seedDemo();
      console.log("✅ seed:demo complete");
    }
  } catch (err) {
    console.error("Seed failed:", err.message || err);
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
  }
}

main();
