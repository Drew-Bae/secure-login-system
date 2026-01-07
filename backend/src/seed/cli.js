require("dotenv").config();

const mongoose = require("mongoose");
const connectDB = require("../config/db");
const { seedAdmin } = require("./seedAdmin");
const { seedDemo } = require("./seedDemo");

async function main() {
  const mode = (process.argv[2] || "demo").toLowerCase();

  await connectDB();

  try {
    if (mode === "admin") {
      // allow running without touching server startup flags
      process.env.SEED_ADMIN = "true";
      process.env.SEED_ADMIN_EMAIL = process.env.SEED_ADMIN_EMAIL || "admin@example.com";
      process.env.SEED_ADMIN_PASSWORD = process.env.SEED_ADMIN_PASSWORD || "AdminPassword123!";
      process.env.SEED_ADMIN_FORCE_PASSWORD =
        process.env.SEED_ADMIN_FORCE_PASSWORD || "true";

      await seedAdmin();
      console.log("✅ seed:admin complete");
    } else {
      await seedDemo();
      console.log("✅ seed:demo complete");
    }
  } catch (err) {
    console.error("Seed failed:", err);
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
  }
}

main();
