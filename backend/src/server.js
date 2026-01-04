require("dotenv").config();

const connectDB = require("./config/db");
const app = require("./app");
const { seedAdmin } = require("./seed/seedAdmin");

const PORT = process.env.PORT || 5000;

async function start() {
  await connectDB();
  await seedAdmin(); // ✅ seed demo admin if enabled
  app.listen(PORT, "0.0.0.0", () => console.log(`API listening on port ${PORT}`));
}

start();
