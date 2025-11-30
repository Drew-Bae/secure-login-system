const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);

    console.log(`MongoDB connected: ${conn.connection.host}`);
  } catch (err) {
    console.error("Mongo connection failed:", err.message);
    process.exit(1); // Hard fail if DB connection breaks
  }
};

module.exports = connectDB;
