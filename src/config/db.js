const mongoose = require('mongoose');

const connectDB = async () => {
  const uri = process.env.MONGODB_URI;
  if (!uri) {
    console.warn('[Backend DB Warning] MONGODB_URI is not set. Database running in offline mode.');
    return;
  }

  try {
    const conn = await mongoose.connect(uri, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
    });
    console.log(`[Backend DB] MongoDB Connected: ${conn.connection.host}`);
  } catch (err) {
    console.error(`[Backend DB Error] Database connection failure: ${err.message}`);
  }
};

module.exports = connectDB;
