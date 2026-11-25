const mongoose = require('mongoose');
const path = require('path');
const dotenv = require('dotenv');

async function inspect(envFile, label) {
  dotenv.config({ path: path.join(__dirname, '..', envFile), override: true });
  const uri = process.env.MONGODB_URI;
  console.log(`\n=== INSPECTING: ${label} ===`);
  console.log(`URI Database: ${uri.split('/').pop().split('?')[0]}`);
  
  await mongoose.connect(uri);
  const db = mongoose.connection.db;
  
  const users = await db.collection('users').find({}).toArray();
  const depts = await db.collection('departments').find({}).toArray();
  const audits = await db.collection('auditlogs').countDocuments();
  
  console.log(`Users count: ${users.length}`);
  users.forEach((u) => console.log(`  - ${u._id}: ${u.email} | ${u.role} | status: ${u.status}`));
  
  console.log(`Departments count: ${depts.length}`);
  depts.forEach((d) => console.log(`  - ${d.code}: ${d.name}`));
  
  console.log(`Audit logs count: ${audits}`);
  await mongoose.disconnect();
}

(async () => {
  try {
    await inspect('.env.staging', 'STAGING (tameer_rekhta_staging)');
    await inspect('.env', 'PRODUCTION (tameer_rekhta)');
  } catch (err) {
    console.error('Error inspecting:', err);
  }
})();
