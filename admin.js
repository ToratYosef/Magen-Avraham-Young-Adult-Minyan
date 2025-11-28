const admin = require('firebase-admin');

// Load Service Account Key
const serviceAccount = require('./serviceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

// --- CONFIG ---
const ADMIN_EMAIL = "Admin@MKY.com";
const ADMIN_PASSWORD = "MKYadmin12!";

async function createAdmin() {
  try {
    // 1️⃣ Create the user
    const userRecord = await admin.auth().createUser({
      email: ADMIN_EMAIL,
      password: ADMIN_PASSWORD,
      emailVerified: true,
      disabled: false,
    });

    console.log(`\n👤 Created admin user: ${userRecord.uid}`);

    // 2️⃣ Assign admin privileges
    await admin.auth().setCustomUserClaims(userRecord.uid, { admin: true, superAdmin: true });

    // 3️⃣ Force token refresh so claim takes effect
    await admin.auth().revokeRefreshTokens(userRecord.uid);

    console.log(`\n✅ Admin user created & granted admin privileges.`);
    console.log("➡ Email:", ADMIN_EMAIL);
    console.log("➡ Password:", ADMIN_PASSWORD);
    console.log("➡ UID:", userRecord.uid);
    console.log("\nUser must log out & log back in to receive admin claim.");
  } catch (err) {
    // If user already exists, set claim instead of failing
    if (err.code === "auth/email-already-exists") {
      console.log("\n⚠ Email already exists. Fetching user...");
      const existing = await admin.auth().getUserByEmail(ADMIN_EMAIL);

      console.log("👤 Found UID:", existing.uid);
      await admin.auth().setCustomUserClaims(existing.uid, { admin: true, superAdmin: true });
      await admin.auth().revokeRefreshTokens(existing.uid);

      console.log(`\n✅ Existing user promoted to admin with full privileges.`);
      return;
    }

    console.error("\n❌ Error:", err.message);
  }
}

createAdmin();
