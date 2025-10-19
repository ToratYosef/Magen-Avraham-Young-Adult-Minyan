const admin = require('firebase-admin');

// --- SETUP: Replace with your actual credentials path ---
// IMPORTANT: This script requires a Service Account JSON file. 
// Download it from Firebase Console > Project Settings > Service Accounts.
const serviceAccount = require('/workspaces/Magen-Avraham-Young-Adult-Minyan/magenavrahamyoungadultminyan-firebase-adminsdk-fbsvc-0736efef0c.json');

// Replace with your project ID
const projectId = 'magenavrahamyoungadultminyan'; 

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  projectId: projectId
});

/**
 * Promotes a specific user by UID to a general 'admin' role.
 * @param {string} targetUid The UID of the user to promote.
 */
async function setAdminClaim(targetUid) {
  if (!targetUid) {
    console.error('Error: Please provide a user UID.');
    return;
  }

  try {
    // 1. Set the custom claim: 'admin: true'
    await admin.auth().setCustomUserClaims(targetUid, { admin: true });

    // 2. Revoke existing tokens to force the user to re-authenticate and pick up new claims
    await admin.auth().revokeRefreshTokens(targetUid);

    console.log(`\n✅ Success: User ${targetUid} has been granted 'admin' privileges.`);
    console.log('The user must log out and log back in to see the changes.');

  } catch (error) {
    console.error('\n❌ Failed to set custom claims:', error.message);
  }
}

// --- EXECUTION ---
// Replace 'TARGET_USER_UID_HERE' with the actual UID of the user you want to promote.
const targetUid = process.argv[2]; 

if (!targetUid) {
    console.log("Usage: node setAdminClaim.js [UID_OF_USER]");
} else {
    setAdminClaim(targetUid);
}
