#!/usr/bin/env node
/**
 * Generate 500 demo tickets (1–500) into Firestore `spin_tickets`.
 * Uses service account JSON in the repo root.
 *
 * Fields:
 * - ticketNumber: number
 * - name: "Demo #N"
 * - status: "claimed"
 * - createdAt: serverTimestamp
 * - demo: true
 */
const admin = require('firebase-admin');
const path = require('path');

function getServiceAccountPath() {
  // Default location at repo root: serviceAccountKey.json
  return path.resolve(__dirname, '..', 'serviceAccountKey.json');
}

async function main() {
  const saPath = getServiceAccountPath();
  try {
    const serviceAccount = require(saPath);
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
        projectId: serviceAccount.project_id,
      });
    }
  } catch (e) {
    console.error('Failed to load service account at', saPath);
    console.error(e.message || e);
    process.exit(1);
  }

  const db = admin.firestore();
  const batch = db.batch();
  const total = 500;

  console.log(`Generating ${total} demo tickets...`);

  for (let i = 1; i <= total; i++) {
    const docRef = db.collection('spin_tickets').doc(String(i));
    batch.set(docRef, {
      ticketNumber: i,
      name: `Demo #${i}`,
      status: 'claimed',
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      demo: true,
    }, { merge: true });
  }

  await batch.commit();
  console.log('Done. Created/updated 500 demo tickets in `spin_tickets`.');
  process.exit(0);
}

main().catch(err => {
  console.error('Error generating demo tickets:', err);
  process.exit(1);
});
