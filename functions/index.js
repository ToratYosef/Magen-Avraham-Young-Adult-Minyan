const functions = require('firebase-functions/v1');
const admin = require('firebase-admin');
const cors = require('cors'); 
require('dotenv').config();

// IMPORTANT: Initialize the Firebase Admin SDK
admin.initializeApp();

// --- STRIPE INITIALIZATION ---
// NOTE: For this sandbox environment, ensure you deploy this function to a separate Firebase
// project and set the STRIPE_SECRET_KEY environment variable (or functions config `stripe.secret_key`)
// using your **Stripe TEST Secret Key** (sk_test_...).
const stripeSecretKey = process.env.STRIPE_SECRET_KEY || (functions.config().stripe && functions.config().stripe.secret_key);

if (!stripeSecretKey) {
    throw new Error('Missing Stripe secret key. Set STRIPE_SECRET_KEY env var or functions config stripe.secret_key.');
}

const stripe = require('stripe')(stripeSecretKey);

// Updated CORS origins for sandbox and local testing
const corsHandler = cors({
    origin: true, // Allow all origins for callable functions
});

// --- Utility Functions ---

/**
 * Rounds a number to exactly two decimal places for financial calculations.
 * @param {number} value The number to round.
 * @returns {number} The rounded number.
 */
function cleanAmount(value) {
    const num = parseFloat(value);
    if (isNaN(num)) return 0;
    return Math.round(num * 100) / 100;
}

/**
 * Checks if the user is authorized as a super admin.
 */
function isSuperAdmin(context) {
    return context.auth && context.auth.token.superAdmin === true;
}

/**
 * NEW: Checks if the user is authorized as a general admin (requires 'admin: true' claim).
 */
function isAdmin(context) {
    // Requires the user to be authenticated AND have the custom claim 'admin: true'
    return context.auth && (context.auth.token.admin === true || context.auth.token.superAdmin === true);
}

// --- USER MANAGEMENT FUNCTIONS (Kept for general admin utility) ---

/**
 * Callable function to fetch all users from Firebase Auth, excluding anonymous users.
 * Requires Super Admin role.
 */
exports.getAllAuthUsers = functions.runWith({ runtime: 'nodejs20' }).https.onCall(async (data, context) => {
    if (!isSuperAdmin(context)) { 
        throw new functions.https.HttpsError('permission-denied', 'Access denied. Requires Super Admin role.');
    }

    let users = [];
    let nextPageToken;
    let totalUsersFetched = 0;

    try {
        do {
            const listUsersResult = await admin.auth().listUsers(1000, nextPageToken);
            
            listUsersResult.users.forEach(userRecord => {
                if (!userRecord.email) {
                    return; // Skip anonymous users
                }
                
                const claims = userRecord.customClaims || {};
                
                users.push({
                    uid: userRecord.uid,
                    email: userRecord.email,
                    displayName: userRecord.displayName || 'N/A',
                    disabled: userRecord.disabled,
                    emailVerified: userRecord.emailVerified,
                    createdAt: userRecord.metadata.creationTime,
                    lastSignInTime: userRecord.metadata.lastSignInTime,
                    isSuperAdmin: claims.superAdmin || false,
                });
            });

            nextPageToken = listUsersResult.pageToken;
            totalUsersFetched = users.length;

        } while (nextPageToken && totalUsersFetched < 10000); 

        return { users };

    } catch (error) {
        console.error('Error fetching all users:', error);
        throw new functions.https.HttpsError('internal', 'Failed to fetch user list.', error.message);
    }
});

/**
 * Callable function to batch reset passwords for multiple users.
 * Requires Super Admin role.
 */
exports.adminResetMultiPassword = functions.runWith({ runtime: 'nodejs20' }).https.onCall(async (data, context) => {
    if (!isSuperAdmin(context)) { 
        throw new functions.https.HttpsError('permission-denied', 'Access denied. Requires Super Admin role.');
    }

    const { uids, newPassword } = data;

    if (!uids || !Array.isArray(uids) || uids.length === 0 || !newPassword || newPassword.length < 6) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing or invalid UIDs array or new password (min 6 chars).');
    }

    let successfulResets = [];
    let failedResets = [];

    const resetPromises = uids.map(uid => 
        admin.auth().updateUser(uid, { password: newPassword })
            .then(() => {
                successfulResets.push(uid);
            })
            .catch(error => {
                console.error(`Failed to reset password for UID ${uid}: ${error.message}`);
                failedResets.push({ uid, error: error.message });
            })
    );

    await Promise.all(resetPromises);

    return {
        success: true,
        message: `Successfully reset ${successfulResets.length} password(s). Failed: ${failedResets.length}.`,
        successfulResets,
        failedResets
    };
});


// --- ADMIN PASSWORD RESET LOGIC ---

async function getUidByEmail(email) {
    try {
        const userRecord = await admin.auth().getUserByEmail(email);
        return userRecord.uid;
    } catch (error) {
        if (error.code === 'auth/user-not-found') {
            console.warn(`User not found for email: ${email}`);
        } else {
            console.error(`Error retrieving user by email: ${error.message}`);
        }
        return null;
    }
}

async function adminResetPassword(uid, newPassword) {
    try {
        await admin.auth().updateUser(uid, {
            password: newPassword
        });
        console.log(`Password reset success for UID: ${uid}`);
        return true;
    } catch (error) {
        console.error(`Error resetting password for UID ${uid}:`, error.message);
        return false;
    }
}


/**
 * HTTP Function endpoint for Super Admins to directly reset a user's password 
 */
exports.adminResetPasswordByEmail = functions.runWith({ runtime: 'nodejs20' }).https.onRequest((req, res) => {
    corsHandler(req, res, async () => {
        
        // !!! CRITICAL SECURITY CHECK PLACEHOLDER !!!
        // NOTE: In a production environment, this should be protected by Firebase Authentication, 
        // but for an HTTP endpoint outside of callable functions, we rely on a secret API key.
        const ADMIN_SECRET_KEY = functions.config().admin?.api_key;
        const providedKey = req.headers['x-admin-api-key'];

        if (!providedKey || providedKey !== ADMIN_SECRET_KEY) {
             return res.status(403).send({ message: 'Forbidden. Invalid Admin API Key.' });
        }
        // !!! END CRITICAL SECURITY CHECK PLACEHOLDER !!!

        if (req.method !== 'POST') {
            return res.status(405).send({ message: 'Method Not Allowed. Use POST.' });
        }

        const { email, newPassword } = req.body;

        if (!email || !newPassword) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email and newPassword are required in the request body.' 
            });
        }

        try {
            const uid = await getUidByEmail(email);

            if (!uid) {
                return res.status(404).json({ 
                    success: false, 
                    message: `User not found for email: ${email}.` 
                });
            }

            const success = await adminResetPassword(uid, newPassword);

            if (success) {
                return res.status(200).json({ 
                    success: true, 
                    message: `Password for user ${email} successfully reset. Communicate securely to the user.` 
                });
            } else {
                return res.status(500).json({ 
                    success: false, 
                    message: 'Internal server error during password update.' 
                });
            }

        } catch (error) {
            console.error("Admin Reset Endpoint execution error:", error.message);
            return res.status(500).json({ 
                success: false, 
                message: 'A general server error occurred.' 
            });
        }
    });
});


// --- TICKET CLEANUP FUNCTIONS (Spin Tickets) ---

/**
 * Scheduled function to remove reserved spin tickets (spin_tickets) older than 5 minutes.
 */
exports.cleanupReservedTickets = functions.runWith({ runtime: 'nodejs20' }).pubsub.schedule('every 5 minutes').onRun(async (context) => {
    const db = admin.firestore();
    const fiveMinutesInMs = 5 * 60 * 1000; 
    const fiveMinutesAgo = new Date(Date.now() - fiveMinutesInMs); 

    try {
        const reservedTicketsSnapshot = await db.collection('spin_tickets')
            .where('status', '==', 'reserved')
            .where('timestamp', '<', fiveMinutesAgo) 
            .get();

        if (reservedTicketsSnapshot.empty) {
            return null;
        }

        const batch = db.batch();
        reservedTicketsSnapshot.forEach(doc => {
            batch.delete(doc.ref);
        });

        await batch.commit();
        return null;

    } catch (error) {
        console.error('Error during reserved ticket cleanup:', error);
        return null;
    }
});

/**
 * Callable function to retrieve counts of reserved and expired tickets for the admin tool.
 * NOW Requires general Admin role.
 */
exports.getReservedTicketCounts = functions.runWith({ runtime: 'nodejs20' }).https.onCall(async (data, context) => {
    if (!isAdmin(context)) { 
        throw new functions.https.HttpsError('permission-denied', 'Access denied. Requires Admin role.');
    }

    const db = admin.firestore();
    const fiveMinutesInMs = 5 * 60 * 1000;
    const tenMinutesInMs = 10 * 60 * 1000;
    const fiveMinutesAgo = new Date(Date.now() - fiveMinutesInMs);
    const tenMinutesAgo = new Date(Date.now() - tenMinutesInMs);
    
    let totalReserved = 0;
    let expired5Min = 0;
    let expired10Min = 0;

    try {
        const allReservedSnapshot = await db.collection('spin_tickets')
            .where('status', '==', 'reserved')
            .get();

        totalReserved = allReservedSnapshot.size;

        allReservedSnapshot.forEach(doc => {
            const ticket = doc.data();
            const timestamp = ticket.timestamp.toDate ? ticket.timestamp.toDate() : ticket.timestamp;

            if (timestamp < fiveMinutesAgo) {
                expired5Min++;
            }
            if (timestamp < tenMinutesAgo) {
                expired10Min++;
            }
        });

        return { totalReserved, expired5Min, expired10Min };

    } catch (error) {
        console.error('Error fetching reserved ticket counts:', error);
        throw new functions.https.HttpsError('internal', 'Failed to retrieve ticket counts.', error.message);
    }
});

/**
 * Callable function to manually delete reserved tickets older than a specified number of minutes.
 * Defaults to 7 minutes if no argument is provided.
 * NOW Requires general Admin role.
 */
exports.deleteExpiredReservedTickets = functions.runWith({ runtime: 'nodejs20' }).https.onCall(async (data, context) => {
    if (!isAdmin(context)) {
        throw new functions.https.HttpsError('permission-denied', 'Access denied. Requires Admin role.');
    }

    const db = admin.firestore();
    // Default to 7 minutes if timeoutMinutes is not provided or invalid
    const defaultTimeoutMinutes = 7;
    const timeoutMinutes = data && typeof data.timeoutMinutes === 'number' && data.timeoutMinutes > 0 ? data.timeoutMinutes : defaultTimeoutMinutes;
    
    const timeoutInMs = timeoutMinutes * 60 * 1000;
    const timeoutAgo = new Date(Date.now() - timeoutInMs); 

    try {
        // Query must use Firebase Timestamps (whichFirestore automatically handles, but checking for nulls is safer)
        const reservedTicketsSnapshot = await db.collection('spin_tickets')
            .where('status', '==', 'reserved')
            // Using FieldValue.serverTimestamp() equivalent for comparison
            .where('timestamp', '<', admin.firestore.Timestamp.fromDate(timeoutAgo)) 
            .get();

        if (reservedTicketsSnapshot.empty) {
            return { deletedCount: 0, message: `No reserved tickets older than ${timeoutMinutes} minutes found to delete.` };
        }

        const batch = db.batch();
        reservedTicketsSnapshot.forEach(doc => {
            batch.delete(doc.ref);
        });

        await batch.commit();
        
        return { deletedCount: reservedTicketsSnapshot.size, message: `Successfully deleted ${reservedTicketsSnapshot.size} reserved tickets older than ${timeoutMinutes} minutes.` };

    } catch (error) {
        console.error('Error during manual reserved ticket cleanup:', error);
        // Throw a specific error code to help the client understand the generic 500 error
        throw new functions.https.HttpsError('internal', 'Failed to perform manual cleanup.', error.message);
    }
});


// --- PAYMENT INTENT FUNCTIONS ---

const ALLOWED_PAYMENT_ORIGINS = [
    'https://mi-keamcha-yisrael.web.app',
    'http://localhost:5000'
];

async function createSpinPaymentIntentCore(data) {
    let ticketNumber;
    const SOURCE_APP_TAG = 'Mi Keamcha Yisrael Spin';
    const TOTAL_TICKETS = 500;

    const { name, email, phone } = data || {};
    const firstName = (name || '').split(' ')[0] || name;

    if (!name || !email || !phone) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields: name, email, or phone.');
    }

    const db = admin.firestore();
    let foundUniqueTicket = false;

    for (let i = 0; i < TOTAL_TICKETS * 2; i++) {
        const randomTicket = Math.floor(Math.random() * TOTAL_TICKETS) + 1;
        const ticketRef = db.collection('spin_tickets').doc(randomTicket.toString());

        try {
            await db.runTransaction(async (transaction) => {
                const docSnapshot = await transaction.get(ticketRef);
                if (!docSnapshot.exists || (docSnapshot.data().status !== 'reserved' && docSnapshot.data().status !== 'paid' && docSnapshot.data().status !== 'claimed')) {
                    transaction.set(ticketRef, {
                        status: 'reserved',
                        timestamp: admin.firestore.FieldValue.serverTimestamp(),
                        name: name,
                        firstName: firstName,
                        email: email,
                        phoneNumber: phone,
                        sourceApp: SOURCE_APP_TAG,
                    }, { merge: true });

                    foundUniqueTicket = true;
                }
            });

            if (foundUniqueTicket) {
                ticketNumber = randomTicket;
                break;
            }
        } catch (e) {
            console.error("Transaction failed during ticket reservation: ", e);
        }
    }

    if (!foundUniqueTicket) {
        throw new functions.https.HttpsError('resource-exhausted', 'All tickets have been claimed. Please try again later.');
    }

    const amountInCents = ticketNumber * 100;

    try {
        const paymentIntent = await stripe.paymentIntents.create({
            amount: amountInCents,
            currency: 'usd',
            description: `${SOURCE_APP_TAG} - Ticket ${ticketNumber}`,
            payment_method_types: ['card'],
            metadata: {
                name,
                email,
                phone,
                ticketsBought: '1',
                baseAmount: ticketNumber.toString(),
                ticketNumber: ticketNumber.toString(),
                entryType: 'spin',
                sourceApp: SOURCE_APP_TAG,
            },
        });

        return { clientSecret: paymentIntent.client_secret, ticketNumber };
    } catch (error) {
        if (ticketNumber) {
            try {
                await admin.firestore().collection('spin_tickets').doc(ticketNumber.toString()).delete();
            } catch (cleanupError) {
                console.error('Failed to clean up reserved ticket after Stripe error:', cleanupError);
            }
        }

        throw error;
    }
}

exports.createSpinPaymentIntent = functions.runWith({ runtime: 'nodejs20' }).https.onCall(async (data, context) => {
    try {
        return await createSpinPaymentIntentCore(data);
    } catch (error) {
        console.error('Error creating Stripe PaymentIntent for spin game:', error);
        if (error instanceof functions.https.HttpsError) {
            throw error;
        }
        throw new functions.https.HttpsError('internal', 'Failed to create PaymentIntent for spin game.', error.message);
    }
});

exports.createSpinPaymentIntentHttp = functions.runWith({ runtime: 'nodejs20' }).https.onRequest(async (req, res) => {
    const origin = req.get('Origin');
    if (origin && ALLOWED_PAYMENT_ORIGINS.includes(origin)) {
        res.set('Access-Control-Allow-Origin', origin);
    } else {
        res.set('Access-Control-Allow-Origin', '*');
    }
    res.set('Access-Control-Allow-Methods', 'POST,OPTIONS');
    res.set('Access-Control-Allow-Headers', 'Content-Type');

    if (req.method === 'OPTIONS') {
        return res.status(204).send('');
    }

    if (req.method !== 'POST') {
        return res.status(405).json({ message: 'Method not allowed' });
    }

    try {
        const result = await createSpinPaymentIntentCore(req.body || {});
        return res.status(200).json(result);
    } catch (error) {
        console.error('Error creating Stripe PaymentIntent for spin game (HTTP):', error);

        if (error instanceof functions.https.HttpsError) {
            const statusMap = {
                'invalid-argument': 400,
                'resource-exhausted': 429,
                'permission-denied': 403,
            };
            const statusCode = statusMap[error.code] || 500;
            return res.status(statusCode).json({ message: error.message });
        }

        return res.status(500).json({ message: 'Failed to create PaymentIntent for spin game.' });
    }
});


/**
 * Firebase Callable Function to create a Stripe PaymentIntent for a general donation.
 * (Kept for the separate Donate button functionality)
 */
exports.createDonationPaymentIntent = functions.runWith({ runtime: 'nodejs20' }).https.onCall(async (data, context) => {
    const SOURCE_APP_TAG = 'Mi Keamcha Yisrael Donation';

    try {
        const { amount, name, email, phone } = data; // Removed 'referral'
        const cleanedAmount = cleanAmount(amount);

        if (!cleanedAmount || !name || !email || !phone) {
            throw new functions.https.HttpsError('invalid-argument', 'Missing required fields: amount, name, email, or phone.');
        }
        
        const amountInCents = Math.round(cleanedAmount * 100);

        const paymentIntent = await stripe.paymentIntents.create({
            amount: amountInCents,
            currency: 'usd',
            description: `${SOURCE_APP_TAG} Donation`, 
            payment_method_types: ['card'],
            metadata: {
                name,
                email,
                phone,
                amount: cleanedAmount.toString(),
                entryType: 'donation',
                sourceApp: SOURCE_APP_TAG,
            },
        });

        // Store PI creation details
        await admin.firestore().collection('stripe_donation_payment_intents').doc(paymentIntent.id).set({
            name,
            email,
            phone,
            amount: cleanedAmount, 
            status: 'created',
            sourceApp: SOURCE_APP_TAG, 
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        return { clientSecret: paymentIntent.client_secret, paymentIntentId: paymentIntent.id };

    } catch (error) {
        console.error('Error creating Stripe PaymentIntent for donation:', error);
        throw new functions.https.HttpsError('internal', 'Failed to create donation PaymentIntent.');
    }
});

/**
 * Stripe Webhook Listener (HTTP Request Function).
 * Simplified to ONLY handle 'spin' (spin) and 'donation' entry types.
 */
exports.stripeWebhook = functions.runWith({ runtime: 'nodejs20' }).https.onRequest(async (req, res) => {
    const sig = req.headers['stripe-signature'];
    
    // NOTE: For sandbox testing, ensure you use the **Stripe TEST Webhook Secret** for this endpoint.
    const webhookSecret = functions.config().stripe.webhook_secret; 
    let event;

    try {
      event = stripe.webhooks.constructEvent(req.rawBody, sig, webhookSecret);
    } catch (err) {
      console.error(`Webhook signature verification failed: ${err.message}`);
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    if (event.type === 'payment_intent.succeeded') {
      const paymentIntent = event.data.object;

      // Metadata extraction
      const { name, email, phone, ticketNumber, entryType, sourceApp } = paymentIntent.metadata;

      const firstName = name.split(' ')[0] || name;
      const amountCharged = cleanAmount(paymentIntent.amount / 100); 
      
      try {
        const db = admin.firestore();

        // --- spin Ticket Processing (Spin to Win) ---
        if (entryType === 'spin') {
            // ticketNumber is the document ID/base price in USD
            const spinTicketRef = db.collection('spin_tickets').doc(ticketNumber); 
            
            // The amountPaid field stores the base amount (ticketNumber in this case)
            const amountForSaleRecord = cleanAmount(ticketNumber);
            
            await spinTicketRef.update({
                status: 'paid',
                paymentIntentId: paymentIntent.id,
                name,
                firstName: firstName, 
                email,
                phoneNumber: phone, 
                amountPaid: amountForSaleRecord, // Store fee-excluded base amount
                updatedAt: admin.firestore.FieldValue.serverTimestamp(),
                sourceApp: sourceApp || 'Mi Keamcha Yisrael Spin (Webhook)',
            });

            // Update the temporary PI status doc (if it existed) to prevent reprocessing
            // NOTE: Since the ticket itself is the primary record, we don't need a separate PI status doc here.

        }
        
        // --- Donation Processing ---
        else if (entryType === 'donation') {
            // Update the stripe_donation_payment_intents document
            const donationIntentRef = db.collection('stripe_donation_payment_intents').doc(paymentIntent.id);
            
            // Use the amount from the metadata for the base donation value
            const donationBaseAmount = cleanAmount(paymentIntent.metadata.amount) || amountCharged;

            await donationIntentRef.update({
                status: 'succeeded',
                amountPaid: amountCharged, // Store actual charged amount for PI tracking
                baseDonationAmount: donationBaseAmount, // Store the intended donation amount
                webhookProcessed: true,
                updatedAt: admin.firestore.FieldValue.serverTimestamp(),
                sourceApp: sourceApp || 'Mi Keamcha Yisrael Donation (Webhook)'
            });
        }
        
        // --- Unknown/Unsupported Entry Type ---
        else {
            console.warn(`Webhook received for unknown entry type: ${entryType}. Ignoring.`);
            return res.status(200).send('Webhook processed (ignored unsupported entry type).');
        }

        res.status(200).send('Webhook processed successfully.');

      } catch (error) {
        console.error('Error processing payment_intent.succeeded webhook:', error);
        res.status(500).send('Internal Server Error during webhook processing.');
      }
    } else {
      res.status(200).send('Webhook event ignored (uninteresting type).');
    }
});


// --- ADMIN MANAGEMENT FUNCTIONS (Kept for general admin utility) ---

/**
 * Callable function to create a new Super Admin account.
 * Requires an existing Super Admin role.
 */
exports.createSuperAdmin = functions.runWith({ runtime: 'nodejs20' }).https.onCall(async (data, context) => {
    if (!isSuperAdmin(context)) {
        throw new functions.https.HttpsError('permission-denied', 'Only Super Admins can create new admins.');
    }
    const { email, password, name } = data;

    if (!email || !password || !name) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields.');
    }

    try {
        const userRecord = await admin.auth().createUser({ email, password, displayName: name });
        const uid = userRecord.uid;

        // Set custom claims for Super Admin access
        await admin.auth().setCustomUserClaims(uid, { admin: true, superAdmin: true });

        return { success: true, message: `Super Admin ${name} created successfully.` };
    } catch (error) {
        console.error('Error creating new admin:', error);
        throw new functions.https.HttpsError('internal', 'Failed to create admin.', error.message);
    }
});

/**
 * Callable function to set a user as Super Admin.
 */
exports.setSuperAdminClaim = functions.runWith({ runtime: 'nodejs20' }).https.onCall(async (data, context) => {
    if (!isSuperAdmin(context)) {
        throw new functions.https.HttpsError('permission-denied', 'Access denied. Only a Super Admin can promote another user.');
    }

    const { uid } = data;

    if (!uid) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing target user ID (uid).');
    }

    try {
        // Get existing claims to avoid overwriting (there should be none now)
        const user = await admin.auth().getUser(uid);
        const existingClaims = user.customClaims || {};

        // Set the new claims
        const updatedClaims = {
            ...existingClaims,
            admin: true, // Ensure they also have general admin access
            superAdmin: true
        };

        // Set the custom claim on the Firebase user object
        await admin.auth().setCustomUserClaims(uid, updatedClaims);

        // Force user to re-authenticate on their device to pick up the new claims immediately
        await admin.auth().revokeRefreshTokens(uid);

        return { 
            success: true, 
            message: `User ${uid} successfully promoted to Super Admin status. Tokens revoked.` 
        };

    } catch (error) {
        console.error(`Error promoting user ${uid} to Super Admin:`, error);
        throw new functions.https.HttpsError('internal', 'Failed to update user claims.', error.message);
    }
});
