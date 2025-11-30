const functions = require('firebase-functions/v1');
const admin = require('firebase-admin');
const cors = require('cors');
require('dotenv').config();

// IMPORTANT: Initialize the Firebase Admin SDK
admin.initializeApp();

// --- SOLA (Cardknox) INITIALIZATION ---
// The Sola/Cardknox credentials mirror the values described in the Transaction API docs.
// These should be supplied via environment variables or Functions config:
//   SOLA_KEY                -> xKey (private merchant key)
//   SOLA_SOFTWARE_NAME      -> xSoftwareName (software identifier)
//   SOLA_SOFTWARE_VERSION   -> xSoftwareVersion
//   SOLA_VERSION            -> xVersion
//   SOLA_ENV                -> Which environment to target (x1, x2, b1)
const solaConfig = {
    key: process.env.SOLA_KEY || (functions.config().sola && functions.config().sola.key),
    softwareName: process.env.SOLA_SOFTWARE_NAME || (functions.config().sola && functions.config().sola.software_name) || 'MA Minyan',
    softwareVersion: process.env.SOLA_SOFTWARE_VERSION || (functions.config().sola && functions.config().sola.software_version) || '1.0.0',
    version: process.env.SOLA_VERSION || (functions.config().sola && functions.config().sola.version) || '5.0.0',
    environment: process.env.SOLA_ENV || (functions.config().sola && functions.config().sola.environment) || 'x1',
};

if (!solaConfig.key) {
    throw new Error('Missing SOLA_KEY. Set SOLA_KEY env var or functions config sola.key.');
}

// CORS handler for HTTP endpoints only (callable functions handle CORS automatically)
const corsHandler = cors({
    origin: true,
});

const SPIN_SOURCE_APP_TAG = 'Mi Keamcha Yisrael Spin';

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
 * Sends a transaction request to the Sola/Cardknox gateway.
 * @param {Object} payload Key/value pairs to send to the gateway.
 */
async function sendSolaTransaction(payload) {
    const endpoint = `https://${solaConfig.environment}.cardknox.com/gatewayjson`;

    const body = {
        xKey: solaConfig.key,
        xVersion: solaConfig.version,
        xSoftwareName: solaConfig.softwareName,
        xSoftwareVersion: solaConfig.softwareVersion,
        ...payload,
    };

    const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });

    if (!response.ok) {
        throw new Error(`Gateway error ${response.status}: ${response.statusText}`);
    }

    const data = await response.json();

    if (data.xErrorCode && data.xErrorCode !== '00000') {
        throw new Error(`Sola error ${data.xErrorCode}: ${data.xErrorMessage || 'Unknown error'}`);
    }

    return data;
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

/**
 * HTTP Endpoint version of deleteExpiredReservedTickets for admin dashboard.
 * This bypasses callable function CORS issues by using fetch().
 */
exports.deleteExpiredReservedTicketsHttp = functions.runWith({ runtime: 'nodejs20' }).https.onRequest((req, res) => {
    corsHandler(req, res, async () => {
        if (req.method !== 'POST') {
            return res.status(405).send({ message: 'Method Not Allowed. Use POST.' });
        }

        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ message: 'Unauthorized. Missing or invalid Bearer token.' });
            }

            const idToken = authHeader.slice(7); // Remove 'Bearer ' prefix

            // Verify the Firebase ID token
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            const uid = decodedToken.uid;

            // Get user's custom claims
            const userRecord = await admin.auth().getUser(uid);
            const isAdminUser = userRecord.customClaims && (userRecord.customClaims.admin === true || userRecord.customClaims.superAdmin === true);

            if (!isAdminUser) {
                return res.status(403).json({ message: 'Forbidden. User does not have admin privileges.' });
            }

            const db = admin.firestore();
            const defaultTimeoutMinutes = 7;
            const timeoutMinutes = req.body && typeof req.body.timeoutMinutes === 'number' && req.body.timeoutMinutes > 0 ? req.body.timeoutMinutes : defaultTimeoutMinutes;
            
            const timeoutInMs = timeoutMinutes * 60 * 1000;
            const timeoutAgo = new Date(Date.now() - timeoutInMs);

            const reservedTicketsSnapshot = await db.collection('spin_tickets')
                .where('status', '==', 'reserved')
                .where('timestamp', '<', admin.firestore.Timestamp.fromDate(timeoutAgo))
                .get();

            if (reservedTicketsSnapshot.empty) {
                return res.status(200).json({ 
                    deletedCount: 0, 
                    message: `No reserved tickets older than ${timeoutMinutes} minutes found to delete.` 
                });
            }

            const batch = db.batch();
            reservedTicketsSnapshot.forEach(doc => {
                batch.delete(doc.ref);
            });

            await batch.commit();

            return res.status(200).json({ 
                deletedCount: reservedTicketsSnapshot.size, 
                message: `Successfully deleted ${reservedTicketsSnapshot.size} reserved tickets older than ${timeoutMinutes} minutes.` 
            });

        } catch (error) {
            console.error('Error during HTTP reserved ticket cleanup:', error);
            return res.status(500).json({ message: 'Failed to perform manual cleanup.', error: error.message });
        }
    });
});


// --- PAYMENT INTENT FUNCTIONS ---

const ALLOWED_PAYMENT_ORIGINS = [
    'https://mi-keamcha-yisrael.web.app',
    'http://localhost:5000'
];

async function createSpinPaymentIntentCore(data) {
    let ticketNumber;
    const SOURCE_APP_TAG = SPIN_SOURCE_APP_TAG;
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

    return { ticketNumber, amount: cleanAmount(ticketNumber) };
}

exports.createSpinPaymentIntent = functions.runWith({ runtime: 'nodejs20' }).https.onCall(async (data, context) => {
    try {
        return await createSpinPaymentIntentCore(data);
    } catch (error) {
        console.error('Error creating Sola transaction reservation for spin game:', error);
        if (error instanceof functions.https.HttpsError) {
            throw error;
        }
        throw new functions.https.HttpsError('internal', 'Failed to reserve ticket for spin game.', error.message);
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
        console.error('Error creating Sola reservation for spin game (HTTP):', error);

        if (error instanceof functions.https.HttpsError) {
            const statusMap = {
                'invalid-argument': 400,
                'resource-exhausted': 429,
                'permission-denied': 403,
            };
            const statusCode = statusMap[error.code] || 500;
            return res.status(statusCode).json({ message: error.message });
        }

        return res.status(500).json({ message: 'Failed to reserve ticket for spin game.' });
    }
});

/**
 * Charges a reserved spin ticket using the Sola/Cardknox gateway.
 * Expects SUT tokens (xCardNum/xCVV) from the iFields client integration.
 */
async function processSpinPayment(data) {
    const { ticketNumber, name, email, phone, cardToken, cvvToken, exp } = data || {};

    if (!ticketNumber || !name || !email || !phone || !cardToken) {
        throw new functions.https.HttpsError('invalid-argument', 'Missing required fields for processing the payment.');
    }

    const db = admin.firestore();
    const ticketRef = db.collection('spin_tickets').doc(ticketNumber.toString());
    const ticketSnapshot = await ticketRef.get();

    if (!ticketSnapshot.exists) {
        throw new functions.https.HttpsError('failed-precondition', 'Ticket reservation not found.');
    }

    const ticketData = ticketSnapshot.data();
    if (ticketData.status === 'paid') {
        return { status: 'already-paid' };
    }

    const amount = cleanAmount(ticketNumber);

    const solaPayload = {
        xCommand: 'cc:sale',
        xAmount: amount.toFixed(2),
        xCardNum: cardToken,
        xCVV: cvvToken,
        xExp: exp,
        xBillFirstName: name.split(' ')[0] || name,
        xBillLastName: name.split(' ').slice(1).join(' ') || name,
        xEmail: email,
        xBillPhone: phone,
        xInvoice: `spin-${ticketNumber}`,
        xDescription: `Spin Ticket ${ticketNumber}`,
        xOrderID: ticketNumber.toString(),
        xAllowDuplicate: 'true',
    };

    const gatewayResponse = await sendSolaTransaction(solaPayload);

    await ticketRef.update({
        status: 'paid',
        paymentGateway: 'sola',
        transactionId: gatewayResponse.xRefNum || gatewayResponse.xTransactionID,
        name,
        firstName: name.split(' ')[0] || name,
        email,
        phoneNumber: phone,
        amountPaid: amount,
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
        sourceApp: SPIN_SOURCE_APP_TAG,
    });

    return {
        status: gatewayResponse.xResult || 'A',
        ticketNumber,
        referenceNumber: gatewayResponse.xRefNum,
        rawResponse: gatewayResponse,
    };
}

exports.processSpinPayment = functions.runWith({ runtime: 'nodejs20' }).https.onCall(async (data, context) => {
    try {
        return await processSpinPayment(data);
    } catch (error) {
        console.error('Error processing Sola payment for spin game:', error);
        if (error instanceof functions.https.HttpsError) {
            throw error;
        }
        throw new functions.https.HttpsError('internal', 'Failed to process spin payment.', error.message);
    }
});

exports.processSpinPaymentHttp = functions.runWith({ runtime: 'nodejs20' }).https.onRequest(async (req, res) => {
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
        const result = await processSpinPayment(req.body || {});
        return res.status(200).json(result);
    } catch (error) {
        console.error('Error processing Sola payment for spin game (HTTP):', error);
        if (error instanceof functions.https.HttpsError) {
            const statusMap = {
                'invalid-argument': 400,
                'failed-precondition': 412,
                'permission-denied': 403,
            };
            const statusCode = statusMap[error.code] || 500;
            return res.status(statusCode).json({ message: error.message });
        }
        return res.status(500).json({ message: 'Failed to process spin payment.' });
    }
});


/**
 * Firebase Callable Function to process a donation via Sola/Cardknox.
 */
exports.processDonation = functions.runWith({ runtime: 'nodejs20' }).https.onCall(async (data, context) => {
    const SOURCE_APP_TAG = 'Mi Keamcha Yisrael Donation';

    try {
        const { amount, name, email, phone, cardToken, cvvToken, exp } = data;
        const cleanedAmount = cleanAmount(amount);

        if (!cleanedAmount || !name || !email || !phone || !cardToken) {
            throw new functions.https.HttpsError('invalid-argument', 'Missing required fields: amount, name, email, phone, or card token.');
        }

        const gatewayResponse = await sendSolaTransaction({
            xCommand: 'cc:sale',
            xAmount: cleanedAmount.toFixed(2),
            xCardNum: cardToken,
            xCVV: cvvToken,
            xExp: exp,
            xBillFirstName: name.split(' ')[0] || name,
            xBillLastName: name.split(' ').slice(1).join(' ') || name,
            xEmail: email,
            xBillPhone: phone,
            xDescription: `${SOURCE_APP_TAG} Donation`,
            xAllowDuplicate: 'true',
        });

        await admin.firestore().collection('donations').add({
            name,
            email,
            phone,
            amount: cleanedAmount,
            status: 'succeeded',
            gateway: 'sola',
            referenceNumber: gatewayResponse.xRefNum,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            sourceApp: SOURCE_APP_TAG,
        });

        return { status: gatewayResponse.xResult || 'A', referenceNumber: gatewayResponse.xRefNum };

    } catch (error) {
        console.error('Error processing Sola donation:', error);
        if (error instanceof functions.https.HttpsError) {
            throw error;
        }
        throw new functions.https.HttpsError('internal', 'Failed to process donation.');
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

/**
 * HTTP Endpoint to add a manual cash payment ticket
 * Admin can manually add a ticket for cash payments and immediately mark as paid
 */
exports.addManualTicketHttp = functions.runWith({ runtime: 'nodejs20' }).https.onRequest((req, res) => {
    corsHandler(req, res, async () => {
        if (req.method !== 'POST') {
            return res.status(405).send({ message: 'Method Not Allowed. Use POST.' });
        }

        try {
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ message: 'Unauthorized. Missing or invalid Bearer token.' });
            }

            const idToken = authHeader.slice(7);
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            const userRecord = await admin.auth().getUser(decodedToken.uid);
            const isAdminUser = userRecord.customClaims && (userRecord.customClaims.admin === true || userRecord.customClaims.superAdmin === true);

            if (!isAdminUser) {
                return res.status(403).json({ message: 'Forbidden. User does not have admin privileges.' });
            }

            const { name, email, phone, amount } = req.body;

            if (!name || !email || !phone || !amount || amount < 1 || amount > 500) {
                return res.status(400).json({ message: 'Invalid input. Please provide name, email, phone, and amount (1-500).' });
            }

            const db = admin.firestore();
            const ticketRef = db.collection('spin_tickets').doc();
            
            await ticketRef.set({
                id: ticketRef.id,
                name,
                email,
                phoneNumber: phone,
                status: 'paid',
                amountPaid: parseInt(amount),
                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                sourceApp: 'Mi Keamcha Yisrael Admin (Manual Cash)',
            });

            return res.status(200).json({ 
                success: true, 
                ticketId: ticketRef.id,
                message: `Manual ticket created successfully for ${name}.` 
            });

        } catch (error) {
            console.error('Error adding manual ticket:', error);
            return res.status(500).json({ message: 'Failed to add manual ticket.', error: error.message });
        }
    });
});
