const functions = require('firebase-functions/v1');
const admin = require('firebase-admin');
const cors = require('cors'); 
const nodemailer = require('nodemailer');
const express = require('express');
const bodyParser = require('body-parser');
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

const stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

const stripe = require('stripe')(stripeSecretKey);

// CORS handler for HTTP endpoints only (callable functions handle CORS automatically)
const corsHandler = cors({
    origin: true,
});

// --- NODEMAILER CONFIGURATION ---
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false,
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// --- EMAIL TEMPLATES ---

/**
 * Generates styled HTML email with site branding
 */
function getEmailTemplate(title, content) {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            margin: 0;
            padding: 0;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #050810 0%, #0A0E27 100%);
            color: #ffffff;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background: rgba(15, 21, 39, 0.95);
            border: 2px solid rgba(201, 169, 97, 0.3);
            border-radius: 16px;
            overflow: hidden;
        }
        .header {
            background: rgba(10, 14, 39, 0.9);
            padding: 30px 20px;
            text-align: center;
            border-bottom: 2px solid rgba(201, 169, 97, 0.3);
        }
        .logo {
            width: 80px;
            height: 80px;
            margin: 0 auto 15px;
            border-radius: 50%;
            border: 2px solid #C9A961;
            padding: 5px;
            background: #0A0E27;
        }
        .title {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 32px;
            color: #C9A961;
            margin: 0;
            letter-spacing: 2px;
        }
        .subtitle {
            font-size: 14px;
            color: #9CA3AF;
            margin: 5px 0 0;
        }
        .content {
            padding: 40px 30px;
        }
        .highlight-box {
            background: rgba(201, 169, 97, 0.1);
            border: 2px solid rgba(201, 169, 97, 0.3);
            border-radius: 12px;
            padding: 25px;
            margin: 25px 0;
            text-align: center;
        }
        .ticket-number {
            font-family: 'Bebas Neue', sans-serif;
            font-size: 48px;
            color: #C9A961;
            margin: 10px 0;
            text-shadow: 0 0 20px rgba(201, 169, 97, 0.4);
        }
        .amount {
            font-size: 36px;
            font-weight: bold;
            color: #C9A961;
        }
        .label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #9CA3AF;
            margin-bottom: 8px;
        }
        .info-row {
            margin: 15px 0;
            padding: 12px;
            background: rgba(5, 8, 16, 0.5);
            border-radius: 8px;
        }
        .button {
            display: inline-block;
            padding: 15px 35px;
            background: #C9A961;
            color: #0A0E27;
            text-decoration: none;
            border-radius: 50px;
            font-weight: bold;
            margin: 20px 0;
            box-shadow: 0 0 20px rgba(201, 169, 97, 0.3);
        }
        .footer {
            background: rgba(0, 0, 0, 0.4);
            padding: 25px;
            text-align: center;
            border-top: 1px solid rgba(201, 169, 97, 0.2);
            font-size: 12px;
            color: #9CA3AF;
        }
        .footer a {
            color: #C9A961;
            text-decoration: none;
        }
        .divider {
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(201, 169, 97, 0.3), transparent);
            margin: 25px 0;
        }
        h2 {
            color: #C9A961;
            font-family: 'Bebas Neue', sans-serif;
            font-size: 24px;
            letter-spacing: 1.5px;
        }
        p {
            line-height: 1.6;
            color: #D1D5DB;
            margin: 12px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <img src="https://raw.githubusercontent.com/ToratYosef/Magen-Avraham-Young-Adult-Minyan/refs/heads/main/assets/logo.png" alt="Mi Keamcha Yisrael" class="logo">
            <h1 class="title">MI KEAMCHA YISRAEL</h1>
            <p class="subtitle">${title}</p>
        </div>
        <div class="content">
            ${content}
        </div>
        <div class="footer">
            <p><strong>Mi Keamcha Yisrael</strong><br>
            Supporting our community through charitable initiatives</p>
            <p style="margin-top: 15px;">
                <a href="https://mi-keamcha-yisrael.web.app">Home</a> | 
                <a href="https://mi-keamcha-yisrael.web.app/terms.html">Terms</a> | 
                <a href="https://mi-keamcha-yisrael.web.app/privacy.html">Privacy</a>
            </p>
            <p style="margin-top: 10px; font-size: 11px;">
                &copy; 2026 Mi Keamcha Yisrael. All Rights Reserved.<br>
                Questions? Text us at <a href="sms:9295845753">929-584-5753</a>
            </p>
        </div>
    </div>
</body>
</html>
    `;
}

/**
 * Sends a tax-deductible receipt email
 */
async function sendReceiptEmail(recipientEmail, recipientName, ticketNumber, amount, paymentMethod = 'card') {
    const content = `
        <p>Dear ${recipientName},</p>
        <p>Thank you for your generous contribution to Mi Keamcha Yisrael!</p>
        
        <div class="highlight-box">
            <p class="label">Your Ticket Number</p>
            <p class="ticket-number">#${ticketNumber}</p>
            <div class="divider"></div>
            <p class="label">Amount Paid</p>
            <p class="amount">$${amount.toFixed(2)}</p>
        </div>

        <h2>Donation Details</h2>
        <div class="info-row">
            <strong>Date:</strong> ${new Date().toLocaleDateString('en-US', { 
                weekday: 'long', 
                year: 'numeric', 
                month: 'long', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            })}
        </div>
        <div class="info-row">
            <strong>Payment Method:</strong> ${paymentMethod === 'cash' ? 'Cash/Check' : 'Credit Card'}
        </div>
        <div class="info-row">
            <strong>Ticket Number:</strong> #${ticketNumber}
        </div>

        <div class="divider"></div>

        <h2>Tax Information</h2>
        <p>Your donation is tax-deductible to the extent allowed by law. <strong>No goods or services were provided in exchange for this contribution.</strong></p>
        
        <p style="font-size: 14px; margin-top: 20px;">
            <strong>Organization Information:</strong><br>
            Mi Keamcha Yisrael<br>
            Brooklyn, NY<br>
            EIN: [Your EIN Number Here]
        </p>

        <p style="margin-top: 25px; padding: 15px; background: rgba(201, 169, 97, 0.1); border-radius: 8px; border-left: 4px solid #C9A961;">
            <strong>Please keep this email for your tax records.</strong>
        </p>

        <div style="text-align: center; margin-top: 30px;">
            <a href="https://mi-keamcha-yisrael.web.app" class="button">View Raffle Details</a>
        </div>

        <p style="margin-top: 30px; text-align: center; color: #9CA3AF;">
            Good luck in the drawing! 🎉
        </p>
    `;

    const mailOptions = {
        from: process.env.EMAIL_FROM || '"Mi Keamcha Yisrael" <sales@secondhandcell.com>',
        to: recipientEmail,
        subject: `Tax-Deductible Receipt – Ticket #${ticketNumber} ($${amount.toFixed(2)})`,
        html: getEmailTemplate('Tax-Deductible Donation Receipt', content),
    };

    await transporter.sendMail(mailOptions);
    console.log(`✅ Receipt email sent to ${recipientEmail} for ticket #${ticketNumber}`);
}

/**
 * Saves email to Firestore emails collection
 */
async function saveEmailToCollection(email, name) {
    const db = admin.firestore();
    try {
        await db.collection('emails').doc(email).set({
            email: email,
            name: name,
            addedAt: admin.firestore.FieldValue.serverTimestamp(),
            subscribed: true,
        }, { merge: true });
        console.log(`✅ Email ${email} saved to collection`);
    } catch (error) {
        console.error('Error saving email to collection:', error);
    }
}


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

        // Update ticket with payment intent ID for webhook lookup
        await db.collection('spin_tickets').doc(ticketNumber.toString()).update({
            paymentIntentId: paymentIntent.id,
            id: ticketNumber.toString(),
        });

        // Save email to collection immediately
        await saveEmailToCollection(email, name);

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
    if (!stripeWebhookSecret) {
        console.error('Missing STRIPE_WEBHOOK_SECRET environment variable');
        return res.status(500).send('Webhook Error: Missing webhook secret');
    }
    
    let event;

    try {
      event = stripe.webhooks.constructEvent(req.rawBody, sig, stripeWebhookSecret);
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

/**
 * HTTP Endpoint to add a manual cash payment ticket
 * Admin can manually add a ticket with "waiting for payment" status
 * Admin can later mark them as paid in the dashboard
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

            const { name, email, phone } = req.body;

            if (!name || !email || !phone) {
                return res.status(400).json({ message: 'Invalid input. Please provide name, email, and phone.' });
            }

            const db = admin.firestore();
            const TOTAL_TICKETS = 500;
            const SOURCE_APP = 'Mi Keamcha Yisrael Admin (Manual Cash)';
            const firstName = name.split(' ')[0] || name;

            let ticketNumber = null;

            for (let i = 0; i < TOTAL_TICKETS * 2; i++) {
                const randomTicket = Math.floor(Math.random() * TOTAL_TICKETS) + 1;
                const ticketRef = db.collection('spin_tickets').doc(randomTicket.toString());

                let assigned = false;

                try {
                    await db.runTransaction(async (transaction) => {
                        const ticketSnap = await transaction.get(ticketRef);

                        if (!ticketSnap.exists || (ticketSnap.data().status !== 'reserved' && ticketSnap.data().status !== 'paid' && ticketSnap.data().status !== 'claimed' && ticketSnap.data().status !== 'waiting_for_payment')) {
                            const amount = cleanAmount(randomTicket);
                            
                            transaction.set(ticketRef, {
                                id: randomTicket.toString(),
                                status: 'waiting_for_payment',
                                timestamp: admin.firestore.FieldValue.serverTimestamp(),
                                name,
                                firstName,
                                email,
                                phoneNumber: phone,
                                amountDue: amount,
                                paymentMethod: 'cash',
                                sourceApp: SOURCE_APP,
                            }, { merge: true });
                            assigned = true;
                        }
                    });

                    if (assigned) {
                        ticketNumber = randomTicket;
                        break;
                    }
                } catch (error) {
                    console.error('Transaction failed when assigning manual ticket:', error);
                }
            }

            if (!ticketNumber) {
                return res.status(409).json({ message: 'Unable to assign a ticket. All tickets may be claimed.' });
            }

            const amountDue = cleanAmount(ticketNumber);

            // Save email to collection
            await saveEmailToCollection(email, name);

            return res.status(200).json({
                success: true,
                ticketId: ticketNumber.toString(),
                ticketNumber: ticketNumber,
                amountDue: amountDue,
                message: `Manual ticket #${ticketNumber} created with amount $${amountDue.toFixed(2)} - waiting for payment.`
            });

        } catch (error) {
            console.error('Error adding manual ticket:', error);
            return res.status(500).json({ message: 'Failed to add manual ticket.', error: error.message });
        }
    });
});

// ============================================================
// EMAIL & WEBHOOK SYSTEM
// ============================================================

/**
 * Stripe Webhook Handler
 * Handles payment_intent.succeeded events and sends receipt emails
 */
const webhookApp = express();
webhookApp.use('/webhook', bodyParser.raw({ type: 'application/json' }));

webhookApp.post('/webhook', async (req, res) => {
    let event;

    try {
        const sig = req.headers['stripe-signature'];
        event = stripe.webhooks.constructEvent(
            req.body,
            sig,
            stripeWebhookSecret
        );
    } catch (err) {
        console.error('⚠️  Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // Handle successful payment
    if (event.type === 'payment_intent.succeeded') {
        const paymentIntent = event.data.object;
        
        try {
            const db = admin.firestore();
            
            // Find the ticket by payment intent ID
            const ticketsSnapshot = await db.collection('spin_tickets')
                .where('paymentIntentId', '==', paymentIntent.id)
                .limit(1)
                .get();

            if (!ticketsSnapshot.empty) {
                const ticketDoc = ticketsSnapshot.docs[0];
                const ticketData = ticketDoc.data();
                
                // Update ticket status to paid
                await ticketDoc.ref.update({
                    status: 'paid',
                    paidAt: admin.firestore.FieldValue.serverTimestamp(),
                });

                // Save email to collection
                await saveEmailToCollection(ticketData.email, ticketData.name);

                // Send receipt email
                await sendReceiptEmail(
                    ticketData.email,
                    ticketData.name,
                    ticketData.id,
                    parseFloat(ticketData.id), // Amount is the ticket number
                    'card'
                );

                console.log(`✅ Processed payment for ticket #${ticketData.id}`);
            } else {
                console.warn(`⚠️  No ticket found for payment intent ${paymentIntent.id}`);
            }
        } catch (error) {
            console.error('Error processing payment webhook:', error);
        }
    }

    res.json({ received: true });
});

exports.stripeWebhook = functions.runWith({ runtime: 'nodejs20' }).https.onRequest(webhookApp);

/**
 * HTTP Endpoint to mark manual ticket as paid and send receipt
 * Called when admin marks a waiting_for_payment ticket as paid
 */
exports.markTicketPaidHttp = functions.runWith({ runtime: 'nodejs20' }).https.onRequest((req, res) => {
    corsHandler(req, res, async () => {
        if (req.method !== 'POST') {
            return res.status(405).send({ message: 'Method Not Allowed. Use POST.' });
        }

        try {
            // Verify admin authorization
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ message: 'Unauthorized. Missing or invalid Bearer token.' });
            }

            const idToken = authHeader.slice(7);
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            const userRecord = await admin.auth().getUser(decodedToken.uid);
            const isAdminUser = userRecord.customClaims && (userRecord.customClaims.admin === true || userRecord.customClaims.superAdmin === true);

            if (!isAdminUser) {
                return res.status(403).json({ message: 'Forbidden. Admin privileges required.' });
            }

            const { ticketId } = req.body;
            if (!ticketId) {
                return res.status(400).json({ message: 'Missing ticketId.' });
            }

            const db = admin.firestore();
            const ticketRef = db.collection('spin_tickets').doc(ticketId);
            const ticketDoc = await ticketRef.get();

            if (!ticketDoc.exists) {
                return res.status(404).json({ message: 'Ticket not found.' });
            }

            const ticketData = ticketDoc.data();

            // Update to paid status
            await ticketRef.update({
                status: 'paid',
                paidAt: admin.firestore.FieldValue.serverTimestamp(),
            });

            // Save email to collection
            await saveEmailToCollection(ticketData.email, ticketData.name);

            // Send receipt email
            await sendReceiptEmail(
                ticketData.email,
                ticketData.name,
                ticketData.id,
                ticketData.amountDue || parseFloat(ticketData.id),
                ticketData.paymentMethod || 'cash'
            );

            return res.status(200).json({ 
                success: true, 
                message: `Ticket #${ticketId} marked as paid and receipt sent.` 
            });

        } catch (error) {
            console.error('Error marking ticket as paid:', error);
            return res.status(500).json({ message: 'Failed to mark ticket as paid.', error: error.message });
        }
    });
});

/**
 * HTTP Endpoint to send "Drawing Soon" email to all subscribers
 */
exports.sendDrawingSoonEmailHttp = functions.runWith({ runtime: 'nodejs20' }).https.onRequest((req, res) => {
    corsHandler(req, res, async () => {
        if (req.method !== 'POST') {
            return res.status(405).send({ message: 'Method Not Allowed. Use POST.' });
        }

        try {
            // Verify admin authorization
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ message: 'Unauthorized.' });
            }

            const idToken = authHeader.slice(7);
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            const userRecord = await admin.auth().getUser(decodedToken.uid);
            const isAdminUser = userRecord.customClaims && (userRecord.customClaims.admin === true || userRecord.customClaims.superAdmin === true);

            if (!isAdminUser) {
                return res.status(403).json({ message: 'Forbidden.' });
            }

            const db = admin.firestore();
            const emailsSnapshot = await db.collection('emails')
                .where('subscribed', '==', true)
                .get();

            const content = `
                <p>The moment you've been waiting for is almost here!</p>
                
                <div class="highlight-box">
                    <h2 style="margin: 0; font-size: 36px;">🎉 RAFFLE DRAWING SOON!</h2>
                    <p style="font-size: 18px; margin-top: 15px;">Stay tuned for the announcement</p>
                </div>

                <p>Thank you for supporting Mi Keamcha Yisrael. We'll be announcing the winners very soon!</p>

                <p>Make sure to check your email and our website for the results.</p>

                <div style="text-align: center; margin-top: 30px;">
                    <a href="https://mi-keamcha-yisrael.web.app" class="button">Visit Website</a>
                </div>

                <p style="margin-top: 30px; text-align: center; color: #9CA3AF;">
                    Good luck to all participants! 🍀
                </p>
            `;

            let successCount = 0;
            let failCount = 0;

            for (const doc of emailsSnapshot.docs) {
                const emailData = doc.data();
                try {
                    const mailOptions = {
                        from: process.env.EMAIL_FROM,
                        to: emailData.email,
                        subject: '🎉 Mi Keamcha Yisrael Raffle - Drawing Soon!',
                        html: getEmailTemplate('Raffle Drawing Announcement', content),
                    };

                    await transporter.sendMail(mailOptions);
                    successCount++;
                } catch (error) {
                    console.error(`Failed to send to ${emailData.email}:`, error);
                    failCount++;
                }
            }

            return res.status(200).json({ 
                success: true, 
                message: `Sent ${successCount} emails, ${failCount} failed.`,
                sent: successCount,
                failed: failCount
            });

        } catch (error) {
            console.error('Error sending drawing soon emails:', error);
            return res.status(500).json({ message: 'Failed to send emails.', error: error.message });
        }
    });
});

/**
 * HTTP Endpoint to send "Tickets Running Out" email to all subscribers
 */
exports.sendTicketsRunningOutEmailHttp = functions.runWith({ runtime: 'nodejs20' }).https.onRequest((req, res) => {
    corsHandler(req, res, async () => {
        if (req.method !== 'POST') {
            return res.status(405).send({ message: 'Method Not Allowed. Use POST.' });
        }

        try {
            // Verify admin authorization
            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ message: 'Unauthorized.' });
            }

            const idToken = authHeader.slice(7);
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            const userRecord = await admin.auth().getUser(decodedToken.uid);
            const isAdminUser = userRecord.customClaims && (userRecord.customClaims.admin === true || userRecord.customClaims.superAdmin === true);

            if (!isAdminUser) {
                return res.status(403).json({ message: 'Forbidden.' });
            }

            const db = admin.firestore();
            
            // Calculate tickets left
            const ticketsSnapshot = await db.collection('spin_tickets')
                .where('status', 'in', ['paid', 'claimed'])
                .get();
            
            const ticketsLeft = 500 - ticketsSnapshot.size;

            const emailsSnapshot = await db.collection('emails')
                .where('subscribed', '==', true)
                .get();

            const content = `
                <p>Don't miss your chance to win amazing prizes!</p>
                
                <div class="highlight-box">
                    <p class="label">Tickets Remaining</p>
                    <p class="ticket-number">${ticketsLeft}</p>
                    <div class="divider"></div>
                    <h2 style="margin: 10px 0; font-size: 28px; color: #ef4444;">⚠️ RUNNING OUT FAST!</h2>
                </div>

                <p>Only <strong style="color: #C9A961;">${ticketsLeft} tickets</strong> remain in our raffle. Once they're gone, they're gone for good!</p>

                <h2>Amazing Prizes:</h2>
                <div class="info-row">
                    🏆 <strong>1st Prize:</strong> Oyster Perpetual Datejust ($16.5K Value)
                </div>
                <div class="info-row">
                    🌴 <strong>2nd Prize:</strong> Surfside Florida Getaway
                </div>
                <div class="info-row">
                    💵 <strong>3rd Prize:</strong> $2,000 Cash
                </div>
                <div class="info-row">
                    💵 <strong>4th Prize:</strong> $1,000 Cash
                </div>

                <div style="text-align: center; margin-top: 30px;">
                    <a href="https://mi-keamcha-yisrael.web.app" class="button">Get Your Ticket Now!</a>
                </div>

                <p style="margin-top: 30px; text-align: center; color: #9CA3AF;">
                    Act fast before all ${ticketsLeft} remaining tickets are sold! 🎟️
                </p>
            `;

            let successCount = 0;
            let failCount = 0;

            for (const doc of emailsSnapshot.docs) {
                const emailData = doc.data();
                try {
                    const mailOptions = {
                        from: process.env.EMAIL_FROM,
                        to: emailData.email,
                        subject: `⚠️ Only ${ticketsLeft} Tickets Left - Mi Keamcha Yisrael Raffle!`,
                        html: getEmailTemplate('Limited Tickets Remaining', content),
                    };

                    await transporter.sendMail(mailOptions);
                    successCount++;
                } catch (error) {
                    console.error(`Failed to send to ${emailData.email}:`, error);
                    failCount++;
                }
            }

            return res.status(200).json({ 
                success: true, 
                message: `Sent ${successCount} emails about ${ticketsLeft} tickets left. ${failCount} failed.`,
                sent: successCount,
                failed: failCount,
                ticketsLeft: ticketsLeft
            });

        } catch (error) {
            console.error('Error sending tickets running out emails:', error);
            return res.status(500).json({ message: 'Failed to send emails.', error: error.message });
        }
    });
});

