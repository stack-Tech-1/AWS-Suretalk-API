const AWS = require('aws-sdk');
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs'); 
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const dns = require('dns').promises;
const sanitizeHtml = require('sanitize-html');
const nodemailer = require('nodemailer');
const winston = require('winston');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { OAuth2Client } = require('google-auth-library');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const price_id = process.env.STRIPE_PRICE_ID;
const bodyParser = require('body-parser');
const Twilio = require('twilio');
const twilio = require('twilio');




// ==================== Initialize Express ====================
const app = express();


const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY,
  secretAccessKey: process.env.AWS_SECRET_KEY,
  region: process.env.AWS_REGION
});
const uploadToS3 = async (filePath, s3Key) => {
  const fileContent = fs.readFileSync(filePath);
  const uploadParams = {
    Bucket: process.env.S3_BUCKET_NAME,
    Key: s3Key,
    Body: fileContent,
    ContentType: 'audio/mpeg'
  };

  try {
    // 1. Upload the file
    await s3.upload(uploadParams).promise();
    
    // 2. Generate presigned URL (valid for 7 days)
    const url = s3.getSignedUrl('getObject', {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: s3Key,
      Expires: 604800 // 7 days in seconds
    });
    
    logger.info('File uploaded and presigned URL generated', {
      bucket: process.env.S3_BUCKET_NAME,
      key: s3Key,
      url: url // Log truncated URL for security
    });
    
    return url;
    
  } catch (error) {
    logger.error('S3 Upload Failed', {
      error: error.message,
      stack: error.stack,
      params: {
        Bucket: uploadParams.Bucket,
        Key: uploadParams.Key,
        ContentType: uploadParams.ContentType
      }
    });
    throw error;
  }
};

const {
  DynamoDBClient
} = require('@aws-sdk/client-dynamodb');

const {
  DynamoDBDocumentClient,
  PutCommand,
  GetCommand,
  QueryCommand,
  UpdateCommand,
  DeleteCommand
} = require('@aws-sdk/lib-dynamodb');

const dynamo = DynamoDBDocumentClient.from(new DynamoDBClient({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY,
    secretAccessKey: process.env.AWS_SECRET_KEY
  }
}));



// ==================== Logger Configuration ====================
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});


// ==================== Security Middlewares ====================
app.use(helmet());
app.set('trust proxy', 1);

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false
});


// ==================== Stripe functions ====================
app.post('/api/stripe-webhook', 
  express.raw({ type: 'application/json' }),
  async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!sig) {
      logger.error('Missing Stripe-Signature header');
      return res.status(400).json({ error: 'Missing signature header' });
    }
    
    if (!webhookSecret) {
      logger.error('Missing STRIPE_WEBHOOK_SECRET');
      return res.status(500).json({ error: 'Server misconfigured' });
    }

    let event;
    try {
      console.log('[Stripe Hook] Is Buffer:', Buffer.isBuffer(req.body));
      console.log('[Stripe Hook] Raw Body Type:', typeof req.body);
      event = stripe.webhooks.constructEvent(
        req.body, 
        sig,
        webhookSecret
      );
      logger.info(`Stripe webhook received: ${event.type}`);
    } catch (err) {
      logger.error('Stripe webhook verification failed', { error: err.message });
      return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    try {
      switch (event.type) {
        case 'invoice.paid':
          await handlePaymentSuccess(event.data.object);
          break;
          
        case 'invoice.payment_failed':
          await handlePaymentFailure(event.data.object);
          break;
          
        case 'customer.subscription.deleted':
        case 'customer.subscription.updated':
          await handleSubscriptionChange(event.data.object);
          break;
          
        default:
          logger.debug(`Unhandled event type: ${event.type}`);
      }
      res.status(200).json({ received: true });
    } catch (error) {
      logger.error('Webhook processing failed', { error: error.message });
      res.status(500).json({ error: 'Processing failed' });
    }
  }
);

      //console.log('[Stripe Hook] Headers:', req.headers);
      //console.log('[Stripe Hook] Raw body type:', typeof req.body);

// ==================== Helper Functions ====================

async function handleSubscriptionChange(subscription) {
  try {
    const customer = await stripe.customers.retrieve(subscription.customer);
    const user = await findUserRef(subscription, customer);
    
    if (!user) {
      logger.warn('No matching user found for subscription', {
        subscriptionId: subscription.id,
        customerId: subscription.customer
      });
      return;
    }

    const subscriptionData = {
      stripeSubscriptionId: subscription.id,
      subscriptionStatus: subscription.status,
      plan: subscription.items?.data[0]?.plan?.nickname || 'Unknown Plan',
      currentPeriodEnd: subscription.current_period_end 
        ? new Date(subscription.current_period_end * 1000).toISOString()
        : null,
      updatedAt: new Date().toISOString(),
      verified: ['active', 'trialing'].includes(subscription.status)
    };

    await dynamo.send(new UpdateCommand({
      TableName: 'Users',
      Key: { userId: user.userId },
      UpdateExpression: 'SET ' + Object.keys(subscriptionData)
        .map(k => `${k} = :${k}`)
        .join(', '),
      ExpressionAttributeValues: Object.fromEntries(
        Object.entries(subscriptionData).map(([k, v]) => [`:${k}`, v])
    )}));

    if (['canceled', 'unpaid', 'past_due'].includes(subscription.status)) {
      await sendDiscontinuationEmail(user.email, user.firstName || 'Customer');
    }

    if (subscription.status === 'canceled') {
      await sendSubscriptionEndNotification(user.userId);
    }

  } catch (error) {
    logger.error('Failed to process subscription change', error);
    throw error;
  }
}


// Optional notification function
async function sendSubscriptionEndNotification(userId) {
  if (process.env.SEND_SUBSCRIPTION_EMAILS !== 'true') return;
  
  try {
    const { Item: user } = await dynamo.send(new GetCommand({
      TableName: 'Users',
      Key: { userId }
    }));
    
    if (user?.email) {
      await transporter.sendMail({
        from: `"SureTalk Support" <${process.env.EMAIL_USER}>`,
        to: user.email,
        subject: 'Your Subscription Has Ended',
        html: `<h2>Subscription Update</h2>
          <p>Your SureTalk subscription has ended.</p>
          <a href="${process.env.FRONTEND_URL}/resubscribe" style="...">
            Renew Your Subscription
          </a>`
      });
    }
  } catch (error) {
    logger.error('Failed to send subscription end notification', { userId, error });
  }
}



async function handlePaymentSuccess(invoice) {
  const customer = await stripe.customers.retrieve(invoice.customer);
  const user = await findUserRef(invoice, customer);
  
  if (!user) {
    logger.warn('No matching user found for payment', {
      invoiceId: invoice.id,
      customer: customer.id
    });
    return;
  }

  await dynamo.send(new UpdateCommand({
    TableName: 'Users',
    Key: { userId: user.userId },
    UpdateExpression: 'SET verified = :v, lastPaymentDate = :lpd, subscriptionStatus = :ss, stripeCustomerId = :scid',
    ExpressionAttributeValues: {
      ':v': true,
      ':lpd': new Date().toISOString(),
      ':ss': 'active',
      ':scid': customer.id
    }
  }));
  
  logger.info(`User verified via payment: ${user.userId}`);
}


async function handlePaymentFailure(invoice) {
  const customer = await stripe.customers.retrieve(invoice.customer);
  const user = await findUserRef(invoice, customer);
  
  if (user) {
    await dynamo.send(new UpdateCommand({
      TableName: 'Users',
      Key: { userId: user.userId },
      UpdateExpression: 'SET lastPaymentFailed = :lpf, paymentFailureDate = :pfd',
      ExpressionAttributeValues: {
        ':lpf': true,
        ':pfd': new Date().toISOString()
      }
    }));
  }
}



async function findUserRef(stripeObject, customer) {
  // 1. Try metadata first
  if (stripeObject.metadata?.userId) {
    const { Item: user } = await dynamo.send(new GetCommand({
      TableName: 'Users',
      Key: { userId: stripeObject.metadata.userId }
    }));
    if (user) return user;
  }
  
  // 2. Try email lookup
  if (customer.email) {
    const result = await dynamo.send(new QueryCommand({
      TableName: 'Users',
      IndexName: 'email-index',
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: { ':email': customer.email },
      Limit: 1
    }));
    
    if (result.Items && result.Items.length > 0) {
      return result.Items[0];
    }
  }
  
  // 3. Try phone lookup
  if (customer.phone) {
    const result = await dynamo.send(new QueryCommand({
      TableName: 'Users',
      IndexName: 'phone-index',
      KeyConditionExpression: 'phone = :phone',
      ExpressionAttributeValues: {
        ':phone': customer.phone.replace(/\D/g, '')
      },
      Limit: 1
    }));
    
    if (result.Items?.length > 0) {
      return result.Items[0];
    }    
  }
  
  return null;
}



// ==================== CORS Configuration ====================
const allowedOrigins = [
  'http://51.20.70.31:10000',
  'http://51.20.142.251:10000',
  'http://sign-in.suretalknow.com',
  'http://api.suretalknow.com'    
];


const corsOptions = {
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  exposedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  optionsSuccessStatus: 200 
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
app.use(express.json());


// ==================== Email Configuration ====================
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  },
  logger: true,
  debug: true
});


// ==================== Twilio Configuration ====================
if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN) {
  logger.error("Missing Twilio credentials. Please check your environment variables.");
  process.exit(1);
}

const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);


// ==================== Helper Functions ====================
const disposableDomains = process.env.DISPOSABLE_DOMAINS?.split(',') || [
  'tempmail.com', 
  'mailinator.com'
];

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const isDisposableEmail = (email) => {
  const domain = email.split('@')[1];
  return disposableDomains.includes(domain);
};

const isDomainValid = async (email) => {
  try {
    await dns.resolveMx(email.split('@')[1]);
    return true;
  } catch {
    return false;
  }
};

const generateUserId = () => crypto.randomBytes(16).toString('hex');

const generateToken = () => crypto.randomBytes(32).toString('hex');

// ==================== Email Verification Functions ====================
const sendVerificationEmail = async (email, userId) => {
  const token = generateToken();
  const expiresAt = new Date();
  expiresAt.setHours(expiresAt.getHours() + 24);

  await dynamo.send(new PutCommand({
    TableName: 'VerificationTokens',
    Item: {
      token,
      email,
      userId,
      expiresAt: expiresAt.toISOString(),
      used: false,
      type: 'email-verification',
      createdAt: new Date().toISOString()
    }
  }));
  
  const verificationLink = `${process.env.FRONTEND_URL}/confirm-email-link?token=${token}`;
  const subscriptionLink = "https://buy.stripe.com/test_6oU14pfj6cd457Rett8so00";   
  await transporter.sendMail({
    from: `"SureTalk" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Verify Your Email Address',
    html: `
      <h2>Welcome to SureTalk!</h2>
      <p>Please verify your email address to complete your registration:</p>
      <a href="${verificationLink}" style="...">Verify Email</a>      
      <p>This link expires in 24 hours.</p>
    `
  });
};

function generateAuthToken(userId) {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ==================== Routes ====================

// Check email availability
app.get('/api/check-email', async (req, res) => {
  const email = req.query.email?.toLowerCase().trim();
  if (!email) return res.status(400).json({ error: 'Email is required' });

  try {
    const result = await dynamo.send(new QueryCommand({
      TableName: 'Users',
      IndexName: 'email-index', // Assumes you created this
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: {
        ':email': email
      }
    }));

    if (result.Items.length > 0) {
      return res.status(409).json({ error: 'Email already in use' });
    }

    res.json({ available: true });
  } catch (err) {
    console.error('Email check failed', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Check userId availability
app.get('/api/check-userid', async (req, res) => {
  const userId = req.query.userId?.trim();
  if (!userId) return res.status(400).json({ error: 'User ID is required' });

  try {
    const result = await dynamo.send(new GetCommand({
      TableName: 'Users',
      Key: { userId } // Assumes userId is the primary key
    }));

    if (result.Item) {
      return res.status(409).json({ error: 'User ID already taken' });
    }

    res.json({ available: true });
  } catch (err) {
    console.error('User ID check failed', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});




// Function to generate a verification token
function generateVerificationToken(userId, email) {
  const token = crypto.randomBytes(32).toString('hex'); 
  return token;
}


// Signup Route
app.post('/api/signup', limiter, async (req, res) => {
  try {
    let { firstName, email, phone, userPin, userId, ...rest } = req.body;

    // Validation
    if (!firstName || !email || !phone || !userPin) {
      return res.status(400).json({ 
        error: 'Missing required fields',
        details: { requires: ['firstName', 'email', 'phone', 'userPin'] }
      });
    }

    const normalizedEmail = sanitizeHtml(email).toLowerCase().trim();

    if (!isValidEmail(normalizedEmail)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }

    if (isDisposableEmail(normalizedEmail)) {
      return res.status(400).json({ error: 'Disposable emails not allowed' });
    }

    if (!(await isDomainValid(normalizedEmail))) {
      return res.status(400).json({ error: 'Email domain does not exist' });
    }

    // Generate userId if not provided
    userId = userId || generateUserId();

    //console.log('Checking for email:', normalizedEmail);
    //console.log('Checking for userId:', userId);


    // Check for existing user
    await dynamo.send(new PutCommand({
      TableName: 'Users',
      Item: {
        userId,
        firstName: sanitizeHtml(firstName),
        email: normalizedEmail,
        phone: sanitizeHtml(phone),
        userPin: await bcrypt.hash(userPin, parseInt(process.env.BCRYPT_SALT_ROUNDS || 12)),
        isInterestedInPartnership: Boolean(rest.joinProgram),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        status: 'pending',
        verified: false,
        emailVerified: false,
        smsConsent: true
      }
    }));
    

    // Send verification email
    await sendVerificationEmail(normalizedEmail, userId);
    logger.info('User created and verification email sent', { userId, email: normalizedEmail });

    res.status(201).json({
      success: true,
      message: 'User created. Verification email sent.',
      userId
    });

  } catch (error) {
    logger.error('Signup failed', { error: error.message });
    res.status(500).json({ 
      error: 'Registration failed',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


// Service discontinuation email
const sendDiscontinuationEmail = async (email, firstName) => {
  try {
    await transporter.sendMail({
      from: `"SureTalk" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'We Miss You at SureTalk',
      html: `
        <h2>Hi ${firstName},</h2>
        <p>We noticed your SureTalk service has been discontinued.</p>
        <p>We'd love to have you back! Here's a special link to resubscribe:</p>
        <a href="https://buy.stripe.com/bIY1806DG7qw6uk144">Resubscribe to SureTalk</a>
        <p>If this was a mistake, please contact our support team.</p>
      `
    });
    logger.info('Discontinuation email sent', { email });
  } catch (error) {
    logger.error('Failed to send discontinuation email', { email, error });
  }
};





// Resend Verification Email Route
app.get('/api/resend-verification', async (req, res) => {
  const { email } = req.query;

  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }

  try {
    // Check if the user exists
    const result = await dynamo.send(new QueryCommand({
      TableName: 'Users',
      IndexName: 'email-index',
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: {
        ':email': email
      }
    }));
    
    if (!result.Items.length) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Assuming `userDoc` is a single document and we're accessing the first item
    const user = result.Items[0];
    const userId = user.userId;
    
      
    // Generate a new token using the defined function
    const token = generateVerificationToken(userId, email);

    //expiration date set to 24 hours from now
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
    
    // Store the token in DynamoDB
await dynamo.send(new PutCommand({
  TableName: 'VerificationTokens',
  Item: {
    token,
    userId,
    email,
    used: false,
    expiresAt: expiresAt.toISOString(),
    createdAt: new Date().toISOString()
  }
}));

    // Send the verification email again
    await sendVerificationEmail(email, userId, token);

    res.status(200).json({ message: 'Verification email resent successfully' });

  } catch (error) {
    logger.error('Resend verification failed', { error: error.message });
    res.status(500).json({ error: 'Failed to resend verification email' });
  }
});




const sendWelcomeEmail = async (email, firstName) => {
  try {
    await transporter.sendMail({
      from: `"SureTalk" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Welcome to SureTalk!',
      html: `
        <h2>Welcome to SureTalk, ${firstName}!</h2>
        <p>Thank you for joining our community.</p>
        <p>You can now complete your subscription to start using our services:</p>
        <a href="https://buy.stripe.com/bIY1806DG7qw6uk144">Complete Subscription</a>
        <p>If you have any questions, please reply to this email.</p>
      `
    });
  } catch (error) {
    logger.error('Failed to send welcome email', { email, error });
  }
};



// Email Verification Route
app.get('/api/verify-email', async (req, res) => {
  const { token } = req.query;

  try {
    // 1. Validate token exists
    const { Item: tokenData } = await dynamo.send(new GetCommand({
      TableName: 'VerificationTokens',
      Key: { token }
    }));
    
    if (!tokenData) {
      logger.error('Token not found in DynamoDB', { token });
      return res.redirect(`${process.env.FRONTEND_URL}/failedEmailVerification?error=invalid_token`);
    }
    
    // 2. Extract token data
    const userId = tokenData.userId;
    const email = tokenData.email;

    logger.info('Verification attempt started', { token, email, userId });

    if (tokenData.used) {
      logger.warn('Token already used', { token });
      return res.redirect(`${process.env.FRONTEND_URL}/failedEmailVerification?error=used_token`);
    }

    let expiresAt = tokenData.expiresAt;
    if (expiresAt?.toDate) expiresAt = expiresAt.toDate();
    if (new Date() > new Date(expiresAt)) {
      logger.warn('Token expired', { token, expiresAt });
      return res.redirect(`${process.env.FRONTEND_URL}/failedEmailVerification?error=expired_token`);
    }

    // 3. Verify user exists in DynamoDB
    const { Item: user } = await dynamo.send(new GetCommand({
      TableName: 'Users',
      Key: { userId }
    }));
    
    if (!user) {
      logger.error('User not found during verification', { userId });
      return res.redirect(`${process.env.FRONTEND_URL}/failedEmailVerification?error=user_not_found`);
    }

     // 4. Update records in DynamoDB
     await dynamo.send(new UpdateCommand({
      TableName: 'VerificationTokens',
      Key: { token },
      UpdateExpression: 'set #used = :used',
      ExpressionAttributeValues: {
        ':used': true
      },
      ExpressionAttributeNames: {
        '#used': 'used'
      }
    }));
    
    await dynamo.send(new UpdateCommand({
      TableName: 'Users',
      Key: { userId },
      UpdateExpression: 'set emailVerified = :ev, #st = :status, updatedAt = :updatedAt',
      ExpressionAttributeValues: {
        ':ev': true,
        ':status': 'active',
        ':updatedAt': new Date().toISOString()
      },
      ExpressionAttributeNames: {
        '#st': 'status'
      }
    }));

    logger.info('Email verification successful', { userId, email });

    // 5. Send welcome email
    await sendWelcomeEmail(user.email, user.firstName);

    // 6. Respond with success page
    res.setHeader('Content-Type', 'text/html');
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Email Verified</title>
        <style>
          body { 
            font-family: Arial, sans-serif; 
            text-align: center; 
            padding: 50px;
            background-color: #f5f5f5;
          }
          .container { 
            max-width: 500px; 
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          }
          h1 { 
            color: #28a745; 
            margin-bottom: 20px;
          }
          p {
            margin-bottom: 15px;
            line-height: 1.5;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Email Verified Successfully!</h1>
          <p>Thank you for verifying your email address. Please check your email for the subscription link.</p>
          <p>You can now close this window.</p>
        </div>
      </body>
      </html>
    `);

  } catch (error) {
    logger.error('Verification failed', {
      message: error.message,
      stack: error.stack,
      token: token
    });    
    return res.redirect(`${process.env.FRONTEND_URL}/failedEmailVerification`);
  }
});


// ==================== Login Route ====================
// Login Endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user by email - NEEDS MIGRATION
    const result = await dynamo.send(new QueryCommand({
      TableName: 'Users',
      IndexName: 'email-index',
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: { ':email': email },
      Limit: 1
    }));

    if (!result.Items || result.Items.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.Items[0];
    
    if (!user.emailVerified) {
      return res.status(403).json({ error: 'Email not verified' });
    }
    
    const validPassword = await bcrypt.compare(password, user.userPin);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate token with userId
    const token = generateAuthToken(user.userId);
    res.json({ 
      token,
      userId: user.userId,
      firstName: user.firstName,
      email: user.email
    });
  } catch (error) {
    logger.error('Login failed', { error });
    res.status(500).json({ error: 'Login failed' });
  }
});

// ==================== Account Recovery Endpoints ====================

// Request recovery - Fixed Version
app.post('/api/request-recovery', limiter, async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        status: 'error',
        error: 'Email is required',
        code: 'MISSING_EMAIL'
      });
    }

    const normalizedEmail = sanitizeHtml(email).toLowerCase().trim();

    // Check if user exists in DynamoDB
    const result = await dynamo.send(new QueryCommand({
      TableName: 'Users',
      IndexName: 'email-index',
      KeyConditionExpression: 'email = :email',
      ExpressionAttributeValues: { ':email': normalizedEmail },
      Limit: 1
    }));

    if (!result.Items || result.Items.length === 0) {
      return res.status(404).json({ 
        status: 'error',
        error: 'No account found with this email',
        code: 'USER_NOT_FOUND'
      });
    }

    const user = result.Items[0];
    const recoveryToken = generateToken();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 1);

    // Save recovery token in DynamoDB
    await dynamo.send(new PutCommand({
      TableName: 'VerificationTokens',
      Item: {
        token: recoveryToken,
        email: normalizedEmail,
        userId: user.userId,
        expiresAt: expiresAt.toISOString(),
        used: false,
        type: 'account-recovery',
        createdAt: new Date().toISOString()
      }
    }));

    // Send recovery email
    const recoveryLink = `${process.env.FRONTEND_URL}/recover-account?token=${recoveryToken}`;
    
    await transporter.sendMail({
      from: `"SureTalk Support" <${process.env.EMAIL_USER}>`,
      to: normalizedEmail,
      subject: 'Account Recovery Request',
      html: `
        <p>We received a request to recover your account information.</p>
        <p>Click the link below to view your User ID and PIN (valid for 1 hour):</p>
        <a href="${recoveryLink}">Recover Account</a>
        <p>If you didn't request this, please ignore this email.</p>
      `
    });

    res.status(200).json({ 
      status: 'success',
      message: 'Recovery email sent. Please check your inbox.',
      data: {
        email: normalizedEmail,
        timestamp: new Date().toISOString()
      }
    });

  } catch (error) {
    logger.error('Recovery request failed', { 
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ 
      status: 'error',
      error: 'Account recovery failed',
      code: 'SERVER_ERROR',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Complete recovery - Fixed Version
app.post('/api/complete-recovery', limiter, async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ error: 'Recovery token is required' });
    }

    // Get token from DynamoDB
    const { Item: tokenData } = await dynamo.send(new GetCommand({
      TableName: 'VerificationTokens',
      Key: { token }
    }));

    if (!tokenData) {
      return res.status(404).json({ error: 'Invalid or expired recovery link' });
    }

    // Check token status
    if (tokenData.used) {
      return res.status(400).json({ error: 'This recovery link has already been used' });
    }

    if (new Date() > new Date(tokenData.expiresAt)) {
      return res.status(400).json({ error: 'This recovery link has expired' });
    }

    // Get user data
    const { Item: user } = await dynamo.send(new GetCommand({
      TableName: 'Users',
      Key: { userId: tokenData.userId }
    }));

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Generate 4-digit temporary PIN
    const tempPin = Math.floor(1000 + Math.random() * 9000).toString();
    const tempPinExpiry = new Date();
    tempPinExpiry.setHours(tempPinExpiry.getHours() + 1);

    // Update records in DynamoDB
    await dynamo.send(new UpdateCommand({
      TableName: 'VerificationTokens',
      Key: { token },
      UpdateExpression: 'set #used = :used',
      ExpressionAttributeValues: { ':used': true },
      ExpressionAttributeNames: { '#used': 'used' }
    }));

    await dynamo.send(new UpdateCommand({
      TableName: 'Users',
      Key: { userId: tokenData.userId },
      UpdateExpression: 'set tempPin = :tp, tempPinExpiry = :tpe, requiresPinReset = :rpr',
      ExpressionAttributeValues: {
        ':tp': await bcrypt.hash(tempPin, 12),
        ':tpe': tempPinExpiry.toISOString(),
        ':rpr': true
      }
    }));

    // Send email with User ID + Temporary PIN
    await transporter.sendMail({
      from: `"SureTalk Support" <${process.env.EMAIL_USER}>`,
      to: tokenData.email,
      subject: 'Your Temporary Access Details',
      html: `
        <p>Here are your temporary access details:</p>
        <p><strong>User ID:</strong> ${user.userId}</p>  
        <p><strong>Temporary PIN:</strong> ${tempPin}</p>
        <p>This PIN will expire in 1 hour. You will be required to set a new PIN after login.</p>
        <p>If you didn't request this, please contact our support team immediately.</p>
      `
    });

    res.json({ 
      success: true, 
      message: 'Temporary access details have been sent to your email' 
    });

  } catch (error) {
    logger.error('Recovery completion failed', { error });
    res.status(500).json({ error: 'Failed to complete account recovery' });
  }
});




// ==================== Twilio Recording Routes ====================
app.post('/api/fetch-recording', limiter, async (req, res, next) => {
  logger.info("Incoming recording fetch request", { body: req.body });

  const { RECORDING_URL } = req.body;
  if (!RECORDING_URL) {
      return res.status(400).json({ error: 'Missing RECORDING_URL parameter' });
  }

  const match = RECORDING_URL.match(/Recordings\/(RE[a-zA-Z0-9]+)/);
  if (!match) {
      return res.status(400).json({ error: 'Invalid RECORDING_URL format' });
  }

  const recordingSid = match[1];
  logger.info("Extracted Recording SID", { recordingSid });

  try {
      // Fetch recording details
      const recording = await twilioClient.recordings(recordingSid).fetch();
      logger.info("Recording data fetched", { recording });

      const mediaUrl = `https://api.twilio.com${recording.uri.replace('.json', '.mp3')}`;
      logger.info("Downloading recording", { mediaUrl });

      // Download the file
      const response = await axios({
          method: 'GET',
          url: mediaUrl,
          responseType: 'stream',
          auth: {
              username: process.env.TWILIO_ACCOUNT_SID, 
              password: process.env.TWILIO_AUTH_TOKEN
          }
      });

      const tempFilePath = path.join(__dirname, 'suretalk-voicenotes-prod', `${recordingSid}.mp3`);
      
      // Ensure directory exists
      if (!fs.existsSync(path.join(__dirname, 'suretalk-voicenotes-prod'))) {
          fs.mkdirSync(path.join(__dirname, 'suretalk-voicenotes-prod'));
      }

      const writer = fs.createWriteStream(tempFilePath);
      response.data.pipe(writer);

      return new Promise((resolve, reject) => {
          writer.on('finish', async () => {
              logger.info(`Recording saved temporarily`, { tempFilePath });

              try {
                const destination = `recordings/${recordingSid}.mp3`;
                const s3Url = await uploadToS3(tempFilePath, destination);
                logger.info("Recording uploaded to S3", { s3Url });
                                 
                  // Delete temp file
                  try {
                    fs.unlinkSync(tempFilePath);
                  } catch (err) {
                    logger.warn("Temp file already deleted or missing", { path: tempFilePath });
                  }                

                  // Return S3 URL
                  res.json({
                      success: true,
                      message: "Recording uploaded successfully",
                      recordingSid: recordingSid,
                      s3Url: s3Url
                  });
                  resolve();
              } catch (uploadError) {
                  logger.error("Error uploading file to S3", { error: uploadError });
                  reject(uploadError);
              }
          });

          writer.on('error', (err) => {
              logger.error("Error saving file", { error: err });
              reject(err);
          });
      });

  } catch (error) {
      logger.error("Error processing recording", { 
          error: error.message, 
          stack: error.stack,
          recordingSid: recordingSid 
      });
      res.status(500).json({ 
          error: "Failed to process recording",
          details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
  }
});




// ===================code to use token from Twilio=======================
app.post('/api/subscribe-user', async (req, res) => {
  const { paymentToken, userId, token } = req.body;

  if (!token || token !== process.env.TWILIO_SECRET_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized access' });
  }

  try {
    // 1. Create a new customer and attach the payment token as their default payment method
    const customer = await stripe.customers.create({
      payment_method: paymentToken,
      invoice_settings: { default_payment_method: paymentToken }
    });

    // 2. Create subscription
    const subscription = await stripe.subscriptions.create({
      customer: customer.id,
      items: [{ price: process.env.STRIPE_MONTHLY_PRICE_ID }],
      expand: ['latest_invoice.payment_intent']
    });

    // 3. Update dynamoDB with subscription details    
    await dynamo.send(new UpdateCommand({
      TableName: 'Users',
      Key: { userId },
      UpdateExpression: `
        SET verified = :v,
            stripeCustomerId = :scid,
            subscriptionId = :subid,
            subscriptionStatus = :status,
            updatedAt = :updatedAt
      `,
      ExpressionAttributeValues: {
        ':v': true,
        ':scid': customer.id,
        ':subid': subscription.id,
        ':status': 'active',
        ':updatedAt': new Date().toISOString()
      }
    }));
    
    res.status(200).json({ success: true });

  } catch (err) {
    logger.error('Failed to subscribe user via token', { error: err.message });
    res.status(500).json({ error: 'Subscription setup failed', details: err.message });
  }
});

// Verify environment variables
const requiredVars = ['STRIPE_SECRET_KEY', 'TWILIO_ACCOUNT_SID', 'STUDIO_FLOW_SID'];
for (const varName of requiredVars) {
  if (!process.env[varName]) {
    console.error(`❌ Missing required environment variable: ${varName}`);
    process.exit(1);
  }
}

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Twilio endpoint
app.post('/twilio-payment-handler', (req, res) => {
  try {
    const twiml = new Twilio.twiml.VoiceResponse();
    
    twiml.say("We are saving your card for future monthly payments.");
    twiml.pay({
      paymentConnector: "Stripe_Connector_2",
      tokenType: "payment-method",
      postalCode: false,
      action: "http://51.20.142.251:10000/start-payment-setup" 
    });

    res.type('text/xml');
res.send(twiml.toString());
  } catch (err) {
    console.error('Twilio handler error:', err);
    res.status(500).send('Server error');
  }
});

// Payment processing endpoint
app.post('/start-payment-setup', async (req, res) => {
  try {
    console.log('Payment webhook received:', req.body);
    
    const { PaymentToken, Result, FlowSid, FlowExecutionSid } = req.body;
    
    if (Result !== 'success' || !PaymentToken) {
      throw new Error(`Payment failed - Result: ${Result}, Token: ${!!PaymentToken}`);
    }

    // Process Stripe subscription
    const customer = await stripe.customers.create();
    await stripe.paymentMethods.attach(PaymentToken, { customer: customer.id });
    await stripe.customers.update(customer.id, {
      invoice_settings: { default_payment_method: PaymentToken }
    });

    await stripe.subscriptions.create({
      customer: customer.id,
      items: [{ price: process.env.STRIPE_DEFAULT_PRICE_ID }],
      payment_settings: {
        payment_method_types: ['card'],
        save_default_payment_method: 'on_subscription'
      }
    });

    if (!process.env.STRIPE_DEFAULT_PRICE_ID) {
      throw new Error('STRIPE_DEFAULT_PRICE_ID is not defined in environment');
    }    

    console.log('✅ Subscription created for:', customer.id);

    // TwiML response
    const twiml = new Twilio.twiml.VoiceResponse();
    twiml.say("Thank you! Your payment was processed successfully.");
    
    // Use the FlowSid from the request if available, fallback to env var
    const flowSid = FlowSid || process.env.STUDIO_FLOW_SID;
    
    if (FlowExecutionSid) {
      // If we have execution context, use the execution-aware return URL
      twiml.redirect({
        method: 'POST'
      }, `https://webhooks.twilio.com/v1/Accounts/${process.env.TWILIO_ACCOUNT_SID}/Flows/${flowSid}/Executions/${FlowExecutionSid}`);
    } else {
      // Fallback to simple return (may not work as well)
      twiml.redirect({
        method: 'POST'
      }, `https://webhooks.twilio.com/v1/Accounts/${process.env.TWILIO_ACCOUNT_SID}/Flows/${flowSid}?FlowEvent=return`);
    }

    res.type('text/xml').send(twiml.toString());

  } catch (err) {
    console.error('❌ Payment processing failed:', err);
    res.type('text/xml').send(`
      <Response>
        <Say>Error: ${err.message.replace(/[^\w\s]/gi, '')}</Say>
        <Hangup/>
      </Response>
    `);
  }
});


// Error-handling middleware
app.use((err, req, res, next) => {
  logger.error("Unhandled error", { 
      error: err.message, 
      stack: err.stack,
      path: req.path,
      method: req.method
  });
  res.status(500).json({ 
      error: "Internal Server Error",
      details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});


// ==================== Server Startup ====================
const PORT = 10000; 
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Backend running on port ${PORT}`); 
});





// Created by: stacktechnologies
// Last Updated: 2025-04-10
// Project: SureTalk backend server







