// server.js
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER || 'otp_user',
  host: process.env.DB_HOST || 'localhost',
  database: process.env.DB_NAME || 'otp_authenticator',
  password: process.env.DB_PASSWORD || 'your_secure_password',
  port: process.env.DB_PORT || 5432,
});

// Test database connection
pool.connect((err) => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Connected to PostgreSQL database');
  }
});

// Utility function to generate secret key
function generateSecretKey(phoneNumber) {
  const timestamp = Date.now().toString();
  const randomSalt = crypto.randomBytes(16).toString('hex');
  const combinedString = `${phoneNumber}-${timestamp}-${randomSalt}`;
  
  // Create a hash and encode it as base32 (common for OTP secrets)
  const hash = crypto.createHash('sha256').update(combinedString).digest('hex');
  return hash.substring(0, 32).toUpperCase(); // 32 character secret key
}

// Utility function to generate OTP based on type and digits
function generateOTP(type, digits) {
  const length = parseInt(digits);
  let charset = '';
  
  switch (type) {
    case 'alphabets':
      charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
      break;
    case 'numeric':
      charset = '0123456789';
      break;
    case 'alphanumeric':
      charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      break;
    case 'complex':
      charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
      break;
    default:
      charset = '0123456789';
  }
  
  let otp = '';
  for (let i = 0; i < length; i++) {
    otp += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  
  return otp;
}

// Enhanced validation middleware
const validateRegistration = (req, res, next) => {
  const { fullName, phoneNumber, email, otpDigits, otpType } = req.body;
  
  // Basic validation
  if (!fullName || !phoneNumber || !email) {
    return res.status(400).json({
      success: false,
      message: 'Full name, phone number, and email are required'
    });
  }
  
  // Phone number validation (basic)
  const phoneRegex = /^\+?[\d\s\-\(\)]{10,15}$/;
  if (!phoneRegex.test(phoneNumber)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid phone number format'
    });
  }
  
  // Email validation
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid email format'
    });
  }
  
  // OTP digits validation
  if (otpDigits && (otpDigits < 4 || otpDigits > 7)) {
    return res.status(400).json({
      success: false,
      message: 'OTP digits must be between 4 and 7'
    });
  }
  
  // OTP type validation
  const validOtpTypes = ['alphabets', 'numeric', 'alphanumeric', 'complex'];
  if (otpType && !validOtpTypes.includes(otpType)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid OTP type'
    });
  }
  
  next();
};

// Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'OTP Authenticator API is running' });
});

// User registration endpoint
app.post('/api/register', validateRegistration, async (req, res) => {
  const { 
    fullName, 
    phoneNumber, 
    email, 
    otpDigits = 6, 
    otpType = 'numeric' 
  } = req.body;
  
  try {
    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE phone_number = $1 OR email = $2',
      [phoneNumber, email]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'User with this phone number or email already exists'
      });
    }
    
    // Generate secret key
    const secretKey = generateSecretKey(phoneNumber);
    
    // Insert new user with OTP settings
    const result = await pool.query(
      `INSERT INTO users (full_name, phone_number, email, secret_key, otp_request_limit, otp_requests_used, otp_digits, otp_type) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
       RETURNING id, full_name, phone_number, email, secret_key, otp_request_limit, otp_digits, otp_type, created_at`,
      [fullName, phoneNumber, email, secretKey, 10, 0, parseInt(otpDigits), otpType]
    );
    
    const newUser = result.rows[0];
    
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      data: {
        userId: newUser.id,
        fullName: newUser.full_name,
        phoneNumber: newUser.phone_number,
        email: newUser.email,
        secretKey: newUser.secret_key,
        otpRequestLimit: newUser.otp_request_limit,
        otpDigits: newUser.otp_digits,
        otpType: newUser.otp_type,
        createdAt: newUser.created_at
      }
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during registration'
    });
  }
});

// Check OTP request availability by secret key endpoint
app.post('/api/check-otp-availability', async (req, res) => {
  const { secretKey } = req.body;
  
  try {
    // Validate input
    if (!secretKey) {
      return res.status(400).json({
        success: false,
        message: 'Secret key is required'
      });
    }
    
    // Get user details by secret key
    const userResult = await pool.query(
      `SELECT id, full_name, phone_number, email, otp_digits, otp_type, 
              otp_requests_used, otp_request_limit, is_active 
       FROM users 
       WHERE secret_key = $1`,
      [secretKey]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Invalid secret key or user not found'
      });
    }
    
    const user = userResult.rows[0];
    
    // Check if user is active
    if (!user.is_active) {
      return res.status(403).json({
        success: false,
        message: 'User account is inactive'
      });
    }
    
    // Check if user has remaining OTP requests
    const remainingRequests = user.otp_request_limit - user.otp_requests_used;
    
    if (remainingRequests <= 0) {
      return res.status(400).json({
        success: false,
        message: 'OTP request limit exhausted',
        data: {
          userId: user.id,
          otpRequestsUsed: user.otp_requests_used,
          otpRequestLimit: user.otp_request_limit,
          remainingRequests: 0,
          otpDigits: user.otp_digits,
          otpType: user.otp_type,
          canGenerateOTP: false
        }
      });
    }
    
    // Requests available - return OTP type details
    res.json({
      success: true,
      message: 'OTP requests available',
      data: {
        userId: user.id,
        fullName: user.full_name,
        phoneNumber: user.phone_number,
        email: user.email,
        otpType: user.otp_type,
        otpDigits: user.otp_digits,
        otpRequestsUsed: user.otp_requests_used,
        otpRequestLimit: user.otp_request_limit,
        remainingRequests: remainingRequests,
        canGenerateOTP: true
      }
    });
    
  } catch (error) {
    console.error('OTP availability check error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during OTP availability check'
    });
  }
});

// Generate OTP endpoint
app.post('/api/generate-otp/:userId', async (req, res) => {
  const { userId } = req.params;
  
  try {
    // Get user details including OTP settings
    const userResult = await pool.query(
      'SELECT otp_digits, otp_type, otp_requests_used, otp_request_limit FROM users WHERE id = $1 AND is_active = true',
      [userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found or inactive'
      });
    }
    
    const user = userResult.rows[0];
    
    // Check if user has remaining OTP requests
    if (user.otp_requests_used >= user.otp_request_limit) {
      return res.status(400).json({
        success: false,
        message: 'OTP request limit exceeded'
      });
    }
    
    // Generate OTP based on user settings
    const otp = generateOTP(user.otp_type, user.otp_digits);
    
    // Update OTP usage count
    await pool.query(
      'UPDATE users SET otp_requests_used = otp_requests_used + 1 WHERE id = $1',
      [userId]
    );
    
    res.json({
      success: true,
      data: {
        otp: otp,
        otpType: user.otp_type,
        otpDigits: user.otp_digits,
        remainingRequests: user.otp_request_limit - user.otp_requests_used - 1
      }
    });
    
  } catch (error) {
    console.error('OTP generation error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during OTP generation'
    });
  }
});

// Get user details endpoint (enhanced with OTP settings)
app.get('/api/user/:phoneNumber', async (req, res) => {
  const { phoneNumber } = req.params;
  
  try {
    const result = await pool.query(
      'SELECT id, full_name, phone_number, email, otp_request_limit, otp_requests_used, otp_digits, otp_type, is_active, created_at FROM users WHERE phone_number = $1',
      [phoneNumber]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    const user = result.rows[0];
    
    res.json({
      success: true,
      data: {
        id: user.id,
        fullName: user.full_name,
        phoneNumber: user.phone_number,
        email: user.email,
        otpRequestLimit: user.otp_request_limit,
        otpRequestsUsed: user.otp_requests_used,
        otpDigits: user.otp_digits,
        otpType: user.otp_type,
        isActive: user.is_active,
        createdAt: user.created_at,
        remainingRequests: user.otp_request_limit - user.otp_requests_used
      }
    });
    
  } catch (error) {
    console.error('User lookup error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update user OTP settings endpoint
app.put('/api/user/:userId/otp-settings', async (req, res) => {
  const { userId } = req.params;
  const { otpDigits, otpType } = req.body;
  
  try {
    // Validate input
    if (otpDigits && (otpDigits < 4 || otpDigits > 7)) {
      return res.status(400).json({
        success: false,
        message: 'OTP digits must be between 4 and 7'
      });
    }
    
    const validOtpTypes = ['alphabets', 'numeric', 'alphanumeric', 'complex'];
    if (otpType && !validOtpTypes.includes(otpType)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid OTP type'
      });
    }
    
    // Build update query dynamically
    const updateFields = [];
    const values = [];
    let paramIndex = 1;
    
    if (otpDigits !== undefined) {
      updateFields.push(`otp_digits = ${paramIndex++}`);
      values.push(parseInt(otpDigits));
    }
    
    if (otpType !== undefined) {
      updateFields.push(`otp_type = ${paramIndex++}`);
      values.push(otpType);
    }
    
    if (updateFields.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'No valid fields to update'
      });
    }
    
    values.push(userId);
    
    const result = await pool.query(
      `UPDATE users SET ${updateFields.join(', ')} WHERE id = ${paramIndex} RETURNING otp_digits, otp_type`,
      values
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }
    
    res.json({
      success: true,
      message: 'OTP settings updated successfully',
      data: {
        otpDigits: result.rows[0].otp_digits,
        otpType: result.rows[0].otp_type
      }
    });
    
  } catch (error) {
    console.error('OTP settings update error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get OTP statistics endpoint
app.get('/api/stats/otp-types', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        otp_type,
        otp_digits,
        COUNT(*) as user_count,
        AVG(otp_requests_used) as avg_requests_used
      FROM users 
      WHERE is_active = true
      GROUP BY otp_type, otp_digits
      ORDER BY otp_type, otp_digits
    `);
    
    res.json({
      success: true,
      data: result.rows
    });
    
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Increment OTP usage endpoint (enhanced)
app.post('/api/user/:userId/use-otp', async (req, res) => {
  const { userId } = req.params;
  
  try {
    const result = await pool.query(
      `UPDATE users 
       SET otp_requests_used = otp_requests_used + 1 
       WHERE id = $1 AND otp_requests_used < otp_request_limit AND is_active = true
       RETURNING otp_requests_used, otp_request_limit, otp_digits, otp_type`,
      [userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'OTP request limit exceeded, user not found, or user inactive'
      });
    }
    
    const user = result.rows[0];
    
    res.json({
      success: true,
      data: {
        otpRequestsUsed: user.otp_requests_used,
        otpRequestLimit: user.otp_request_limit,
        remainingRequests: user.otp_request_limit - user.otp_requests_used,
        otpDigits: user.otp_digits,
        otpType: user.otp_type
      }
    });
    
  } catch (error) {
    console.error('OTP usage error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Something went wrong!'
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found'
  });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Available endpoints:`);
  console.log(`- GET /api/health`);
  console.log(`- POST /api/register`);
  console.log(`- GET /api/user/:phoneNumber`);
  console.log(`- POST /api/generate-otp/:userId`);
  console.log(`- PUT /api/user/:userId/otp-settings`);
  console.log(`- GET /api/stats/otp-types`);
  console.log(`- POST /api/user/:userId/use-otp`);
});

module.exports = app;