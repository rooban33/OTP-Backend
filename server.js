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

// OTP Manager Class
class SecureOTPManager {
  constructor() {
    this.otpData = null;
    this.type1 = 0;
    this.generatedAt = null;
    this.attempts = 0;
    this.maxAttempts = 3;
    this.expiryMinutes = 5;
  }

  generateOTP(digitString, type1) {
    // Decode type1
    let v = type1;
    const getType = v % 10;
    v = Math.floor(v / 10);
    const formatType = v % 10;
    v = Math.floor(v / 10);
    const digits = v;

    console.log("Parsed -> Digits:", digits, "Format:", formatType, "Logic:", getType);

    // Step 1: Break digitString into pairs
    const pairs = [];
    for (let i = 0; i < digitString.length; i += 2) {
      pairs.push(digitString.slice(i, i + 2));
    }

    // Step 2: Reduce each pair to a single digit
    const singleDigits = pairs.map(pair => {
      let sum = parseInt(pair[0]) + parseInt(pair[1]);
      while (sum >= 10) {
        sum = Math.floor(sum / 10) + (sum % 10);
      }
      return sum;
    });

    // Step 3: Apply transformation logic
    let transformedDigits = [];

    switch (getType) {
      case 0: {
        let reversed = singleDigits.slice().reverse();
        const firstTwo = reversed.slice(0, 2);
        const remaining = reversed.slice(2);
        let shifted = remaining.concat(firstTwo);
        if (shifted.length > 3) [shifted[1], shifted[3]] = [shifted[3], shifted[1]];
        transformedDigits = shifted;
        break;
      }
      case 1: {
        const key = 'DECAF';
        const keyAscii = Array.from(key).map(c => c.charCodeAt(0));
        transformedDigits = singleDigits.map((digit, i) => digit & (keyAscii[i % keyAscii.length] % 10));
        break;
      }
      case 2: {
        transformedDigits = singleDigits.map(d => d >> 1);
        break;
      }
      case 3: {
        transformedDigits = singleDigits.map((d, i) => {
          let product = d * singleDigits[(i + 1) % singleDigits.length];
          while (product >= 10) {
            product = Math.floor(product / 10) + (product % 10);
          }
          return product;
        });
        break;
      }
      default: {
        transformedDigits = singleDigits.map((d, i) => {
          let product = d * singleDigits[(i - 1 + singleDigits.length) % singleDigits.length];
          while (product >= 10) {
            product = Math.floor(product / 10) + (product % 10);
          }
          return product;
        });
      }
    }

    // Step 4: Final digit-only OTP (trim or pad to exact 'digits' length)
    let digitOtp = transformedDigits.join('').slice(0, digits);
    if (digitOtp.length < digits) {
      // pad with repeating digits (from beginning)
      const pad = digitOtp.padEnd(digits, digitOtp[0]);
      digitOtp = pad.slice(0, digits);
    }

    // Step 5: Apply format type — ensure 1-to-1 mapping per digit
    let finalOtp = '';

    if (formatType === 0) {
      finalOtp = digitOtp;
    } else if (formatType === 1) {
      // Alphabetic: 0 → A, 1 → B, ..., 9 → J
      finalOtp = digitOtp.split('').map(d => String.fromCharCode('A'.charCodeAt(0) + parseInt(d))).join('');
    } else if (formatType === 2) {
      // Type 2 → Alphanumeric: Digit + Letter of Next Digit
      const chars = digitOtp.split('');
      let formatted = '';
      for (let i = 0; i < chars.length; i += 2) {
        formatted += chars[i]; // Keep digit
        if (i + 1 < chars.length) {
          const nextDigit = parseInt(chars[i + 1]);
          const letter = String.fromCharCode('A'.charCodeAt(0) + nextDigit);
          formatted += letter;
        }
      }
      finalOtp = formatted;
    } else if (formatType === 3) {
      // Type 3 → Complex: Digit + Letter + Special Symbol (3-char pattern)
      const specialChars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')'];
      const chars = digitOtp.split('');
      let formatted = '';

      for (let i = 0; i < chars.length; i += 3) {
        if (i < chars.length) {
          formatted += chars[i]; // digit
        }
        if (i + 1 < chars.length) {
          const d = parseInt(chars[i + 1]);
          formatted += String.fromCharCode('A'.charCodeAt(0) + d); // letter
        }
        if (i + 2 < chars.length) {
          const d = parseInt(chars[i + 2]);
          formatted += specialChars[d]; // symbol
        }
      }

      finalOtp = formatted;
    }

    console.log("Final OTP:", finalOtp);
    this.otpData = finalOtp;
    this.generatedAt = new Date();
    this.attempts = 0;
    return finalOtp;
  }

  verifyOTP(inputOTP) {
    if (!this.otpData) {
      return { success: false, message: 'No OTP generated' };
    }

    if (this.attempts >= this.maxAttempts) {
      this.clearOTP();
      return { success: false, message: 'Maximum attempts exceeded. Please generate a new OTP.' };
    }

    this.attempts++;

    if (this.otpData === inputOTP) {
      this.clearOTP();
      return { success: true, message: 'OTP verified successfully!' };
    } else {
      const remainingAttempts = this.maxAttempts - this.attempts;
      return {
        success: false,
        message: `Invalid OTP. ${remainingAttempts} attempts remaining.`
      };
    }
  }

  clearOTP() {
    this.otpData = null;
    this.generatedAt = null;
    this.attempts = 0;
  }
}

// QR Encoding Functions
const convertDigitsToAlphabets = (digitString) => {
  const digitToAlphabetMap = {
    '0': 'A', '1': 'B', '2': 'C', '3': 'D', '4': 'E',
    '5': 'F', '6': 'G', '7': 'H', '8': 'I', '9': 'J'
  };

  return digitString
    .split('')
    .map(digit => digitToAlphabetMap[digit])
    .join('');
};

const transformDigitsForQR = (digitString, type1) => {
  const generateRandomDigits = () => {
    return Math.floor(Math.random() * 900) + 100; // 3-digit random number
  };

  const first3 = digitString.slice(0, 3);
  const middle4 = digitString.slice(3, 7);
  const last3 = digitString.slice(7, 10);

  const random2 = generateRandomDigits().toString();

  const transformedData = last3 + type1.toString() + middle4 + random2 + first3;
  console.log("Transformed Data:", transformedData);
  return transformedData;
};

const completeTransformation = (digitString, type1) => {
  const transformedDigits = transformDigitsForQR(digitString, type1);
  const alphabetData = convertDigitsToAlphabets(transformedDigits);
  return { transformedDigits, alphabetData };
};

// Utility function to generate secret key
function generateSecretKey(phoneNumber) {
  const timestamp = Date.now().toString();
  const randomSalt = crypto.randomBytes(16).toString('hex');
  const combinedString = `${phoneNumber}-${timestamp}-${randomSalt}`;
  
  // Create a hash and encode it as base32 (common for OTP secrets)
  const hash = crypto.createHash('sha256').update(combinedString).digest('hex');
  return hash.substring(0, 32).toUpperCase(); // 32 character secret key
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

// NEW: Generate OTP with QR Encoding endpoint
app.post('/api/generate-otp', async (req, res) => {
  const { phoneNumber, secretKey } = req.body;
  
  try {
    // Validate input
    if (!phoneNumber || !secretKey) {
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
        message: 'Invalid authentication key. Please check your configuration.'
      });
    }
    
    const user = userResult.rows[0];
    
    // Check if user is active
    if (!user.is_active) {
      return res.status(403).json({
        success: false,
        message: 'User account is inactive. Please contact support.'
      });
    }
    
    // Check if user has remaining OTP requests
    const remainingRequests = user.otp_request_limit - user.otp_requests_used;
    
    if (remainingRequests <= 0) {
      return res.status(400).json({
        success: false,
        message: 'OTP request limit has been exhausted. Please contact support.'
      });
    }
    
    // Generate the type configuration based on your logic
    const type = user.otp_type;
    const digits = user.otp_digits;
    let formatCode = 0;

    if (type === 'numeric') formatCode = 1;
    else if (type === 'alphanumeric') formatCode = 2;
    else if (type === 'complex') formatCode = 3;

    const logicCode = Math.floor(Math.random() * 5);
    const finalType = digits * 100 + formatCode * 10 + logicCode;

    console.log('OTP Config → digits:', digits, 'format:', formatCode, 'logic:', logicCode, '→ type:', finalType);

    // Generate a 10-digit string for OTP generation
    const digitString = phoneNumber;
    
    // Create OTP manager instance
    const otpManager = new SecureOTPManager();
    
    // Generate OTP using your custom logic
    console.log("Number:",digitString);
    const generatedOTP = otpManager.generateOTP(digitString, finalType);
    
    // Generate QR encoding data
    const qrData = completeTransformation(digitString, finalType);
    
    // Update OTP usage count
    await pool.query(
      'UPDATE users SET otp_requests_used = otp_requests_used + 1 WHERE id = $1',
      [user.id]
    );
    
    // Store OTP session (you might want to store this in database for production)
    // For now, we'll just return the data
    
    res.json({
      success: true,
      message: 'OTP generated successfully',
      data: {
        otp: generatedOTP,
        otpType: user.otp_type,
        otpDigits: user.otp_digits,
        qrData: {
          transformedDigits: qrData.transformedDigits,
          alphabetData: qrData.alphabetData
        },
        remainingRequests: remainingRequests - 1,
        canGenerateOTP: (remainingRequests - 1) > 0,
        userId: user.id,
        fullName: user.full_name,
        phoneNumber: user.phone_number,
        email: user.email
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

// Verify OTP endpoint
app.post('/api/verify-otp', async (req, res) => {
  const { secretKey, otp } = req.body;
  
  try {
    // Validate input
    if (!secretKey || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Secret key and OTP are required'
      });
    }
    
    // Get user details by secret key
    const userResult = await pool.query(
      'SELECT id, full_name FROM users WHERE secret_key = $1 AND is_active = true',
      [secretKey]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Invalid secret key or user not found'
      });
    }
    
    const user = userResult.rows[0];
    
    // In a production environment, you would retrieve the stored OTP from database
    // For now, we'll create a simple verification (you should implement proper OTP storage)
    
    res.json({
      success: true,
      message: 'OTP verification endpoint ready',
      data: {
        userId: user.id,
        fullName: user.full_name,
        providedOTP: otp
      }
    });
    
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during OTP verification'
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
      updateFields.push(`otp_digits = $${paramIndex++}`);
      values.push(parseInt(otpDigits));
    }
    
    if (otpType !== undefined) {
      updateFields.push(`otp_type = $${paramIndex++}`);
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
      `UPDATE users SET ${updateFields.join(', ')} WHERE id = $${paramIndex} RETURNING otp_digits, otp_type`,
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

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Available endpoints:`);
  console.log(`- GET /api/health`);
  console.log(`- POST /api/register`);
  console.log(`- POST /api/check-otp-availability`);
  console.log(`- POST /api/generate-otp`);
  console.log(`- POST /api/verify-otp`);
  console.log(`- GET /api/user/:phoneNumber`);
  console.log(`- PUT /api/user/:userId/otp-settings`);
});

module.exports = app;