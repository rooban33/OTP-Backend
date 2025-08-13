// server.js
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const { Pool } = require('pg');
const { exec } = require('child_process');
const util = require('util');
require('dotenv').config();

const execAsync = util.promisify(exec);

const app = express();
const PORT = process.env.PORT || 3001;

// Allowed MAC addresses (whitelist)
const ALLOWED_MAC_ADDRESSES = [
  '10:A5:1D:7F:65:75',//Shajith
  '2C:33:58:89:76:05',//Raj
  'de:a1:79:ad:84:a8',//Babloo
  '3e:64:40:b5:1a:f8',//babloo2
  'C8:94:02:47:1E:65',//Allwin
  "92:35:61:70:4f:99",//Akash
  "28:c5:d2:2c:bb:f4",//Prgathy
  "d0:39:57:01:14:a7",//Manoj
  "dc:21:5c:da:b6:e6",//Varnasri
  "b4:8c:9d:2d:9a:6f",//Tarun
  "f2:ba:ab:59:52:14",//Akash2
  "14:13:33:72:f2:9f",//prasanna
  "4e:9a:c3:95:ce:38",//babloo lok
  '00:11:22:33:44:55',
  'aa:bb:cc:dd:ee:ff',
  '12:34:56:78:90:ab',
 '76:18:f4:5a:28:11' ,
 "50:c2:e8:17:9a:63",
 "cc:6b:1e:59:05:fd",
 "ee:14:fd:79:f6:a8",
 "c8:94:02:48:3b:af"

];

// Cross-platform MAC address retrieval function
const getMACAddress = async (ip) => {
  const cleanIP = ip.replace('::ffff:', '');
  let clientMAC = null;
  
  // Detect operating system
  const isWindows = process.platform === 'win32';
  const isLinux = process.platform === 'linux';
  const isMac = process.platform === 'darwin';
  
  try {
    if (isWindows) {
      // Windows commands
      try {
        // First try to ping to populate ARP table
        await execAsync(`ping -n 1 -w 1000 ${cleanIP} >nul 2>&1`);
        
        // Get ARP table on Windows
        const { stdout } = await execAsync(`arp -a ${cleanIP}`);
        const macMatch = stdout.match(/([0-9a-fA-F]{2}[-]){5}[0-9a-fA-F]{2}/i);
        if (macMatch) {
          clientMAC = macMatch[0].replace(/-/g, ':').toLowerCase();
        }
      } catch (error) {
        console.log('Windows ARP lookup failed:', error.message);
        
        // Alternative Windows method using netsh
        try {
          const { stdout } = await execAsync(`netsh interface ip show neighbors | findstr ${cleanIP}`);
          const macMatch = stdout.match(/([0-9a-fA-F]{2}[-]){5}[0-9a-fA-F]{2}/i);
          if (macMatch) {
            clientMAC = macMatch[0].replace(/-/g, ':').toLowerCase();
          }
        } catch (altError) {
          console.log('Alternative Windows method failed:', altError.message);
        }
      }
    } else if (isLinux || isMac) {
      // Linux/Mac commands
      try {
        // Try ping first to populate ARP table
        const pingCmd = isMac ? `ping -c 1 -W 1000 ${cleanIP}` : `ping -c 1 -W 1 ${cleanIP}`;
        await execAsync(`${pingCmd} > /dev/null 2>&1`);
        
        // Get ARP table
        const { stdout } = await execAsync(`arp -n ${cleanIP}`);
        const arpLines = stdout.split('\n');
        
        for (const line of arpLines) {
          if (line.includes(cleanIP)) {
            const parts = line.split(/\s+/);
            const macMatch = parts.find(part => /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/.test(part));
            if (macMatch) {
              clientMAC = macMatch.toLowerCase();
              break;
            }
          }
        }
      } catch (error) {
        console.log('Unix ARP lookup failed:', error.message);
        
        // Alternative method for Unix systems
        try {
          const { stdout } = await execAsync(`arp -a | grep ${cleanIP}`);
          const macMatch = stdout.match(/([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}/i);
          if (macMatch) {
            clientMAC = macMatch[0].toLowerCase();
          }
        } catch (altError) {
          console.log('Alternative Unix method failed:', altError.message);
        }
      }
    }
  } catch (error) {
    console.log('MAC address retrieval failed:', error.message);
  }
  
  return clientMAC;
};

// Simple MAC address firewall middleware
const macAddressFirewall = async (req, res, next) => {
  try {
    const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
    const cleanIP = clientIP.replace('::ffff:', '');
    
    // Skip firewall for health check and debug endpoints from localhost
    if(clientIP === '127.0.0.1')
        return next();
    if ((req.path === '/api/health' || req.path === '/api/debug/network-info' || req.path === '/api/admin/temp-allow-ip') && 
        (clientIP === '127.0.0.1' || clientIP === '::1' || clientIP === '::ffff:127.0.0.1')) {
      return next();
    }
    
    // Check for temporarily allowed IPs
    if (global.tempAllowedIPs && global.tempAllowedIPs.has(cleanIP)) {
      const expiryTime = global.tempAllowedIPs.get(cleanIP);
      if (Date.now() < expiryTime) {
        console.log(`✅ Temporary access granted for IP: ${clientIP}`);
        return next();
      } else {
        // Remove expired entry
        global.tempAllowedIPs.delete(cleanIP);
        console.log(`⏰ Temporary access expired for IP: ${clientIP}`);
      }
    }
    
    // Get MAC address using cross-platform method
    const clientMAC = await getMACAddress(clientIP);
    
    console.log(`Request from IP: ${clientIP}, MAC: ${clientMAC || 'Unknown'}`);
    
    // Check if MAC address is in allowed list
    if (clientMAC && ALLOWED_MAC_ADDRESSES.map(mac => mac.toLowerCase()).includes(clientMAC)) {
      console.log(`✅ Access granted for MAC: ${clientMAC}`);
      return next();
    }
    
    // Block request if MAC is not allowed or couldn't be determined
    console.log(`❌ Access denied for IP: ${clientIP}, MAC: ${clientMAC || 'Unknown'}`);
    
    return res.status(403).json({
      success: false,
      message: 'Access denied: Device not authorized',
      code: 'MAC_ADDRESS_NOT_ALLOWED',
      debug: {
        clientIP: clientIP,
        detectedMAC: clientMAC,
        platform: process.platform,
        hint: 'Use /api/debug/network-info from localhost to find your MAC address'
      }
    });
    
  } catch (error) {
    console.error('MAC firewall error:', error);
    // In case of firewall error, deny access for security
    return res.status(500).json({
      success: false,
      message: 'Security check failed',
      code: 'FIREWALL_ERROR'
    });
  }
};

// Middleware
app.use(cors());
app.use(express.json());

// Apply MAC address firewall to all routes
app.use(macAddressFirewall);

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
  
    // Step 1: Break digitString into 2-char pairs
    const pairs = [];
    for (let i = 0; i < digitString.length; i += 2) {
      pairs.push(digitString.slice(i, i + 2));
    }
  
    // Step 2: Reduce each pair to a single digit (digit sum reduction)
    const singleDigits = pairs.map(pair => {
      let sum = parseInt(pair[0]) + parseInt(pair[1]);
      while (sum >= 10) {
        sum = Math.floor(sum / 10) + (sum % 10);
      }
      return sum;
    });
  
    // Step 3: Transformation logic (getType)
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
  
    // Step 4: Create digitOtp and apply Flutter-style digit length logic
    let digitOtp = transformedDigits.join('');
  
    // Flutter-style digit adjustment
    if (digits === 4) {
      digitOtp = digitOtp.slice(0, -1);
    } else if (digits === 6) {
      const last = parseInt(digitOtp[digitOtp.length - 1]);
      digitOtp += (last >> 1).toString();
    } else if (digits === 7) {
      const last = parseInt(digitOtp[digitOtp.length - 1]);
      const s1 = last >> 1;
      const s2 = s1 >> 1;
      digitOtp += s1.toString() + s2.toString();
    }
  
    // Truncate to correct length: base digits + any appended shift
    digitOtp = digitOtp.slice(0, digits + (digits === 6 ? 1 : 0) + (digits === 7 ? 2 : 0));
  
    // Step 5: Apply format type
    let finalOtp = '';
  
    if (formatType === 0) {
      finalOtp = digitOtp;
    } else if (formatType === 1) {
      finalOtp = digitOtp.split('').map(d => String.fromCharCode('A'.charCodeAt(0) + parseInt(d))).join('');
    } else if (formatType === 2) {
      const chars = digitOtp.split('');
      let formatted = '';
      for (let i = 0; i < chars.length; i += 2) {
        formatted += chars[i]; // digit
        if (i + 1 < chars.length) {
          const nextDigit = parseInt(chars[i + 1]);
          formatted += String.fromCharCode('A'.charCodeAt(0) + nextDigit);
        }
      }
      finalOtp = formatted;
    } else if (formatType === 3) {
      const specialChars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')'];
      const chars = digitOtp.split('');
      let formatted = '';
      for (let i = 0; i < chars.length; i += 3) {
        if (i < chars.length) formatted += chars[i]; // digit
        if (i + 1 < chars.length) {
          const d = parseInt(chars[i + 1]);
          formatted += String.fromCharCode('A'.charCodeAt(0) + d); // letter
        }
        if (i + 2 < chars.length) {
          const d = parseInt(chars[i + 2]);
          formatted += specialChars[d]; // special char
        }
      }
      finalOtp = formatted;
    }
  
    // Optional tracking
    this.otpData = finalOtp;
    this.generatedAt = new Date();
    this.attempts = 0;

    console.log("Final OTP:",finalOtp);
  
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
  const validOtpTypes = ['alphabets', 'numeric', 'alphanumeric', 'complex', 'random_rotation'];
  if (otpType && !validOtpTypes.includes(otpType)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid OTP type'
    });
  }
  
  next();
};

// Debug endpoint to help identify MAC addresses (bypasses firewall)
app.get('/api/debug/network-info', async (req, res) => {
  try {
    const clientIP = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
    const cleanIP = clientIP.replace('::ffff:', '');
    
    // Get MAC address
    const clientMAC = await getMACAddress(clientIP);
    
    // Get full ARP table for debugging
    let arpTable = [];
    const isWindows = process.platform === 'win32';
    
    try {
      let stdout;
      if (isWindows) {
        const result = await execAsync('arp -a');
        stdout = result.stdout;
      } else {
        const result = await execAsync('arp -a');
        stdout = result.stdout;
      }
      
      // Parse ARP table
      const lines = stdout.split('\n');
      for (const line of lines) {
        const macMatch = line.match(/([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}/i);
        const ipMatch = line.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
        
        if (macMatch && ipMatch) {
          arpTable.push({
            ip: ipMatch[0],
            mac: macMatch[0].replace(/-/g, ':').toLowerCase()
          });
        }
      }
    } catch (error) {
      console.log('Could not retrieve ARP table:', error.message);
    }
    
    res.json({
      success: true,
      data: {
        clientIP: clientIP,
        cleanIP: cleanIP,
        detectedMAC: clientMAC,
        platform: process.platform,
        isAllowed: clientMAC ? ALLOWED_MAC_ADDRESSES.map(mac => mac.toLowerCase()).includes(clientMAC) : false,
        allowedMACs: ALLOWED_MAC_ADDRESSES,
        arpTable: arpTable.slice(0, 10), // Limit to first 10 entries
        timestamp: new Date().toISOString()
      }
    });
    
  } catch (error) {
    console.error('Network debug error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve network information',
      error: error.message
    });
  }
});

// Endpoint to temporarily allow an IP address (for initial setup)
app.post('/api/admin/temp-allow-ip', (req, res) => {
  const { ipAddress, duration = 300 } = req.body; // Default 5 minutes
  
  if (!ipAddress) {
    return res.status(400).json({
      success: false,
      message: 'IP address is required'
    });
  }
  
  // Store temporarily allowed IPs (in production, use Redis or database)
  if (!global.tempAllowedIPs) {
    global.tempAllowedIPs = new Map();
  }
  
  const expiryTime = Date.now() + (duration * 1000);
  global.tempAllowedIPs.set(ipAddress, expiryTime);
  
  // Clean up expired entries
  setTimeout(() => {
    if (global.tempAllowedIPs.has(ipAddress)) {
      global.tempAllowedIPs.delete(ipAddress);
      console.log(`Temporary access removed for IP: ${ipAddress}`);
    }
  }, duration * 1000);
  
  console.log(`Temporary access granted to IP: ${ipAddress} for ${duration} seconds`);
  
  res.json({
    success: true,
    message: `Temporary access granted for ${duration} seconds`,
    data: {
      ipAddress: ipAddress,
      expiresAt: new Date(expiryTime).toISOString(),
      duration: duration
    }
  });
});

// Routes
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'OTP Authenticator API with MAC firewall is running',
    platform: process.platform,
    timestamp: new Date().toISOString()
  });
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

    const rotationEnabled = otpType === 'random_rotation';
    const actualOtpType = rotationEnabled ? 'numeric' : otpType; 
    
    // Generate secret key
    const secretKey = generateSecretKey(phoneNumber);
    
    // Insert new user with OTP settings
    const result = await pool.query(
      `INSERT INTO users (full_name, phone_number, email, secret_key, otp_request_limit, otp_requests_used, otp_digits, otp_type, rotation_enabled, current_rotation_index) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
       RETURNING id, full_name, phone_number, email, secret_key, otp_request_limit, otp_digits, otp_type, rotation_enabled, created_at`,
      [fullName, phoneNumber, email, secretKey, 10, 0, parseInt(otpDigits), actualOtpType, rotationEnabled, 0]
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

// Transaction logging function
const logTransaction = async (userId, endpoint, requestData, responseData, statusCode, success, req) => {
  try {
    const ipAddress = req.ip || req.connection.remoteAddress || req.socket.remoteAddress;
    const userAgent = req.get('User-Agent') || 'Unknown';
    
    await pool.query(
      `INSERT INTO transactions (user_id, endpoint, request_data, response_data, status_code, success, ip_address, user_agent) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [userId, endpoint, requestData, responseData, statusCode, success, ipAddress, userAgent]
    );
  } catch (error) {
    console.error('Transaction logging error:', error);
    // Don't throw error to avoid breaking the main flow
  }
};

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
              otp_requests_used, otp_request_limit, is_active, rotation_enabled, current_rotation_index 
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
    let currentOtpType = user.otp_type;
    
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
    if (user.rotation_enabled) {
      const rotationTypes = ['numeric', 'alphabets', 'alphanumeric', 'complex'];
      const currentIndex = user.current_rotation_index;
      currentOtpType = rotationTypes[currentIndex];
      
      // Calculate next rotation index
      const nextIndex = (currentIndex + 1) % rotationTypes.length;
      
      // Update rotation index for next time
      await pool.query(
        'UPDATE users SET current_rotation_index = $1 WHERE id = $2',
        [nextIndex, user.id]
      );
    }
    await logTransaction(
      user.id, 
      'check-otp-availability', 
      { secretKey: secretKey.substring(0, 8) + '...' }, // Partial secret for security
      { canGenerateOTP: true, remainingRequests }, 
      200, 
      true, 
      req
    );
    // Requests available - return OTP type details
    res.json({
      success: true,
      message: 'OTP requests available',
      data: {
        userId: user.id,
        fullName: user.full_name,
        phoneNumber: user.phone_number,
        email: user.email,
        otpType: currentOtpType, // Use the rotated type
        otpDigits: user.otp_digits,
        otpRequestsUsed: user.otp_requests_used,
        otpRequestLimit: user.otp_request_limit,
        remainingRequests: remainingRequests,
        canGenerateOTP: true,
        rotationEnabled: user.rotation_enabled
      }
    });
    
  }  catch (error) {
    console.error('OTP availability check error:', error);
    await logTransaction(
      null, 
      'check-otp-availability', 
      { secretKey: secretKey ? secretKey.substring(0, 8) + '...' : null }, 
      { error: error.message }, 
      500, 
      false, 
      req
    );
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
              otp_requests_used, otp_request_limit, is_active, rotation_enabled, current_rotation_index 
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
    let currentOtpType = user.otp_type;
    
    // Use the same rotation logic as check-availability
    if (user.rotation_enabled) {
      const rotationTypes = ['numeric', 'alphabets', 'alphanumeric', 'complex'];
      const currentIndex = user.current_rotation_index;
      currentOtpType = rotationTypes[currentIndex];
      
      // Calculate next rotation index for next time
      const nextIndex = (currentIndex + 1) % rotationTypes.length;
      
      // Update rotation index for next OTP generation
      await pool.query(
        'UPDATE users SET current_rotation_index = $1 WHERE id = $2',
        [nextIndex, user.id]
      );
    }
    
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

    // Generate the type configuration based on currentOtpType (rotated type)
    const digits = user.otp_digits;
    let formatCode = 0;

    if (currentOtpType === 'alphabets') formatCode = 1;
    else if (currentOtpType === 'alphanumeric') formatCode = 2;
    else if (currentOtpType === 'complex') formatCode = 3;

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

    await logTransaction(
      user.id, 
      'generate-otp', 
      { phoneNumber, secretKey: secretKey.substring(0, 8) + '...' }, 
      { 
        otpGenerated: true, 
        otpType: currentOtpType, 
        otpDigits: user.otp_digits,
        remainingRequests: remainingRequests - 1 
      }, 
      200, 
      true, 
      req
    );
    
    res.json({
      success: true,
      message: 'OTP generated successfully',
      data: {
        otp: generatedOTP,
        otpType: currentOtpType, // Use the rotated type
        otpDigits: user.otp_digits,
        phoneNumber: phoneNumber,
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
    await logTransaction(
      null, 
      'generate-otp', 
      { phoneNumber, secretKey: secretKey ? secretKey.substring(0, 8) + '...' : null }, 
      { error: error.message }, 
      500, 
      false, 
      req
    );
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

// MAC address management endpoints
app.get('/api/admin/allowed-macs', (req, res) => {
  res.json({
    success: true,
    data: {
      allowedMacs: ALLOWED_MAC_ADDRESSES,
      count: ALLOWED_MAC_ADDRESSES.length
    }
  });
});

app.post('/api/admin/add-mac', (req, res) => {
  const { macAddress } = req.body;
  
  if (!macAddress) {
    return res.status(400).json({
      success: false,
      message: 'MAC address is required'
    });
  }
  
  // Validate MAC address format
  const macRegex = /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/;
  if (!macRegex.test(macAddress)) {
    return res.status(400).json({
      success: false,
      message: 'Invalid MAC address format. Use format: xx:xx:xx:xx:xx:xx'
    });
  }
  
  const normalizedMac = macAddress.toLowerCase();
  
  if (ALLOWED_MAC_ADDRESSES.map(mac => mac.toLowerCase()).includes(normalizedMac)) {
    return res.status(409).json({
      success: false,
      message: 'MAC address already exists in allowed list'
    });
  }
  
  ALLOWED_MAC_ADDRESSES.push(normalizedMac);
  
  res.json({
    success: true,
    message: 'MAC address added successfully',
    data: {
      addedMac: normalizedMac,
      allowedMacs: ALLOWED_MAC_ADDRESSES
    }
  });
});

app.delete('/api/admin/remove-mac', (req, res) => {
  const { macAddress } = req.body;
  
  if (!macAddress) {
    return res.status(400).json({
      success: false,
      message: 'MAC address is required'
    });
  }
  
  const normalizedMac = macAddress.toLowerCase();
  const index = ALLOWED_MAC_ADDRESSES.map(mac => mac.toLowerCase()).indexOf(normalizedMac);
  
  if (index === -1) {
    return res.status(404).json({
      success: false,
      message: 'MAC address not found in allowed list'
    });
  }
  
  ALLOWED_MAC_ADDRESSES.splice(index, 1);
  
  res.json({
    success: true,
    message: 'MAC address removed successfully',
    data: {
      removedMac: normalizedMac,
      allowedMacs: ALLOWED_MAC_ADDRESSES
    }
  });
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
  console.log(`MAC Address Firewall Active - Platform: ${process.platform}`);
  console.log(`Allowed MAC Addresses (${ALLOWED_MAC_ADDRESSES.length}):`);
  ALLOWED_MAC_ADDRESSES.forEach((mac, index) => {
    console.log(`  ${index + 1}. ${mac}`);
  });
  
  console.log(`\n🔧 Setup Help:`);
  console.log(`1. Visit http://localhost:${PORT}/api/debug/network-info to find your MAC address`);
  console.log(`2. Add your MAC address to ALLOWED_MAC_ADDRESSES array`);
  console.log(`3. Or use temporary access: POST /api/admin/temp-allow-ip with your IP`);
  
  console.log(`\n📋 Available endpoints:`);
  console.log(`- GET /api/health`);
  console.log(`- GET /api/debug/network-info (localhost only)`);
  console.log(`- POST /api/admin/temp-allow-ip (localhost only)`);
  console.log(`- POST /api/register`);
  console.log(`- POST /api/check-otp-availability`);
  console.log(`- POST /api/generate-otp`);
  console.log(`- POST /api/verify-otp`);
  console.log(`- GET /api/user/:phoneNumber`);
  console.log(`- PUT /api/user/:userId/otp-settings`);
  console.log(`\n🛡️ MAC Management endpoints:`);
  console.log(`- GET /api/admin/allowed-macs`);
  console.log(`- POST /api/admin/add-mac`);
  console.log(`- DELETE /api/admin/remove-mac`);
});

module.exports = app;