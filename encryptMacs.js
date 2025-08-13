// encryptMacs.js
const crypto = require("crypto");
const fs = require("fs");

require("dotenv").config(); // Load SECRET_KEY and IV from .env

const SECRET_KEY = Buffer.from(process.env.SECRET_KEY, "hex");
const IV = Buffer.from(process.env.IV, "hex");

// Read MAC addresses from local file
const macs = JSON.parse(fs.readFileSync("allowedMacs.json", "utf8"));

// Encrypt
const cipher = crypto.createCipheriv("aes-256-cbc", SECRET_KEY, IV);
let encrypted = cipher.update(JSON.stringify(macs), "utf8", "hex");
encrypted += cipher.final("hex");

// Save encrypted file
fs.writeFileSync("allowedMacs.enc", encrypted);
console.log("MAC addresses encrypted and saved to allowedMacs.enc");


// const key = crypto.randomBytes(32).toString("hex"); // 32 bytes = 256-bit AES key
// const iv = crypto.randomBytes(16).toString("hex");  // 16 bytes = AES block size

// console.log("SECRET_KEY=", key);
// console.log("IV=", iv);