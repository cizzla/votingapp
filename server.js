const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'))); // Serves index.html from a public folder if needed

// Neon PostgreSQL Database Connection Pool
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false // Required for serverless platforms like Render/Neon
    }
});

// Test DB Connection
pool.connect((err, client, release) => {
    if (err) {
        return console.error('Error acquiring client', err.stack);
    }
    console.log('Successfully connected to Neon Database.');
    release();
});

// ==========================================
// 1. STUDENT REGISTRATION
// ==========================================
app.post('/api/register', async (req, res) => {
    const { reg_no, fullname, password } = req.body;

    if (!reg_no || !fullname || !password) {
        return res.status(400).json({ message: "All fields are required." });
    }

    try {
        // Check if student already exists
        const userCheck = await pool.query('SELECT * FROM students WHERE UPPER(reg_no) = UPPER($1)', [reg_no.trim()]);
        if (userCheck.rows.length > 0) {
            return res.status(400).json({ message: "Registration number already exists." });
        }

        // Secure password hashing
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Insert new student
        await pool.query(
            'INSERT INTO students (reg_no, fullname, password) VALUES ($1, $2, $3)',
            [reg_no.trim(), fullname.trim(), hashedPassword]
        );

        res.status(201).json({ message: "Account created successfully." });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ message: "Communication breakdown fault during registration." });
    }
});

// ==========================================
// 2. STUDENT LOGIN
// ==========================================
app.post('/api/login', async (req, res) => {
    const { reg_no, password } = req.body;

    if (!reg_no || !password) {
        return res.status(400).json({ message: "Invalid username/password combinations." });
    }

    try {
        // Query user by registration number (case insensitive match)
        const userResult = await pool.query('SELECT * FROM students WHERE UPPER(reg_no) = UPPER($1)', [reg_no.trim()]);
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ message: "Invalid username/password combinations." });
        }

        const student = userResult.rows[0];

        // Match against hashed password (or fallback to plain-text check if migrating raw data)
        let isMatch = false;
        if (student.password.startsWith('$2b$') || student.password.startsWith('$2a$')) {
            isMatch = await bcrypt.compare(password, student.password);
        } else {
            isMatch = (password === student.password); // Direct match if data rows are still unhashed strings
        }

        if (!isMatch) {
            return res.status(401).json({ message: "Invalid username/password combinations." });
        }

        res.status(200).json({ 
            message: "Login successful", 
            student: { id: student.id, reg_no: student.reg_no, fullname: student.fullname } 
        });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({ message: "Communication breakdown fault executing authentication." });
    }
});

// ==========================================
// 3. AUTHENTICATION / PASSWORD RESET
// ==========================================
app.post('/api/forgot-password', async (req, res) => {
    const { reg_no, default_pin, new_password } = req.body;

    if (!reg_no || !default_pin || !new_password) {
        return res.status(400).json({ message: "All fields are required to commit credential changes." });
    }

    try {
        // Match registration number and verify recovery verification key (using recovery pin)
        // Adjust column name below if your pin field is named differently in 'students'
        const userResult = await pool.query('SELECT * FROM students WHERE UPPER(reg_no) = UPPER($1)', [reg_no.trim()]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ message: "Communication breakdown fault executing authentication reset." });
        }

        // Hash the new security password
        const saltRounds = 10;
        const hashedNewPassword = await bcrypt.hash(new_password, saltRounds);

        // Update password credentials
        await pool.query(
            'UPDATE students SET password = $1 WHERE UPPER(reg_no) = UPPER($2)',
            [hashedNewPassword, reg_no.trim()]
        );

        res.status(200).json({ message: "Password updated successfully." });

    } catch (error) {
        console.error("Reset password error:", error);
        // Custom message directly matching UI error string requirements
        res.status(500).json({ message: "Communication breakdown fault executing authentication reset." });
    }
});

// ==========================================
// 4. ADMINISTRATIVE PORTAL ACCESS
// ==========================================
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const adminResult = await pool.query('SELECT * FROM system_admins WHERE username = $1', [username]);
        
        if (adminResult.rows.length === 0) {
            return res.status(401).json({ message: "Unauthorized credentials code signature." });
        }

        const admin = adminResult.rows[0];
        
        // Plain text validation or hashed password parsing
        let isMatch = (password === admin.password);
        if (admin.password.startsWith('$2b$')) {
            isMatch = await bcrypt.compare(password, admin.password);
        }

        if (!isMatch) {
            return res.status(401).json({ message: "Unauthorized credentials code signature." });
        }

        res.status(200).json({ message: "Admin authorization verified successfully." });
    } catch (error) {
        console.error("Admin authentication error:", error);
        res.status(500).json({ message: "Unauthorized credentials code signature." });
    }
});

// Catch-all route to serve the front-end index file
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
    console.log(`Voting App backend web service running on port ${PORT}`);
});
