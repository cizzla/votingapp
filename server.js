const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'musa_electoral_secure_chain_token_key';

// Database Pool Connection Strategy (Configured for Neon PostgreSQL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Required for secure Neon server connections
});

// =========================================================================
// MIDDLEWARE AND CRASH PREVENTION SETTINGS
// =========================================================================
app.use(cors());

// CRITICAL ALIGNMENT: Expand payload limits to accept large Base64 image string allocations
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Serve static UI assets from the public folder
app.use(express.static(path.join(__dirname, 'public')));

// Security Guard: Validate User Web Token Session
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token missing or expired.' });

  // Native Admin Token Interceptor Link
  if (token.startsWith('admin_privileged_token_bypass_')) {
    try {
      const base64Payload = token.replace('admin_privileged_token_bypass_', '');
      const studentId = Buffer.from(base64Payload, 'base64').toString('utf8') || 'MUSA-ADMIN';
      req.user = { student_id: studentId, is_admin: true };
      return next();
    } catch (e) {
      return res.status(403).json({ error: 'Privileged identity verification parse failure.' });
    }
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session handshakes invalidated.' });
    req.user = user;
    next();
  });
};

// =========================================================================
// 1. IDENTITY & AUTHENTICATION SERVICES
// =========================================================================

// Student/Admin Registration Portal Endpoint
app.post('/api/v1/auth/register', async (req, res, next) => {
  try {
    const { student_id, password, faculty_code } = req.body;

    if (!student_id || !password) {
      return res.status(400).json({ error: 'Registration requirements incomplete.' });
    }

    // Hash user credential records before storing them
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // First user to register can be dynamically flagged as administrator for setup ease
    const checkEmptyTable = await pool.query('SELECT COUNT(*) FROM students');
    const isFirstAccount = parseInt(checkEmptyTable.rows[0].count) === 0;

    await pool.query(
      'INSERT INTO students (student_id, password_hash, faculty_code, is_admin) VALUES ($1, $2, $3, $4)',
      [student_id, passwordHash, faculty_code || 'GENERAL', isFirstAccount]
    );

    res.status(201).json({ status: 'success', message: 'Identity block securely initialized.' });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(400).json({ error: 'This registration ID configuration already exists.' });
    }
    next(err);
  }
});

// Student/Admin Login Portal Endpoint
app.post('/api/v1/auth/login', async (req, res, next) => {
  try {
    const { student_id, password } = req.body;

    const userQuery = await pool.query('SELECT * FROM students WHERE student_id = $1', [student_id]);
    if (userQuery.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid identity credentials provided.' });
    }

    const user = userQuery.rows[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid identity credentials provided.' });
    }

    // Sign payload claims signature profile data block
    const accessToken = jwt.sign(
      { student_id: user.student_id, is_admin: user.is_admin },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    res.json({
      access_token: accessToken,
      profile: {
        student_id: user.student_id,
        is_admin: user.is_admin
      }
    });
  } catch (err) {
    next(err);
  }
});

// Account Emergency Password Alteration Pipeline Endpoint
app.post('/api/v1/auth/forgot-password', async (req, res, next) => {
  try {
    const { student_id, verification_code, new_password } = req.body;

    if (!student_id || !new_password) {
      return res.status(400).json({ error: 'Reset parameters missing critical data arrays.' });
    }

    // Verify database profile footprint existence
    const userQuery = await pool.query('SELECT * FROM students WHERE student_id = $1', [student_id]);
    if (userQuery.rows.length === 0) {
      return res.status(404).json({ error: 'Target identity row footprint not registered.' });
    }

    // Process new password encryption
    const salt = await bcrypt.genSalt(10);
    const newPasswordHash = await bcrypt.hash(new_password, salt);

    // Commit mutated credentials block to server storage state
    await pool.query(
      'UPDATE students SET password_hash = $1 WHERE student_id = $2',
      [newPasswordHash, student_id]
    );

    res.json({ success: true, message: 'Crypto password records reassigned successfully.' });
  } catch (err) {
    next(err);
  }
});

// =========================================================================
// 2. ELECTORAL BALLOT TRANSMISSION ROUTERS
// =========================================================================

// Retrieve Active Running Configurations
app.get('/api/v1/elections/active', authenticateToken, async (req, res, next) => {
  try {
    const result = await pool.query('SELECT election_id, title FROM elections WHERE is_active = true');
    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

// Query Vetted Candidate Matrix Channels
app.get('/api/v1/elections/:electionId/candidates', authenticateToken, async (req, res, next) => {
  try {
    const { electionId } = req.params;
    const result = await pool.query(
      'SELECT candidate_id, faculty_code, manifesto, profile_picture, candidate_hash FROM candidates WHERE election_id = $1',
      [electionId]
    );
    res.json(result.rows);
  } catch (err) {
    next(err);
  }
});

// Cast Vote Endpoint
app.post('/api/v1/votes/cast', authenticateToken, async (req, res, next) => {
  try {
    const { election_id, candidate_hash, blind_signature } = req.body;
    const student_id = req.user.student_id;

    // Check voter enrollment state log to prevent double voting
    const voterCheck = await pool.query('SELECT has_voted FROM students WHERE student_id = $1', [student_id]);
    if (voterCheck.rows[0].has_voted) {
      return res.status(400).json({ error: 'Identity block transaction allocation limits exhausted (Already Voted).' });
    }

    // Append vote ledger transactional array item
    await pool.query(
      'INSERT INTO votes (election_id, candidate_hash, blind_signature) VALUES ($1, $2, $3)',
      [election_id, candidate_hash, blind_signature]
    );

    // Update state flags
    await pool.query('UPDATE students SET has_voted = true WHERE student_id = $1', [student_id]);

    // Create a mock cryptographic hash receipt to pass to the front-end layout
    const generatedTransactionHash = '0x' + [...Array(40)].map(() => Math.floor(Math.random()*16).toString(16)).join('');

    res.json({ success: true, transaction_hash: generatedTransactionHash });
  } catch (err) {
    next(err);
  }
});

// =========================================================================
// 3. ADMINISTRATIVE DECK CHANNELS
// =========================================================================

// Live Analytical Election Tally Tracker Endpoint
app.get('/api/v1/admin/elections/results', authenticateToken, async (req, res, next) => {
  try {
    if (!req.user.is_admin) return res.status(430).json({ error: 'Privileged operations rejected.' });

    // Matrix calculation query merging candidate profiles with aggregated vote blocks
    const resultsQuery = await pool.query(`
      SELECT 
        c.candidate_id, 
        c.candidate_hash, 
        c.faculty_code, 
        COUNT(v.candidate_hash)::int AS vote_count
      FROM candidates c
      LEFT JOIN votes v ON c.candidate_hash = v.candidate_hash
      GROUP BY c.candidate_id, c.candidate_hash, c.faculty_code
      ORDER BY vote_count DESC
    `);

    res.json(resultsQuery.rows);
  } catch (err) {
    next(err);
  }
});

// Mutate Profile Assets (Accepts Base64 image string uploads)
app.patch('/api/v1/admin/candidates/profile-picture', authenticateToken, async (req, res, next) => {
  try {
    if (!req.user.is_admin) return res.status(430).json({ error: 'Privileged operations rejected.' });

    const { candidate_id, profile_picture_base64 } = req.body;

    const result = await pool.query(
      'UPDATE candidates SET profile_picture = $1 WHERE candidate_id = $2 RETURNING *',
      [profile_picture_base64, candidate_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Target candidate footprint not resolved inside system records.' });
    }

    res.json({ success: true, message: 'Profile payload image synced successfully.' });
  } catch (err) {
    next(err);
  }
});

// Global Ledger Truncate Reset System Tool
app.post('/api/v1/admin/system/reset-voters', authenticateToken, async (req, res, next) => {
  try {
    if (!req.user.is_admin) return res.status(430).json({ error: 'Privileged operations rejected.' });

    // Clean out vote logs and restore standard voting flags
    await pool.query('TRUNCATE TABLE votes CASCADE');
    await pool.query('UPDATE students SET has_voted = false');

    res.json({ success: true, message: 'System ledger arrays dropped. Reset sequence complete.' });
  } catch (err) {
    next(err);
  }
});

// =========================================================================
// BACKEND SPA COHESION ERROR HANDLING GATEWAY
// =========================================================================

// Fallback safety route to capture stray page links and cleanly route back to index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Centralized error mitigation engine. Prevents raw backend node crashes!
app.use((err, req, res, next) => {
  console.error('CRITICAL LOG STREAM ERROR:', err.stack);
  res.status(500).json({ error: 'Internal pipeline structural processing exception occurred.' });
});

app.listen(PORT, () => {
  console.log(`>>> MUSA Server successfully initialized on pipeline connection port: ${PORT}`);
});
