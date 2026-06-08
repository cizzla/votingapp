/**
 * MERU UNIVERSITY DIGITAL ELECTORAL MANAGEMENT PLATFORM
 * Core Unified Operations Platform Server Infrastructure
 * Technologies: Node.js, Express.js, Neon Serverless PostgreSQL, JWT Authentication
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

// Load environment variables with fallback configuration profiles
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 10000;

// Token Config validation checks
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_high_entropy_meru_cryptographic_ecdsa_key_string';
const SYSTEM_BLINDING_SECRET = process.env.SYSTEM_BLINDING_SECRET || 'fallback_voter_ballot_decoupling_salt_hash';

// ==========================================
// DATABASE LAYER (NEON CONNECTION POOL)
// ==========================================
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: true,
  },
});

// Test connection pooling status on initialization
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Critical Database connection failure to Neon infrastructure:', err.stack);
  } else {
    console.log('Secure SSL connection established with Neon PostgreSQL at:', res.rows[0].now);
  }
});

// ==========================================
// MIDDLEWARE CONFIGURATIONS
// ==========================================
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

/**
 * Zero-Trust Identity Verification Middleware
 * Validates down-stream access eligibility via signed Http Bearer JWT tokens
 */
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token tracking identity missing' });
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Invalid or expired cryptographic authentication token' });
  }
};

// ==========================================
// ENDPOINT IMPLEMENTATIONS (REST API LEDGER)
// ==========================================

/**
 * AUTHENTICATION SERVICE: Student Identity Management Login Gate
 * POST /api/v1/auth/login
 */
app.post('/api/v1/auth/login', async (req, res) => {
  const { student_id, password } = req.body;

  if (!student_id || !password) {
    return res.status(400).json({ error: 'Missing registration identity or security password parameters' });
  }

  try {
    const result = await pool.query('SELECT * FROM students WHERE student_id = $1', [student_id]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid identifier or security credentials' });
    }

    const student = result.rows[0];

    if (!student.is_active_enrollment) {
      return res.status(403).json({ error: 'Academic enrollment state suspended or inactive' });
    }

    const isMatch = await bcrypt.compare(password, student.password_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid identifier or security credentials' });
    }

    // Sign identity parameters into access token container
    const accessToken = jwt.sign(
      { student_id: student.student_id, faculty_code: student.faculty_code },
      JWT_SECRET,
      { expiresIn: '15m' }
    );

    return res.status(200).json({
      status: 'SUCCESS',
      access_token: accessToken,
      profile: {
        student_id: student.student_id,
        faculty_code: student.faculty_code,
        has_voted: student.has_voted_active_session
      }
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Internal Identity Management processing error' });
  }
});

/**
 * ELECTION SERVICE: Active Configurations Extraction
 * GET /api/v1/elections/active
 */
app.get('/api/v1/elections/active', verifyToken, async (req, res) => {
  try {
    const queryText = `
      SELECT election_id, title, start_timestamp, end_timestamp, electoral_status 
      FROM elections 
      WHERE electoral_status = 'ACTIVE' AND NOW() BETWEEN start_timestamp AND end_timestamp
    `;
    const { rows } = await pool.query(queryText);
    return res.status(200).json(rows);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to extract active configuration parameters' });
  }
});

/**
 * CANDIDATE SERVICE: Fetch Vetted Profiles by Election Scope
 * GET /api/v1/elections/:electionId/candidates
 */
app.get('/api/v1/elections/:electionId/candidates', verifyToken, async (req, res) => {
  const { electionId } = req.params;
  try {
    const queryText = `
      SELECT c.candidate_id, c.candidate_hash, c.manifesto, s.faculty_code
      FROM candidates c
      JOIN students s ON c.student_id = s.student_id
      WHERE c.election_id = $1 AND c.vetting_status = 'APPROVED'
    `;
    const { rows } = await pool.query(queryText, [electionId]);
    return res.status(200).json(rows);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to map candidate lifecycle records' });
  }
});

/**
 * VOTING SERVICE: Real-Time Vote Processing (Identity Separation Guard Point)
 * POST /api/v1/votes/cast
 */
app.post('/api/v1/votes/cast', verifyToken, async (req, res) => {
  const { election_id, candidate_hash, blind_signature } = req.body;
  const student_id = req.user.student_id; 

  if (!election_id || !candidate_hash || !blind_signature) {
    return res.status(400).json({ error: 'Missing strict vote registration metadata parameters' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Enforce voter identity double-voting boundaries
    const voterCheck = await client.query(
      'SELECT has_voted_active_session, is_active_enrollment FROM students WHERE student_id = $1 FOR UPDATE',
      [student_id]
    );

    const voter = voterCheck.rows[0];
    if (!voter || !voter.is_active_enrollment) {
      throw new Error('Voter enrollment records invalid or barred');
    }
    if (voter.has_voted_active_session) {
      return res.status(403).json({ error: 'Electoral integrity infraction: Vote already committed for this session' });
    }

    // Verify operational timeline windows
    const electionCheck = await client.query(
      'SELECT electoral_status FROM elections WHERE election_id = $1 AND NOW() BETWEEN start_timestamp AND end_timestamp',
      [election_id]
    );
    if (electionCheck.rows.length === 0) {
      throw new Error('Target election window closed or uninitialized');
    }

    // Mutate state variable on identity table BEFORE processing the ballot injection
    await client.query(
      'UPDATE students SET has_voted_active_session = TRUE WHERE student_id = $1',
      [student_id]
    );

    // Cryptographic Blockchain Ledger Pattern Simulation: Pull trailing hash run
    const lastBallot = await client.query(
      'SELECT previous_block_hash FROM ballots ORDER BY ledger_sequence_number DESC LIMIT 1'
    );
    
    let previousHash = '0000000000000000000000000000000000000000000000000000000000000000';
    if (lastBallot.rows.length > 0) {
      previousHash = lastBallot.rows[0].previous_block_hash;
    }

    // Generate current transactional validation token 
    const currentBlockHash = crypto
      .createHmac('sha256', SYSTEM_BLINDING_SECRET)
      .update(`${election_id}-${candidate_hash}-${blind_signature}-${previousHash}`)
      .digest('hex');

    // Execution Separation Point: Write completely decoupled record tracking ledger data
    await client.query(
      'INSERT INTO ballots (election_id, candidate_identifier_hash, previous_block_hash) VALUES ($1, $2, $3)',
      [election_id, candidate_hash, currentBlockHash]
    );

    await client.query('COMMIT');
    return res.status(201).json({ status: 'ACCEPTED', transaction_hash: currentBlockHash });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    return res.status(500).json({ error: err.message || 'Electoral transaction orchestration failure' });
  } finally {
    client.release();
  }
});

/**
 * RESULTS SERVICE: Real-Time Vote Processing Calculations
 * GET /api/v1/votes/realtime
 */
app.get('/api/v1/votes/realtime', verifyToken, async (req, res) => {
  const { electionId } = req.query;
  if (!electionId) {
    return res.status(400).json({ error: 'Missing election target parameter query parameters' });
  }
  try {
    const queryText = `
      SELECT candidate_identifier_hash as candidate, COUNT(*) as tally
      FROM ballots
      WHERE election_id = $1
      GROUP BY candidate_identifier_hash
      ORDER BY tally DESC
    `;
    const { rows } = await pool.query(queryText, [electionId]);
    return res.status(200).json({ election_id: electionId, data: rows });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to aggregate real-time transaction tallies' });
  }
});

// Single Page Application client-side routing tracking safety handlers
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start application runtime orchestration layer
app.listen(PORT, () => {
  console.log(`Meru University Unified Operations Framework live on cluster port: ${PORT}`);
});
