const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const cors = require('cors');

const app = express();

// Enable cross-origin requests and expand payload processing boundaries for heavy base64 uploads
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Link pooling variables securely matching your Neon connection strings
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Serve frontend static materials directly from root workspace setup
app.use(express.static(__dirname));

// =========================================================================
// CANDIDATE PROFILE IMAGE SYNC ROUTES
// =========================================================================

// Draw down candidate images safely from persistence layers
app.get("/api/candidates/photos", async (req, res) => {
  try {
    const result = await pool.query("SELECT candidate_name, photo_url FROM candidate_profiles");
    
    // Core default fallback profiles matching your original layout system
    const photoMapping = {
      "Candidate A": "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150",
      "Candidate B": "https://images.unsplash.com/photo-1544005313-94ddf0286df2?w=150",
      "Candidate C": "https://images.unsplash.com/photo-1506794778202-cad84cf45f1d?w=150"
    };

    result.rows.forEach(row => {
      photoMapping[row.candidate_name] = row.photo_url;
    });

    res.json(photoMapping);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update or store candidate photographs inside targeted rows
app.post("/api/admin/update-candidate-photo", async (req, res) => {
  const { candidateName, photoData } = req.body;
  if (!candidateName || !photoData) {
    return res.status(400).json({ success: false, message: "Missing payload details." });
  }
  try {
    await pool.query(`
      INSERT INTO candidate_profiles (candidate_name, photo_url) 
      VALUES ($1, $2) 
      ON CONFLICT (candidate_name) 
      DO UPDATE SET photo_url = EXCLUDED.photo_url
    `, [candidateName, photoData]);

    res.json({ success: true, message: "Candidate image updated permanently inside database." });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// =========================================================================
// USER AUTHENTICATION & VOTING CORE MANAGEMENT
// =========================================================================

// Student Login Verification Routing
app.post("/api/login/student", async (req, res) => {
  const { regNum, password } = req.body;
  try {
    const result = await pool.query(
      "SELECT id, reg_no, fullname, has_voted, photo_url FROM students WHERE LOWER(reg_no) = LOWER($1) AND password = $2",
      [regNum.trim(), password]
    );

    if (result.rows.length > 0) {
      const student = result.rows[0];
      res.json({
        success: true,
        user: { id: student.id, regNum: student.reg_no, name: student.fullname, voted: student.has_voted, photoUrl: student.photo_url }
      });
    } else {
      res.status(404).json({ success: false, message: "Account not found. Please register your student details first." });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Registration Endpoint
app.post("/api/register", async (req, res) => {
  const { name, regNum, password } = req.body;
  try {
    await pool.query(
      "INSERT INTO students (fullname, reg_no, password, has_voted) VALUES ($1, $2, $3, false)",
      [name, regNum, password]
    );
    res.json({ success: true, message: "Registration processing finalized successfully!" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Submit Ballot Tracking Endpoint (FIXED COLUMN IDENTIFIER MATCHING SCHEMA)
app.post("/api/vote", async (req, res) => {
  const { studentId, candidate } = req.body;
  try {
    // Start transactional block
    await pool.query("BEGIN");
    
    // Log choice into votes table, targeting the 'candidate' column directly
    await pool.query("INSERT INTO votes (student_id, candidate) VALUES ($1, $2)", [studentId, candidate]);
    
    // Toggle active authorization record flag on the voters list
    await pool.query("UPDATE students SET has_voted = true WHERE id = $1", [studentId]);
    
    await pool.query("COMMIT");
    res.json({ success: true, message: "Ballot cast successfully! Your vote has been recorded." });
  } catch (err) {
    await pool.query("ROLLBACK");
    res.status(500).json({ success: false, message: err.message });
  }
});

// Admin authentication verification endpoint
app.post("/api/login/admin", async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query(
      "SELECT * FROM system_admins WHERE LOWER(username) = LOWER($1) AND password = $2",
      [username.trim(), password]
    );
    if (result.rows.length > 0) {
      res.json({ success: true });
    } else {
      res.status(401).json({ success: false, message: "Unauthorized credentials code signature." });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Aggregate live results data totals
app.get("/api/results", async (req, res) => {
  try {
    const result = await pool.query("SELECT candidate, COUNT(*) as count FROM votes GROUP BY candidate");
    const tallies = { "Candidate A": 0, "Candidate B": 0, "Candidate C": 0 };
    result.rows.forEach(row => {
      if (row.candidate) tallies[row.candidate] = parseInt(row.count);
    });
    res.json(tallies);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Administrative overview data sync
app.get("/api/admin/voters", async (req, res) => {
  try {
    const result = await pool.query("SELECT id, reg_no, fullname, has_voted, photo_url FROM students ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/admin/update-photo", async (req, res) => {
  const { studentId, photoData } = req.body;
  try {
    await pool.query("UPDATE students SET photo_url = $1 WHERE id = $2", [photoData, studentId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Safe universal root interface view callback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Server executing securely on system port: ${PORT}`);
});
