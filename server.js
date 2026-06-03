const express = require("express");
const cors = require("cors");
const path = require("path");
const { Pool } = require("pg");

const app = express();

app.use(cors());
// Set operational memory buffers to 50MB to successfully route uploaded voter photographs
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// 1. PostgreSQL Structural Instantiation
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// 2. Client Side Explicit View Mount
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// 3. API Production Data Routes

// Fetch production ballot counts mapped specifically by unique Candidate Identifiers
app.get("/api/results", async (req, res) => {
  try {
    const queryText = `
      SELECT candidate_name, COUNT(*) as vote_count 
      FROM votes 
      GROUP BY candidate_name
    `;
    const dbResult = await pool.query(queryText);
    
    // Default structural schema initialization
    const clientTallies = { "Candidate A": 0, "Candidate B": 0, "Candidate C": 0 };
    
    dbResult.rows.forEach(row => {
      if (clientTallies[row.candidate_name] !== undefined) {
        clientTallies[row.candidate_name] = parseInt(row.vote_count, 10);
      }
    });
    
    res.json(clientTallies);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fetch administrative list of authenticated student rows
app.get("/api/admin/voters", async (req, res) => {
  try {
    const result = await pool.query("SELECT id, reg_no, fullname, photo_url, has_voted FROM students ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Submit voter account registration securely into data engine
app.post("/api/register", async (req, res) => {
  const { name, regNum, password } = req.body;
  if (!name || !regNum || !password) {
    return res.status(400).json({ success: false, message: "Missing required registration parameters." });
  }

  try {
    const normalizeReg = regNum.trim();
    const checkDuplicate = await pool.query("SELECT id FROM students WHERE LOWER(reg_no) = LOWER($1)", [normalizeReg]);
    
    if (checkDuplicate.rows.length > 0) {
      return res.status(400).json({ success: false, message: "This registration number is already bound to an active profile." });
    }

    await pool.query(
      "INSERT INTO students (fullname, reg_no, password) VALUES ($1, $2, $3)",
      [name.trim(), normalizeReg, password]
    );

    res.json({ success: true, message: "Voter registry account created successfully!" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Verify student registration authentication state
app.post("/api/login/student", async (req, res) => {
  const { regNum, password } = req.body;
  if (!regNum || !password) {
    return res.status(400).json({ success: false, message: "Credentials cannot be empty." });
  }

  try {
    const result = await pool.query(
      "SELECT id, reg_no, fullname, has_voted FROM students WHERE LOWER(reg_no) = LOWER($1) AND password = $2",
      [regNum.trim().toLowerCase(), password]
    );

    if (result.rows.length > 0) {
      const studentProfile = result.rows[0];
      res.json({
        success: true,
        user: { 
          id: studentProfile.id, 
          regNum: studentProfile.reg_no, 
          name: studentProfile.fullname, 
          voted: studentProfile.has_voted 
        }
      });
    } else {
      res.status(401).json({ success: false, message: "Access Denied: Invalid Student registration number or security token." });
    }
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// Authenticate administrative clearance
app.post("/api/login/admin", (req, res) => {
  const { username, password } = req.body;
  if (username === "admin" && password === "meru2026") {
    res.json({ success: true });
  } else {
    res.status(401).json({ success: false, message: "Access Denied: High authority clearance failure." });
  }
});

// Atomic Transaction Vote Processing Engine
app.post("/api/vote", async (req, res) => {
  const { studentId, candidate } = req.body;
  if (!studentId || !candidate) {
    return res.status(400).json({ success: false, message: "Incomplete vote request payload." });
  }

  try {
    // Initiate lock transaction to explicitly defend against double execution exploits
    await pool.query("BEGIN");

    const verificationRecord = await pool.query("SELECT has_voted FROM students WHERE id = $1 FOR UPDATE", [studentId]);
    
    if (verificationRecord.rows.length === 0) {
      await pool.query("ROLLBACK");
      return res.status(404).json({ success: false, message: "Identity Verification Failure: Student profile absent from registry." });
    }

    if (verificationRecord.rows[0].has_voted) {
      await pool.query("ROLLBACK");
      return res.status(403).json({ success: false, message: "Security Block: System registers a prior ballot submission from this account." });
    }

    // Insert atomic vote record entry
    await pool.query("INSERT INTO votes (student_id, candidate_name) VALUES ($1, $2)", [studentId, candidate]);
    // Set account state flag to permanent truth
    await pool.query("UPDATE students SET has_voted = TRUE WHERE id = $1", [studentId]);

    await pool.query("COMMIT");
    res.json({ success: true, message: "Your verification identity has been updated and ballot cast successfully." });
  } catch (err) {
    await pool.query("ROLLBACK");
    res.status(500).json({ success: false, message: err.message });
  }
});

// Administration Action: Directly save Base64 student image references down to table storage
app.post("/api/admin/update-photo", async (req, res) => {
  const { studentId, photoData } = req.body;
  if (!studentId || !photoData) {
    return res.status(400).json({ success: false, message: "Missing tracking payload arguments." });
  }

  try {
    await pool.query("UPDATE students SET photo_url = $1 WHERE id = $2", [photoData, studentId]);
    res.json({ success: true, message: "Voter photograph committed successfully to memory table." });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// 4. Runtime Ingress Configuration
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Production server online and routing efficiently on cluster port ${PORT}`);
});

module.exports = pool;
