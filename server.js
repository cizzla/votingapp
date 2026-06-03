const express = require("express");
const cors = require("cors");
const path = require("path");
const { Pool } = require("pg");

const app = express();

app.use(cors());
app.use(express.json());

// 1. PostgreSQL Database Connection Setup
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

// 2. EXPLICIT INDEX PAGE ROUTE
// This completely overrides the old JSON message and forces the student login page to open
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// 3. API Placeholder Routes (For your fetch calls in index.html to communicate with)
app.get("/api/results", async (req, res) => {
  try {
    // Replace this with an actual database query later when your tables are ready
    // e.g., const results = await pool.query("SELECT candidate, COUNT(*) FROM votes GROUP BY candidate");
    res.json({ A: 0, B: 0, C: 0 });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/login/student", (req, res) => {
  const { regNum, password } = req.body;
  // Placeholder logic - always succeeds for now until you map registration validation
  if (regNum && password) {
    res.json({ success: true });
  } else {
    res.json({ success: false, message: "Missing credentials" });
  }
});

app.post("/api/login/admin", (req, res) => {
  const { username, password } = req.body;
  if (username && password) {
    res.json({ success: true });
  } else {
    res.json({ success: false, message: "Missing credentials" });
  }
});

app.post("/api/vote", (req, res) => {
  const { candidate } = req.body;
  if (candidate) {
    res.json({ success: true });
  } else {
    res.json({ success: false, message: "No candidate chosen" });
  }
});

// 4. Server Port Configuration
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = pool;
