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

// Export pool in case other files in your project require it
module.exports = pool;

// 2. API Status Route (Moved so it doesn't conflict with your homepage)
app.get("/api/status", (req, res) => {
  res.json({
    message: "Meru University Voting API Running",
    database: "Connected"
  });
});

// 3. Root Route - Directly serves the index.html file from your main root folder
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// 4. Server Port Configuration
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
