const express = require('express');
const path = require('path');
const app = express();

// INCREASE PAYLOAD LIMITS: Base64 image strings are large!
// Without these lines, Express will throw a "413 Payload Too Large" error.
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Serve your static frontend files (make sure index.html is in a 'public' folder or root)
app.use(express.static(path.join(__dirname, 'public')));

// -------------------------------------------------------------------------
// DATABASE PLACEHOLDER
// Replace this block with your actual Neon PostgreSQL pool configuration!
// -------------------------------------------------------------------------
const pool = {
    query: async (text, params) => {
        console.log(`[DB Mock Query]: ${text}`, params);
        // This is a temporary fallback so the app doesn't crash before you link your pool
        return { rows: [] }; 
    }
};

// =========================================================================
// PERSISTENT CANDIDATE PHOTO ROUTES
// =========================================================================

// 1. Fetch persistent Candidate images from the database
app.get("/api/candidates/photos", async (req, res) => {
  try {
    const result = await pool.query("SELECT candidate_name, photo_url FROM candidate_profiles");
    
    // Default fallback images matching your original config
    const photoMapping = {
      "Candidate A": "https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=150",
      "Candidate B": "https://images.unsplash.com/photo-1544005313-94ddf0286df2?w=150",
      "Candidate C": "https://images.unsplash.com/photo-1506794778202-cad84cf45f1d?w=150"
    };

    // Override defaults with whatever is saved in your DB
    result.rows.forEach(row => {
      photoMapping[row.candidate_name] = row.photo_url;
    });

    res.json(photoMapping);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 2. Save an uploaded Candidate image permanently to the database
app.post("/api/admin/update-candidate-photo", async (req, res) => {
  const { candidateName, photoData } = req.body;
  if (!candidateName || !photoData) {
    return res.status(400).json({ success: false, message: "Missing tracking payload arguments." });
  }

  try {
    // UPSERT syntax: Inserts if missing, updates if it already exists
    await pool.query(`
      INSERT INTO candidate_profiles (candidate_name, photo_url) 
      VALUES ($1, $2) 
      ON CONFLICT (candidate_name) 
      DO UPDATE SET photo_url = EXCLUDED.photo_url
    `, [candidateName, photoData]);

    res.json({ success: true, message: "Candidate photograph saved permanently to database." });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// -------------------------------------------------------------------------
// YOUR OTHER ROUTES HERE
// (Keep your existing /api/login, /api/register, /api/vote routes below this)
// -------------------------------------------------------------------------


// Fallback route to serve index.html for any layout requests
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server environment
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
    console.log(`Server is running smoothly on port ${PORT}`);
});
