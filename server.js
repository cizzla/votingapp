// 1. Fetch persistent Candidate images from the database
app.get("/api/candidates/photos", async (req, res) => {
  try {
    const result = await pool.query("SELECT candidate_name, photo_url FROM candidate_profiles");
    
    // Create a fallback mapping matching your original frontend memory configuration
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
