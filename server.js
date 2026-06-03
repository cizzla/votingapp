app.post("/api/login/admin", async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "Username and password are required." });
  }

  try {
    const queryText = "SELECT id, username FROM system_admins WHERE LOWER(username) = LOWER($1) AND password = $2";
    
    // FIX: Apply .trim() to both parameters to prevent whitespace mismatches
    const result = await pool.query(queryText, [username.trim(), password.trim()]);

    if (result.rows.length > 0) {
      res.json({ 
        success: true, 
        message: "Administrative clearance verified successfully.",
        admin: { username: result.rows[0].username }
      });
    } else {
      res.status(401).json({ success: false, message: "Unauthorized credentials code signature." });
    }
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});
