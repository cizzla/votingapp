// Verify student registration authentication state
app.post("/api/login/student", async (req, res) => {
  const { regNum, password } = req.body;
  if (!regNum || !password) {
    return res.status(400).json({ success: false, message: "Credentials cannot be empty." });
  }

  try {
    // FIX: Explicitly pulled photo_url out here so it transfers to client session
    const result = await pool.query(
      "SELECT id, reg_no, fullname, photo_url, has_voted FROM students WHERE LOWER(reg_no) = LOWER($1) AND password = $2",
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
          voted: studentProfile.has_voted,
          photoUrl: studentProfile.photo_url
        }
      });
    } else {
      res.status(401).json({ success: false, message: "Access Denied: Invalid Student registration number or security token." });
    }
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});
