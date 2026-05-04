// server/routes/auth.js
const express = require("express");
const bcrypt = require("bcryptjs");
const { neon } = require("@neondatabase/serverless");
const {
  createRateLimiter,
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  rotateRefreshToken,
  revokeAllUserTokens,
  authenticate,
} = require("../middleware/gateway");

const router = express.Router();
const sql = neon(process.env.DATABASE_URL);

// ─── Rate Limiters ─────────────────────────────────────────────────────
const loginLimiter = createRateLimiter(15 * 60 * 1000, 5); // 5 attempts per 15 minutes
const refreshLimiter = createRateLimiter(60 * 60 * 1000, 20); // 20 refreshes per hour
const generalLimiter = createRateLimiter(15 * 60 * 1000, 100); // 100 requests per 15 minutes

// ─── Login ─────────────────────────────────────────────────────────────
router.post("/login", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: "Email and password are required",
        requestId: req.requestId,
      });
    }

    const result = await sql`
      SELECT * FROM faculty
      WHERE email = ${email} AND is_active = true
    `;

    if (result.length === 0) {
      return res.status(401).json({
        success: false,
        error: "Invalid credentials",
        requestId: req.requestId,
      });
    }

    const faculty = result[0];
    const validPassword = await bcrypt.compare(password, faculty.password_hash);

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        error: "Invalid credentials",
        requestId: req.requestId,
      });
    }

    // Update last login
    await sql`
      UPDATE faculty SET last_login = NOW() WHERE faculty_id = ${faculty.faculty_id}
    `;

    // Generate tokens
    const tokenPayload = {
      faculty_id: faculty.faculty_id,
      email: faculty.email,
      role: faculty.role,
    };

    const accessToken = generateAccessToken(tokenPayload);
    const refreshToken = generateRefreshToken(tokenPayload);

    // Remove sensitive data
    const { password_hash, face_descriptor, ...facultyData } = faculty;

    res.json({
      success: true,
      data: {
        ...facultyData,
        accessToken,
        refreshToken,
        expiresIn: 900, // 15 minutes in seconds
      },
      requestId: req.requestId,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      error: "Login failed",
      requestId: req.requestId,
    });
  }
});

// ─── Refresh Token ─────────────────────────────────────────────────────
router.post("/refresh-token", refreshLimiter, async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        error: "Refresh token required",
        requestId: req.requestId,
      });
    }

    try {
      const tokenPayload = {
        faculty_id: "", // Will be extracted from old token data
        email: "",
        role: 2,
      };

      // Rotate the refresh token (old one becomes invalid)
      const newRefreshToken = rotateRefreshToken(refreshToken, tokenPayload);

      // Generate new access token
      const accessToken = generateAccessToken(tokenPayload);

      res.json({
        success: true,
        data: {
          accessToken,
          refreshToken: newRefreshToken,
          expiresIn: 900,
        },
        requestId: req.requestId,
      });
    } catch (error) {
      return res.status(401).json({
        success: false,
        error: error.message || "Invalid refresh token",
        requestId: req.requestId,
      });
    }
  } catch (error) {
    console.error("Refresh error:", error);
    res.status(500).json({
      success: false,
      error: "Token refresh failed",
      requestId: req.requestId,
    });
  }
});

// ─── Validate Token ────────────────────────────────────────────────────
router.post("/validate-token", authenticate, async (req, res) => {
  res.json({
    success: true,
    data: {
      valid: true,
      faculty_id: req.user.faculty_id,
      expiresAt: new Date(req.user.exp * 1000).toISOString(),
    },
    requestId: req.requestId,
  });
});

// ─── Logout (Revoke All Tokens) ────────────────────────────────────────
router.post("/logout", authenticate, async (req, res) => {
  try {
    revokeAllUserTokens(req.user.faculty_id);

    res.json({
      success: true,
      message: "All sessions terminated",
      requestId: req.requestId,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Logout failed",
      requestId: req.requestId,
    });
  }
});

// ─── Get Profile (Protected) ───────────────────────────────────────────
router.get("/profile", authenticate, generalLimiter, async (req, res) => {
  try {
    const result = await sql`
      SELECT
        faculty_id, email, first_name, last_name, employee_id,
        role, department, position, employment_type,
        address, contact_number, campus_id, face_enrolled,
        face_enrolled_at, is_active, last_login, created_at, updated_at
      FROM faculty
      WHERE faculty_id = ${req.user.faculty_id} AND is_active = true
    `;

    if (result.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Faculty not found",
        requestId: req.requestId,
      });
    }

    res.json({
      success: true,
      data: result[0],
      requestId: req.requestId,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Failed to fetch profile",
      requestId: req.requestId,
    });
  }
});

module.exports = router;
