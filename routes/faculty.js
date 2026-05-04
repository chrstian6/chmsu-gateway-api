const express = require("express");
const router = express.Router();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { neon } = require("@neondatabase/serverless");
const faceProcessor = require("../utils/faceProcessor");

const sql = neon(process.env.DATABASE_URL);

// ── Generate Clean Faculty ID ──
async function generateFacultyId() {
  const year = new Date().getFullYear();
  const yearPrefix = `FAC-${year}`;

  try {
    // Get the latest faculty ID for current year
    const result = await sql`
      SELECT faculty_id FROM faculty
      WHERE faculty_id LIKE ${yearPrefix + "-%"}
      ORDER BY faculty_id DESC LIMIT 1
    `;

    if (result.length === 0) {
      return `${yearPrefix}-0001`;
    }

    const lastId = result[0].faculty_id;
    const parts = lastId.split("-");

    if (parts.length !== 3) {
      console.error("Invalid faculty ID format:", lastId);
      return `${yearPrefix}-0001`;
    }

    const lastNumber = parseInt(parts[2], 10);

    if (isNaN(lastNumber)) {
      console.error("Invalid number in faculty ID:", lastId);
      return `${yearPrefix}-0001`;
    }

    const nextNumber = (lastNumber + 1).toString().padStart(4, "0");
    return `${yearPrefix}-${nextNumber}`;
  } catch (error) {
    console.error("Error generating faculty ID:", error);
    // Fallback to timestamp-based ID if generation fails
    const timestamp = Date.now().toString(36).toUpperCase();
    return `FAC-${year}-${timestamp.slice(-4)}`;
  }
}

// ── REGISTER FACULTY ──
router.post("/register", async (req, res) => {
  try {
    const {
      email,
      password,
      first_name,
      last_name,
      employee_id,
      department,
      position,
      employment_type,
      address,
      contact_number,
      face_descriptors,
      campus_id,
    } = req.body;

    // Validation
    if (!email || !password || !first_name || !last_name || !employee_id) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields",
        required: [
          "email",
          "password",
          "first_name",
          "last_name",
          "employee_id",
        ],
      });
    }

    // Check existing
    const existing = await sql`
      SELECT email, employee_id FROM faculty
      WHERE email = ${email} OR employee_id = ${employee_id}
    `;

    if (existing.length > 0) {
      const field = existing[0].email === email ? "email" : "employee_id";
      return res.status(409).json({
        success: false,
        error: `${field} already exists`,
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(12);
    const password_hash = await bcrypt.hash(password, salt);

    // Process face descriptors
    let processedDescriptors = null;
    let faceEnrolled = false;

    if (face_descriptors?.length > 0) {
      try {
        processedDescriptors =
          faceProcessor.validateAndProcessDescriptors(face_descriptors);
        faceEnrolled = true;
      } catch (faceError) {
        console.error("Face processing error:", faceError);
        // Continue registration even if face processing fails
      }
    }

    // Generate clean faculty ID
    const faculty_id = await generateFacultyId();

    // Insert faculty
    const result = await sql`
      INSERT INTO faculty (
        faculty_id, email, password_hash, first_name, last_name,
        employee_id, role, department, position, employment_type,
        address, contact_number, face_descriptor, face_enrolled,
        face_enrolled_at, is_active, campus_id, created_at, updated_at
      ) VALUES (
        ${faculty_id}, ${email}, ${password_hash}, ${first_name}, ${last_name},
        ${employee_id}, 2, ${department || null}, ${position || null},
        ${employment_type || null}, ${address || null}, ${contact_number || null},
        ${processedDescriptors ? JSON.stringify(processedDescriptors) : null},
        ${faceEnrolled}, ${faceEnrolled ? new Date().toISOString() : null}, true,
        ${campus_id || null}, NOW(), NOW()
      )
      RETURNING
        faculty_id,
        email,
        first_name,
        last_name,
        employee_id,
        role,
        department,
        position,
        face_enrolled,
        campus_id,
        created_at
    `;

    // Generate token
    const token = jwt.sign(
      {
        faculty_id: result[0].faculty_id,
        email: result[0].email,
        role: result[0].role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" },
    );

    res.status(201).json({
      success: true,
      data: { ...result[0], token },
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      success: false,
      error: "Registration failed. Please try again.",
    });
  }
});

// ── LOGIN ──
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: "Email and password are required",
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
      });
    }

    const faculty = result[0];
    const validPassword = await bcrypt.compare(password, faculty.password_hash);

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        error: "Invalid credentials",
      });
    }

    // Update last login
    await sql`
      UPDATE faculty SET last_login = NOW() WHERE faculty_id = ${faculty.faculty_id}
    `;

    const token = jwt.sign(
      {
        faculty_id: faculty.faculty_id,
        email: faculty.email,
        role: faculty.role,
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" },
    );

    // ✅ Include face_descriptor in response for face login
    const { password_hash, ...facultyData } = faculty;

    // Parse face_descriptor if it's stored as a string
    if (
      facultyData.face_descriptor &&
      typeof facultyData.face_descriptor === "string"
    ) {
      try {
        facultyData.face_descriptor = JSON.parse(facultyData.face_descriptor);
      } catch (e) {
        console.error("Failed to parse face descriptor:", e);
      }
    }

    res.json({
      success: true,
      data: { ...facultyData, token },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      error: "Login failed. Please try again.",
    });
  }
});

// ── GET PROFILE ──
router.get("/profile", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        error: "No token provided",
      });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const result = await sql`
      SELECT
        faculty_id,
        email,
        first_name,
        last_name,
        employee_id,
        role,
        department,
        position,
        employment_type,
        address,
        contact_number,
        campus_id,
        face_enrolled,
        face_enrolled_at,
        is_active,
        last_login,
        created_at,
        updated_at
      FROM faculty
      WHERE faculty_id = ${decoded.faculty_id} AND is_active = true
    `;

    if (result.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Faculty not found",
      });
    }

    res.json({
      success: true,
      data: result[0],
    });
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        success: false,
        error: "Invalid token",
      });
    }
    console.error("Profile error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to fetch profile",
    });
  }
});

// ── UPDATE PROFILE ──
router.put("/profile", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        error: "No token provided",
      });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const {
      first_name,
      last_name,
      department,
      position,
      employment_type,
      address,
      contact_number,
    } = req.body;

    const result = await sql`
      UPDATE faculty
      SET
        first_name = COALESCE(${first_name}, first_name),
        last_name = COALESCE(${last_name}, last_name),
        department = COALESCE(${department}, department),
        position = COALESCE(${position}, position),
        employment_type = COALESCE(${employment_type}, employment_type),
        address = COALESCE(${address}, address),
        contact_number = COALESCE(${contact_number}, contact_number),
        updated_at = NOW()
      WHERE faculty_id = ${decoded.faculty_id} AND is_active = true
      RETURNING
        faculty_id,
        email,
        first_name,
        last_name,
        employee_id,
        role,
        department,
        position,
        employment_type,
        address,
        contact_number,
        campus_id,
        face_enrolled,
        updated_at
    `;

    if (result.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Faculty not found",
      });
    }

    res.json({
      success: true,
      data: result[0],
    });
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        success: false,
        error: "Invalid token",
      });
    }
    console.error("Update profile error:", error);
    res.status(500).json({
      success: false,
      error: "Failed to update profile",
    });
  }
});

// ── ENROLL FACE ──
router.post("/enroll-face", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        success: false,
        error: "No token provided",
      });
    }

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const { face_descriptors } = req.body;

    if (!face_descriptors?.length) {
      return res.status(400).json({
        success: false,
        error: "Face descriptors required",
      });
    }

    const processedDescriptors =
      faceProcessor.validateAndProcessDescriptors(face_descriptors);

    const result = await sql`
      UPDATE faculty
      SET
        face_descriptor = ${JSON.stringify(processedDescriptors)},
        face_enrolled = true,
        face_enrolled_at = NOW(),
        updated_at = NOW()
      WHERE faculty_id = ${decoded.faculty_id} AND is_active = true
      RETURNING faculty_id, email, face_enrolled, face_enrolled_at
    `;

    if (result.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Faculty not found",
      });
    }

    res.json({
      success: true,
      data: result[0],
      message: "Face enrolled successfully",
    });
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({
        success: false,
        error: "Invalid token",
      });
    }
    console.error("Face enrollment error:", error);
    res.status(500).json({
      success: false,
      error: "Face enrollment failed",
    });
  }
});

module.exports = router;
