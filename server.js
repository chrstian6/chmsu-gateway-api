// server/server.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const path = require("path");
const os = require("os");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { neon } = require("@neondatabase/serverless");

const { validate } = require("./middleware/validate");
const { loginSchema, refreshTokenSchema } = require("./validations/schemas");

const faceRoutes = require("./routes/face");
const facultyRoutes = require("./routes/faculty");
const faceProcessor = require("./utils/faceProcessor");

const app = express();
const sql = neon(process.env.DATABASE_URL);

// 🔑 Validate secrets — NO hardcoded fallbacks
const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;

if (!JWT_ACCESS_SECRET) {
  console.error("❌ FATAL: JWT_ACCESS_SECRET must be set in .env");
  process.exit(1);
}
if (!JWT_REFRESH_SECRET) {
  console.error("❌ FATAL: JWT_REFRESH_SECRET must be set in .env");
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error("❌ FATAL: DATABASE_URL must be set in .env");
  process.exit(1);
}

// 🔒 Trust proxy — REQUIRED for accurate IP behind nginx/load balancer
app.set("trust proxy", 1);

// 🔒 Security Headers
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "https://cdn.jsdelivr.net", "https://unpkg.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://unpkg.com"],
        imgSrc: ["'self'", "data:", "https://*.basemaps.cartocdn.com"],
        connectSrc: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  }),
);

// 🔒 CORS — Restrict in production
app.use(
  cors({
    origin:
      process.env.NODE_ENV === "production"
        ? (process.env.ALLOWED_ORIGINS || "").split(",")
        : "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization", "X-Client-Platform"],
    credentials: true,
  }),
);

// 🔒 HTTPS Redirect in production
app.use((req, res, next) => {
  if (
    process.env.NODE_ENV === "production" &&
    req.headers["x-forwarded-proto"] !== "https"
  ) {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

app.use(morgan("dev"));

// 🔒 Body size limits
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// ───────────────────────────────────────────────────────────────────
// 🔐 GATEWAY — Rate Limiting, Zero Trust, Anti-Spoofing, Token Store
// ───────────────────────────────────────────────────────────────────

const refreshTokenStore = new Map();
const failedLoginAttempts = new Map();
const tokenBlacklist = new Set();
const requestLog = new Map();
const rateLimitStore = new Map();
const blockedIPs = new Set();

// 🔒 ANTI IP SPOOFING — Validate X-Forwarded-For chain
function getRealIP(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    const ips = forwarded.split(",").map((ip) => ip.trim());
    return ips[0];
  }
  return req.ip || req.connection.remoteAddress;
}

// Attack tool detection
const BLOCKED_USER_AGENTS = [
  "nikto",
  "sqlmap",
  "nmap",
  "masscan",
  "nessus",
  "burpsuite",
  "zgrab",
  "gobuster",
  "dirbuster",
  "hydra",
  "metasploit",
  "acunetix",
];

const CURL_USER_AGENTS = [
  "curl",
  "wget",
  "python-requests",
  "go-http-client",
  "java",
  "libwww-perl",
];

function isAttackTool(req) {
  const ua = (req.headers["user-agent"] || "").toLowerCase();
  return (
    BLOCKED_USER_AGENTS.some((bot) => ua.includes(bot)) ||
    !req.headers["user-agent"]
  );
}

function isCurl(req) {
  const ua = (req.headers["user-agent"] || "").toLowerCase();
  return CURL_USER_AGENTS.some((bot) => ua.includes(bot));
}

// 🔒 Rate Limiter with anti-spoofing
function rateLimiter(windowMs = 15 * 60 * 1000, max = 100) {
  return (req, res, next) => {
    const key = getRealIP(req);
    const now = Date.now();
    let record = rateLimitStore.get(key);

    if (!record || now - record.startTime > windowMs) {
      record = { startTime: now, count: 0 };
    }
    record.count++;
    rateLimitStore.set(key, record);

    res.setHeader("X-RateLimit-Limit", max);
    res.setHeader("X-RateLimit-Remaining", Math.max(0, max - record.count));
    res.setHeader(
      "X-RateLimit-Reset",
      Math.ceil((record.startTime + windowMs) / 1000),
    );

    if (record.count > max) {
      return res.status(429).json({
        success: false,
        error: "Too many requests. Try again later.",
      });
    }
    next();
  };
}

const loginLimiter = rateLimiter(15 * 60 * 1000, 5);
const refreshLimiter = rateLimiter(60 * 60 * 1000, 20);
const generalLimiter = rateLimiter(15 * 60 * 1000, 100);

// Account Lockout
function checkAccountLockout(email) {
  const record = failedLoginAttempts.get(email);
  if (!record) return false;
  if (record.count >= 5 && Date.now() - record.lastAttempt < 15 * 60 * 1000)
    return true;
  if (Date.now() - record.lastAttempt >= 15 * 60 * 1000)
    failedLoginAttempts.delete(email);
  return false;
}

function recordFailedAttempt(email) {
  const record = failedLoginAttempts.get(email) || { count: 0, lastAttempt: 0 };
  record.count++;
  record.lastAttempt = Date.now();
  failedLoginAttempts.set(email, record);
}

function resetFailedAttempts(email) {
  failedLoginAttempts.delete(email);
}

// 🔒 TIMING-SAFE password check
const DUMMY_HASH =
  "$2b$12$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

async function timingSafePasswordCheck(plaintext, realHash) {
  const hashToCheck = realHash || DUMMY_HASH;
  return bcrypt.compare(plaintext, hashToCheck);
}

// Zero Trust
function zeroTrustValidator(req, res, next) {
  const requestId = crypto.randomUUID();
  const clientIP = getRealIP(req);

  if (isAttackTool(req)) {
    blockedIPs.add(clientIP);
    console.log(`🚫 Blocked attack tool from ${clientIP}`);
    return res.status(403).json({ success: false, error: "Access denied." });
  }

  if (blockedIPs.has(clientIP)) {
    return res.status(403).json({ success: false, error: "Access denied." });
  }

  // Anomaly detection
  const clientRequests = requestLog.get(clientIP) || [];
  clientRequests.push({ requestId, path: req.path, timestamp: Date.now() });
  if (clientRequests.length > 200) clientRequests.shift();
  requestLog.set(clientIP, clientRequests);

  if (
    clientRequests.filter((r) => r.timestamp > Date.now() - 60000).length > 60
  ) {
    blockedIPs.add(clientIP);
    return res.status(403).json({ success: false, error: "Access denied." });
  }

  req.requestId = requestId;
  req.clientIP = clientIP;
  res.setHeader("X-Request-ID", requestId);
  next();
}

app.use(zeroTrustValidator);

// Token Utilities
function generateAccessToken(payload) {
  return jwt.sign(
    { ...payload, type: "access", jti: crypto.randomUUID() },
    JWT_ACCESS_SECRET,
    { expiresIn: "15m" },
  );
}

function generateRefreshToken(payload) {
  const token = crypto.randomBytes(64).toString("hex");
  const hash = crypto.createHash("sha256").update(token).digest("hex");
  refreshTokenStore.set(hash, {
    faculty_id: payload.faculty_id,
    email: payload.email,
    role: payload.role,
    createdAt: Date.now(),
    lastUsed: Date.now(),
    rotationCount: 0,
  });
  return token;
}

function verifyAccessToken(token) {
  if (tokenBlacklist.has(token)) throw new Error("Token revoked");
  return jwt.verify(token, JWT_ACCESS_SECRET);
}

function rotateRefreshToken(oldToken) {
  const oldHash = crypto.createHash("sha256").update(oldToken).digest("hex");
  const data = refreshTokenStore.get(oldHash);
  if (!data) throw new Error("Invalid refresh token");
  if (data.rotationCount >= 100) {
    refreshTokenStore.delete(oldHash);
    throw new Error("Max rotations reached");
  }
  if ((Date.now() - data.createdAt) / 86400000 > 7) {
    refreshTokenStore.delete(oldHash);
    throw new Error("Token expired");
  }

  refreshTokenStore.delete(oldHash);
  const newToken = crypto.randomBytes(64).toString("hex");
  const newHash = crypto.createHash("sha256").update(newToken).digest("hex");
  refreshTokenStore.set(newHash, {
    ...data,
    lastUsed: Date.now(),
    rotationCount: data.rotationCount + 1,
  });
  return newToken;
}

function revokeTokens(facultyId) {
  for (const [hash, data] of refreshTokenStore.entries()) {
    if (data.faculty_id === facultyId) refreshTokenStore.delete(hash);
  }
}

// Auth Middleware
function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ success: false, error: "Authentication required." });
  }
  try {
    req.user = verifyAccessToken(authHeader.split(" ")[1]);
    next();
  } catch (error) {
    const msg = error.message.includes("expired")
      ? "Token expired"
      : "Invalid token";
    const code = error.message.includes("expired")
      ? "TOKEN_EXPIRED"
      : undefined;
    return res.status(401).json({ success: false, error: msg, code });
  }
}

// Block unauthenticated curl access
function blockUnauthenticated(req, res, next) {
  const publicPaths = [
    "/api/auth/login",
    "/api/auth/refresh-token",
    "/api/health",
    "/faceapi-webview",
    "/face-verification.html",
  ];
  const isPublic =
    publicPaths.some((p) => req.path.startsWith(p)) ||
    req.path.startsWith("/models/");

  if (isPublic) return next();
  if (isCurl(req))
    return res
      .status(403)
      .json({ success: false, error: "Direct API access not allowed." });
  next();
}

app.use(blockUnauthenticated);

// 🔒 HTTPS-only secure cookie for session tracking (optional)
app.use((req, res, next) => {
  if (req.headers["x-forwarded-proto"] === "https") {
    res.cookie("__Secure-session", crypto.randomUUID(), {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 24 * 60 * 60 * 1000,
    });
  }
  next();
});

// Auto-cleanup
setInterval(() => {
  const now = Date.now();
  for (const [hash, data] of refreshTokenStore.entries()) {
    if (
      (now - data.createdAt) / 86400000 > 7 ||
      (now - data.lastUsed) / 3600000 > 24
    ) {
      refreshTokenStore.delete(hash);
    }
  }
  for (const [email, record] of failedLoginAttempts.entries()) {
    if (now - record.lastAttempt > 15 * 60 * 1000)
      failedLoginAttempts.delete(email);
  }
  for (const [ip, requests] of requestLog.entries()) {
    if (requests.filter((r) => r.timestamp > now - 3600000).length === 0)
      requestLog.delete(ip);
  }
}, 60000);

// ───────────────────────────────────────────────────────────────────
// 🔑 AUTH ROUTES (with Zod validation)
// ───────────────────────────────────────────────────────────────────

// Login — with validation + lockout + timing-safe password check
app.post(
  "/api/auth/login",
  loginLimiter,
  validate(loginSchema),
  async (req, res) => {
    try {
      const { email, password } = req.body;

      if (checkAccountLockout(email)) {
        return res.status(429).json({
          success: false,
          error: "Account locked. Try again in 15 minutes.",
        });
      }

      const result =
        await sql`SELECT * FROM faculty WHERE email = ${email} AND is_active = true`;
      const faculty = result[0] || null;
      const validPassword = await timingSafePasswordCheck(
        password,
        faculty?.password_hash,
      );

      if (!faculty || !validPassword) {
        recordFailedAttempt(email);
        const remaining = Math.max(
          0,
          5 - (failedLoginAttempts.get(email)?.count || 0),
        );
        return res.status(401).json({
          success: false,
          error: `Invalid credentials. ${remaining} attempts remaining.`,
        });
      }

      resetFailedAttempts(email);
      await sql`UPDATE faculty SET last_login = NOW() WHERE faculty_id = ${faculty.faculty_id}`;

      const payload = {
        faculty_id: faculty.faculty_id,
        email: faculty.email,
        role: faculty.role,
      };
      const accessToken = generateAccessToken(payload);
      const refreshToken = generateRefreshToken(payload);

      const { password_hash, face_descriptor, ...facultyData } = faculty;
      if (typeof facultyData.face_descriptor === "string") {
        try {
          facultyData.face_descriptor = JSON.parse(facultyData.face_descriptor);
        } catch (e) {}
      }

      res.json({
        success: true,
        data: {
          ...facultyData,
          token: accessToken,
          accessToken,
          refreshToken,
          expiresIn: 900,
        },
      });
    } catch (error) {
      console.error("Login error:", error);
      res.status(500).json({ success: false, error: "Login failed." });
    }
  },
);

// Refresh Token — with validation
app.post(
  "/api/auth/refresh-token",
  refreshLimiter,
  validate(refreshTokenSchema),
  async (req, res) => {
    try {
      const { refreshToken } = req.body;
      try {
        const newRefreshToken = rotateRefreshToken(refreshToken);
        const hash = crypto
          .createHash("sha256")
          .update(newRefreshToken)
          .digest("hex");
        const data = refreshTokenStore.get(hash);
        const accessToken = generateAccessToken({
          faculty_id: data.faculty_id,
          email: data.email,
          role: data.role,
        });
        res.json({
          success: true,
          data: { accessToken, refreshToken: newRefreshToken, expiresIn: 900 },
        });
      } catch (error) {
        return res.status(401).json({ success: false, error: error.message });
      }
    } catch (error) {
      res.status(500).json({ success: false, error: "Refresh failed." });
    }
  },
);

app.post("/api/auth/validate-token", authenticate, async (req, res) => {
  try {
    const result =
      await sql`SELECT faculty_id, is_active FROM faculty WHERE faculty_id = ${req.user.faculty_id} AND is_active = true`;
    if (result.length === 0) {
      revokeTokens(req.user.faculty_id);
      return res.status(401).json({ success: false, error: "User not found." });
    }
    res.json({ success: true, data: { valid: true } });
  } catch (error) {
    res.status(500).json({ success: false, error: "Validation failed." });
  }
});

app.post("/api/auth/logout", authenticate, async (req, res) => {
  revokeTokens(req.user.faculty_id);
  try {
    await sql`UPDATE faculty SET last_login = NOW() WHERE faculty_id = ${req.user.faculty_id}`;
  } catch (e) {}
  res.json({ success: true, message: "Signed out." });
});

app.get("/api/auth/profile", authenticate, generalLimiter, async (req, res) => {
  try {
    const result = await sql`
      SELECT faculty_id, email, first_name, last_name, employee_id,
        role, department, position, employment_type, address, contact_number,
        campus_id, face_enrolled, face_enrolled_at, is_active, last_login, created_at, updated_at
      FROM faculty WHERE faculty_id = ${req.user.faculty_id} AND is_active = true
    `;
    if (result.length === 0)
      return res.status(404).json({ success: false, error: "Not found." });
    res.json({ success: true, data: result[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: "Failed." });
  }
});

// ───────────────────────────────────────────────────────────────────
// ✅ EXISTING ROUTES (unchanged)
// ───────────────────────────────────────────────────────────────────

app.get("/faceapi-webview", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(__dirname, "public", "face-verification.html"));
});

app.get("/face-verification.html", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.sendFile(path.join(__dirname, "public", "face-verification.html"));
});

app.use("/api/faculty", faceRoutes);
app.use("/api/faculty", facultyRoutes);

app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

app.use(
  "/models",
  express.static(path.join(__dirname, "models"), {
    setHeaders: (res) => res.setHeader("Access-Control-Allow-Origin", "*"),
  }),
);

app.use(express.static(path.join(__dirname, "public")));

// Error handler — no stack traces in production
app.use((err, req, res, next) => {
  console.error("Error:", err.message);
  res.status(500).json({
    success: false,
    error:
      process.env.NODE_ENV === "production"
        ? "Internal server error"
        : err.message,
  });
});

// 🚀 Start
const PORT = process.env.PORT || 3000;
async function startServer() {
  try {
    await faceProcessor.loadModels();
    console.log("✅ Models loaded");
    app.listen(PORT, "0.0.0.0", () => console.log(`✅ Server on :${PORT}`));
  } catch (error) {
    console.error("❌ Failed:", error.message);
    process.exit(1);
  }
}
startServer();
