// server/middleware/gateway.js
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

// In-memory store for refresh tokens (use Redis in production)
const refreshTokenStore = new Map();
const tokenBlacklist = new Set();
const requestLog = new Map(); // For zero-trust request tracking

// ─── Rate Limiter Configuration ────────────────────────────────────────
const createRateLimiter = (windowMs = 15 * 60 * 1000, max = 100) => {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      res.status(429).json({
        success: false,
        error: "Too many requests. Please try again later.",
        retryAfter: Math.ceil(windowMs / 1000 / 60) + " minutes",
      });
    },
    skip: (req) => {
      // Skip rate limiting for health checks
      return req.path === "/api/health";
    },
  });
};

// ─── Zero Trust Request Validator ──────────────────────────────────────
const zeroTrustValidator = (req, res, next) => {
  const requestId = crypto.randomUUID();
  const clientIP = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers["user-agent"] || "unknown";
  const timestamp = Date.now();

  // Track request metadata
  const requestMeta = {
    requestId,
    clientIP,
    userAgent,
    timestamp,
    path: req.path,
    method: req.method,
  };

  // Store request for anomaly detection
  const clientRequests = requestLog.get(clientIP) || [];
  clientRequests.push(requestMeta);

  // Keep only last 100 requests per IP
  if (clientRequests.length > 100) {
    clientRequests.shift();
  }
  requestLog.set(clientIP, clientRequests);

  // Anomaly detection: check for suspicious patterns
  const recentRequests = clientRequests.filter(
    (r) => r.timestamp > timestamp - 60000,
  );

  if (recentRequests.length > 60) {
    return res.status(403).json({
      success: false,
      error: "Suspicious activity detected. Access denied.",
      requestId,
    });
  }

  // Attach request metadata
  req.requestMeta = requestMeta;
  req.requestId = requestId;

  // Add security headers
  res.setHeader("X-Request-ID", requestId);
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains",
  );

  next();
};

// ─── Token Utilities ───────────────────────────────────────────────────
const generateAccessToken = (payload) => {
  return jwt.sign(
    { ...payload, type: "access" },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: "15m" },
  );
};

const generateRefreshToken = (payload) => {
  const refreshToken = crypto.randomBytes(64).toString("hex");
  const refreshTokenHash = crypto
    .createHash("sha256")
    .update(refreshToken)
    .digest("hex");

  // Store refresh token with metadata
  refreshTokenStore.set(refreshTokenHash, {
    ...payload,
    createdAt: Date.now(),
    lastUsed: Date.now(),
    rotationCount: 0,
  });

  return refreshToken;
};

const verifyAccessToken = (token) => {
  // Check blacklist first
  if (tokenBlacklist.has(token)) {
    throw new Error("Token has been revoked");
  }

  return jwt.verify(token, process.env.JWT_ACCESS_SECRET);
};

const rotateRefreshToken = (oldToken, payload) => {
  const oldHash = crypto.createHash("sha256").update(oldToken).digest("hex");

  const tokenData = refreshTokenStore.get(oldHash);

  if (!tokenData) {
    throw new Error("Invalid refresh token");
  }

  // Check rotation count (max 100 rotations per session)
  if (tokenData.rotationCount >= 100) {
    refreshTokenStore.delete(oldHash);
    throw new Error("Maximum token rotations reached. Please re-authenticate.");
  }

  // Check token age (max 7 days)
  const tokenAge = (Date.now() - tokenData.createdAt) / (1000 * 60 * 60 * 24);
  if (tokenAge > 7) {
    refreshTokenStore.delete(oldHash);
    throw new Error("Refresh token expired. Please re-authenticate.");
  }

  // Delete old token (token rotation)
  refreshTokenStore.delete(oldHash);

  // Generate new refresh token with updated metadata
  const newRefreshToken = crypto.randomBytes(64).toString("hex");
  const newHash = crypto
    .createHash("sha256")
    .update(newRefreshToken)
    .digest("hex");

  refreshTokenStore.set(newHash, {
    ...payload,
    createdAt: tokenData.createdAt, // Keep original creation time
    lastUsed: Date.now(),
    rotationCount: tokenData.rotationCount + 1,
  });

  return newRefreshToken;
};

const revokeAllUserTokens = (facultyId) => {
  for (const [hash, data] of refreshTokenStore.entries()) {
    if (data.faculty_id === facultyId) {
      refreshTokenStore.delete(hash);
    }
  }
};

// ─── Auth Middleware ────────────────────────────────────────────────────
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      error: "Access token required",
      requestId: req.requestId,
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = verifyAccessToken(token);
    req.user = decoded;
    next();
  } catch (error) {
    if (error.message === "Token has been revoked") {
      return res.status(401).json({
        success: false,
        error: "Token has been revoked",
        requestId: req.requestId,
      });
    }

    if (error.name === "TokenExpiredError") {
      return res.status(401).json({
        success: false,
        error: "Access token expired",
        code: "TOKEN_EXPIRED",
        requestId: req.requestId,
      });
    }

    return res.status(401).json({
      success: false,
      error: "Invalid access token",
      requestId: req.requestId,
    });
  }
};

// ─── Role-Based Access Control ─────────────────────────────────────────
const authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: "Authentication required",
        requestId: req.requestId,
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: "Insufficient permissions",
        requestId: req.requestId,
      });
    }

    next();
  };
};

// ─── Cleanup Job ───────────────────────────────────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [hash, data] of refreshTokenStore.entries()) {
    const age = (now - data.createdAt) / (1000 * 60 * 60 * 24);
    const idleTime = (now - data.lastUsed) / (1000 * 60 * 60);

    // Remove tokens older than 7 days or idle for 24 hours
    if (age > 7 || idleTime > 24) {
      refreshTokenStore.delete(hash);
    }
  }

  // Clean request logs older than 1 hour
  for (const [ip, requests] of requestLog.entries()) {
    const recentRequests = requests.filter((r) => r.timestamp > now - 3600000);
    if (recentRequests.length === 0) {
      requestLog.delete(ip);
    } else {
      requestLog.set(ip, recentRequests);
    }
  }
}, 60000); // Run every minute

module.exports = {
  createRateLimiter,
  zeroTrustValidator,
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  rotateRefreshToken,
  revokeAllUserTokens,
  authenticate,
  authorize,
};
