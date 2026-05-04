// server/validations/schemas.js
const { z } = require("zod");

const loginSchema = z.object({
  email: z.string().email("Invalid email format").max(255).trim().toLowerCase(),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(128),
});

const registerSchema = z.object({
  email: z.string().email("Invalid email").max(255).trim().toLowerCase(),
  password: z.string().min(8).max(128),
  first_name: z.string().min(1, "First name required").max(100).trim(),
  last_name: z.string().min(1, "Last name required").max(100).trim(),
  employee_id: z.string().min(1, "Employee ID required").max(50).trim(),
  department: z.string().max(100).trim().optional().nullable(),
  position: z.string().max(100).trim().optional().nullable(),
  employment_type: z.string().max(50).trim().optional().nullable(),
  address: z.string().max(255).trim().optional().nullable(),
  contact_number: z.string().max(20).trim().optional().nullable(),
  campus_id: z.string().uuid("Invalid campus ID").optional().nullable(),
  face_descriptors: z
    .array(
      z.object({
        descriptor: z.array(z.number()),
        dimensions: z.number(),
        confidence: z.number().optional(),
        timestamp: z.number().optional(),
      }),
    )
    .max(5)
    .optional(),
});

const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, "Refresh token required").max(500),
});

const faceVerifySchema = z.object({
  employee_id: z.string().min(1).max(50).trim(),
  face_descriptor: z.array(z.number()).min(128, "Invalid face descriptor"),
});

const enrollFaceSchema = z.object({
  face_descriptors: z
    .array(
      z.object({
        descriptor: z.array(z.number()),
        dimensions: z.number(),
        confidence: z.number().optional(),
        timestamp: z.number().optional(),
      }),
    )
    .min(1)
    .max(5),
});

const updateProfileSchema = z.object({
  first_name: z.string().min(1).max(100).trim().optional(),
  last_name: z.string().min(1).max(100).trim().optional(),
  department: z.string().max(100).trim().optional().nullable(),
  position: z.string().max(100).trim().optional().nullable(),
  employment_type: z.string().max(50).trim().optional().nullable(),
  address: z.string().max(255).trim().optional().nullable(),
  contact_number: z.string().max(20).trim().optional().nullable(),
});

module.exports = {
  loginSchema,
  registerSchema,
  refreshTokenSchema,
  faceVerifySchema,
  enrollFaceSchema,
  updateProfileSchema,
};
