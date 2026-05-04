// server/middleware/validate.js
const { ZodError } = require("zod");

function validate(schema) {
  return (req, res, next) => {
    try {
      req.body = schema.parse(req.body);
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const errors = error.errors.map((err) => ({
          field: err.path.join("."),
          message: err.message,
        }));
        return res.status(400).json({
          success: false,
          error: "Validation failed",
          details: errors,
          requestId: req.requestId,
        });
      }
      next(error);
    }
  };
}

module.exports = { validate };
