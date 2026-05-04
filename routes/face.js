const express = require("express");
const router = express.Router();
const faceProcessor = require("../utils/faceProcessor");

// ── EXTRACT FACE DESCRIPTOR FROM IMAGE ──
router.post("/extract-face", async (req, res) => {
  try {
    const { image } = req.body;

    if (!image) {
      return res.status(400).json({
        success: false,
        error: "Image data is required",
      });
    }

    // Extract face descriptor using face-api.js
    const result = await faceProcessor.extractFaceDescriptor(image);

    res.json({
      success: true,
      data: {
        descriptor: result.descriptor,
        score: result.score,
      },
    });
  } catch (error) {
    console.error("Face extraction error:", error.message);

    if (error.message === "No face detected in image") {
      return res.status(422).json({
        success: false,
        error: "No face detected. Please ensure your face is clearly visible.",
      });
    }

    res.status(500).json({
      success: false,
      error: "Failed to process face data",
    });
  }
});

module.exports = router;
