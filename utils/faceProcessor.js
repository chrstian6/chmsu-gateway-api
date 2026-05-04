const faceapi = require("face-api.js");
const canvas = require("canvas");
const path = require("path");
const fs = require("fs");

const { Canvas, Image, ImageData } = canvas;
faceapi.env.monkeyPatch({ Canvas, Image, ImageData });

class FaceProcessor {
  constructor() {
    this.modelsLoaded = false;
  }

  areModelsLoaded() {
    return this.modelsLoaded;
  }

  async loadModels() {
    if (this.modelsLoaded) return;

    const modelPath = path.join(__dirname, "..", "models");

    // Check if models exist
    const requiredFiles = [
      "ssd_mobilenetv1_model-shard1",
      "face_landmark_68_model-shard1",
      "face_recognition_model-shard1",
    ];

    for (const file of requiredFiles) {
      if (!fs.existsSync(path.join(modelPath, file))) {
        throw new Error(
          `Model file missing: ${file}. Run download script first.`,
        );
      }
    }

    await Promise.all([
      faceapi.nets.ssdMobilenetv1.loadFromDisk(modelPath),
      faceapi.nets.faceLandmark68Net.loadFromDisk(modelPath),
      faceapi.nets.faceRecognitionNet.loadFromDisk(modelPath),
    ]);

    this.modelsLoaded = true;
    console.log("✅ Face recognition models loaded");
  }

  async extractFaceDescriptor(base64Image) {
    if (!this.modelsLoaded) await this.loadModels();

    const base64Data = base64Image.replace(/^data:image\/\w+;base64,/, "");
    const img = new Image();
    img.src = Buffer.from(base64Data, "base64");

    const detection = await faceapi
      .detectSingleFace(img)
      .withFaceLandmarks()
      .withFaceDescriptor();

    if (!detection) {
      throw new Error("No face detected in image");
    }

    return {
      descriptor: Array.from(detection.descriptor),
      score: detection.detection.score,
    };
  }

  validateAndProcessDescriptors(descriptors) {
    const valid = descriptors
      .filter((d) => d.descriptor?.length === 128)
      .slice(0, parseInt(process.env.MAX_FACE_DESCRIPTORS) || 5);

    if (valid.length === 0) {
      throw new Error("No valid 128-dimension descriptors");
    }

    return {
      descriptors: valid,
      count: valid.length,
      processed_at: new Date().toISOString(),
    };
  }

  compareDescriptors(captured, storedJson) {
    const stored =
      typeof storedJson === "string" ? JSON.parse(storedJson) : storedJson;
    const capturedArray = captured.descriptor || captured;
    const threshold = parseFloat(process.env.FACE_MATCH_THRESHOLD) || 0.6;

    for (const s of stored.descriptors) {
      const distance = this.euclideanDistance(capturedArray, s.descriptor);
      if (distance < threshold) {
        return { match: true, distance };
      }
    }

    return { match: false, distance: null };
  }

  euclideanDistance(a, b) {
    return Math.sqrt(
      a.reduce((sum, val, i) => sum + Math.pow(val - b[i], 2), 0),
    );
  }
}

module.exports = new FaceProcessor();
